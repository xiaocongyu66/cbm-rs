//! mem.rs — 1:1 rewrite of `src/foundation/mem.{c,h}`.
//!
//! Memory budget management. The C version unifies everything through
//! mimalloc (budget from real RSS, allocator-owned heap walks, ownership
//! audits); Rust's GlobalAlloc architecture moves the allocator-internal
//! telemetry to the allocator crate that the binary adopts (mirroring the
//! MI_MALLOC_OVERRIDE split the C documents). This module keeps the
//! budget/pressure/phase logic 1:1 and reads RSS from the OS.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::Mutex;

const MAX_RAM_FRACTION: f64 = 1.0;
const RAM_FRACTION_DEFAULT: f64 = 0.5;
const RAM_FRACTION_16GB: f64 = 0.25;
const RAM_FRACTION_32GB: f64 = 0.35;
const RAM_BYTES_PER_GB: u64 = 1024 * 1024 * 1024;
const MB_DIVISOR: usize = 1024 * 1024;

/// Resolved memory budget (C cbm_mem_budget_t).
#[derive(Debug, Clone)]
pub struct Budget {
    /// Resolved budget in bytes.
    pub budget: usize,
    /// "ram_fraction" | "CBM_MEM_BUDGET_MB" | "daemon_worker_cap".
    pub source: &'static str,
    /// Override was valid but exceeded total_ram → clamped down.
    pub clamped: bool,
    /// Override was present but unparseable / out-of-range / ≤0.
    pub invalid: bool,
    /// Internal worker hard cap reduced the resolved budget.
    pub hard_capped: bool,
}

/// Gradient: smaller machines keep a smaller fraction of their RAM.
pub fn ram_fraction_for_total(total_ram_bytes: u64) -> f64 {
    if total_ram_bytes <= 16 * RAM_BYTES_PER_GB {
        return RAM_FRACTION_16GB;
    }
    if total_ram_bytes <= 32 * RAM_BYTES_PER_GB {
        return RAM_FRACTION_32GB;
    }
    RAM_FRACTION_DEFAULT
}

/// Strict env-override parse (`CBM_MEM_BUDGET_MB`): reject trailing
/// garbage, overflow, and non-positive values — a fat-fingered value
/// ("8GB", a 20-digit typo) becomes fallback-with-warning, never a
/// silently wrong budget.
fn parse_budget_mb(budget_mb: &str) -> Option<i64> {
    let s = budget_mb.trim();
    if s.is_empty() {
        return None;
    }
    // Full-consumption integer parse (strtoll + *end=='\0' semantics).
    // C used base 10 only — a hex prefix is garbage by that contract.
    if s.starts_with("0x") || s.starts_with("0X") {
        return None;
    }
    let digits = s;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok().filter(|&v| v > 0)
}

/// Resolve the budget from total RAM + fraction + optional env override.
pub fn resolve_budget(total_ram: u64, ram_fraction: f64, budget_mb: Option<&str>) -> Budget {
    let fraction = if ram_fraction <= 0.0 || ram_fraction > MAX_RAM_FRACTION {
        RAM_FRACTION_DEFAULT
    } else {
        ram_fraction
    };
    let mut result = Budget {
        budget: (total_ram as f64 * fraction) as usize,
        source: "ram_fraction",
        clamped: false,
        invalid: false,
        hard_capped: false,
    };

    let Some(raw) = budget_mb else {
        return result;
    };
    if raw.is_empty() {
        return result;
    }
    // Strict parse (limits.c convention): trailing garbage / overflow /
    // non-positive → invalid, keep the fraction-derived budget.
    let Some(want_mb) = parse_budget_mb(raw) else {
        result.invalid = true;
        return result;
    };

    result.source = "CBM_MEM_BUDGET_MB";
    let want = want_mb as u64;
    if total_ram > 0 {
        // Compare in MiB space so a valid-but-huge request clamps cleanly.
        if want > total_ram / (MB_DIVISOR as u64) {
            result.budget = total_ram as usize;
            result.clamped = true;
        } else {
            result.budget = (want * MB_DIVISOR as u64) as usize;
        }
    } else if want > (usize::MAX as u64) / MB_DIVISOR as u64 {
        // No clamp target + astronomically large → cap, don't wrap.
        result.budget = usize::MAX;
    } else {
        result.budget = (want * MB_DIVISOR as u64) as usize;
    }
    result
}

/// Apply the per-worker hard cap (N workers × an absolute override would
/// oversubscribe the host, #1654). A lower explicit value still wins;
/// `CBM_MEM_BUDGET_MB` stays the source so the ceiling reads as the user's
/// aggregate, not a silent daemon_worker_cap rewrite.
pub fn resolve_budget_capped(
    total_ram: u64,
    ram_fraction: f64,
    budget_mb: Option<&str>,
    hard_cap_bytes: usize,
) -> Budget {
    let mut result = resolve_budget(total_ram, ram_fraction, budget_mb);
    if hard_cap_bytes > 0 && (result.budget == 0 || result.budget > hard_cap_bytes) {
        let explicit_override = result.source == "CBM_MEM_BUDGET_MB";
        result.budget = hard_cap_bytes;
        if !explicit_override {
            result.source = "daemon_worker_cap";
        }
        result.hard_capped = true;
    }
    result
}

// ── Process-wide budget state ───────────────────────────────────

static BUDGET: AtomicUsize = AtomicUsize::new(0);
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static WAS_OVER: AtomicBool = AtomicBool::new(false);

/// OS-reported resident set size in bytes.
fn os_rss() -> usize {
    // Linux: /proc/self/statm field 2 × page size — authoritative OS RSS
    // (the C documents why mimalloc's current_rss is low-biased there).
    let Ok(statm) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let rss_pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (rss_pages * if ps > 0 { ps as u64 } else { 4096 }) as usize
}

/// Current RSS (bytes).
pub fn rss() -> usize {
    os_rss()
}

/// Peak RSS: getrusage ru_maxrss (KB on Linux), reconciled to be ≥ current
/// (page-granular statm can momentarily exceed the KB-granular peak).
pub fn peak_rss() -> usize {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let kb = unsafe {
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
            ru.ru_maxrss as usize
        } else {
            0
        }
    };
    let peak = kb * 1024;
    peak.max(rss())
}

fn check_pressure(rss_bytes: usize) {
    let budget = BUDGET.load(Ordering::Relaxed);
    if budget == 0 {
        return;
    }
    let over = rss_bytes > budget;
    let was = WAS_OVER.load(Ordering::Relaxed);
    let rss_mb = (rss_bytes / MB_DIVISOR).to_string();
    let budget_mb = (budget / MB_DIVISOR).to_string();
    let pct = ((rss_bytes * 100) / budget).to_string();
    let fields: [(&str, &str); 3] = [
        ("rss_mb", &rss_mb),
        ("budget_mb", &budget_mb),
        ("pct", &pct),
    ];
    if over && !was {
        WAS_OVER.store(true, Ordering::Relaxed);
        crate::log::warn("mem.pressure.warn", &fields);
    } else if !over && was {
        WAS_OVER.store(false, Ordering::Relaxed);
        crate::log::info("mem.pressure.ok", &fields);
    }
}

/// Initialize the budget (first call wins) from `ram_fraction`.
pub fn init(ram_fraction: f64) {
    init_with_cap(ram_fraction, 0);
}

/// Initialize with an optional hard cap.
pub fn init_with_cap(ram_fraction: f64, hard_cap_bytes: usize) {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let total_ram = crate::system_info::system_info().total_ram;
    let resolved = resolve_budget_capped(
        total_ram,
        ram_fraction,
        std::env::var("CBM_MEM_BUDGET_MB").ok().as_deref(),
        hard_cap_bytes,
    );
    BUDGET.store(resolved.budget, Ordering::Relaxed);
    crate::log::info(
        "mem.init",
        &[
            ("budget_mb", &(resolved.budget / MB_DIVISOR).to_string()),
            ("total_ram_mb", &(total_ram / MB_DIVISOR as u64).to_string()),
            ("source", resolved.source),
        ],
    );
    // Record one pressure sample so the state starts consistent.
    check_pressure(rss());
}

/// Test hook: set the budget directly.
pub fn set_budget_for_tests(bytes: usize) {
    INITIALIZED.store(true, Ordering::SeqCst);
    BUDGET.store(bytes, Ordering::SeqCst);
}

pub fn budget() -> usize {
    BUDGET.load(Ordering::Relaxed)
}

pub fn over_budget() -> bool {
    rss() > BUDGET.load(Ordering::Relaxed)
}

/// Per-worker slice of the budget.
pub fn worker_budget(num_workers: i32) -> usize {
    let n = if num_workers <= 0 { 1 } else { num_workers };
    BUDGET.load(Ordering::Relaxed) / n as usize
}

/// Prompt the allocator to return freed pages (mimalloc purge analogue).
/// The Rust global allocator's behavior is runtime-selected; nothing to
/// force here (documented parity gap, same as macOS builds without the
/// override).
pub fn collect() {}

// ── Size-class map (heap walk → OS counters only in this build) ────

pub const MEM_MAP_BUCKETS: usize = 8;

const MEM_MAP_BUCKET_LIMITS: [usize; MEM_MAP_BUCKETS] = [
    64, 256, 1024, 4096, 16384, 65536, 1048576, 0, /* open-ended */
];

pub fn map_bucket_limit(bucket: i32) -> usize {
    if bucket < 0 || bucket as usize >= MEM_MAP_BUCKETS {
        return 0;
    }
    MEM_MAP_BUCKET_LIMITS[bucket as usize]
}

/// Allocator/OS memory map snapshot (C cbm_mem_map_t). Allocator-owned
/// fields (live_*/area_*) are zero in this build: Rust's GlobalAlloc is
/// not introspectable without an allocator crate; the OS fields carry the
/// authoritative numbers.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemMap {
    pub malloc_is_allocator_owned: bool,
    pub os_committed_bytes: usize,
    pub os_rss_bytes: usize,
    pub live_bytes: usize,
    pub live_blocks: usize,
    pub area_committed_bytes: usize,
    pub area_reserved_bytes: usize,
    pub bucket_bytes: [usize; MEM_MAP_BUCKETS],
    pub bucket_blocks: [usize; MEM_MAP_BUCKETS],
}

pub fn map_collect() -> MemMap {
    // With no override, plain allocations are served by the std allocator —
    // mimalloc region ownership does not apply.
    MemMap {
        os_rss_bytes: rss(),
        malloc_is_allocator_owned: false,
        ..MemMap::default()
    }
}

pub fn map_collect_os() -> MemMap {
    map_collect()
}

// ── Pointer ownership counters ───────────────────────────────────

static FOREIGN_POINTERS: AtomicUsize = AtomicUsize::new(0);
static OWNED_POINTERS: AtomicUsize = AtomicUsize::new(0);

pub fn record_pointer_ownership(owned: bool) {
    if owned {
        OWNED_POINTERS.fetch_add(1, Ordering::Relaxed);
    } else {
        FOREIGN_POINTERS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn foreign_pointer_count() -> usize {
    FOREIGN_POINTERS.load(Ordering::Relaxed)
}

pub fn owned_pointer_count() -> usize {
    OWNED_POINTERS.load(Ordering::Relaxed)
}

// ── Phase map (commit deltas per labeled phase) ─────────────────

pub const MEM_PHASE_SLOTS: usize = 24;
pub const MEM_TRACKED_REGIONS: usize = 6;

#[derive(Clone, Copy)]
struct PhaseSlot {
    label: &'static str,
    bytes: i64,
    hits: i64,
}

struct PhaseState {
    slots: Vec<PhaseSlot>,
    open: Option<&'static str>,
    baseline: usize,
}

static PHASE_ENABLED: AtomicI32 = AtomicI32::new(-1); // -1 = undecided
static PHASES: Mutex<Option<PhaseState>> = Mutex::new(None);

fn phase_committed() -> usize {
    // Commit accounting is allocator-internal; RSS is the observable here.
    rss()
}

fn phase_enabled() -> bool {
    let state = PHASE_ENABLED.load(Ordering::Acquire);
    if state >= 0 {
        return state == 1;
    }
    let on = std::env::var("CBM_MEM_PHASES")
        .map(|v| v == "1")
        .unwrap_or(false);
    PHASE_ENABLED.store(if on { 1 } else { 0 }, Ordering::Release);
    on
}

/// Attribute RSS deltas since the previous mark to the previously open
/// phase, then open `label`.
pub fn phase_mark(label: &'static str) {
    if !phase_enabled() {
        return;
    }
    let now = phase_committed();
    let mut guard = PHASES.lock().unwrap_or_else(|e| e.into_inner());
    let st = guard.get_or_insert_with(|| PhaseState {
        slots: Vec::new(),
        open: None,
        baseline: now,
    });
    if let Some(open) = st.open {
        let exists = st.slots.iter_mut().any(|s| s.label == open);
        if !exists && st.slots.len() < MEM_PHASE_SLOTS {
            st.slots.push(PhaseSlot {
                label: open,
                bytes: 0,
                hits: 0,
            });
        }
        if let Some(slot) = st.slots.iter_mut().find(|s| s.label == open) {
            slot.bytes += now as i64 - st.baseline as i64;
            slot.hits += 1;
        }
    }
    st.open = Some(label);
    st.baseline = now;
}

pub fn phase_reset() {
    if !phase_enabled() {
        return;
    }
    let mut guard = PHASES.lock().unwrap_or_else(|e| e.into_inner());
    let st = guard.get_or_insert_with(|| PhaseState {
        slots: Vec::new(),
        open: None,
        baseline: phase_committed(),
    });
    st.slots.clear();
    st.open = None;
    st.baseline = phase_committed();
}

/// Biggest retainer first; `["{\"label\": ..., \"bytes\": ..., \"hits\": ...}"]`.
pub fn phase_report_json() -> String {
    if !phase_enabled() {
        return String::new();
    }
    let guard = PHASES.lock().unwrap_or_else(|e| e.into_inner());
    let Some(st) = guard.as_ref() else {
        return String::new();
    };
    let mut copy = st.slots.clone();
    copy.sort_by_key(|s| std::cmp::Reverse(s.bytes)); // biggest first
    let parts: Vec<String> = copy
        .iter()
        .map(|s| {
            format!(
                "{{\"label\": \"{}\", \"bytes\": {}, \"hits\": {}}}",
                s.label, s.bytes, s.hits
            )
        })
        .collect();
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize tests touching global statics.
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn fraction_gradient() {
        assert!((ram_fraction_for_total(8 * RAM_BYTES_PER_GB) - 0.25).abs() < 1e-9);
        assert!((ram_fraction_for_total(24 * RAM_BYTES_PER_GB) - 0.35).abs() < 1e-9);
        assert!((ram_fraction_for_total(64 * RAM_BYTES_PER_GB) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn resolve_no_override() {
        let b = resolve_budget(10 * MB_DIVISOR as u64, 0.5, None);
        assert_eq!(b.budget, 5 * MB_DIVISOR);
        assert_eq!(b.source, "ram_fraction");
        assert!(!b.clamped && !b.invalid);

        // Invalid fraction → default 0.5.
        let b = resolve_budget(10 * MB_DIVISOR as u64, 2.0, None);
        assert_eq!(b.budget, 5 * MB_DIVISOR);
        let b = resolve_budget(10 * MB_DIVISOR as u64, -0.1, None);
        assert_eq!(b.budget, 5 * MB_DIVISOR);
    }

    #[test]
    fn resolve_with_override() {
        let b = resolve_budget(1024 * MB_DIVISOR as u64, 0.5, Some("256"));
        assert_eq!(b.budget, 256 * MB_DIVISOR);
        assert_eq!(b.source, "CBM_MEM_BUDGET_MB");

        // Above total → clamp.
        let b = resolve_budget(100 * MB_DIVISOR as u64, 0.5, Some("9999"));
        assert_eq!(b.budget, 100 * MB_DIVISOR);
        assert!(b.clamped);

        // Empty string → C returns the fraction budget WITHOUT invalid flag
        // (budget_mb[0]=='\0' early-out happens before the parse).
        let b = resolve_budget(1024 * MB_DIVISOR as u64, 0.5, Some(""));
        assert!(!b.invalid);
        assert_eq!(b.budget, 512 * MB_DIVISOR);

        // Garbage → invalid, fraction budget survives.
        for bad in ["8GB", "0", "-5", "12abc", "abc", "99999999999999999999999"] {
            let b = resolve_budget(1024 * MB_DIVISOR as u64, 0.5, Some(bad));
            assert!(b.invalid, "want invalid for {bad:?}");
            assert_eq!(b.budget, 512 * MB_DIVISOR);
            assert_eq!(b.source, "ram_fraction");
        }
    }

    #[test]
    fn resolve_capped() {
        // Cap below the fraction budget → capped wins (source changes).
        let b = resolve_budget_capped(1024 * MB_DIVISOR as u64, 0.5, None, 100 * MB_DIVISOR);
        assert_eq!(b.budget, 100 * MB_DIVISOR);
        assert_eq!(b.source, "daemon_worker_cap");
        assert!(b.hard_capped);

        // Explicit override stays the source under the cap.
        let b = resolve_budget_capped(1024 * MB_DIVISOR as u64, 0.5, Some("200"), 100 * MB_DIVISOR);
        assert_eq!(b.budget, 100 * MB_DIVISOR);
        assert_eq!(b.source, "CBM_MEM_BUDGET_MB");
        assert!(b.hard_capped);

        // Cap above budget → untouched.
        let b = resolve_budget_capped(1024 * MB_DIVISOR as u64, 0.5, None, 999 * MB_DIVISOR);
        assert_eq!(b.budget, 512 * MB_DIVISOR);
        assert!(!b.hard_capped);
    }

    #[test]
    fn rss_and_peak() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(rss() > 0, "statm RSS must read on Linux CI");
        assert!(peak_rss() >= rss());
    }

    #[test]
    fn budget_tracking_and_pressure() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Set a budget the process surely exceeds? No: use a tiny budget to
        // trip over-budget, then a huge one to clear.
        set_budget_for_tests(1); // 1 byte → over
        assert!(over_budget());
        set_budget_for_tests(usize::MAX / 2);
        assert!(!over_budget());
        assert_eq!(budget(), usize::MAX / 2);
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1) as i32;
        assert_eq!(worker_budget(n), usize::MAX / 2 / n as usize);
        assert_eq!(worker_budget(0), usize::MAX / 2); // <=0 → 1
    }

    #[test]
    fn bucket_limits() {
        assert_eq!(map_bucket_limit(0), 64);
        assert_eq!(map_bucket_limit(6), 1048576);
        assert_eq!(map_bucket_limit(7), 0); // open tail
        assert_eq!(map_bucket_limit(-1), 0);
        assert_eq!(map_bucket_limit(99), 0);
    }

    #[test]
    fn ownership_counters() {
        record_pointer_ownership(true);
        record_pointer_ownership(false);
        assert!(owned_pointer_count() >= 1);
        assert!(foreign_pointer_count() >= 1);
    }

    #[test]
    fn phase_mark_and_report() {
        std::env::set_var("CBM_MEM_PHASES", "1");
        PHASE_ENABLED.store(-1, Ordering::Release);
        phase_reset();
        // C semantics: each mark closes the PREVIOUS open phase, so the
        // final "init" mark stays open at report time → 1 hit each.
        phase_mark("init");
        phase_mark("index");
        phase_mark("init");
        let json = phase_report_json();
        assert!(json.contains("\"label\": \"init\""));
        assert!(json.contains("\"hits\": 1"));
        // Biggest first — both slots present.
        assert!(json.contains("\"label\": \"index\""));
        phase_reset();
        assert_eq!(phase_report_json(), "");
        std::env::remove_var("CBM_MEM_PHASES");
        PHASE_ENABLED.store(-1, Ordering::Release);
    }
}
