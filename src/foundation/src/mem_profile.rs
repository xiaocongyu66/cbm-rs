//! mem_profile.rs — 1:1 rewrite of `src/foundation/mem_profile.{c,h}`.
//!
//! Opt-in heap profiling harness: two open-addressed tables (sites keyed by
//! stack hash, pointers keyed by block address) guarded by one mutex. A
//! reentrancy guard makes the profiler invisible to itself — anything it
//! calls that allocates would otherwise recurse through the hooks.
//! Stack capture uses libc backtrace(3) as the C does.

use std::sync::Mutex;
use std::sync::OnceLock;

const FRAMES: usize = 8;
#[cfg(not(test))]
const SKIP_FRAMES: usize = 2;
const SITES: usize = 4096;
const POINTERS: usize = 262_144;
const DEFAULT_MIN: usize = 32768;

#[derive(Debug, Clone, Copy, Default)]
pub struct Totals {
    pub sites: usize,
    pub live_bytes: usize,
    pub live_blocks: usize,
    pub total_bytes: usize,
    pub untracked_frees: usize,
    pub site_table_full: usize,
    pub pointer_table_full: usize,
    /// Stack capture returned nothing (Windows ARM64 can legitimately fail).
    pub capture_failed: usize,
}

#[derive(Clone, Copy)]
struct Site {
    hash: u64, // 0 = empty
    frames: [usize; FRAMES],
    frame_count: usize,
    live_bytes: usize,
    live_blocks: usize,
    total_bytes: usize,
    total_blocks: usize,
    peak_live_bytes: usize,
}

#[derive(Clone, Copy)]
struct Pointer {
    block: usize, // 0 = empty
    size: usize,
    site: usize,
}

#[derive(Default)]
struct ProfileState {
    sites: Vec<Site>,
    pointers: Vec<Pointer>,
    totals: Totals,
}

static STATE: OnceLock<Mutex<ProfileState>> = OnceLock::new();
static ENABLED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static MIN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(DEFAULT_MIN);

fn state() -> &'static Mutex<ProfileState> {
    STATE.get_or_init(|| {
        Mutex::new(ProfileState {
            sites: vec![
                Site {
                    hash: 0,
                    frames: [0; FRAMES],
                    frame_count: 0,
                    live_bytes: 0,
                    live_blocks: 0,
                    total_bytes: 0,
                    total_blocks: 0,
                    peak_live_bytes: 0
                };
                SITES
            ],
            pointers: vec![
                Pointer {
                    block: 0,
                    size: 0,
                    site: 0
                };
                POINTERS
            ],
            totals: Totals::default(),
        })
    })
}

// Thread-local reentrancy guard (profiler runs inside the allocator).
std::thread_local! {
    static REENTRANT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn enabled() -> bool {
    let s = ENABLED.load(std::sync::atomic::Ordering::Acquire);
    if s >= 0 {
        return s == 1;
    }
    let on = std::env::var("CBM_MEM_PROFILE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if on {
        if let Ok(min) = std::env::var("CBM_MEM_PROFILE_MIN") {
            if let Ok(p) = min.parse::<usize>() {
                if p > 0 {
                    MIN.store(p, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }
    ENABLED.store(if on { 1 } else { 0 }, std::sync::atomic::Ordering::Release);
    on
}

pub fn threshold() -> usize {
    let _ = enabled();
    MIN.load(std::sync::atomic::Ordering::Relaxed)
}

#[allow(unused_variables)]
fn capture(frames: &mut [usize; FRAMES], caller: Option<usize>) -> usize {
    #[cfg(all(not(test), not(target_env = "gnu")))]
    let _ = frames;
    // backtrace(3) is glibc-only (absent from musl's libc bindings); musl
    // targets degrade to capture_failed, preserving totals semantics.
    #[cfg(all(not(test), target_env = "gnu"))]
    unsafe {
        let mut raw: [*mut libc::c_void; FRAMES + SKIP_FRAMES] =
            [std::ptr::null_mut(); FRAMES + SKIP_FRAMES];
        let got = libc::backtrace(raw.as_mut_ptr(), (FRAMES + SKIP_FRAMES) as i32);
        if got <= SKIP_FRAMES as i32 {
            return 0;
        }
        let count = (got as usize - SKIP_FRAMES).min(FRAMES);
        for (i, slot) in frames.iter_mut().enumerate().take(count) {
            *slot = raw[i + SKIP_FRAMES] as usize;
        }
        count
    }
    #[cfg(all(not(test), not(target_env = "gnu")))]
    {
        let _ = caller;
        0
    }
    // Test builds have no malloc hook path; synthesize a stack from the caller.
    #[cfg(test)]
    {
        let _ = caller;
        frames[0] = caller.unwrap_or(0x1000);
        for f in frames.iter_mut().skip(1) {
            *f = 0;
        }
        1
    }
}

fn site_hash(frames: &[usize; FRAMES], count: usize) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &f in &frames[..count] {
        h ^= f as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn intern_site(st: &mut ProfileState, frames: &[usize; FRAMES], count: usize) -> usize {
    let hash = site_hash(frames, count);
    let mut index = (hash as usize) % SITES;
    for _ in 0..SITES {
        let site = &mut st.sites[index];
        if site.hash == hash {
            return index;
        }
        if site.hash == 0 {
            site.hash = hash;
            site.frames[..count].copy_from_slice(&frames[..count]);
            site.frame_count = count;
            st.totals.sites += 1;
            return index;
        }
        index = (index + 1) % SITES;
    }
    usize::MAX
}

fn pointer_slot(block: usize) -> usize {
    let mut v = block;
    // Mix high bits down: page-aligned addresses would collide.
    v ^= v >> 20;
    v = v.wrapping_mul(2654435761);
    v % POINTERS
}

/// Record an allocation of `size` bytes at `block`, attributed to the call
/// site (optionally attributing to `caller` directly).
pub fn alloc_at(block: *mut u8, size: usize, caller: Option<usize>) {
    if block.is_null() || REENTRANT.with(|r| r.get()) {
        return;
    }
    REENTRANT.with(|r| r.set(true));
    if !enabled() || size < threshold() {
        REENTRANT.with(|r| r.set(false));
        return;
    }
    let mut frames = [0usize; FRAMES];
    let count = capture(&mut frames, caller);
    if count == 0 {
        let mut st = state().lock().unwrap();
        st.totals.capture_failed += 1;
        drop(st);
        REENTRANT.with(|r| r.set(false));
        return;
    }
    let mut st = state().lock().unwrap();
    let site_index = intern_site(&mut st, &frames, count);
    if site_index == usize::MAX {
        st.totals.site_table_full += 1;
        drop(st);
        REENTRANT.with(|r| r.set(false));
        return;
    }
    let block_addr = block as usize;
    let mut slot = pointer_slot(block_addr);
    let mut stored = false;
    for _ in 0..POINTERS {
        if st.pointers[slot].block == 0 {
            st.pointers[slot] = Pointer {
                block: block_addr,
                size,
                site: site_index,
            };
            stored = true;
            break;
        }
        slot = (slot + 1) % POINTERS;
    }
    if !stored {
        st.totals.pointer_table_full += 1;
        drop(st);
        REENTRANT.with(|r| r.set(false));
        return;
    }
    let site = &mut st.sites[site_index];
    site.live_bytes += size;
    site.live_blocks += 1;
    site.total_bytes += size;
    site.total_blocks += 1;
    if site.live_bytes > site.peak_live_bytes {
        site.peak_live_bytes = site.live_bytes;
    }
    st.totals.live_bytes += size;
    st.totals.live_blocks += 1;
    st.totals.total_bytes += size;
    drop(st);
    REENTRANT.with(|r| r.set(false));
}

pub fn alloc(block: *mut u8, size: usize) {
    alloc_at(block, size, None);
}

/// Release the tracking record for `block`. Untracked frees (below
/// threshold or never allocated) count as a scale check, not an error.
pub fn free(block: *mut u8) {
    if block.is_null() || REENTRANT.with(|r| r.get()) {
        return;
    }
    REENTRANT.with(|r| r.set(true));
    if !enabled() {
        REENTRANT.with(|r| r.set(false));
        return;
    }
    let mut st = state().lock().unwrap();
    let block_addr = block as usize;
    let mut slot = pointer_slot(block_addr);
    for _ in 0..POINTERS {
        let entry = st.pointers[slot];
        if entry.block == block_addr {
            let site = &mut st.sites[entry.site];
            site.live_bytes -= entry.size;
            site.live_blocks -= 1;
            st.totals.live_bytes -= entry.size;
            st.totals.live_blocks -= 1;
            st.pointers[slot] = Pointer {
                block: 0,
                size: 0,
                site: 0,
            };
            drop(st);
            REENTRANT.with(|r| r.set(false));
            return;
        }
        if entry.block == 0 {
            break; // linear probe ended: never tracked
        }
        slot = (slot + 1) % POINTERS;
    }
    st.totals.untracked_frees += 1;
    drop(st);
    REENTRANT.with(|r| r.set(false));
}

/// Test-only: clear all tables and totals (C tests run in separate
/// processes; Rust unit tests share one).
#[cfg(test)]
pub fn reset_state() {
    let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
    for site in st.sites.iter_mut() {
        *site = Site {
            hash: 0,
            frames: [0; FRAMES],
            frame_count: 0,
            live_bytes: 0,
            live_blocks: 0,
            total_bytes: 0,
            total_blocks: 0,
            peak_live_bytes: 0,
        };
    }
    for p in st.pointers.iter_mut() {
        *p = Pointer {
            block: 0,
            size: 0,
            site: 0,
        };
    }
    st.totals = Totals::default();
}

pub fn totals() -> Totals {
    if !enabled() {
        return Totals::default();
    }
    let st = state().lock().unwrap();
    st.totals
}

/// Append a JSON dump (totals + per-site records) to `path`.
pub fn dump(path: &std::path::Path, label: &str) -> bool {
    if !enabled() {
        return false;
    }
    use std::io::Write;
    let Ok(mut out) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    else {
        return false;
    };
    let st = state().lock().unwrap();
    let t = &st.totals;
    let _ = writeln!(
        out,
        "{{\"label\":\"{label}\",\"threshold\":{},\"sites\":{},\"live_bytes\":{},\"live_blocks\":{},\"total_bytes\":{},\"untracked_frees\":{},\"site_table_full\":{},\"pointer_table_full\":{}}}",
        MIN.load(std::sync::atomic::Ordering::Relaxed),
        t.sites,
        t.live_bytes,
        t.live_blocks,
        t.total_bytes,
        t.untracked_frees,
        t.site_table_full,
        t.pointer_table_full
    );
    for site in &st.sites {
        if site.hash == 0 || site.total_blocks == 0 {
            continue;
        }
        let frames: Vec<String> = site.frames[..site.frame_count]
            .iter()
            .map(|f| format!("\"{f:#x}\""))
            .collect();
        let _ = writeln!(
            out,
            "{{\"label\":\"{label}\",\"site\":{},\"live_bytes\":{},\"live_blocks\":{},\"total_bytes\":{},\"total_blocks\":{},\"peak_live\":{},\"frames\":[{}]}}",
            site.hash,
            site.live_bytes,
            site.live_blocks,
            site.total_bytes,
            site.total_blocks,
            site.peak_live_bytes,
            frames.join(",")
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Global profiler state + env; serialize the tests that touch it.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard(on: bool) {
        if on {
            std::env::set_var("CBM_MEM_PROFILE", "1");
        } else {
            std::env::remove_var("CBM_MEM_PROFILE");
        }
        ENABLED.store(-1, std::sync::atomic::Ordering::Release);
        MIN.store(DEFAULT_MIN, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn disabled_is_noop() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        env_guard(false);
        let mut b = Box::new([0u8; 16]);
        alloc(b.as_mut_ptr(), 16);
        free(b.as_mut_ptr());
        let t = totals();
        assert_eq!(t.sites, 0);
        assert_eq!(t.total_bytes, 0);
    }

    #[test]
    fn alloc_free_tracking() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        env_guard(true);
        // Use a stack buffer as a stand-in block (capture is synthesized in tests).
        let mut buf = [0u8; 65536];
        let ptr = buf.as_mut_ptr();
        alloc(ptr, 65536);
        let t = totals();
        assert_eq!(t.sites, 1);
        assert_eq!(t.live_bytes, 65536);
        assert_eq!(t.live_blocks, 1);
        assert_eq!(t.total_bytes, 65536);
        free(ptr);
        let t = totals();
        assert_eq!(t.live_bytes, 0);
        assert_eq!(t.live_blocks, 0);
        assert_eq!(t.untracked_frees, 0);
        // Freeing an unknown pointer counts, not errors.
        let mut other = [0u8; 8];
        free(other.as_mut_ptr());
        assert_eq!(totals().untracked_frees, 1);
        env_guard(false);
    }

    #[test]
    fn sub_threshold_untracked() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        env_guard(true);
        std::env::set_var("CBM_MEM_PROFILE_MIN", "1000");
        ENABLED.store(-1, std::sync::atomic::Ordering::Release);
        MIN.store(1000, std::sync::atomic::Ordering::Relaxed);
        let mut buf = [0u8; 16];
        alloc(buf.as_mut_ptr(), 16); // below min → ignored
        assert_eq!(totals().total_bytes, 0);
        env_guard(false);
    }

    #[test]
    fn dump_emits_json() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();
        env_guard(true);
        let mut buf = [0u8; 40000];
        alloc(buf.as_mut_ptr(), 40000);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cbm-memprof-{}.json", std::process::id()));
        assert!(dump(&path, "test"));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"label\":\"test\""));
        assert!(content.contains("\"live_bytes\":40000")); // this test's block is live
        assert!(content.contains("\"frames\":["));
        std::fs::remove_file(&path).ok();
        free(buf.as_mut_ptr());
        env_guard(false);
    }
}
