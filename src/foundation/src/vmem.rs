//! vmem.rs — 1:1 rewrite of `src/foundation/vmem.{c,h}`.
//!
//! Budget-tracked virtual-memory allocator: mmap-based, page-aligned,
//! OS-zeroed allocations tracked against a configurable budget (fraction
//! of physical RAM). Pressure transitions are logged with hysteresis to
//! avoid storms near the budget boundary.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MB: usize = 1024 * 1024;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static WAS_OVER: AtomicBool = AtomicBool::new(false);
static INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Budget lives behind a mutex: written once at init, read on the hot path
/// via cached copies below (AtomicUsize) for lock-free access.
static BUDGET: AtomicUsize = AtomicUsize::new(0);

fn page_size() -> usize {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 {
        ps as usize
    } else {
        4096
    }
}

fn round_to_page(size: usize) -> usize {
    let ps = page_size();
    (size + ps - 1) & !(ps - 1)
}

fn check_pressure(allocated: usize) {
    let budget = BUDGET.load(Ordering::Relaxed);
    if budget == 0 {
        return;
    }
    let over = allocated > budget;
    let was = WAS_OVER.load(Ordering::Relaxed);
    if over && !was {
        WAS_OVER.store(true, Ordering::Relaxed);
        crate::log::warn(
            "mem.pressure.warn",
            &[
                ("allocated_mb", &(allocated / MB).to_string()),
                ("budget_mb", &(budget / MB).to_string()),
                ("pct", &((allocated * 100) / budget).to_string()),
            ],
        );
    } else if !over && was {
        WAS_OVER.store(false, Ordering::Relaxed);
        crate::log::info(
            "mem.pressure.ok",
            &[
                ("allocated_mb", &(allocated / MB).to_string()),
                ("budget_mb", &(budget / MB).to_string()),
                ("pct", &((allocated * 100) / budget).to_string()),
            ],
        );
    }
}

fn update_peak(allocated: usize) {
    let mut old_peak = PEAK.load(Ordering::Relaxed);
    while allocated > old_peak {
        match PEAK.compare_exchange_weak(old_peak, allocated, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => old_peak = actual,
        }
    }
}

/// Set the budget to `total_ram * ram_fraction`. Only the first call takes
/// effect; invalid fractions default to 0.5.
pub fn init(ram_fraction: f64) {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let fraction = if ram_fraction <= 0.0 || ram_fraction > 1.0 {
        0.5
    } else {
        ram_fraction
    };
    let info = crate::system_info::system_info();
    let budget = (info.total_ram as f64 * fraction) as usize;
    BUDGET.store(budget, Ordering::Relaxed);
    crate::log::info(
        "vmem.init",
        &[
            ("budget_mb", &(budget / MB).to_string()),
            ("total_ram_mb", &(info.total_ram / MB as u64).to_string()),
        ],
    );
}

/// Test hook: reset static state (the C has none; needed for hermetic tests).
pub fn reset_for_tests(budget: usize) {
    INITIALIZED.store(true, Ordering::SeqCst);
    BUDGET.store(budget, Ordering::SeqCst);
}

/// Page-aligned mmap allocation, tracked against the budget.
/// Returns a guard freeing on drop — the C free(ptr, size) pairing is
/// collapsed into RAII.
pub struct VmemBuf {
    ptr: *mut u8,
    alloc_size: usize,
    request_size: usize,
}

// Raw mmap handle; the buffer itself is plain memory.
unsafe impl Send for VmemBuf {}

impl VmemBuf {
    pub fn len(&self) -> usize {
        self.request_size
    }
    pub fn is_empty(&self) -> bool {
        self.request_size == 0
    }
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: alloc_size bytes are mapped PROT_READ|PROT_WRITE.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.request_size) }
    }
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts(self.ptr, self.request_size) }
    }
}

impl Drop for VmemBuf {
    fn drop(&mut self) {
        // SAFETY: paired with mmap in alloc.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.alloc_size);
        }
        let new_total = ALLOCATED.fetch_sub(self.alloc_size, Ordering::SeqCst) - self.alloc_size;
        check_pressure(new_total);
    }
}

/// Allocate `size` bytes (page-rounded mapping, zeroed by OS).
pub fn alloc(size: usize) -> Option<VmemBuf> {
    if size == 0 {
        return None;
    }
    let alloc_size = round_to_page(size);
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        crate::log::error(
            "vmem.alloc.fail",
            &[("size_mb", if size > MB { "large" } else { "small" })],
        );
        return None;
    }
    let new_total = ALLOCATED.fetch_add(alloc_size, Ordering::SeqCst) + alloc_size;
    update_peak(new_total);
    check_pressure(new_total);
    Some(VmemBuf {
        ptr: ptr as *mut u8,
        alloc_size,
        request_size: size,
    })
}

/// Current total mapped bytes.
pub fn allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed)
}

/// High-water mark of total mapped bytes.
pub fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// Configured budget in bytes (0 = not initialized).
pub fn budget() -> usize {
    BUDGET.load(Ordering::Relaxed)
}

pub fn over_budget() -> bool {
    ALLOCATED.load(Ordering::Relaxed) > BUDGET.load(Ordering::Relaxed)
}

/// Per-worker slice of the budget.
pub fn worker_budget(num_workers: i32) -> usize {
    let n = if num_workers <= 0 { 1 } else { num_workers };
    BUDGET.load(Ordering::Relaxed) / n as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialize tests that touch global statics.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn alloc_roundtrip_and_tracking() {
        let _g = LOCK.lock().unwrap();
        reset_for_tests(64 * MB);
        let before = allocated();
        {
            let mut buf = alloc(10_000).expect("mmap alloc");
            assert_eq!(buf.len(), 10_000);
            assert!(allocated() >= before + 12_288); // 3 pages (4K pages)
                                                     // OS-zeroed:
            assert!(buf.as_slice().iter().all(|&b| b == 0));
            buf.as_slice_mut()[0] = 42;
            assert_eq!(buf.as_slice()[0], 42);
        } // drop → munmap, tracking decremented
        assert_eq!(allocated(), before);
    }

    #[test]
    fn peak_never_decreases() {
        let _g = LOCK.lock().unwrap();
        reset_for_tests(64 * MB);
        let p0 = peak();
        {
            let _b = alloc(2 * MB).unwrap();
        }
        assert!(peak() >= p0);
        let _b2 = alloc(MB).unwrap();
        assert!(peak() >= p0);
    }

    #[test]
    fn budget_helpers() {
        let _g = LOCK.lock().unwrap();
        reset_for_tests(100 * MB);
        assert_eq!(budget(), 100 * MB);
        assert_eq!(worker_budget(4), 25 * MB);
        assert_eq!(worker_budget(0), 100 * MB); // <=0 → 1 worker
        assert!(!over_budget());
        // Overshoot the budget:
        let keep: Vec<VmemBuf> = (0..4).map(|_| alloc(30 * MB).unwrap()).collect();
        assert!(over_budget());
        drop(keep);
        assert!(!over_budget());
    }

    #[test]
    fn zero_alloc_is_none() {
        assert!(alloc(0).is_none());
    }
}
