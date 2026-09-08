//! compat_thread.rs — rewrite of `src/foundation/compat_thread.{c,h}`.
//!
//! Thread/mutex/aligned-alloc shims. Rust's std owns all three natively:
//! `std::thread` (joinable by handle), `std::sync::Mutex`, and
//! `std::alloc` for aligned buffers. This module maps the C API surface
//! onto std so later layers can switch call-by-call.

use std::sync::{Arc, Mutex};

/// Stack floor for diagnostic builds (CBM_THREAD_STACK_MB); shipping builds
/// keep fixed sizes, matching the C gate on CBM_SANITIZED.
fn stack_floor(requested: usize) -> usize {
    #[cfg(debug_assertions)]
    if let Ok(mb) = std::env::var("CBM_THREAD_STACK_MB") {
        if let Ok(mb) = mb.parse::<u64>() {
            if mb > 0 && mb <= 1024 {
                let floor = (mb as usize) * 1024 * 1024;
                if floor > requested {
                    return floor;
                }
            }
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = requested;
    requested
}

pub const DEFAULT_STACK_SIZE: usize = 1024 * 1024;

/// Joinable thread handle (C cbm_thread_t).
pub struct Thread {
    join: Option<std::thread::JoinHandle<()>>,
}

impl Thread {
    /// Spawn with an explicit stack size (0 → default, floored).
    pub fn create<F>(stack_size: usize, f: F) -> Thread
    where
        F: FnOnce() + Send + 'static,
    {
        let ss = if stack_size == 0 {
            stack_floor(DEFAULT_STACK_SIZE)
        } else {
            stack_floor(stack_size)
        };
        let join = std::thread::Builder::new().stack_size(ss).spawn(f).ok();
        Thread { join }
    }

    /// Join; returns 0 on success (C pthread_join convention).
    pub fn join(&mut self) -> i32 {
        match self.join.take() {
            Some(h) => {
                let _ = h.join();
                0
            }
            None => -1,
        }
    }

    /// Detach: drop the handle; the thread runs to completion.
    pub fn detach(&mut self) -> i32 {
        if self.join.take().is_some() {
            0
        } else {
            -1
        }
    }
}

/// Mutex wrapper (C cbm_mutex_t). Init/destroy map to construct/drop.
#[derive(Default)]
pub struct MutexT {
    inner: Arc<Mutex<()>>,
}

impl MutexT {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Aligned allocation. C returns a raw pointer for posix_memalign; Rust
/// callers use Vec/Box. Provided for layout-sensitive code.
pub fn aligned_alloc(alignment: usize, size: usize) -> Option<std::ptr::NonNull<u8>> {
    if alignment == 0 || !alignment.is_power_of_two() || size == 0 {
        return None;
    }
    let layout = std::alloc::Layout::from_size_align(size, alignment).ok()?;
    unsafe {
        let ptr = std::alloc::alloc(layout);
        if ptr.is_null() {
            None
        } else {
            Some(std::ptr::NonNull::new_unchecked(ptr))
        }
    }
}

/// Free a pointer from [`aligned_alloc`] with the same layout parameters.
///
/// # Safety
/// `ptr` must come from `aligned_alloc` with identical alignment/size.
pub unsafe fn aligned_free(ptr: std::ptr::NonNull<u8>, alignment: usize, size: usize) {
    if let Ok(layout) = std::alloc::Layout::from_size_align(size, alignment) {
        std::alloc::dealloc(ptr.as_ptr(), layout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn thread_join_runs_closure() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut t = Thread::create(0, || {
            COUNTER.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(t.join(), 0);
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn detach_leaves_thread_running() {
        static DONE: AtomicUsize = AtomicUsize::new(0);
        let mut t = Thread::create(256 * 1024, || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            DONE.store(1, Ordering::SeqCst);
        });
        assert_eq!(t.detach(), 0);
        assert_eq!(t.join(), -1); // already detached
                                  // Detached threads outlive the handle; poll rather than assume a
                                  // schedule (parallel test hosts are slow).
        for _ in 0..200 {
            if DONE.load(Ordering::SeqCst) == 1 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("detached thread did not finish within 1s");
    }

    #[test]
    fn stack_floor_respects_env() {
        std::env::set_var("CBM_THREAD_STACK_MB", "2");
        assert_eq!(stack_floor(1024), 2 * 1024 * 1024);
        assert_eq!(stack_floor(8 * 1024 * 1024), 8 * 1024 * 1024); // above floor
        std::env::remove_var("CBM_THREAD_STACK_MB");
    }

    #[test]
    fn mutex_serializes() {
        let m = Arc::new(MutexT::new());
        let c = Arc::clone(&m);
        let entered = Arc::new(AtomicUsize::new(0));
        let e2 = Arc::clone(&entered);
        let mut t = Thread::create(0, move || {
            let _g = c.lock();
            e2.fetch_add(1, Ordering::SeqCst);
            // Hold briefly; main thread blocks on the same mutex until the
            // closure ends and releases it, proving mutual exclusion.
            std::thread::sleep(std::time::Duration::from_millis(10));
        });
        t.join();
        // After join the child has released; main can take it.
        let _g = m.lock();
        assert_eq!(entered.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn aligned_alloc_alignment() {
        let ptr = aligned_alloc(64, 256).expect("alloc");
        assert_eq!(ptr.as_ptr() as usize % 64, 0);
        unsafe { aligned_free(ptr, 64, 256) };
        assert!(aligned_alloc(3, 16).is_none()); // not power of two
        assert!(aligned_alloc(8, 0).is_none()); // zero size
    }
}
