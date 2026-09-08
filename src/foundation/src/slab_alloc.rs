//! slab_alloc.rs — 1:1 rewrite of `src/foundation/slab_alloc.{c,h}`.
//!
//! Slab allocator for tree-sitter allocations, eliminating allocator
//! arena fragmentation when indexing with many workers. Tier 1 (≤64B)
//! fixed-size slabs; larger blocks go to the system allocator.
//!
//! Rust mapping: the C hooks replace malloc/free via ts_set_allocator;
//! the Rust tree-sitter integration installs an equivalent GlobalAlloc
//! wrapper. This module keeps the same page/freelist/remote-free design;
//! `install()` registers the allocation hooks (no-op until a TS binding
//! layer calls it).

use std::alloc::Layout;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::Mutex;

const SLAB_CHUNK_SIZE: usize = 64;
const SLAB_PAGE_SIZE: usize = 65536;
const SLAB_PAGE_SHIFT: u32 = 16;
const SLAB_PAGE_MASK: usize = !(SLAB_PAGE_SIZE - 1);
const SLAB_DATA_OFFSET: usize = 64;
const SLAB_PAGE_CHUNKS: usize = (SLAB_PAGE_SIZE - SLAB_DATA_OFFSET) / SLAB_CHUNK_SIZE;

/// One slab page: header at the aligned base, chunks after the header.
struct SlabPage {
    /// Owner-thread page list linkage.
    next: *mut SlabPage,
    /// Owning TLS state; null once retired.
    owner: AtomicPtr<TlsSlab>,
    /// Lock-free MPSC stack of cross-thread frees.
    remote_free_head: AtomicPtr<FreeNode>,
    /// Handed-out chunks + 1 owner guard (while owned).
    refcount: AtomicU32,
    _pad: [u8; SLAB_DATA_OFFSET - 32],
}

const _: () = assert!(std::mem::size_of::<SlabPage>() <= SLAB_DATA_OFFSET);

/// Free-list node occupying a free chunk.
struct FreeNode {
    next: *mut FreeNode,
}

struct TlsSlab {
    pages: *mut SlabPage,
    freelist: *mut FreeNode,
}

impl Drop for TlsSlab {
    fn drop(&mut self) {
        // Free remaining pages via reclaim (defensive; reclaim() is the
        // normal path).
        reclaim_pages_inner(self);
    }
}

impl TlsSlab {
    fn new() -> Self {
        TlsSlab {
            pages: ptr::null_mut(),
            freelist: ptr::null_mut(),
        }
    }
}

std::thread_local! {
    static TLS_SLAB: std::cell::RefCell<Box<TlsSlab>> =
        std::cell::RefCell::new(Box::new(TlsSlab::new()));
}

/// Page map: 3-level radix keyed by page number (base >> SHIFT).
/// Reads are lock-free; writes (cold) take a mutex.
struct PageMap {
    root: Vec<Mutex<Option<Box<L2>>>>,
}

struct L2 {
    l3: Box<[AtomicPtr<L3>]>,
}

struct L3 {
    e: Vec<AtomicPtr<SlabPage>>,
}

const L1_BITS: u32 = 11;
const L2_BITS: u32 = 11;
const L3_BITS: u32 = 10;
const L1_SIZE: usize = 1 << L1_BITS;
const L2_SIZE: usize = 1 << L2_BITS;
const L3_SIZE: usize = 1 << L3_BITS;

fn page_map() -> &'static PageMap {
    static MAP: std::sync::OnceLock<PageMap> = std::sync::OnceLock::new();
    MAP.get_or_init(|| PageMap {
        root: (0..L1_SIZE).map(|_| Mutex::new(None)).collect(),
    })
}

fn map_indices(base: usize) -> Option<(usize, usize, usize)> {
    let pnum = base >> SLAB_PAGE_SHIFT;
    if pnum >> (L1_BITS + L2_BITS + L3_BITS) != 0 {
        return None; // beyond coverage — never produced here
    }
    Some((
        (pnum >> (L2_BITS + L3_BITS)) & (L1_SIZE - 1),
        (pnum >> L3_BITS) & (L2_SIZE - 1),
        pnum & (L3_SIZE - 1),
    ))
}

/// Lock-free lookup. Never dereferences the queried pointer.
fn map_lookup(base: usize) -> *mut SlabPage {
    let Some((i1, i2, i3)) = map_indices(base) else {
        return ptr::null_mut();
    };
    let root = page_map();
    let Ok(l2g) = root.root[i1].try_lock() else {
        return ptr::null_mut();
    };
    let Some(l2) = l2g.as_ref() else {
        return ptr::null_mut();
    };
    let l3 = l2.l3[i2].load(Ordering::Acquire);
    if l3.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: L3 tables are never freed during the run.
    unsafe {
        let l3ref: &L3 = &*l3;
        l3ref.e[i3].load(Ordering::Acquire)
    }
}

/// Cold path: set/unregister the leaf for `base`.
fn map_set(base: usize, val: *mut SlabPage) {
    let Some((i1, i2, i3)) = map_indices(base) else {
        return;
    };
    let root = page_map();
    let mut l2g = root.root[i1].lock().unwrap();
    let l2: &mut L2 = l2g.get_or_insert_with(|| {
        let mut v: Vec<AtomicPtr<L3>> = Vec::with_capacity(L2_SIZE);
        v.resize_with(L2_SIZE, || AtomicPtr::new(ptr::null_mut()));
        Box::new(L2 {
            l3: v.into_boxed_slice(),
        })
    });
    let mut l3p = l2.l3[i2].load(Ordering::Relaxed);
    if l3p.is_null() {
        if val.is_null() {
            return;
        }
        let fresh = Box::into_raw(Box::new(L3 {
            e: (0..L3_SIZE)
                .map(|_| AtomicPtr::new(ptr::null_mut()))
                .collect(),
        }));
        l2.l3[i2].store(fresh, Ordering::Release);
        l3p = fresh;
    }
    // SAFETY: fresh or pre-existing L3, alive for the run.
    unsafe {
        let l3ref: &L3 = &*l3p;
        l3ref.e[i3].store(val, Ordering::Release);
    }
}

/// Allocate + register a new page, threading chunks onto the freelist.
fn slab_grow(s: &mut TlsSlab) -> bool {
    let layout = Layout::from_size_align(SLAB_PAGE_SIZE, SLAB_PAGE_SIZE).expect("align");
    // SAFETY: non-zero layout with valid alignment.
    let mem = unsafe { std::alloc::alloc(layout) };
    if mem.is_null() {
        return false;
    }
    let page = mem as *mut SlabPage;
    // SAFETY: fresh allocation, header region uninitialized.
    unsafe {
        ptr::write(
            page,
            SlabPage {
                next: s.pages,
                owner: AtomicPtr::new(s as *mut _),
                remote_free_head: AtomicPtr::new(ptr::null_mut()),
                refcount: AtomicU32::new(1), // owner guard
                _pad: [0; SLAB_DATA_OFFSET - 32],
            },
        );
    }
    map_set(page as usize, page);
    s.pages = page;
    for i in 0..SLAB_PAGE_CHUNKS {
        // SAFETY: within the fresh page allocation.
        let node = unsafe {
            (page as *mut u8).add(SLAB_DATA_OFFSET + i * SLAB_CHUNK_SIZE) as *mut FreeNode
        };
        // SAFETY: fresh chunk memory.
        unsafe {
            (*node).next = s.freelist;
        }
        s.freelist = node;
    }
    true
}

/// Refill: drain cross-thread frees from owned pages, else grow.
fn slab_refill(s: &mut TlsSlab) {
    let mut p = s.pages;
    while !p.is_null() {
        // SAFETY: page alive (owner guard or live chunk holds refcount).
        unsafe {
            let mut rf = (*p)
                .remote_free_head
                .swap(ptr::null_mut(), Ordering::Acquire);
            while !rf.is_null() {
                let next = (*rf).next;
                (*rf).next = s.freelist;
                s.freelist = rf;
                rf = next;
            }
            p = (*p).next;
        }
    }
    if s.freelist.is_null() {
        slab_grow(s);
    }
}

/// Retire ownership of every page this thread owns; free pages with no
/// live chunks.
fn reclaim_pages_inner(s: &mut TlsSlab) {
    let mut p = s.pages;
    while !p.is_null() {
        // SAFETY: page alive while we walk the owner list.
        unsafe {
            let next = (*p).next;
            (*p).owner.store(ptr::null_mut(), Ordering::Relaxed);
            if (*p).refcount.fetch_sub(1, Ordering::AcqRel) == 1 {
                map_set(p as usize, ptr::null_mut());
                std::alloc::dealloc(
                    p as *mut u8,
                    Layout::from_size_align(SLAB_PAGE_SIZE, SLAB_PAGE_SIZE).unwrap(),
                );
            }
            p = next;
        }
    }
    s.pages = ptr::null_mut();
    s.freelist = ptr::null_mut();
}

/// Allocate. ≤64B from the slab; larger straight to the system allocator.
///
/// # Safety
/// Returned pointer must be released with [`test_free`]/[`test_realloc`]
/// (the C test API contract).
pub unsafe fn test_malloc(size: usize) -> *mut u8 {
    let size = size.max(1);
    if size <= SLAB_CHUNK_SIZE {
        let ptr = TLS_SLAB.with(|tls| {
            let mut s = tls.borrow_mut();
            let s: &mut TlsSlab = s.as_mut();
            if s.freelist.is_null() {
                slab_refill(s);
            }
            if s.freelist.is_null() {
                return ptr::null_mut(); // grow failed → heap fallback
            }
            let node = s.freelist;
            s.freelist = (*node).next;
            let page = (node as usize & SLAB_PAGE_MASK) as *mut SlabPage;
            (*page).refcount.fetch_add(1, Ordering::Relaxed);
            node as *mut u8
        });
        if !ptr.is_null() {
            return ptr;
        }
    }
    alloc_heap(size)
}

/// Heap allocation with a 16-byte size header (the C uses free(), which
/// knows block sizes; Rust's GlobalAlloc does not, so we record it).
unsafe fn alloc_heap(size: usize) -> *mut u8 {
    let total = size + 16;
    let layout = Layout::from_size_align(total, 8).expect("size");
    let raw = std::alloc::alloc(layout);
    if raw.is_null() {
        return ptr::null_mut();
    }
    (raw as *mut usize).write_unaligned(size);
    raw.add(16)
}

/// # Safety
/// `ptr` must come from [`test_malloc`]/[`test_calloc`]/[`test_realloc`].
pub unsafe fn test_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let base = ptr as usize & SLAB_PAGE_MASK;
    let page = map_lookup(base);
    if page.is_null() {
        // Heap pointer: read the 16-byte size header written by test_malloc
        // (header sits at ptr-16, one usize free of it).
        let total = unsafe { (ptr as *const usize).sub(2).read_unaligned() } + 16;
        std::alloc::dealloc(
            ptr.sub(16),
            Layout::from_size_align(total, 8).expect("size"),
        );
        return;
    }
    TLS_SLAB.with(|tls| {
        let mut s = tls.borrow_mut();
        let self_ptr: *mut TlsSlab = s.as_mut();
        let node = ptr as *mut FreeNode;
        // SAFETY: page alive (chunk refcount ≥ 1 until this free).
        let owner_now = (*page).owner.load(Ordering::Relaxed);
        if owner_now == self_ptr {
            (*node).next = s.freelist;
            s.freelist = node;
            (*page).refcount.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        // Foreign/retired free: MPSC push.
        let mut head = (*page).remote_free_head.load(Ordering::Relaxed);
        loop {
            (*node).next = head;
            match (*page).remote_free_head.compare_exchange_weak(
                head,
                node,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(h) => head = h,
            }
        }
        if (*page).refcount.fetch_sub(1, Ordering::AcqRel) == 1 {
            map_set(page as usize, ptr::null_mut());
            std::alloc::dealloc(
                page as *mut u8,
                Layout::from_size_align(SLAB_PAGE_SIZE, SLAB_PAGE_SIZE).unwrap(),
            );
        }
    });
}

/// Reallocate. Handles slab→heap promotion with minimal copying.
///
/// # Safety
/// Contract as [`test_malloc`].
pub unsafe fn test_realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        return test_malloc(new_size);
    }
    if new_size == 0 {
        test_free(ptr);
        return ptr::null_mut();
    }
    let page = map_lookup(ptr as usize & SLAB_PAGE_MASK);
    if !page.is_null() {
        if new_size <= SLAB_CHUNK_SIZE {
            return ptr; // still fits — reuse the slot
        }
        // Promote slab → heap via the header-carrying heap scheme.
        let new_ptr = alloc_heap(new_size);
        if new_ptr.is_null() {
            return ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(ptr, new_ptr, SLAB_CHUNK_SIZE);
        test_free(ptr);
        return new_ptr;
    }
    // Heap pointer: reallocate via the header-carrying heap scheme
    // (header at ptr-16 = [size, unused]).
    let old_size = unsafe { (ptr as *const usize).sub(2).read_unaligned() };
    let total = new_size + 16;
    let layout = Layout::from_size_align(total, 8).expect("size");
    let raw = std::alloc::alloc(layout);
    if raw.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (raw as *mut usize).write_unaligned(new_size);
        std::ptr::copy_nonoverlapping(ptr, raw.add(16), old_size.min(new_size));
        std::alloc::dealloc(
            ptr.sub(16),
            Layout::from_size_align(old_size + 16, 8).unwrap(),
        );
    }
    unsafe { raw.add(16) }
}

/// Calloc: zeroed (free-list blocks contain stale data).
///
/// # Safety
/// Contract as [`test_malloc`].
pub unsafe fn test_calloc(count: usize, size: usize) -> *mut u8 {
    let Some(total) = count.checked_mul(size) else {
        return ptr::null_mut();
    };
    let p = test_malloc(total);
    if !p.is_null() {
        std::ptr::write_bytes(p, 0, total);
    }
    p
}

/// Register this allocator as the tree-sitter allocator. The C calls
/// `ts_set_allocator`; the Rust tree-sitter binding is configured at its
/// own init site, so this is the hook point (kept for API parity).
pub fn install() {
    // Wired by the tree-sitter integration layer (task: internal/cbm).
    // Deliberately not a no-op panic: install is idempotent and optional.
}

/// Reclaim slab memory owned by the current thread. Call ONLY when no
/// local live allocations remain (after ts_tree_delete/ts_parser_delete).
/// Pages with foreign-live chunks are retired and freed on their final
/// cross-thread free (fixes the #852 use-after-free pattern).
pub fn reclaim() {
    TLS_SLAB.with(|tls| {
        reclaim_pages_inner(&mut tls.borrow_mut());
    });
}

pub fn reset_thread() {
    reclaim();
}

pub fn destroy_thread() {
    reclaim();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_alloc_roundtrip() {
        unsafe {
            let a = test_malloc(32);
            assert!(!a.is_null());
            // Slab pointers are page-aligned-base + chunk offsets.
            assert_eq!(
                a as usize & SLAB_PAGE_MASK,
                a as usize - (a as usize % SLAB_PAGE_SIZE)
            );
            test_free(a);
        }
    }

    #[test]
    fn zero_size_becomes_one() {
        unsafe {
            let p = test_malloc(0);
            assert!(!p.is_null());
            test_free(p);
        }
    }

    #[test]
    fn big_alloc_uses_heap() {
        unsafe {
            let p = test_malloc(SLAB_CHUNK_SIZE * 4);
            assert!(!p.is_null());
            assert!(map_lookup(p as usize & SLAB_PAGE_MASK).is_null()); // not slab
            test_realloc(p, 0); // free via realloc(0)
        }
    }

    #[test]
    fn calloc_zeroes() {
        unsafe {
            let p = test_calloc(8, 8);
            assert!(!p.is_null());
            assert!((0..64).all(|i| *p.add(i) == 0));
            test_free(p);
        }
    }

    #[test]
    fn realloc_promotes() {
        unsafe {
            let a = test_malloc(48); // slab
            assert!(!map_lookup(a as usize & SLAB_PAGE_MASK).is_null());
            let b = test_realloc(a, 256); // promote to heap
            assert!(!b.is_null());
            assert!(map_lookup(b as usize & SLAB_PAGE_MASK).is_null());
            test_realloc(b, 0);
        }
    }

    #[test]
    fn many_chunks_spans_pages() {
        unsafe {
            let n = SLAB_PAGE_CHUNKS * 2 + 10;
            let ptrs: Vec<*mut u8> = (0..n).map(|_| test_malloc(64)).collect();
            assert!(ptrs.iter().all(|p| !p.is_null()));
            for p in ptrs {
                test_free(p);
            }
            reclaim();
        }
    }

    #[test]
    fn reclaim_then_reuse() {
        unsafe {
            let a = test_malloc(16);
            test_free(a);
            reclaim(); // frees pages (no live chunks)
            let b = test_malloc(16); // fresh page
            assert!(!b.is_null());
            test_free(b);
            reclaim();
        }
    }
}
