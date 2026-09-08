//! arena.rs — 1:1 rewrite of `src/foundation/arena.{c,h}`.
//!
//! Block-based bump allocator. All memory is freed at once; individual
//! frees are not supported by design (per-file extraction data shares one
//! lifetime). Block growth doubles, capped at [`MAX_BLOCKS`].

use std::alloc::{alloc, dealloc, Layout};

pub const MAX_BLOCKS: usize = 256;
pub const DEFAULT_BLOCK_SIZE: usize = 64 * 1024;

const ALIGN: usize = 8;

pub struct Arena {
    blocks: Vec<Block>,
    /// Capacity of the block that will be allocated next on growth.
    block_size: usize,
    /// Bytes used in the current (last) block.
    used: usize,
    /// Cumulative bytes handed out (for diagnostics).
    total_alloc: usize,
}

struct Block {
    ptr: *mut u8,
    size: usize,
}

// Raw pointers handed out into a Vec we only push to; blocks never move
// (Vec reallocation moves the Block structs, not the heap buffers).
unsafe impl Send for Arena {}

impl Arena {
    pub fn new() -> Self {
        Self::with_block_size(DEFAULT_BLOCK_SIZE)
    }

    pub fn with_block_size(block_size: usize) -> Self {
        let block_size = block_size.max(64); // minimum sanity, matches C
        let mut a = Arena {
            blocks: Vec::new(),
            block_size,
            used: 0,
            total_alloc: 0,
        };
        a.push_block(block_size);
        a
    }

    fn push_block(&mut self, size: usize) -> bool {
        if self.blocks.len() >= MAX_BLOCKS {
            return false;
        }
        let layout = Layout::from_size_align(size, ALIGN).expect("block size overflow");
        // SAFETY: layout has non-zero size.
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return false;
        }
        self.blocks.push(Block { ptr, size });
        true
    }

    /// Allocate `n` bytes (8-byte aligned). Returns `None` on OOM or when
    /// the block cap is hit — mirrors the C allocator returning NULL.
    pub fn alloc(&mut self, n: usize) -> Option<&mut [u8]> {
        if n == 0 || self.blocks.is_empty() {
            return None;
        }
        let n = n.div_ceil(ALIGN) * ALIGN;
        let last = self.blocks.len() - 1;
        if self.used + n > self.blocks[last].size {
            let mut new_size = self.block_size * 2;
            if new_size < n {
                new_size = n;
            }
            if !self.push_block(new_size) {
                return None;
            }
            self.block_size = new_size;
            self.used = 0;
        }
        let last = self.blocks.len() - 1;
        // SAFETY: used + n <= block size just ensured; block is live memory.
        let slice = unsafe {
            let p = self.blocks[last].ptr.add(self.used);
            std::slice::from_raw_parts_mut(p, n)
        };
        self.used += n;
        self.total_alloc += n;
        Some(slice)
    }

    /// Allocate `n` zero-initialized bytes.
    pub fn alloc_zeroed(&mut self, n: usize) -> Option<&mut [u8]> {
        let s = self.alloc(n)?;
        s.fill(0);
        Some(s)
    }

    /// Duplicate a string into arena memory.
    pub fn strdup(&mut self, s: &str) -> Option<&str> {
        let bytes = &mut self.alloc(s.len())?[..s.len()];
        bytes.copy_from_slice(s.as_bytes());
        // SAFETY: we just copied valid UTF-8 of the same length.
        Some(unsafe { std::str::from_utf8_unchecked(bytes) })
    }

    /// Duplicate the first `len` bytes of `s`, as `&str` (caller guarantees
    /// a char boundary, matching the C strndup NUL-termination role).
    pub fn strndup(&mut self, s: &str, len: usize) -> Option<&str> {
        let len = len.min(s.len());
        let bytes = &mut self.alloc(len)?[..len];
        bytes.copy_from_slice(&s.as_bytes()[..len]);
        Some(unsafe { std::str::from_utf8_unchecked(bytes) })
    }

    /// `format!` into arena memory.
    pub fn sprintf(&mut self, args: std::fmt::Arguments<'_>) -> Option<&str> {
        let s = std::fmt::format(args);
        self.strdup(&s)
    }

    /// Reset for reuse: keep the first block, free the rest, zero counters.
    /// `block_size` is restored to the surviving block's capacity so growth
    /// accounting cannot overflow (same fix as the C reset).
    pub fn reset(&mut self) {
        while self.blocks.len() > 1 {
            let b = self.blocks.pop().expect("len checked");
            // SAFETY: block was allocated with this layout.
            unsafe {
                dealloc(b.ptr, Layout::from_size_align(b.size, ALIGN).expect("overflow"));
            }
        }
        if let Some(first) = self.blocks.first() {
            self.block_size = first.size;
        }
        self.used = 0;
        self.total_alloc = 0;
    }

    /// Total bytes allocated over the arena's lifetime (for diagnostics).
    pub fn total(&self) -> usize {
        self.total_alloc
    }

    /// Bytes still unused in the current block.
    pub fn available(&self) -> usize {
        match self.blocks.last() {
            Some(b) => b.size - self.used,
            None => 0,
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        for b in &self.blocks {
            // SAFETY: allocated in push_block with identical layout.
            unsafe {
                dealloc(b.ptr, Layout::from_size_align(b.size, ALIGN).expect("overflow"));
            }
        }
        self.blocks.clear();
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_alloc_and_totals() {
        let mut a = Arena::new();
        let p = a.alloc(100).unwrap();
        assert_eq!(p.len(), 104); // rounded to 8
        assert_eq!(a.total(), 104);
        assert_eq!(a.alloc(0).map(|_| ()), None); // n == 0 → NULL
    }

    #[test]
    fn zeroed_alloc() {
        let mut a = Arena::new();
        let p = a.alloc_zeroed(16).unwrap();
        assert!(p.iter().all(|&b| b == 0));
    }

    #[test]
    fn growth_doubles_and_grows_past_request() {
        let mut a = Arena::with_block_size(1024);
        // Exhaust first block.
        let mut rounds = 0;
        while a.available() >= 512 && rounds < 4 {
            a.alloc(512).unwrap();
            rounds += 1;
        }
        // Force growth well past one block.
        let big = a.alloc(4096).unwrap();
        assert_eq!(big.len(), 4096);
        assert!(a.total() >= 4096 + rounds * 512);
    }

    #[test]
    fn huge_request_gets_own_block() {
        let mut a = Arena::with_block_size(1024);
        let p = a.alloc(1 << 20).unwrap();
        assert_eq!(p.len(), 1 << 20);
    }

    #[test]
    fn strdup_roundtrip() {
        let mut a = Arena::new();
        let s = a.strdup("hello 世界").unwrap();
        assert_eq!(s, "hello 世界");
    }

    #[test]
    fn strndup_truncates() {
        let mut a = Arena::new();
        let s = a.strndup("abcdef", 3).unwrap();
        assert_eq!(s, "abc");
    }

    #[test]
    fn sprintf_formats() {
        let mut a = Arena::new();
        let s = a.sprintf(format_args!("n={} s={}", 42, "x")).unwrap();
        assert_eq!(s, "n=42 s=x");
    }

    #[test]
    fn reset_keeps_first_block_and_restores_block_size() {
        let mut a = Arena::with_block_size(1024);
        let first_cap = a.available();
        // Grow the arena.
        let _ = a.alloc(8192).unwrap();
        assert!(a.blocks.len() > 1);
        a.reset();
        assert_eq!(a.blocks.len(), 1);
        assert_eq!(a.total(), 0);
        assert_eq!(a.available(), first_cap);
        // Post-reset allocation lands in the surviving block.
        let p = a.alloc(64).unwrap();
        assert_eq!(p.len(), 64);
    }

    #[test]
    fn alignment_is_8() {
        let mut a = Arena::new();
        for n in [1usize, 3, 5, 9, 13] {
            let p = a.alloc(n).unwrap();
            let addr = p.as_ptr() as usize;
            assert_eq!(addr % 8, 0, "addr {addr:#x} not 8-aligned");
        }
    }
}
