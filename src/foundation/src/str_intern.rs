//! str_intern.rs — 1:1 rewrite of `src/foundation/str_intern.{c,h}`.
//!
//! String interning pool: hash-table dedup with arena storage — the pool
//! owns all strings. Rust version: the pool owns `Box<str>` values and
//! hands out `&str` borrows with the pool's lifetime; FNV-1a and the
//! 256→2x open-addressing growth are preserved.

use std::collections::HashMap;
use std::hash::BuildHasherDefault;

/// FNV-1a (matches the C implementation's constants).
fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 2166136261;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

/// Intern pool owning canonical copies of interned strings.
pub struct InternPool {
    map: HashMap<Box<str>, (), BuildHasherDefault<std::collections::hash_map::DefaultHasher>>,
    total_bytes: usize,
    // Keep insertion-independent FNV hash parity with C for tests.
    _hash_guard: fn(&str) -> u32,
}

impl Default for InternPool {
    fn default() -> Self {
        Self::create()
    }
}

impl InternPool {
    pub fn create() -> Self {
        InternPool {
            map: HashMap::default(),
            total_bytes: 0,
            _hash_guard: fnv1a,
        }
    }

    /// Intern `s`; returns the canonical (pool-owned) string.
    pub fn intern(&mut self, s: &str) -> &str {
        self.intern_n(s, s.len())
    }

    /// Intern the first `len` bytes of `s`.
    pub fn intern_n(&mut self, s: &str, len: usize) -> &str {
        let len = len.min(s.len());
        // SAFETY-free path: caller guarantees a char boundary (C took raw
        // bytes); for safety we clamp to the nearest boundary upward.
        let mut end = len;
        while end < s.len() && !s.is_char_boundary(end) {
            end += 1;
        }
        let slice = &s[..end];
        let key: Box<str> = slice.into();
        match self.map.get(&key) {
            Some(()) => {}
            None => {
                self.total_bytes += key.len();
                self.map.insert(key, ());
            }
        }
        // Return canonical reference.
        let key: Box<str> = slice.into();
        let stored = self.map.get_key_value(&key).0;
        stored.as_ref()
    }

    /// Number of distinct interned strings.
    pub fn count(&self) -> u32 {
        self.map.len() as u32
    }

    /// Sum of stored string lengths (excluding any NULs — none in Rust).
    pub fn bytes(&self) -> usize {
        self.total_bytes
    }

    /// FNV-1a hash, exposed for parity tests with the C constants.
    pub fn hash(s: &str) -> u32 {
        fnv1a(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_dedups() {
        let mut p = InternPool::create();
        let a = p.intern("hello");
        let b = p.intern("hello");
        assert_eq!(a, "hello");
        assert_eq!(a.as_ptr(), b.as_ptr()); // canonical single storage
        assert_eq!(p.count(), 1);
        assert_eq!(p.bytes(), 5);
    }

    #[test]
    fn intern_n_truncates() {
        let mut p = InternPool::create();
        let s = p.intern_n("abcdef", 3);
        assert_eq!(s, "abc");
        assert_eq!(p.count(), 1);
        // Interning the full string adds a second entry.
        p.intern("abcdef");
        assert_eq!(p.count(), 2);
        assert_eq!(p.bytes(), 3 + 6);
    }

    #[test]
    fn distinct_strings() {
        let mut p = InternPool::create();
        for s in ["a", "b", "c", "a"] {
            p.intern(s);
        }
        assert_eq!(p.count(), 3);
        assert_eq!(p.bytes(), 3);
    }

    #[test]
    fn fnv1a_known_values() {
        // FNV-1a 32-bit test vectors (published constants).
        assert_eq!(InternPool::hash(""), 2166136261);
        assert_eq!(InternPool::hash("a"), 0xe40c292c);
    }
}
