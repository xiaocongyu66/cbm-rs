//! dyn_array.rs — rewrite of `src/foundation/dyn_array.h`.
//!
//! The C original is a header-only macro toolkit (`CBM_DYN_ARRAY(T)` +
//! `cbm_da_push/pop/last/clear/reserve/insert/remove`) wrapping realloc
//! with 2x growth. In Rust this maps directly onto `Vec<T>`: contiguous,
//! amortized O(1) push, same operation set. This module documents the
//! mapping and re-exports Vec; callers use std Vec — no wrapper indirection.

pub use std::vec::Vec as DynArray;

/// C `cbm_da_push(da, item)` → `da.push(item)`
/// C `cbm_da_pop(da)` → `da.pop()` (Option, unlike C's UB on empty)
/// C `cbm_da_last(da)` → `da.last()` (Option, unlike C's UB on empty)
/// C `cbm_da_clear(da)` → `da.clear()`
/// C `cbm_da_free(da)` → drop(da)
/// C `cbm_da_reserve(da, n)` → `da.reserve(n)` (grow-only, same)
/// C `cbm_da_insert(da, idx, item)` → `da.insert(idx, item)`
/// C `cbm_da_remove(da, idx)` → `da.remove(idx)`
#[cfg(test)]
mod tests {
    use super::*;

    /// The C header's own usage example, expressed with the Rust mapping.
    #[test]
    #[allow(clippy::vec_init_then_push)]
    fn c_header_example_translated() {
        let mut nums: DynArray<i32> = DynArray::new(); // {0}
        for x in [42, 99] {
            nums.push(x); // cbm_da_push
        }
        let out: Vec<i32> = nums.iter().copied().collect();
        assert_eq!(out, vec![42, 99]);
        // cbm_da_free is implicit in drop.
    }

    #[test]
    fn insert_remove_shift() {
        let mut v: DynArray<u8> = vec![1, 2, 3];
        v.insert(1, 9); // cbm_da_insert
        assert_eq!(v, vec![1, 9, 2, 3]);
        let removed = v.remove(1); // cbm_da_remove
        assert_eq!(removed, 9);
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn pop_last_semantics() {
        let mut v: DynArray<u8> = vec![7];
        assert_eq!(v.last(), Some(&7)); // cbm_da_last
        assert_eq!(v.pop(), Some(7)); // cbm_da_pop
        assert_eq!(v.pop(), None); // C: UB; Rust: None
        v.clear(); // cbm_da_clear
        assert!(v.is_empty());
    }
}
