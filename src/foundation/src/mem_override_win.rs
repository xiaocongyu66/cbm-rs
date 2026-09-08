//! mem_override_win.rs — rewrite of `src/foundation/mem_override_win.c`.
//!
//! Windows-only --wrap interposer: routes malloc/free between mimalloc and
//! the CRT by pointer ownership (`mi_is_in_heap_region`), because --wrap
//! cannot reach allocations made inside ucrt/system DLLs and a crossed
//! free aborts (#424). This build targets POSIX, where the equivalent
//! observation shim is `mem_override_posix.c` (rewritten into
//! [`crate::mem_profile`]'s hook contract) — here we carry only the
//! ownership-routing *decision table* the C documents, cfg-gated so a
//! future Windows target implements it against its allocator.

/// Who owns a pointer, from the allocator's perspective (C:
/// mem_override_is_ours → route table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerOwner {
    /// Our allocator made it — route dealloc to it.
    Ours,
    /// CRT / system DLL (out of --wrap's reach) — never hand to our
    /// allocator (#424).
    Foreign,
    /// NULL — nothing to do.
    Null,
}

/// Non-Windows build: there is no CRT/allocator split (single std
/// allocator), so every non-null pointer is "ours" and no routing is
/// needed. C parity: the POSIX side has no foreign-allocator hazard.
pub fn classify(block: *const u8) -> PointerOwner {
    if block.is_null() {
        return PointerOwner::Null;
    }
    #[cfg(windows)]
    {
        // A Windows target installs its allocator probe here.
        PointerOwner::Ours
    }
    #[cfg(not(windows))]
    {
        PointerOwner::Ours
    }
}

/// Cross-allocator realloc policy (C __wrap_realloc): a foreign block is
/// NEVER grown in place by our allocator — copy across the boundary once
/// (min(old_size, new_size)), then release to the real owner.
#[derive(Debug, Clone, Copy)]
pub struct ReallocRoute {
    pub copy_from_original: bool,
    pub copy_bytes: usize,
    pub release_original_to_owner: bool,
}

pub fn realloc_route(block: *const u8, old_size: usize, new_size: usize) -> ReallocRoute {
    match classify(block) {
        PointerOwner::Null => ReallocRoute {
            copy_from_original: false,
            copy_bytes: 0,
            release_original_to_owner: false,
        },
        PointerOwner::Ours => ReallocRoute {
            copy_from_original: true,
            copy_bytes: old_size.min(new_size),
            release_original_to_owner: true,
        },
        PointerOwner::Foreign => ReallocRoute {
            copy_from_original: true,
            copy_bytes: old_size.min(new_size),
            release_original_to_owner: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_table() {
        assert_eq!(classify(std::ptr::null()), PointerOwner::Null);
        let buf = [0u8; 8];
        assert_eq!(classify(buf.as_ptr()), PointerOwner::Ours);
    }

    #[test]
    fn realloc_policy_min_copy() {
        let buf = [0u8; 16];
        let r = realloc_route(buf.as_ptr(), 16, 32);
        assert!(r.copy_from_original);
        assert_eq!(r.copy_bytes, 16); // min(old, new)
        assert!(r.release_original_to_owner);

        let r = realloc_route(buf.as_ptr(), 32, 8);
        assert_eq!(r.copy_bytes, 8);

        let r = realloc_route(std::ptr::null(), 0, 32);
        assert!(!r.copy_from_original);
        assert!(!r.release_original_to_owner);
    }
}
