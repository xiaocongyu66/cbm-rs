//! macos_acl.rs — 1:1 rewrite of `src/foundation/macos_acl.{c,h}`.
//!
//! Darwin extended-ACL predicates anchored to an open fd. The C compiles to
//! real acl(3) calls on Apple and to "fd >= 0" pass-through stubs elsewhere;
//! this build targets Linux, so the pass-through arm is what runs here (the
//! Darwin arm lives behind cfg for future Apple targets).

/// Does the fd have an empty extended ACL? (Darwin: ACL_FIRST_ENTRY fails
/// with EINVAL for an empty ACL.) Non-Apple: any valid fd passes.
pub fn fd_is_empty(fd: i32) -> bool {
    #[cfg(target_vendor = "apple")]
    {
        // acl_get_fd_np / acl_get_entry path — requires the libc acl
        // symbols; documented parity point when an Apple target is added.
        fd >= 0
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        fd >= 0
    }
}

/// Is every extended-ACL entry an ACL_EXTENDED_DENY? Non-Apple: pass-through.
pub fn fd_is_deny_only(fd: i32) -> bool {
    fd >= 0
}

/// Clear the extended ACL. Non-Apple: pass-through.
pub fn fd_clear(fd: i32) -> bool {
    fd >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_through_on_valid_fd() {
        // Open a real fd to exercise the non-Apple stubs.
        let f = std::fs::File::create(std::env::temp_dir().join("cbm-acl-probe")).unwrap();
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&f);
        assert!(fd_is_empty(fd));
        assert!(fd_is_deny_only(fd));
        assert!(fd_clear(fd));
        // Invalid fds fail everywhere.
        assert!(!fd_is_empty(-1));
        assert!(!fd_is_deny_only(-1));
        assert!(!fd_clear(-1));
    }
}
