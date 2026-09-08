//! platform.rs — 1:1 rewrite of `src/foundation/platform.{c,h}`.
//!
//! OS abstraction (POSIX path of the C original; the Windows branches are
//! not part of this build target). Clock, CPU count, file probes, mmap
//! read, thread-safe env access, home/config/cache dir resolution.

use std::fs;
use std::path::Path;

pub use crate::system_info::SystemInfo;

/// Monotonic nanoseconds.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid timespec for CLOCK_MONOTONIC.
    unsafe {
        assert_eq!(libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts), 0);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Monotonic milliseconds.
pub fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

/// Online processor count (host view; see `system_info` for cgroup-aware).
pub fn nprocs() -> i32 {
    // SAFETY: sysconf with a valid constant.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 {
        n as i32
    } else {
        1
    }
}

/// Read the whole file via mmap (read-only, page-aligned). Returns the
/// mapping and its byte length; `None` on open/stat failure or empty file.
/// The `MmapRead` guard unmaps on drop.
pub fn mmap_read(path: &Path) -> Option<MmapRead> {
    let file = fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    use std::os::unix::io::AsRawFd;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len as usize,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return None;
    }
    Some(MmapRead {
        ptr: ptr as *mut u8,
        len: len as usize,
    })
}

pub struct MmapRead {
    ptr: *mut u8,
    len: usize,
}

impl MmapRead {
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: mapping is PROT_READ and lives until Drop.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for MmapRead {
    fn drop(&mut self) {
        // SAFETY: paired with mmap in mmap_read.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

// Raw pointer is only a handle to unmapped memory; &self access is read-only.
unsafe impl Send for MmapRead {}
unsafe impl Sync for MmapRead {}

pub fn file_exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

pub fn is_dir(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// File size in bytes, or -1 (CBM_NOT_FOUND) when missing.
pub fn file_size(path: &Path) -> i64 {
    fs::metadata(path).map(|m| m.len() as i64).unwrap_or(-1)
}

/// Replace `\` with `/` and uppercase a bare `X:`/`X:/` drive prefix.
/// Applied on all platforms: backslash paths arrive via stored data,
/// cross-platform DBs, or Windows-style arguments. Drive canonicalization
/// keeps project keys consistent regardless of agent-reported case
/// (upstream #227/#367/#394).
pub fn normalize_path_sep(path: &str) -> String {
    let mut s: Vec<u8> = path
        .bytes()
        .map(|b| if b == b'\\' { b'/' } else { b })
        .collect();
    // Canonicalize a strict drive-root form "x:/" or bare "x:" → "X:…".
    if s.len() >= 2 && s[0].is_ascii_lowercase() && s[1] == b':' && (s.len() == 2 || s[2] == b'/') {
        s[0] = s[0].to_ascii_uppercase();
    }
    String::from_utf8(s).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Thread-safe env read with fallback: returns the variable's value, or
/// `fallback` when unset/empty. Mirrors `cbm_safe_getenv` semantics
/// (empty-but-present counts as present and returns "").
pub fn safe_getenv(name: &str, fallback: &str) -> String {
    match std::env::var(name) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => fallback.to_string(),
        Err(_) => fallback.to_string(),
    }
}

/// Parse env var as a `long` (strict: no leading whitespace, full consume).
pub fn env_long(name: &str) -> Option<i64> {
    let raw = std::env::var(name).ok()?;
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None; // " 5" is a slip, not a number — refuse like C
    }
    raw.parse::<i64>().ok()
}

/// Home directory: `$HOME` or `$USERPROFILE`, path separators normalized.
pub fn home_dir() -> Option<String> {
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return Some(normalize_path_sep(&v));
            }
        }
    }
    None
}

/// Config dir: `$XDG_CONFIG_HOME` or `~/.config` (POSIX).
pub fn app_config_dir() -> Option<String> {
    if let Ok(v) = std::env::var("XDG_CONFIG_HOME") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    home_dir().map(|h| format!("{h}/.config"))
}

/// App-local dir: same as config dir on POSIX (C: LOCALAPPDATA on Windows).
pub fn app_local_dir() -> Option<String> {
    app_config_dir()
}

/// Cache dir: `$CBM_CACHE_DIR` or `<home>/.cache/codebase-memory-mcp`.
pub fn resolve_cache_dir() -> Option<String> {
    if let Ok(v) = std::env::var("CBM_CACHE_DIR") {
        if !v.is_empty() {
            return Some(normalize_path_sep(&v));
        }
    }
    let home = home_dir()?;
    Some(format!("{home}/.cache/codebase-memory-mcp"))
}

/// Worker count — re-export of [`crate::system_info::default_worker_count`].
pub use crate::system_info::default_worker_count;
/// Cached host info — re-export of [`crate::system_info::system_info`].
pub use crate::system_info::system_info;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_monotonic_advances() {
        let a = now_ns();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = now_ns();
        assert!(b > a);
        assert!(now_ms() >= b / 1_000_000);
    }

    #[test]
    fn nprocs_positive() {
        assert!(nprocs() >= 1);
    }

    #[test]
    fn file_probes() {
        assert!(file_exists(Path::new("/etc/hostname")) || file_exists(Path::new("/etc/passwd")));
        assert!(is_dir(Path::new("/tmp")));
        assert_eq!(file_size(Path::new("/nonexistent-cbm-probe")), -1);
    }

    #[test]
    fn normalize_separators_and_drive() {
        assert_eq!(normalize_path_sep("a\\b\\c"), "a/b/c");
        assert_eq!(normalize_path_sep("c:/Users"), "C:/Users");
        assert_eq!(normalize_path_sep("c:"), "C:");
        assert_eq!(normalize_path_sep("/posix/untouched"), "/posix/untouched");
        assert_eq!(normalize_path_sep("xc:/not/drive"), "xc:/not/drive");
    }

    #[test]
    fn env_long_strict() {
        // Existing vars on this machine must not break; test via unset name.
        assert_eq!(env_long("CBM_RUST_REWRITE_TEST_UNSET"), None);
        std::env::set_var("CBM_RUST_REWRITE_TEST_ENVL", "42");
        assert_eq!(env_long("CBM_RUST_REWRITE_TEST_ENVL"), Some(42));
        std::env::set_var("CBM_RUST_REWRITE_TEST_ENVL", " 42");
        assert_eq!(env_long("CBM_RUST_REWRITE_TEST_ENVL"), None);
        std::env::set_var("CBM_RUST_REWRITE_TEST_ENVL", "42x");
        assert_eq!(env_long("CBM_RUST_REWRITE_TEST_ENVL"), None);
        std::env::remove_var("CBM_RUST_REWRITE_TEST_ENVL");
    }

    #[test]
    fn dirs_resolve() {
        // These may or may not have env configured; they must not panic.
        let _ = home_dir();
        let _ = app_config_dir();
        let _ = resolve_cache_dir();
        let _ = app_local_dir();
    }

    #[test]
    fn worker_count_in_range() {
        let w = default_worker_count(true);
        assert!((1..=256).contains(&w));
        let wi = default_worker_count(false);
        assert!((1..=256).contains(&wi));
    }

    #[test]
    fn mmap_roundtrip() {
        let dir = std::env::temp_dir().join("cbm-foundation-mmap-test");
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("probe.txt");
        fs::write(&f, b"hello mmap").unwrap();
        let m = mmap_read(&f).expect("mmap");
        assert_eq!(m.as_slice(), b"hello mmap");
        assert_eq!(m.len(), 10);
        drop(m);
        // Empty file → None.
        let empty = dir.join("empty.txt");
        fs::write(&empty, b"").unwrap();
        assert!(mmap_read(&empty).is_none());
        fs::remove_dir_all(&dir).ok();
    }
}
