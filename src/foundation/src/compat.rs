//! compat.rs — rewrite of `src/foundation/compat.{c,h}` (POSIX surface).
//!
//! Cross-platform shims. The C version forwards to libc on POSIX and
//! implements Windows fallbacks; the Rust build targets POSIX only, so the
//! shims here cover the still-useful pieces: strict env-int parsing
//! (`env_long` lives in `platform`), temp dirs, and EINTR-safe sleeps.
//! str*dup/clock/mkdir/getline are std-native and live at call sites.

use std::path::PathBuf;
use std::time::Duration;

/// Sleep for microseconds, retrying on EINTR until the full duration.
/// C: `cbm_usleep` + `cbm_nanosleep_full` (loop on EINTR).
pub fn nanosleep_full(us: u64) {
    let d = Duration::from_micros(us);
    let start = std::time::Instant::now();
    while let Some(remaining) = d.checked_sub(start.elapsed()) {
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

/// Create a unique temporary directory (mkdtemp semantics): appends random
/// digits to `prefix`, retries on collision. Returns the created path.
pub fn mkdtemp(prefix: &str) -> Option<PathBuf> {
    for _ in 0..64 {
        let n: u64 = {
            let mut b = [0u8; 8];
            crate::secure_random::secure_random(&mut b);
            u64::from_le_bytes(b)
        };
        let dir = std::env::temp_dir().join(format!("{prefix}{n:016x}"));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Some(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

/// `mkstemp` semantics: create a new file with mode 0600, return its path.
pub fn mkstemp(prefix: &str) -> Option<PathBuf> {
    for _ in 0..64 {
        let n: u64 = {
            let mut b = [0u8; 8];
            crate::secure_random::secure_random(&mut b);
            u64::from_le_bytes(b)
        };
        let path = std::env::temp_dir().join(format!("{prefix}{n:016x}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode_0600()
            .open(&path)
        {
            Ok(_) => return Some(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

trait Open0600 {
    fn mode_0600(&mut self) -> &mut Self;
}

#[cfg(unix)]
impl Open0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
    }
}
#[cfg(not(unix))]
impl Open0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_is_finite() {
        let t = std::time::Instant::now();
        nanosleep_full(5000); // 5ms
        assert!(t.elapsed() >= Duration::from_millis(5));
    }

    #[test]
    fn mkdtemp_creates_unique_dir() {
        let a = mkdtemp("cbm-compat-d-").unwrap();
        let b = mkdtemp("cbm-compat-d-").unwrap();
        assert_ne!(a, b);
        assert!(a.is_dir());
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn mkstemp_creates_file() {
        let p = mkstemp("cbm-compat-f-").unwrap();
        assert!(p.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&p).ok();
    }
}
