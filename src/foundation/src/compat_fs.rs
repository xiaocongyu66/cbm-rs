//! compat_fs.rs — 1:1 rewrite of `src/foundation/compat_fs.{c,h}`.
//!
//! Filesystem layer: directory iteration, lstat-style path info (symlinks
//! are reported, not followed — semantic-input walkers must not leave the
//! repository through an alias), mkdir -p, atomic renames (replace and
//! noreplace), SQLite sidecar removal, reflink-or-copy, canonical paths,
//! and no-shell process execution.

use std::fs;
use std::path::{Path, PathBuf};

pub const NOT_FOUND: i32 = -1;

// ── Path info (lstat semantics) ─────────────────────────────────

/// Locale-independent metadata for a UTF-8 path. Symlinks are reported,
/// not followed.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathInfo {
    pub is_regular: bool,
    pub is_directory: bool,
    pub is_symlink: bool,
    pub size: i64,
    /// Unix-epoch nanoseconds.
    pub mtime_ns: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathInfoStatus {
    Ok,
    /// Permission / encoding / transient inspection failure.
    Unavailable,
    /// Proven absent.
    Absent,
}

pub use PathInfoStatus::{Absent, Ok as InfoOk, Unavailable};

pub fn path_info_utf8(path: &Path) -> (PathInfoStatus, Option<PathInfo>) {
    match fs::symlink_metadata(path) {
        Ok(md) => {
            let mtime_ns = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            (
                InfoOk,
                Some(PathInfo {
                    is_regular: md.is_file(),
                    is_directory: md.is_dir(),
                    is_symlink: md.file_type().is_symlink(),
                    size: md.len() as i64,
                    mtime_ns,
                }),
            )
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => (Absent, None),
            _ => (Unavailable, None),
        },
    }
}

// ── Directory iteration ─────────────────────────────────────────

/// One directory entry (C cbm_dirent_t).
pub struct Dirent {
    pub name: String,
    pub is_dir: bool,
    pub d_type: u8,
}

pub const DT_REG: u8 = 8;
pub const DT_DIR: u8 = 4;
pub const DT_LNK: u8 = 10;
pub const DT_UNKNOWN: u8 = 0;

pub struct Dir {
    inner: std::fs::ReadDir,
    pending: Option<Dirent>,
}

/// Open a directory for iteration. `None` on error.
pub fn opendir(path: &Path) -> Option<Dir> {
    let inner = fs::read_dir(path).ok()?;
    Some(Dir {
        inner,
        pending: None,
    })
}

impl Dir {
    /// Read the next entry. `None` when exhausted.
    pub fn readdir(&mut self) -> Option<Dirent> {
        if let Some(p) = self.pending.take() {
            return Some(p);
        }
        loop {
            match self.inner.next() {
                Some(Ok(entry)) => {
                    let ft = entry.file_type().ok();
                    return Some(Dirent {
                        name: entry.file_name().to_string_lossy().into_owned(),
                        is_dir: ft.as_ref().map(|t| t.is_dir()).unwrap_or(false),
                        d_type: match ft.as_ref().map(|t| (t.is_dir(), t.is_symlink())) {
                            Some((true, _)) => DT_DIR,
                            Some((false, true)) => DT_LNK,
                            Some((false, false)) => DT_REG,
                            None => DT_UNKNOWN,
                        },
                    });
                }
                Some(Err(_)) => continue, // transient per-entry error: skip
                None => return None,
            }
        }
    }
}

// ── Mutating operations ─────────────────────────────────────────

/// mkdir -p: create all components. EEXIST components must be real
/// directories (not symlinks) to preserve the C O_NOFOLLOW defense.
pub fn mkdir_p(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    let abs_like = path.is_absolute();
    let mut cur = PathBuf::new();
    let mut components = path.components().peekable();
    // Preserve absolute root.
    if abs_like {
        if let Some(c) = components.next() {
            cur.push(c.as_os_str());
        }
    }
    for c in components {
        cur.push(c.as_os_str());
        match fs::symlink_metadata(&cur) {
            Ok(md) if md.is_dir() && !md.file_type().is_symlink() => continue,
            Ok(_) => return false, // exists but is a file or symlink
            Err(_) => {
                if fs::create_dir(&cur).is_err() {
                    return false;
                }
            }
        }
    }
    is_dir(path)
}

pub fn unlink(path: &Path) -> i32 {
    match fs::remove_file(path) {
        Ok(()) => 0,
        Err(_) => NOT_FOUND,
    }
}

pub fn rmdir(path: &Path) -> i32 {
    match fs::remove_dir(path) {
        Ok(()) => 0,
        Err(_) => NOT_FOUND,
    }
}

/// rename with atomic replace (POSIX rename already replaces).
pub fn rename_replace(src: &Path, dst: &Path) -> i32 {
    match fs::rename(src, dst) {
        Ok(()) => 0,
        Err(_) => NOT_FOUND,
    }
}

/// rename with no-overwrite, via link()+unlink() (portable no-clobber).
/// Both paths are expected to be on the same filesystem (adjacent DB
/// staging files, as in the C contract).
pub fn rename_noreplace(src: &Path, dst: &Path) -> i32 {
    if src.as_os_str().is_empty() || dst.as_os_str().is_empty() {
        return NOT_FOUND;
    }
    // SAFETY: plain libc link(2) with valid CStrings.
    let c_src = match std::ffi::CString::new(src.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return NOT_FOUND,
    };
    let c_dst = match std::ffi::CString::new(dst.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return NOT_FOUND,
    };
    unsafe {
        if libc::link(c_src.as_ptr(), c_dst.as_ptr()) != 0 {
            return NOT_FOUND;
        }
    }
    if unlink(src) != 0 {
        unlink(dst);
        return NOT_FOUND;
    }
    0
}

/// Remove a SQLite database's -wal/-shm/-journal sidecars. Any code path
/// installing a FRESH database over a previous generation must call this
/// first: SQLite replays a leftover WAL ON TOP of the fresh file (#897).
pub fn remove_db_sidecars(db_path: &Path) -> i32 {
    if db_path.as_os_str().is_empty() {
        return NOT_FOUND;
    }
    let as_str = db_path.to_string_lossy();
    if as_str.len() > 4096 - "-journal".len() {
        return NOT_FOUND;
    }
    let mut result = 0;
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = PathBuf::from(format!("{as_str}{suffix}"));
        if unlink(&side) != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound
        {
            result = NOT_FOUND;
        }
    }
    result
}

/// Reflink (copy-on-write clone) when supported, else stream copy.
/// Fails and cleans up `dst` on error.
pub fn clone_or_copy_file(src: &Path, dst: &Path) -> i32 {
    // Linux fast path: FICLONE ioctl.
    use std::os::unix::io::AsRawFd;
    if let (Ok(fin), Ok(fout)) = (
        fs::File::open(src),
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dst),
    ) {
        // FICLONE = 0x40049409 (linux/fs.h). musl's ioctl request param is
        // c_int, glibc's c_ulong — pass through c_int and let the binding
        // sign-extend where needed.
        const FICLONE: libc::c_int = 0x40049409u32 as libc::c_int;
        let cloned = unsafe {
            libc::ioctl(
                fout.as_raw_fd(),
                FICLONE as libc::c_ulong,
                fin.as_raw_fd() as libc::c_ulong,
            )
        };
        if cloned == 0 {
            return 0;
        }
        drop(fout);
        drop(fin);
        let _ = fs::remove_file(dst); // fall through to stream copy
    }
    stream_copy_file(src, dst)
}

fn stream_copy_file(src: &Path, dst: &Path) -> i32 {
    match fs::copy(src, dst) {
        Ok(_) => 0,
        Err(_) => {
            let _ = fs::remove_file(dst);
            NOT_FOUND
        }
    }
}

/// Resolve to a canonical absolute path (realpath).
pub fn canonical_path(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok()
}

/// Run `argv` directly (no shell), wait, and return the exit status code.
/// A missing binary maps to 127 (POSIX "command not found" convention).
pub fn exec_no_shell(argv: &[&str]) -> i32 {
    let Some((prog, args)) = argv.split_first() else {
        return NOT_FOUND;
    };
    match std::process::Command::new(prog).args(args).status() {
        Ok(status) => status.code().unwrap_or(NOT_FOUND),
        // C path: execvp fails in the child → _exit(127).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 127,
        Err(_) => NOT_FOUND,
    }
}

pub fn is_dir(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cbm-cfs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn path_info_lstat_semantics() {
        let d = tmpdir("info");
        let f = d.join("file.txt");
        fs::write(&f, "0123456789").unwrap();
        let (st, info) = path_info_utf8(&f);
        assert_eq!(st, InfoOk);
        let info = info.unwrap();
        assert!(info.is_regular);
        assert!(!info.is_directory);
        assert!(!info.is_symlink);
        assert_eq!(info.size, 10);
        assert!(info.mtime_ns > 0);

        // Symlink is REPORTED, not followed.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&f, d.join("link")).unwrap();
            let (st, info) = path_info_utf8(&d.join("link"));
            assert_eq!(st, InfoOk);
            let info = info.unwrap();
            assert!(info.is_symlink);
            assert!(!info.is_regular);
        }

        assert_eq!(path_info_utf8(&d.join("absent")).0, Absent);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn dir_iteration() {
        let d = tmpdir("iter");
        fs::write(d.join("a.txt"), "x").unwrap();
        fs::create_dir(d.join("sub")).unwrap();
        let mut dir = opendir(&d).unwrap();
        let mut names = Vec::new();
        while let Some(e) = dir.readdir() {
            names.push((e.name, e.is_dir));
        }
        names.sort();
        assert_eq!(
            names,
            vec![("a.txt".to_string(), false), ("sub".to_string(), true)]
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn mkdir_p_creates_and_rejects_file_collision() {
        let d = tmpdir("mkdir");
        let deep = d.join("a/b/c");
        assert!(mkdir_p(&deep));
        assert!(is_dir(&deep));
        assert!(mkdir_p(&deep)); // idempotent

        // A path component that is an existing FILE must fail.
        let f = d.join("f");
        fs::write(&f, "").unwrap();
        assert!(!mkdir_p(&f.join("sub")));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn rename_replace_and_noreplace() {
        let d = tmpdir("ren");
        let a = d.join("a");
        let b = d.join("b");
        fs::write(&a, "src").unwrap();
        fs::write(&b, "dst").unwrap();
        // replace: dst content clobbered atomically
        assert_eq!(rename_replace(&a, &b), 0);
        assert_eq!(fs::read_to_string(&b).unwrap(), "src");
        assert!(!a.exists());

        // noreplace: refuses when dst exists
        let c = d.join("c");
        fs::write(&c, "other").unwrap();
        assert_eq!(rename_noreplace(&c, &b), NOT_FOUND);
        assert!(c.exists());
        assert_eq!(fs::read_to_string(&b).unwrap(), "src");
        // noreplace: succeeds when dst absent
        let e = d.join("e");
        assert_eq!(rename_noreplace(&c, &e), 0);
        assert!(!c.exists());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn sidecars_removed_tolerating_absent() {
        let d = tmpdir("side");
        let db = d.join("proj.db");
        fs::write(&db, "x").unwrap();
        fs::write(d.join("proj.db-wal"), "x").unwrap();
        assert_eq!(remove_db_sidecars(&db), 0); // -shm/-journal absent → OK
        assert!(!d.join("proj.db-wal").exists());
        assert!(db.exists());
        // Missing db itself is not checked — only sidecars are unlinked.
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn clone_or_copy_roundtrip() {
        let d = tmpdir("clone");
        let src = d.join("src.bin");
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();
        let dst = d.join("dst.bin");
        assert_eq!(clone_or_copy_file(&src, &dst), 0);
        assert_eq!(fs::read(&dst).unwrap(), payload);
        // Failure: missing source.
        assert_eq!(clone_or_copy_file(&d.join("nope"), &d.join("x")), NOT_FOUND);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn canonical_and_exec() {
        assert!(canonical_path(Path::new("/tmp")).is_some());
        // /bin/true exits 0; a missing binary is 127.
        #[cfg(target_arch = "x86_64")]
        let true_path = "/bin/true";
        #[cfg(not(target_arch = "x86_64"))]
        let true_path = "/bin/true";
        if Path::new(true_path).exists() {
            assert_eq!(exec_no_shell(&[true_path]), 0);
        }
        assert_eq!(exec_no_shell(&["cbm-definitely-missing-cmd"]), 127);
        assert_eq!(exec_no_shell(&[]), NOT_FOUND);
    }
}
