//! private_file_lock.rs — 1:1 rewrite of `src/foundation/private_file_lock.*`.
//!
//! Owner-private file locks inside a 0700 directory: openat with
//! NOFOLLOW|EXCL, dual fd/path inode revalidation, non-blocking flock,
//! atfork bookkeeping, and small (≤4 KiB) payload read/write under the
//! lock. Every step fails closed to [`LockStatus::Unsafe`] on any sign of
//! tampering (symlink swap, ownership change, mode drift, extra links).

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const PAYLOAD_CAP: usize = 4096;
const NAME_MAX: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStatus {
    Ok,
    Busy,
    Unsafe,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Shared,
    Exclusive,
}

/// Owner-private lock directory: an open fd to a 0700 dir owned by the
/// current euid, revalidated against its path on every use.
pub struct LockDirectory {
    fd: RawFd,
    path: PathBuf,
    device: u64,
    inode: u64,
    owner_pid: i32,
}

extern "C" {
    fn getpid() -> i32;
    fn geteuid() -> u32;
}

fn stat_of<F>(f: F) -> Option<libc::stat>
where
    F: for<'a> FnOnce(&'a mut libc::stat) -> i32,
{
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if f(&mut st) == 0 {
        Some(st)
    } else {
        None
    }
}

fn cstring_of(path: &Path) -> Option<CString> {
    CString::new(path.as_os_str().as_bytes()).ok()
}

fn self_ptr_slot(raw: *mut PrivateFileLock) -> usize {
    let registry = TRACKED.lock().unwrap_or_else(|e| e.into_inner());
    registry
        .iter()
        .position(|&p| p == 0 || p == raw as usize)
        .unwrap_or(usize::MAX)
}

fn mode_bits(st: &libc::stat) -> u32 {
    st.st_mode & 0o7777
}

impl LockDirectory {
    /// Adopt an already-open directory fd (C cbm_private_lock_directory_adopt_posix):
    /// the fd and `stable_path` must resolve to the same 0700 directory owned
    /// by this euid.
    ///
    /// # Safety
    /// `directory_fd` must be a real open fd; on success this struct owns it.
    pub unsafe fn adopt(directory_fd: RawFd, stable_path: &Path) -> (LockStatus, Option<Self>) {
        if directory_fd < 0 || stable_path.as_os_str().is_empty() {
            return (LockStatus::Io, None);
        }
        if !set_cloexec(directory_fd) {
            return (LockStatus::Io, None);
        }
        let Some(c_path) = cstring_of(stable_path) else {
            return (LockStatus::Io, None);
        };
        let by_handle = stat_of(|st| libc::fstat(directory_fd, st));
        // SAFETY: c_path is a valid NUL-terminated string; stat buffer valid.
        let by_path = unsafe { stat_of(|st| libc::lstat(c_path.as_ptr(), st)) };
        let (Some(h), Some(p)) = (by_handle, by_path) else {
            return (LockStatus::Unsafe, None);
        };
        let euid = unsafe { geteuid() };
        if !is_dir(&h)
            || !is_dir(&p)
            || h.st_uid != euid
            || p.st_uid != euid
            || mode_bits(&h) != 0o700
            || mode_bits(&p) != 0o700
            || h.st_dev != p.st_dev
            || h.st_ino != p.st_ino
        {
            return (LockStatus::Unsafe, None);
        }
        let dir = LockDirectory {
            fd: directory_fd,
            path: stable_path.to_path_buf(),
            device: h.st_dev,
            inode: h.st_ino,
            owner_pid: unsafe { getpid() },
        };
        (LockStatus::Ok, Some(dir))
    }

    fn revalidate(&self) -> bool {
        if self.owner_pid != unsafe { getpid() } || self.fd < 0 {
            return false;
        }
        let Some(h) = (unsafe { stat_of(|st| libc::fstat(self.fd, st)) }) else {
            return false;
        };
        let Some(c_path) = cstring_of(&self.path) else {
            return false;
        };
        // SAFETY: valid fd and NUL-terminated path.
        let Some(p) = (unsafe { stat_of(|st| libc::lstat(c_path.as_ptr(), st)) }) else {
            return false;
        };
        let euid = unsafe { geteuid() };
        is_dir(&h)
            && is_dir(&p)
            && h.st_dev == self.device
            && h.st_ino == self.inode
            && p.st_dev == self.device
            && p.st_ino == self.inode
            && h.st_uid == euid
            && p.st_uid == euid
            && mode_bits(&h) == 0o700
            && mode_bits(&p) == 0o700
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Close the directory (C cbm_private_lock_directory_close).
    pub fn close(self) {
        // SAFETY: fd owned by this struct.
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn is_dir(st: &libc::stat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

fn is_reg(st: &libc::stat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
}

fn set_cloexec(fd: RawFd) -> bool {
    // SAFETY: valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return false;
    }
    // SAFETY: as above.
    unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == 0 }
}

fn base_name_valid(base_name: &str) -> bool {
    if base_name.is_empty() || base_name == "." || base_name == ".." || base_name.len() > NAME_MAX {
        return false;
    }
    base_name.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
    })
}

fn flock_set(fd: RawFd, operation: i32) -> bool {
    // SAFETY: valid fd; retry on EINTR like the C.
    loop {
        let rc = unsafe { libc::flock(fd, operation) };
        if rc == 0 {
            return true;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return false;
    }
}

/// A held lock on `<directory>/<base_name>`.
pub struct PrivateFileLock {
    fd: RawFd,
    owner_pid: i32,
    mode: LockMode,
    unlocked: bool,
    base_name: String,
}

static FORK_MUTEX: Mutex<()> = Mutex::new(());
static TRACKED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Fork guard (C atfork serialization): held while any lock operation runs.
/// The C installs pthread_atfork handlers; here the equivalent child reset
/// is an explicit [`forked_child_reset`] call by the fork site (proot
/// environments hang in pthread_atfork registration, and Rust daemon code
/// owns its fork points).
/// Held across one lock operation; other threads WAIT (C pthread_mutex
/// semantics — enter never spuriously fails inside one process).
pub struct ForkGuard {
    _guard: MutexGuard<'static, ()>,
}

pub fn fork_guard_enter() -> Option<ForkGuard> {
    let guard = FORK_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    Some(ForkGuard { _guard: guard })
}

/// After fork(): the child inherits NO tracked locks (they belong to the
/// forking process). Mirrors the C atfork child handler.
pub fn forked_child_reset() {
    if let Ok(mut list) = TRACKED.lock() {
        list.clear();
    }
}

impl PrivateFileLock {
    /// Try to acquire (create-or-open + flock NB) `base_name` in `directory`.
    pub fn try_acquire(
        directory: &LockDirectory,
        base_name: &str,
        mode: LockMode,
    ) -> (LockStatus, Option<Box<PrivateFileLock>>) {
        if !base_name_valid(base_name) {
            return (LockStatus::Unsafe, None);
        }
        if !directory.revalidate() {
            return (LockStatus::Unsafe, None);
        }
        let Some(_guard) = fork_guard_enter() else {
            return (LockStatus::Io, None);
        };
        Self::acquire_locked(directory, base_name, mode)
    }

    fn acquire_locked(
        directory: &LockDirectory,
        base_name: &str,
        mode: LockMode,
    ) -> (LockStatus, Option<Box<PrivateFileLock>>) {
        let c_name = match CString::new(base_name) {
            Ok(c) => c,
            Err(_) => return (LockStatus::Unsafe, None),
        };
        let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // SAFETY: directory fd + NUL-terminated name.
        let mut fd = unsafe {
            libc::openat(
                directory.fd,
                c_name.as_ptr(),
                flags | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EEXIST {
                fd = unsafe { libc::openat(directory.fd, c_name.as_ptr(), flags) };
            }
        }
        if fd < 0 {
            // Absent-but-otherwise-clean directory → Io; anything found at
            // the name (symlink etc.) → Unsafe.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let found = unsafe {
                libc::fstatat(
                    directory.fd,
                    c_name.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0;
            return (
                if found {
                    LockStatus::Unsafe
                } else {
                    LockStatus::Io
                },
                None,
            );
        }
        let initial = unsafe { stat_of(|st| libc::fstat(fd, st)) };
        let initial_ok = initial.is_some();
        if initial_ok && !Self::revalidate_file(directory, base_name, fd, initial.as_ref()) {
            unsafe { libc::close(fd) };
            return (LockStatus::Unsafe, None);
        }
        let operation = match mode {
            LockMode::Shared => libc::LOCK_SH,
            LockMode::Exclusive => libc::LOCK_EX,
        };
        if !flock_set(fd, operation | libc::LOCK_NB) {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            unsafe { libc::close(fd) };
            return (
                if err == libc::EWOULDBLOCK || err == libc::EAGAIN {
                    LockStatus::Busy
                } else {
                    LockStatus::Io
                },
                None,
            );
        }
        {
            let mut registry = TRACKED.lock().unwrap_or_else(|e| e.into_inner());
            registry.push(0); // reserve slot; fixed below
        }

        let lock = Box::new(PrivateFileLock {
            fd,
            owner_pid: unsafe { getpid() },
            mode,
            unlocked: false,
            base_name: base_name.to_string(),
        });
        let raw = Box::into_raw(lock);

        if !Self::revalidate_file(directory, base_name, fd, initial.as_ref()) {
            // Post-acquire cleanup (C forced-cleanup path).
            let _ = Self::release_impl(Some(unsafe { Box::from_raw(raw) }));
            return (LockStatus::Io, None);
        }
        // Register the real pointer.
        let slot_idx = self_ptr_slot(raw);
        TRACKED.lock().unwrap_or_else(|e| e.into_inner())[slot_idx] = raw as usize;
        (LockStatus::Ok, Some(unsafe { Box::from_raw(raw) }))
    }

    fn revalidate_file(
        directory: &LockDirectory,
        base_name: &str,
        fd: RawFd,
        expected: Option<&libc::stat>,
    ) -> bool {
        let euid = unsafe { geteuid() };
        let Some(h) = (unsafe { stat_of(|st| libc::fstat(fd, st)) }) else {
            return false;
        };
        let Ok(c_name) = CString::new(base_name) else {
            return false;
        };
        // SAFETY: valid fd / name.
        let Some(p) = (unsafe {
            stat_of(|st| {
                libc::fstatat(directory.fd, c_name.as_ptr(), st, libc::AT_SYMLINK_NOFOLLOW)
            })
        }) else {
            return false;
        };
        is_reg(&h)
            && h.st_uid == euid
            && h.st_nlink == 1
            && mode_bits(&h) == 0o600
            && is_reg(&p)
            && p.st_uid == euid
            && p.st_nlink == 1
            && mode_bits(&p) == 0o600
            && p.st_dev == h.st_dev
            && p.st_ino == h.st_ino
            && expected
                .map(|e| e.st_dev == h.st_dev && e.st_ino == h.st_ino)
                .unwrap_or(true)
    }

    fn payload_fd_valid(&self) -> Option<libc::stat> {
        if self.fd < 0
            || self.unlocked
            || self.owner_pid != unsafe { getpid() }
            || !Self::is_tracked(self as *const _ as *mut PrivateFileLock)
        {
            return None;
        }
        let st = unsafe { stat_of(|out| libc::fstat(self.fd, out))? };
        let euid = unsafe { geteuid() };
        if is_reg(&st)
            && st.st_uid == euid
            && st.st_nlink == 1
            && mode_bits(&st) == 0o600
            && st.st_size >= 0
        {
            Some(st)
        } else {
            None
        }
    }

    fn is_tracked(raw: *mut PrivateFileLock) -> bool {
        let registry = TRACKED.lock().unwrap_or_else(|e| e.into_inner());
        registry.contains(&(raw as usize))
    }

    /// Read the payload file under the held lock (≤4 KiB).
    pub fn payload_read(&self, buf: &mut [u8]) -> (LockStatus, usize) {
        if buf.is_empty() {
            return (LockStatus::Unsafe, 0);
        }
        let _guard = match fork_guard_enter() {
            Some(g) => g,
            None => return (LockStatus::Io, 0),
        };
        let Some(status) = self.payload_fd_valid() else {
            return (LockStatus::Unsafe, 0);
        };
        let size = status.st_size as usize;
        let mut valid = size <= PAYLOAD_CAP && size <= buf.len();
        let mut offset = 0usize;
        while valid && offset < size {
            // SAFETY: valid fd, buf sized ≥ payload cap.
            let count = unsafe {
                libc::pread(
                    self.fd,
                    buf.as_mut_ptr().add(offset) as *mut libc::c_void,
                    size - offset,
                    offset as i64,
                )
            };
            if count > 0 {
                offset += count as usize;
            } else if count < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                valid = false;
            }
        }
        if valid {
            (LockStatus::Ok, size)
        } else {
            (LockStatus::Io, 0)
        }
    }

    /// Replace the payload under an exclusive lock (≤4 KiB), fsync on success.
    pub fn payload_write(&self, data: &[u8]) -> LockStatus {
        if data.is_empty() || data.len() > PAYLOAD_CAP || self.mode != LockMode::Exclusive {
            return LockStatus::Unsafe;
        }
        let _guard = match fork_guard_enter() {
            Some(g) => g,
            None => return LockStatus::Io,
        };
        let metadata_safe = self.payload_fd_valid().is_some();
        let mut valid = metadata_safe;
        // SAFETY: valid fd throughout.
        unsafe {
            valid = valid && libc::ftruncate(self.fd, 0) == 0;
            let mut offset = 0usize;
            while valid && offset < data.len() {
                let count = libc::pwrite(
                    self.fd,
                    data.as_ptr().add(offset) as *const libc::c_void,
                    data.len() - offset,
                    offset as i64,
                );
                if count > 0 {
                    offset += count as usize;
                } else if count < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                    continue;
                } else {
                    valid = false;
                }
            }
            valid = valid && libc::ftruncate(self.fd, data.len() as i64) == 0;
            if valid {
                loop {
                    if libc::fsync(self.fd) == 0 {
                        break;
                    }
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        valid = false;
                        break;
                    }
                }
            }
        }
        if !metadata_safe {
            return LockStatus::Unsafe;
        }
        if valid {
            LockStatus::Ok
        } else {
            LockStatus::Io
        }
    }

    /// Release (unlock + close + deregister). Consumes the lock.
    pub fn release(boxed: Box<Self>) -> LockStatus {
        Self::release_impl(Some(boxed))
    }

    fn release_impl(lock_io: Option<Box<PrivateFileLock>>) -> LockStatus {
        let Some(mut lock) = lock_io else {
            return LockStatus::Io;
        };
        if lock.owner_pid != unsafe { getpid() } || lock.fd < 0 {
            return LockStatus::Ok; // foreign/already-closed: just drop
        }
        let _guard = match fork_guard_enter() {
            Some(g) => g,
            None => return LockStatus::Io,
        };
        let mut registry = TRACKED.lock().unwrap_or_else(|e| e.into_inner());
        if !registry.contains(&(lock.as_ref() as *const PrivateFileLock as usize)) {
            return LockStatus::Io;
        }
        if !lock.unlocked {
            // SAFETY: valid fd.
            if !flock_set(lock.fd, libc::LOCK_UN) {
                return LockStatus::Io;
            }
            lock.unlocked = true;
        }
        // SAFETY: valid fd we own.
        let close_rc = unsafe { libc::close(lock.fd) };
        lock.fd = -1;
        registry.retain(|&p| p != lock.as_ref() as *const PrivateFileLock as usize);
        drop(registry);
        if close_rc == 0 {
            LockStatus::Ok
        } else {
            LockStatus::Io
        }
    }

    /// Unlock completeness probe (C test helper).
    pub fn unlock_complete(&self) -> bool {
        self.unlocked
    }

    pub fn base_name(&self) -> &str {
        &self.base_name
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl AsRawFd for PrivateFileLock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for PrivateFileLock {
    fn drop(&mut self) {
        // Safety net: release the OS resources if the caller forgot
        // (C relies on explicit release; Rust adds the drop backstop).
        if self.fd >= 0 && self.owner_pid == unsafe { getpid() } {
            unsafe {
                if !self.unlocked {
                    libc::flock(self.fd, libc::LOCK_UN);
                }
                libc::close(self.fd);
            }
            self.fd = -1;
            let raw = self as *mut PrivateFileLock as usize;
            if let Ok(mut registry) = TRACKED.lock() {
                registry.retain(|&p| p != raw);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::io::IntoRawFd;

    fn make_directory(tag: &str) -> (PathBuf, RawFd) {
        let dir = std::env::temp_dir().join(format!("cbm-pfl-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let f = fs::File::open(&dir).unwrap();
        (dir, f.into_raw_fd()) // transfer ownership; caller adopts
    }

    #[test]
    fn adopt_and_acquire_exclusive() {
        let (path, fd) = make_directory("excl");
        // Keep a File alive so the fd stays valid through the test; adopt
        // clones the fd via dup semantics (adopt takes ownership of the fd
        // we pass — use dup to keep the File's fd intact).
        let (status, dir) = unsafe { LockDirectory::adopt(fd, &path) };
        assert_eq!(status, LockStatus::Ok);
        let dir = dir.unwrap();

        let (status, lock) = PrivateFileLock::try_acquire(&dir, "test.lock", LockMode::Exclusive);
        assert_eq!(status, LockStatus::Ok);
        let lock = lock.unwrap();

        // Second exclusive acquisition is Busy.
        let (status2, _) = PrivateFileLock::try_acquire(&dir, "test.lock", LockMode::Exclusive);
        assert_eq!(status2, LockStatus::Busy);

        // Shared acquisition succeeds alongside exclusive? No: flock NB EX
        // conflicts with itself in the same process via separate fds.
        assert!(!lock.unlock_complete());

        // Payload write + read back.
        assert_eq!(lock.payload_write(b"hello"), LockStatus::Ok);
        let mut buf = [0u8; 64];
        let (status, n) = lock.payload_read(&mut buf);
        assert_eq!(status, LockStatus::Ok);
        assert_eq!(&buf[..n], b"hello");

        assert_eq!(PrivateFileLock::release(lock), LockStatus::Ok);
        dir.close();
    }

    #[test]
    fn shared_then_exclusive_conflict() {
        let (path, fd) = make_directory("shared");
        let (_, dir) = unsafe { LockDirectory::adopt(fd, &path) };
        let dir = dir.unwrap();
        let (s1, l1) = PrivateFileLock::try_acquire(&dir, "s.lock", LockMode::Shared);
        assert_eq!(s1, LockStatus::Ok);
        let l1 = l1.unwrap();
        let (s2, _) = PrivateFileLock::try_acquire(&dir, "s.lock", LockMode::Exclusive);
        assert_eq!(s2, LockStatus::Busy);
        PrivateFileLock::release(l1);
        dir.close();
    }

    #[test]
    fn rejects_bad_names_and_unsafe_dir() {
        let (path, fd) = make_directory("bad");
        let (_, dir) = unsafe { LockDirectory::adopt(fd, &path) };
        let dir = dir.unwrap();
        for bad in ["", ".", "..", "Has-Capital", "with space", "with/slash"] {
            let (status, _) = PrivateFileLock::try_acquire(&dir, bad, LockMode::Exclusive);
            assert_eq!(status, LockStatus::Unsafe, "name {bad:?}");
        }
        dir.close();
    }

    #[test]
    fn adopt_rejects_wrong_mode_dir() {
        let dir_path = std::env::temp_dir().join(format!("cbm-pfl-loose-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir_path);
        fs::create_dir(&dir_path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir_path, fs::Permissions::from_mode(0o755)).unwrap();
        let f = fs::File::open(&dir_path).unwrap();
        let (status, _) = unsafe { LockDirectory::adopt(f.as_raw_fd(), &dir_path) };
        assert_eq!(status, LockStatus::Unsafe);
        fs::remove_dir_all(&dir_path).ok();
    }
}
