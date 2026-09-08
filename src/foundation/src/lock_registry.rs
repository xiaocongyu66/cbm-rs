//! lock_registry.rs — 1:1 rewrite of `src/foundation/lock_registry.{c,h}` +
//! `lock_registry_internal.h`.
//!
//! In-process reader/writer lock service layered over the owner-private
//! file locks. Two native file locks per resource: a TURN lock (serializes
//! the handoff, always exclusive) and an RW lock (shared for readers,
//! exclusive for the writer). Waiters park on a fork condition — the C's
//! G→R lock order (fork guard → registry mutex) is preserved: the guard is
//! held across the registry mutex, released only inside the condition wait
//! (which re-acquires it on wake), matching
//! `cbm_private_fork_condition_wait_until_while_guarded`.

use crate::private_file_lock::{
    fork_condition_broadcast_while_guarded, fork_condition_new,
    fork_condition_wait_until_while_guarded, fork_guard_enter, ForkCondition, ForkGuard,
    ForkWaitStatus, LockDirectory, LockMode, LockStatus, PrivateFileLock,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

pub const LOCK_REGISTRY_NAME_CAP: usize = 80;
const LOCK_REGISTRY_RESOURCE_CAP: usize = 4096;
/// Native ownership can change in another process, so the attempt owner
/// keeps a bounded retry even without a local broadcast.
const NATIVE_RETRY_MS: u64 = 50;

/// Cancellation token (C atomic bool).
pub type CancelToken = Arc<AtomicBool>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    TurnBusy,
    TurnHeld,
    RwBusy,
    NativeReady,
}

/// Derive turn/rw file names from the resource key (sha256 hex →
/// "cbm-<hex>.turn" / "cbm-<hex>.rw").
pub fn resource_names(resource_key: &str) -> Option<(String, String)> {
    if resource_key.is_empty() || resource_key.len() > LOCK_REGISTRY_RESOURCE_CAP {
        return None;
    }
    let digest = crate::sha256::sha256_hex(resource_key.as_bytes());
    let turn = format!("cbm-{digest}.turn");
    let rw = format!("cbm-{digest}.rw");
    if turn.len() >= LOCK_REGISTRY_NAME_CAP || rw.len() >= LOCK_REGISTRY_NAME_CAP {
        return None;
    }
    Some((turn, rw))
}

struct Entry {
    #[allow(dead_code)] // kept for parity with the C entry record
    turn_name: String,
    #[allow(dead_code)]
    rw_name: String,
    /// FIFO queue of queued waiter sequence numbers.
    waiters: Vec<u64>,
    /// The waiter currently allowed to attempt the native locks.
    attempt: Option<u64>,
    active_readers: usize,
    writer_active: bool,
}

struct Inner {
    entries: HashMap<(String, String), Entry>,
    waiter_count: usize,
    active_leases: usize,
    #[allow(dead_code)] // parity with the C cleanup accounting
    pending_cleanup: usize,
    closing: bool,
    seq_next: u64,
}

/// The lock registry (C cbm_lock_registry_t).
pub struct LockRegistry {
    directory: *const LockDirectory,
    owner_pid: u64,
    inner: Mutex<Inner>,
    condition: ForkCondition,
    retired: AtomicBool,
}

// SAFETY: directory points at a LockDirectory the owner keeps alive (the
// registry never closes it); all other state is behind the Mutex.
unsafe impl Send for LockRegistry {}
unsafe impl Sync for LockRegistry {}

fn current_pid() -> u64 {
    unsafe { libc::getpid() as u64 }
}

impl LockRegistry {
    /// Create (C cbm_lock_registry_new).
    pub fn new(directory: &LockDirectory) -> Option<Arc<LockRegistry>> {
        Some(Arc::new(LockRegistry {
            directory: directory as *const _,
            owner_pid: current_pid(),
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                waiter_count: 0,
                active_leases: 0,
                pending_cleanup: 0,
                closing: false,
                seq_next: 0,
            }),
            condition: fork_condition_new(),
            retired: AtomicBool::new(false),
        }))
    }

    fn dir(&self) -> &LockDirectory {
        // SAFETY: owner contract — the directory outlives every registry
        // handle (registry free does not close it).
        unsafe { &*self.directory }
    }

    /// Request cancellation via a token (C cbm_lock_registry_request_cancel).
    pub fn request_cancel(&self, token: &CancelToken) -> LockStatus {
        token.store(true, Ordering::SeqCst);
        LockStatus::Ok
    }

    /// Try to acquire without waiting (C cbm_lock_registry_try_acquire).
    pub fn try_acquire(
        self: &Arc<Self>,
        resource_key: &str,
        mode: LockMode,
    ) -> (LockStatus, Option<Lease>) {
        self.acquire_internal(resource_key, mode, u64::MAX, None, true)
    }

    /// Acquire with deadline and cancellation
    /// (C cbm_lock_registry_acquire).
    pub fn acquire(
        self: &Arc<Self>,
        resource_key: &str,
        mode: LockMode,
        deadline_ms: u64,
        cancel_token: Option<&CancelToken>,
    ) -> (LockStatus, Option<Lease>) {
        self.acquire_internal(resource_key, mode, deadline_ms, cancel_token, false)
    }

    fn lock_inner(&self) -> Option<(ForkGuard, MutexGuard<'_, Inner>)> {
        let guard = fork_guard_enter()?;
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.closing || self.owner_pid != current_pid() {
            return None;
        }
        Some((guard, inner))
    }

    fn acquire_internal(
        self: &Arc<Self>,
        resource_key: &str,
        mode: LockMode,
        deadline_ms: u64,
        cancel_token: Option<&CancelToken>,
        try_once: bool,
    ) -> (LockStatus, Option<Lease>) {
        let Some((turn_name, rw_name)) = resource_names(resource_key) else {
            return (LockStatus::Unsafe, None);
        };
        if !try_once && should_stop(deadline_ms, cancel_token) {
            return (LockStatus::Busy, None);
        }

        // Register as a waiter (FIFO by sequence number).
        let Some((guard, mut inner)) = self.lock_inner() else {
            return (LockStatus::Io, None);
        };
        let entry_key = (turn_name.clone(), rw_name.clone());
        inner.seq_next += 1;
        let seq = inner.seq_next;
        let entry = inner
            .entries
            .entry(entry_key.clone())
            .or_insert_with(|| Entry {
                turn_name,
                rw_name,
                waiters: Vec::new(),
                attempt: None,
                active_readers: 0,
                writer_active: false,
            });
        entry.waiters.push(seq);
        inner.waiter_count += 1;
        drop(inner);
        drop(guard);

        loop {
            let stop_now = !try_once && should_stop(deadline_ms, cancel_token);
            let Some((guard, mut inner)) = self.lock_inner() else {
                return (LockStatus::Io, None);
            };
            if inner.closing {
                drop(inner);
                drop(guard);
                // Waiter cleanup happens with registry teardown.
                return (LockStatus::Io, None);
            }
            if stop_now {
                let removed = remove_waiter(&mut inner, &entry_key, seq);
                if removed {
                    return (LockStatus::Busy, None);
                }
                drop(inner);
                drop(guard);
                return (LockStatus::Io, None);
            }
            let entry = inner.entries.get(&entry_key).expect("entry pinned above");
            let can_attempt = entry.waiters.first() == Some(&seq) && entry.attempt.is_none();
            if can_attempt {
                inner.entries.get_mut(&entry_key).unwrap().attempt = Some(seq);
                drop(inner);
                drop(guard);
                return self.attempt_native(
                    &entry_key,
                    seq,
                    mode,
                    deadline_ms,
                    cancel_token,
                    try_once,
                );
            }
            if try_once {
                let removed = remove_waiter(&mut inner, &entry_key, seq);
                if removed {
                    return (LockStatus::Busy, None);
                }
                drop(inner);
                drop(guard);
                return (LockStatus::Io, None);
            }
            let cancelled = cancel_token
                .map(|t| t.load(Ordering::Acquire))
                .unwrap_or(false);
            if cancelled {
                drop(inner);
                drop(guard);
                continue; // loop top: should_stop fires
            }
            // Wait on the fork condition, releasing the registry mutex (the
            // C wait_locked dance: unlock(R) → condwait(G) → lock(R)).
            drop(inner);
            let (guard2, status) = fork_condition_wait_until_while_guarded(
                &self.condition,
                guard,
                wait_deadline(deadline_ms),
            );
            drop(guard2);
            match status {
                ForkWaitStatus::Error => return (LockStatus::Io, None),
                _ => continue,
            }
        }
    }

    /// The turn/rw two-phase acquisition (C lock_registry_attempt_native).
    fn attempt_native(
        self: &Arc<Self>,
        entry_key: &(String, String),
        seq: u64,
        mode: LockMode,
        deadline_ms: u64,
        cancel_token: Option<&CancelToken>,
        try_once: bool,
    ) -> (LockStatus, Option<Lease>) {
        let mut turn: Option<Box<PrivateFileLock>> = None;
        let mut rw: Option<Box<PrivateFileLock>> = None;
        let mut status = LockStatus::Busy;

        while rw.is_none() {
            if !try_once && should_stop(deadline_ms, cancel_token) {
                status = LockStatus::Busy;
                break;
            }
            if turn.is_none() {
                // TURN is always exclusive, including for readers (it
                // exists to serialize the handoff).
                match PrivateFileLock::try_acquire(self.dir(), &entry_key.0, LockMode::Exclusive) {
                    (LockStatus::Ok, t) => {
                        turn = t;
                        notify(self, mode, Stage::TurnHeld);
                    }
                    (LockStatus::Busy, _) => {
                        notify(self, mode, Stage::TurnBusy);
                        if try_once {
                            status = LockStatus::Busy;
                            break;
                        }
                        if !self.park_native(deadline_ms, cancel_token) {
                            status = LockStatus::Io;
                            break;
                        }
                        continue;
                    }
                    (other, _) => {
                        status = other;
                        break;
                    }
                }
            }
            let (st, r) = PrivateFileLock::try_acquire(self.dir(), &entry_key.1, mode);
            match st {
                LockStatus::Ok => {
                    rw = r;
                    status = LockStatus::Ok;
                }
                LockStatus::Busy => {
                    notify(self, mode, Stage::RwBusy);
                    if try_once {
                        status = LockStatus::Busy;
                        break;
                    }
                    if !self.park_native(deadline_ms, cancel_token) {
                        status = LockStatus::Io;
                        break;
                    }
                    continue;
                }
                other => {
                    status = other;
                    break;
                }
            }
            // Readers drop the turn immediately; writers hold both until
            // the accounting handoff below.
            if mode == LockMode::Shared {
                if let Some(t) = turn.take() {
                    if PrivateFileLock::release(t) != LockStatus::Ok {
                        status = LockStatus::Io;
                        break;
                    }
                }
            }
        }

        if rw.is_none() || status != LockStatus::Ok {
            return self.abort_attempt(entry_key, seq, rw, turn, status);
        }

        // Confirm local RW accounting and publish the lease.
        let Some((_guard, mut inner)) = self.lock_inner() else {
            return self.abort_attempt(entry_key, seq, rw, turn, LockStatus::Io);
        };
        let entry = inner.entries.get_mut(entry_key);
        let ok = entry
            .map(|e| {
                let owns = e.attempt == Some(seq) && e.waiters.first() == Some(&seq);
                let local_ready = match mode {
                    LockMode::Shared => !e.writer_active,
                    LockMode::Exclusive => !e.writer_active && e.active_readers == 0,
                };
                owns && local_ready
            })
            .unwrap_or(false);
        if ok && remove_waiter(&mut inner, entry_key, seq) {
            let entry = inner.entries.get_mut(entry_key).unwrap();
            entry.attempt = None;
            match mode {
                LockMode::Shared => entry.active_readers += 1,
                LockMode::Exclusive => entry.writer_active = true,
            }
            inner.active_leases += 1;
            drop(inner);
            fork_condition_broadcast_while_guarded(&self.condition);
            let lease = Lease {
                registry: Arc::clone(self),
                entry_key: entry_key.clone(),
                mode,
                turn,
                rw,
                active: true,
            };
            return (LockStatus::Ok, Some(lease));
        }
        drop(inner);
        self.abort_attempt(entry_key, seq, rw, turn, LockStatus::Busy)
    }

    fn abort_attempt(
        self: &Arc<Self>,
        entry_key: &(String, String),
        seq: u64,
        rw: Option<Box<PrivateFileLock>>,
        turn: Option<Box<PrivateFileLock>>,
        status: LockStatus,
    ) -> (LockStatus, Option<Lease>) {
        if let Some(r) = rw {
            let _ = PrivateFileLock::release(r);
        }
        if let Some(t) = turn {
            let _ = PrivateFileLock::release(t);
        }
        let Some((_guard, mut inner)) = self.lock_inner() else {
            return (LockStatus::Io, None);
        };
        if let Some(entry) = inner.entries.get_mut(entry_key) {
            if entry.attempt == Some(seq) {
                entry.attempt = None;
            }
        }
        let removed = remove_waiter(&mut inner, entry_key, seq);
        if removed {
            return (status, None);
        }
        (LockStatus::Io, None)
    }

    /// Park with a bounded retry: native ownership can change in another
    /// process even without a local broadcast (C lock_registry_park_native).
    fn park_native(&self, deadline_ms: u64, cancel_token: Option<&CancelToken>) -> bool {
        if cancel_token
            .map(|t| t.load(Ordering::Acquire))
            .unwrap_or(false)
        {
            return true; // not an error; the loop's should_stop will fire
        }
        let Some(guard) = fork_guard_enter() else {
            return false;
        };
        let bounded = bounded_deadline(deadline_ms, NATIVE_RETRY_MS);
        let (_, status) = fork_condition_wait_until_while_guarded(&self.condition, guard, bounded);
        status != ForkWaitStatus::Error
    }

    /// Waiter count (C cbm_lock_registry_waiter_count).
    pub fn waiter_count(&self) -> usize {
        let Some((_guard, inner)) = self.lock_inner() else {
            return 0;
        };
        inner.waiter_count
    }

    /// Active lease count (internal.h test API).
    pub fn active_lease_count(&self) -> usize {
        let Some((_guard, inner)) = self.lock_inner() else {
            return 0;
        };
        inner.active_leases
    }

    /// Free the registry (C cbm_lock_registry_free): mark closing, wake all
    /// waiters, clear entries. The directory stays owned by the caller.
    pub fn free(self: Arc<Self>) -> LockStatus {
        {
            let _guard = fork_guard_enter();
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.closing = true;
            inner.entries.clear();
            inner.waiter_count = 0;
        }
        fork_condition_broadcast_while_guarded(&self.condition);
        self.retired.store(true, Ordering::SeqCst);
        LockStatus::Ok
    }

    /// Is the registry closed? (C is_retired_for_test analogue)
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }
}

fn notify(registry: &LockRegistry, _mode: LockMode, _stage: Stage) {
    // Stage hooks (C cbm_lock_registry_stage_hook_fn) are a test seam; the
    // production paths take no action beyond the state transitions.
    let _ = registry;
}

fn remove_waiter(inner: &mut Inner, key: &(String, String), seq: u64) -> bool {
    if let Some(entry) = inner.entries.get_mut(key) {
        if let Some(pos) = entry.waiters.iter().position(|&s| s == seq) {
            entry.waiters.remove(pos);
            inner.waiter_count = inner.waiter_count.saturating_sub(1);
            return true;
        }
    }
    false
}

fn should_stop(deadline_ms: u64, cancel_token: Option<&CancelToken>) -> bool {
    if cancel_token
        .map(|t| t.load(Ordering::Acquire))
        .unwrap_or(false)
    {
        return true;
    }
    deadline_ms != u64::MAX && crate::platform::now_ms() >= deadline_ms
}

fn bounded_deadline(deadline_ms: u64, interval_ms: u64) -> u64 {
    let now = crate::platform::now_ms();
    let bounded = now.saturating_add(interval_ms);
    deadline_ms.min(bounded)
}

fn wait_deadline(deadline_ms: u64) -> u64 {
    deadline_ms
}

/// A held registry lease (C cbm_lock_lease_t). Release restores the
/// reader/writer accounting, then the native file locks (writers drop rw
/// then turn; readers' turn was already dropped at acquire).
pub struct Lease {
    registry: Arc<LockRegistry>,
    entry_key: (String, String),
    mode: LockMode,
    turn: Option<Box<PrivateFileLock>>,
    rw: Option<Box<PrivateFileLock>>,
    active: bool,
}

impl Lease {
    /// Release (C cbm_lock_lease_release): accounting first, then native.
    pub fn release(mut self) -> LockStatus {
        if !self.active {
            return LockStatus::Io;
        }
        {
            let Some((_guard, mut inner)) = self.registry.lock_inner() else {
                return LockStatus::Io;
            };
            if let Some(entry) = inner.entries.get_mut(&self.entry_key) {
                match self.mode {
                    LockMode::Shared => {
                        entry.active_readers = entry.active_readers.saturating_sub(1)
                    }
                    LockMode::Exclusive => entry.writer_active = false,
                }
            }
            inner.active_leases = inner.active_leases.saturating_sub(1);
        }
        fork_condition_broadcast_while_guarded(&self.registry.condition);
        self.active = false;

        let mut status = LockStatus::Ok;
        if let Some(r) = self.rw.take() {
            if PrivateFileLock::release(r) != LockStatus::Ok {
                status = LockStatus::Io;
            }
        }
        if let Some(t) = self.turn.take() {
            if PrivateFileLock::release(t) != LockStatus::Ok {
                status = LockStatus::Io;
            }
        }
        status
    }
}

const _: () = {
    // Timeout duration parity documentation.
    let _ = std::mem::size_of::<Duration>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_file_lock::LockStatus;
    use std::os::unix::io::IntoRawFd;

    fn make_registry(tag: &str) -> (std::path::PathBuf, Arc<LockRegistry>) {
        use std::os::unix::fs::PermissionsExt;
        let dir_path = std::env::temp_dir().join(format!("cbm-lr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir_path);
        std::fs::create_dir(&dir_path).unwrap();
        std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let f = std::fs::File::open(&dir_path).unwrap();
        let fd = f.into_raw_fd();
        let (_, dir) = unsafe { LockDirectory::adopt(fd, &dir_path) };
        let dir = dir.expect("adopt 0700 dir");
        // Leak the directory: the registry borrows it for its lifetime
        // (C ownership contract — the caller keeps the directory alive);
        // test scope ends with the process, so a leak is the clean way.
        let dir: &'static LockDirectory = Box::leak(Box::new(dir));
        let reg = LockRegistry::new(dir).unwrap();
        (dir_path, reg)
    }

    #[test]
    fn resource_names_derive() {
        let (t, r) = resource_names("res-1").unwrap();
        assert!(t.starts_with("cbm-") && t.ends_with(".turn"));
        assert!(r.starts_with("cbm-") && r.ends_with(".rw"));
        assert!(t.len() < LOCK_REGISTRY_NAME_CAP);
        assert_ne!(t, r);
        assert!(resource_names("").is_none());
        let long = "x".repeat(LOCK_REGISTRY_RESOURCE_CAP + 1);
        assert!(resource_names(&long).is_none());
    }

    #[test]
    fn try_acquire_exclusive_then_busy() {
        let (path, reg) = make_registry("excl");
        let (s1, l1) = reg.try_acquire("res", LockMode::Exclusive);
        assert_eq!(s1, LockStatus::Ok);
        let l1 = l1.unwrap();
        let (s2, _) = reg.try_acquire("res", LockMode::Exclusive);
        assert_eq!(s2, LockStatus::Busy);
        assert_eq!(reg.active_lease_count(), 1);
        assert_eq!(l1.release(), LockStatus::Ok);
        // Re-acquirable after release.
        let (s3, l3) = reg.try_acquire("res", LockMode::Exclusive);
        assert_eq!(s3, LockStatus::Ok);
        l3.unwrap().release();
        reg.free();
        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn shared_readers_coexist() {
        let (path, reg) = make_registry("shared");
        let (s1, l1) = reg.try_acquire("doc", LockMode::Shared);
        let (s2, l2) = reg.try_acquire("doc", LockMode::Shared);
        assert_eq!(s1, LockStatus::Ok);
        assert_eq!(s2, LockStatus::Ok);
        assert_eq!(reg.active_lease_count(), 2);
        l1.unwrap().release();
        l2.unwrap().release();
        assert_eq!(reg.active_lease_count(), 0);
        reg.free();
        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn distinct_resources_independent() {
        let (path, reg) = make_registry("distinct");
        let (s1, l1) = reg.try_acquire("a", LockMode::Exclusive);
        let (s2, l2) = reg.try_acquire("b", LockMode::Exclusive);
        assert_eq!(s1, LockStatus::Ok);
        assert_eq!(s2, LockStatus::Ok);
        l1.unwrap().release();
        l2.unwrap().release();
        reg.free();
        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn cancel_and_deadline() {
        let (path, reg) = make_registry("cancel");
        let (s1, l1) = reg.try_acquire("hot", LockMode::Exclusive);
        assert_eq!(s1, LockStatus::Ok);
        // Another waiter with an immediate deadline → Busy.
        let token: CancelToken = Arc::new(AtomicBool::new(false));
        let (s2, _) = reg.acquire(
            "hot",
            LockMode::Exclusive,
            crate::platform::now_ms(),
            Some(&token),
        );
        assert_eq!(s2, LockStatus::Busy);
        // Cancelled token → Busy.
        let token2: CancelToken = Arc::new(AtomicBool::new(true));
        let (s3, _) = reg.acquire("hot", LockMode::Exclusive, u64::MAX, Some(&token2));
        assert_eq!(s3, LockStatus::Busy);
        assert_eq!(l1.unwrap().release(), LockStatus::Ok);
        reg.free();
        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn retire_after_free() {
        let (path, reg) = make_registry("retire");
        assert!(!reg.is_retired());
        assert_eq!(Arc::clone(&reg).free(), LockStatus::Ok);
        assert!(reg.is_retired());
        std::fs::remove_dir_all(&path).ok();
    }
}
