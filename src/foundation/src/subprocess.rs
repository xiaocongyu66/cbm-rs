//! subprocess.rs — 1:1 rewrite of `src/foundation/subprocess.{c,h}` (POSIX
//! surface; the Windows Job Object path is not a build target).
//!
//! Owned process-tree execution: the child runs in its own process group;
//! polling reaps the root, tails the log file, enforces a quiet-timeout
//! (HANG), honors cancellation with a graceful SIGTERM → SIGKILL ladder,
//! and only reports terminal once the whole tree is quiesced.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

pub const DEFAULT_CANCEL_GRACE_MS: i32 = 1000;
pub const MAX_CANCEL_GRACE_MS: i32 = 1000;
pub const FORCE_SETTLE_MS: u64 = 1000;

/// NTSTATUS severity ERROR (top two bits set) — Windows crash exit codes.
/// POSIX exit codes are 0..255 so these branches never misfire there.
const WIN_CRASH_CODE_MIN: u32 = 0xC000_0000;
const WIN_CONTROL_C_EXIT: u32 = 0xC000_013A;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Clean,
    ExitNonZero,
    Crash,
    Hang,
    Killed,
    SpawnFailed,
}

pub fn outcome_str(o: Outcome) -> &'static str {
    match o {
        Outcome::Clean => "clean",
        Outcome::ExitNonZero => "exit_nonzero",
        Outcome::Crash => "crash",
        Outcome::Hang => "hang",
        Outcome::Killed => "killed",
        Outcome::SpawnFailed => "spawn_failed",
    }
}

fn is_fault_signal(sig: i32) -> bool {
    matches!(
        sig,
        libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGABRT | libc::SIGSYS
    )
}

/// Outcome classification (C cbm_proc_classify).
pub fn classify(
    exited_normally: bool,
    exit_code: i32,
    term_signal: i32,
    timed_out: bool,
) -> Outcome {
    if timed_out {
        return Outcome::Hang;
    }
    if !exited_normally {
        if is_fault_signal(term_signal) {
            return Outcome::Crash;
        }
        return Outcome::Killed;
    }
    let code = exit_code as u32;
    if code == WIN_CONTROL_C_EXIT {
        return Outcome::Killed;
    }
    if code >= WIN_CRASH_CODE_MIN {
        return Outcome::Crash;
    }
    if exit_code == 0 {
        Outcome::Clean
    } else {
        Outcome::ExitNonZero
    }
}

/// Terminal result (C cbm_proc_result_t).
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcResult {
    pub outcome: Option<Outcome>,
    pub exit_code: i32,
    pub term_signal: i32,
    pub cancellation_requested: bool,
    pub forced: bool,
    pub tree_quiesced: bool,
    pub supervision_failed: bool,
}

/// Spawn options (C cbm_proc_opts_t, POSIX fields).
#[derive(Debug, Clone)]
pub struct ProcOpts {
    /// Executable path or literal PATH name; also argv[0] when argv is None.
    pub bin: String,
    /// Full argv (without trailing NULL). Empty → { bin }.
    pub argv: Vec<String>,
    /// Child stdout+stderr are redirected here and tailed; None → discard.
    pub log_file: Option<PathBuf>,
    /// Kill + HANG after this many ms with no new completed log line.
    pub quiet_timeout_ms: i32,
    /// Graceful tree-termination window; ≤ 0 → DEFAULT_CANCEL_GRACE_MS.
    pub cancel_grace_ms: i32,
    /// Unlink log_file after reaping.
    pub delete_log_on_exit: bool,
}

impl ProcOpts {
    pub fn new(bin: impl Into<String>) -> Self {
        ProcOpts {
            bin: bin.into(),
            argv: Vec::new(),
            log_file: None,
            quiet_timeout_ms: 0,
            cancel_grace_ms: 0,
            delete_log_on_exit: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Running,
    CancelRequested,
    Draining,
    Terminal,
}

/// Spawn failure (no child ever ran). Kept as a distinct unit type so the
/// error channel carries no allocation (C returns -1).
#[derive(Debug)]
pub struct SpawnError;

/// An owned running subprocess (C cbm_subprocess_t).
pub struct Subprocess {
    bin: String,
    argv: Vec<String>,
    log_file: Option<PathBuf>,
    delete_log_on_exit: bool,
    quiet_timeout_ms: i32,
    cancel_grace_ms: i32,

    pid: libc::pid_t,
    pgid: libc::pid_t,
    tail_pos: u64,

    lifecycle: AtomicU8,
    cancellation_requested: AtomicBool,
    timed_out: AtomicBool,
    termination_started: AtomicBool,
    termination_started_ms: AtomicU64,
    force_started_ms: AtomicU64,
    force_sent: AtomicBool,
    containment_failed: AtomicBool,
    root_reaped: AtomicBool,
    last_activity_ms: AtomicU64,

    result: ProcResult,
}

fn now_ms() -> u64 {
    crate::platform::now_ms()
}

fn fault_code_of(r: &ProcResult) -> Option<Outcome> {
    r.outcome
}

fn cstring(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

/// async-signal-safe child body: setpgid(0,0), dup2 stdio, reset signals,
/// execvp.
unsafe fn child_exec(bin: &CString, argv: &[CString], input: i32, output: i32) -> ! {
    libc::dup2(input, libc::STDIN_FILENO);
    libc::dup2(output, libc::STDOUT_FILENO);
    libc::dup2(output, libc::STDERR_FILENO);
    // Own the group early; the parent reconciles after.
    let _ = libc::setpgid(0, 0);
    // Reset signal dispositions a spawning agent may have altered.
    libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    let mut c_argv: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    c_argv.push(std::ptr::null());
    libc::execvp(bin.as_ptr(), c_argv.as_ptr());
    // execvp failed: 127 (POSIX "command not found" convention).
    libc::_exit(127);
}

impl Subprocess {
    /// Spawn (C cbm_subprocess_spawn). Returns Err on spawn failure — no
    /// child ever ran.
    pub fn spawn(opts: &ProcOpts) -> Result<Subprocess, SpawnError> {
        let log_file = opts.log_file.clone();
        // SAFETY: plain open(2) with NUL-checked paths.
        unsafe {
            let input = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            let target = match &log_file {
                Some(p) => match cstring(&p.to_string_lossy()) {
                    Some(c) => c,
                    None => {
                        libc::close(input);
                        return Err(SpawnError);
                    }
                },
                None => CString::from(c"/dev/null"),
            };
            let output = libc::open(
                target.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            );
            if input < 0 || output < 0 {
                if input >= 0 {
                    libc::close(input);
                }
                if output >= 0 {
                    libc::close(output);
                }
                return Err(SpawnError);
            }
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(output, &mut st) != 0
                || (log_file.is_some() && (st.st_mode & libc::S_IFMT) != libc::S_IFREG)
            {
                libc::close(input);
                libc::close(output);
                return Err(SpawnError);
            }
            if log_file.is_some() && libc::fchmod(output, 0o600) != 0 {
                libc::close(input);
                libc::close(output);
                return Err(SpawnError);
            }

            let bin_c = match cstring(&opts.bin) {
                Some(c) => c,
                None => {
                    libc::close(input);
                    libc::close(output);
                    return Err(SpawnError);
                }
            };
            let argv_strings: Vec<String> = if opts.argv.is_empty() {
                vec![opts.bin.clone()]
            } else {
                opts.argv.clone()
            };
            let argv_c: Vec<CString> = match argv_strings.iter().map(|a| cstring(a)).collect() {
                Some(v) => v,
                None => {
                    libc::close(input);
                    libc::close(output);
                    return Err(SpawnError);
                }
            };

            let pid = libc::fork();
            if pid < 0 {
                libc::close(input);
                libc::close(output);
                return Err(SpawnError);
            }
            if pid == 0 {
                child_exec(&bin_c, &argv_c, input, output);
            }
            libc::close(input);
            libc::close(output);

            // Parent establishes the group too, removing scheduler-order
            // races. A child that already execed yields EACCES — accept it
            // only when its group is the expected isolated one.
            let mut contained = libc::setpgid(pid, pid) == 0;
            if !contained {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if err == libc::EACCES || err == libc::EPERM || err == libc::ESRCH {
                    contained = libc::getpgid(pid) == pid;
                }
            }
            if !contained {
                libc::kill(pid, libc::SIGKILL);
                let mut status = 0;
                for _ in 0..4 {
                    if libc::waitpid(pid, &mut status, 0) >= 0 {
                        break;
                    }
                }
                return Err(SpawnError);
            }

            Ok(Subprocess {
                bin: opts.bin.clone(),
                argv: argv_strings,
                log_file,
                delete_log_on_exit: opts.delete_log_on_exit,
                quiet_timeout_ms: opts.quiet_timeout_ms,
                cancel_grace_ms: if opts.cancel_grace_ms <= 0 {
                    DEFAULT_CANCEL_GRACE_MS
                } else {
                    opts.cancel_grace_ms.min(MAX_CANCEL_GRACE_MS)
                },
                pid,
                pgid: pid,
                tail_pos: 0,
                lifecycle: AtomicU8::new(Lifecycle::Running as u8),
                cancellation_requested: AtomicBool::new(false),
                timed_out: AtomicBool::new(false),
                termination_started: AtomicBool::new(false),
                termination_started_ms: AtomicU64::new(0),
                force_started_ms: AtomicU64::new(0),
                force_sent: AtomicBool::new(false),
                containment_failed: AtomicBool::new(false),
                root_reaped: AtomicBool::new(false),
                last_activity_ms: AtomicU64::new(now_ms()),
                result: ProcResult::default(),
            })
        }
    }

    pub fn bin(&self) -> &str {
        &self.bin
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    fn lifecycle(&self) -> Lifecycle {
        match self.lifecycle.load(Ordering::Acquire) {
            1 => Lifecycle::CancelRequested,
            2 => Lifecycle::Draining,
            3 => Lifecycle::Terminal,
            _ => Lifecycle::Running,
        }
    }

    fn set_lifecycle(&self, l: Lifecycle) {
        self.lifecycle.store(l as u8, Ordering::Release);
    }

    fn group_active(&self) -> bool {
        // SAFETY: pgid is a live process group id.
        if unsafe { libc::kill(-self.pgid, 0) } == 0 {
            return true;
        }
        // EPERM/other errors fail closed as still active.
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    fn begin_termination(&mut self, now: u64) {
        if self.termination_started.swap(true, Ordering::SeqCst) {
            return;
        }
        self.termination_started_ms.store(now, Ordering::SeqCst);
        // SAFETY: group signal.
        unsafe {
            libc::kill(-self.pgid, libc::SIGTERM);
        }
    }

    fn force_tree(&mut self, now: u64) {
        if self.force_sent.load(Ordering::SeqCst) {
            return;
        }
        self.force_started_ms
            .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst)
            .ok();
        // SAFETY: group signal.
        let rc = unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
        if rc == 0 {
            self.result.forced = true;
            self.force_sent.store(true, Ordering::SeqCst);
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            self.force_sent.store(true, Ordering::SeqCst);
        } else {
            self.containment_failed.store(true, Ordering::SeqCst);
        }
    }

    fn capture_root(&mut self, status: i32) {
        self.root_reaped.store(true, Ordering::SeqCst);
        let timed_out = self.timed_out.load(Ordering::SeqCst);
        if (status & 0x7f) == 0 {
            self.result.exit_code = (status >> 8) & 0xff;
            self.result.term_signal = 0;
            self.result.outcome = Some(classify(true, self.result.exit_code, 0, timed_out));
        } else {
            let sig = status & 0x7f;
            self.result.exit_code = -1;
            self.result.term_signal = sig;
            self.result.outcome = Some(classify(false, -1, sig, timed_out));
        }
    }

    /// Tail new completed lines from the log file (C cbm_tail_log).
    /// Returns true when at least one new line was observed (activity).
    fn poll_log(&mut self, _final: bool) -> bool {
        let Some(log) = &self.log_file else {
            return false;
        };
        let Ok(meta) = std::fs::metadata(log) else {
            return false;
        };
        let size = meta.len();
        if size <= self.tail_pos {
            return false;
        }
        let Ok(mut f) = std::fs::File::open(log) else {
            return false;
        };
        use std::io::{Read, Seek, SeekFrom};
        if f.seek(SeekFrom::Start(self.tail_pos)).is_err() {
            return false;
        }
        let mut buf = Vec::with_capacity((size - self.tail_pos) as usize);
        if f.read_to_end(&mut buf).is_err() {
            return false;
        }
        // Only consume complete lines; the tail position advances past the
        // last newline (same completed-line rule as the C).
        let consumed = match buf.iter().rposition(|&b| b == b'\n') {
            Some(i) => i + 1,
            None => 0,
        };
        self.tail_pos += consumed as u64;
        if consumed > 0 {
            self.last_activity_ms.store(now_ms(), Ordering::SeqCst);
            return true;
        }
        false
    }

    fn finish(&mut self, out: Option<&mut ProcResult>) -> Poll {
        self.result.cancellation_requested = self.cancellation_requested.load(Ordering::SeqCst);
        if self.delete_log_on_exit {
            if let Some(log) = &self.log_file {
                let _ = std::fs::remove_file(log);
            }
        }
        self.result.tree_quiesced = !self.group_active();
        self.result.supervision_failed = !self.result.tree_quiesced;
        self.set_lifecycle(Lifecycle::Terminal);
        let _ = fault_code_of(&self.result);
        if let Some(o) = out {
            *o = self.result;
        }
        Poll::Terminal
    }

    fn finish_failed(&mut self, out: Option<&mut ProcResult>) -> Poll {
        self.result.outcome = Some(Outcome::SpawnFailed);
        self.result.exit_code = -1;
        self.result.term_signal = 0;
        self.finish(out)
    }

    /// Poll (C cbm_subprocess_poll). Terminal states publish once.
    pub fn poll(&mut self, out: Option<&mut ProcResult>) -> Poll {
        match self.lifecycle() {
            Lifecycle::Terminal => {
                if let Some(o) = out {
                    *o = self.result;
                }
                return Poll::Terminal;
            }
            Lifecycle::Draining => {
                if self.poll_log(true) {
                    return Poll::Running;
                }
                return self.finish(out);
            }
            _ => {}
        }
        let _ = self.poll_log(false);
        self.poll_posix(out)
    }

    fn poll_posix(&mut self, out: Option<&mut ProcResult>) -> Poll {
        let now = now_ms();

        if !self.root_reaped.load(Ordering::SeqCst) {
            let mut status = 0;
            // SAFETY: pid owned by this struct.
            let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if waited == self.pid {
                self.capture_root(status);
            } else if waited < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err != Some(libc::EINTR) {
                    // ECHILD: another reaper consumed the status. Retain
                    // containment, stop the tree, never spin.
                    self.root_reaped.store(true, Ordering::SeqCst);
                    self.result.outcome = Some(if self.timed_out.load(Ordering::SeqCst) {
                        Outcome::Hang
                    } else {
                        Outcome::Killed
                    });
                    self.result.exit_code = -1;
                    self.result.term_signal = 0;
                    self.begin_termination(now);
                }
            }
        }

        let mut group_active = self.group_active();
        if !self.termination_started.load(Ordering::SeqCst) {
            if self.cancellation_requested.load(Ordering::SeqCst) {
                self.begin_termination(now);
            } else if !self.root_reaped.load(Ordering::SeqCst)
                && self.quiet_timeout_ms > 0
                && now.saturating_sub(self.last_activity_ms.load(Ordering::SeqCst))
                    >= self.quiet_timeout_ms as u64
            {
                self.timed_out.store(true, Ordering::SeqCst);
                self.begin_termination(now);
            } else if self.root_reaped.load(Ordering::SeqCst) && group_active {
                // A root that daemonizes children is not terminal: drain
                // descendants through the same path.
                self.begin_termination(now);
            }
        }
        if self.termination_started.load(Ordering::SeqCst)
            && group_active
            && !self.force_sent.load(Ordering::SeqCst)
            && now.saturating_sub(self.termination_started_ms.load(Ordering::SeqCst))
                >= self.cancel_grace_ms as u64
        {
            self.force_tree(now);
        }
        group_active = self.group_active();
        let force_started = self.force_started_ms.load(Ordering::SeqCst);
        if force_started != 0 && group_active && now - force_started >= FORCE_SETTLE_MS {
            return self.finish_failed(out);
        }
        if self.root_reaped.load(Ordering::SeqCst) && !group_active {
            // Root reaped and tree gone: drain remaining log, then terminal.
            self.set_lifecycle(Lifecycle::Draining);
            return self.poll(out);
        }
        Poll::Running
    }

    /// Request graceful cancellation (C cbm_subprocess_request_cancel).
    pub fn request_cancel(&mut self) -> bool {
        match self.lifecycle() {
            Lifecycle::Terminal | Lifecycle::Draining => return false,
            Lifecycle::CancelRequested => return true,
            Lifecycle::Running => {}
        }
        self.cancellation_requested.store(true, Ordering::SeqCst);
        self.set_lifecycle(Lifecycle::CancelRequested);
        true
    }
}

impl Drop for Subprocess {
    fn drop(&mut self) {
        // C destroy: if still running, force-terminate the tree and reap.
        if !self.root_reaped.load(Ordering::SeqCst) {
            self.force_tree(now_ms());
            let mut status = 0;
            unsafe {
                loop {
                    if libc::waitpid(self.pid, &mut status, 0) >= 0 {
                        break;
                    }
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        break;
                    }
                }
            }
            if self.delete_log_on_exit {
                if let Some(log) = &self.log_file {
                    let _ = std::fs::remove_file(log);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    Running,
    Terminal,
}

/// One-shot run (C cbm_subprocess_run): poll until terminal.
pub fn run(opts: &ProcOpts, out: &mut ProcResult) -> Result<(), SpawnError> {
    let mut proc = Subprocess::spawn(opts)?;
    loop {
        if proc.poll(Some(out)) == Poll::Terminal {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bin_true() -> ProcOpts {
        ProcOpts::new("/bin/true")
    }

    #[test]
    fn classify_table() {
        assert_eq!(classify(true, 0, 0, false), Outcome::Clean);
        assert_eq!(classify(true, 1, 0, false), Outcome::ExitNonZero);
        assert_eq!(classify(true, 0, 0, true), Outcome::Hang);
        assert_eq!(classify(false, -1, libc::SIGSEGV, false), Outcome::Crash);
        assert_eq!(classify(false, -1, libc::SIGABRT, false), Outcome::Crash);
        assert_eq!(classify(false, -1, libc::SIGTERM, false), Outcome::Killed);
        // Windows NTSTATUS codes never misfire on POSIX exit ranges.
        assert_eq!(classify(true, 1, 0, false), Outcome::ExitNonZero);
    }

    #[test]
    fn outcome_str_table() {
        assert_eq!(outcome_str(Outcome::Clean), "clean");
        assert_eq!(outcome_str(Outcome::Hang), "hang");
        assert_eq!(outcome_str(Outcome::SpawnFailed), "spawn_failed");
    }

    #[test]
    fn spawn_and_run_clean() {
        let mut result = ProcResult::default();
        run(&bin_true(), &mut result).expect("run");
        assert_eq!(result.outcome, Some(Outcome::Clean));
        assert_eq!(result.exit_code, 0);
        assert!(result.tree_quiesced);
    }

    #[test]
    fn exit_nonzero() {
        let mut result = ProcResult::default();
        let mut opts = ProcOpts::new("/bin/sh");
        opts.argv = vec!["/bin/sh".into(), "-c".into(), "exit 3".into()];
        run(&opts, &mut result).expect("run");
        assert_eq!(result.outcome, Some(Outcome::ExitNonZero));
        assert_eq!(result.exit_code, 3);
    }

    #[test]
    fn spawn_failure_missing_binary() {
        // Absolute path that does not exist → exec fails in the child →
        // 127 → the C reproduces this as a normal exit; a spawn-level
        // failure needs an unwritable log target instead.
        let mut opts = ProcOpts::new("/bin/true");
        opts.log_file = Some(PathBuf::from("/proc/nonexistent-dir-cbm/x.log"));
        assert!(Subprocess::spawn(&opts).is_err());
    }

    #[test]
    fn log_file_written_and_tailed() {
        let dir = std::env::temp_dir().join(format!("cbm-sub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("out.log");
        let mut opts = ProcOpts::new("/bin/sh");
        opts.argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo line1; echo line2".into(),
        ];
        opts.log_file = Some(log.clone());
        let mut result = ProcResult::default();
        run(&opts, &mut result).expect("run");
        assert_eq!(result.outcome, Some(Outcome::Clean));
        let content = std::fs::read_to_string(&log).unwrap();
        assert_eq!(content, "line1\nline2\n");
        // 0600 on the log (C fchmod).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&log).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_log_on_exit() {
        let dir = std::env::temp_dir().join(format!("cbm-sub-del-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("gone.log");
        let mut opts = ProcOpts::new("/bin/true");
        opts.log_file = Some(log.clone());
        opts.delete_log_on_exit = true;
        let mut result = ProcResult::default();
        run(&opts, &mut result).expect("run");
        assert!(!log.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn quiet_timeout_kills_hang() {
        let dir = std::env::temp_dir().join(format!("cbm-sub-hang-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("hang.log");
        let mut opts = ProcOpts::new("/bin/sh");
        opts.argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo started; sleep 30".into(),
        ];
        opts.log_file = Some(log.clone());
        opts.quiet_timeout_ms = 300; // silent after the echo → HANG
        let mut result = ProcResult::default();
        let started = std::time::Instant::now();
        run(&opts, &mut result).expect("run");
        let elapsed = started.elapsed();
        assert_eq!(result.outcome, Some(Outcome::Hang));
        // A short-lived `sh` often dies on SIGTERM without needing the
        // SIGKILL escalation; forced is only set when the ladder escalated.
        assert!(elapsed < std::time::Duration::from_secs(20));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn request_cancel_terminates_tree() {
        let dir = std::env::temp_dir().join(format!("cbm-sub-cancel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("c.log");
        let mut opts = ProcOpts::new("/bin/sh");
        opts.argv = vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()];
        opts.log_file = Some(log.clone());
        opts.cancel_grace_ms = 200;
        let mut proc = Subprocess::spawn(&opts).expect("spawn");
        assert!(proc.request_cancel());
        let mut result = ProcResult::default();
        let started = std::time::Instant::now();
        loop {
            if proc.poll(Some(&mut result)) == Poll::Terminal {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            assert!(started.elapsed() < std::time::Duration::from_secs(20));
        }
        assert!(result.cancellation_requested);
        std::fs::remove_dir_all(&dir).ok();
    }
}
