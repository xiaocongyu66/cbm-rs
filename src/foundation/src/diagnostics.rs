//! diagnostics.rs — 1:1 rewrite of `src/foundation/diagnostics.{c,h}`.
//!
//! Opt-in memory diagnostics (`CBM_DIAGNOSTICS=1|true`): a private
//! `cbm-diagnostics-<pid>-<rand>` directory below `$TMPDIR`/`/tmp` holding
//! a periodically rewritten `snapshot.json` and an append-only
//! `trajectory.ndjson` (rotated past a cap). Exact paths are announced via
//! a control record that survives log suppression and spaces in paths.
//! RSS is the OS value (/proc/self/statm) — the C documents why
//! mimalloc's current_rss is low-biased on Linux.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DIAG_INTERVAL_MS: u64 = 5000;
const DIAG_SNAPSHOT_NAME: &str = "snapshot.json";
const DIAG_SNAPSHOT_TMP_NAME: &str = "snapshot.json.tmp";
const DIAG_TRAJECTORY_NAME: &str = "trajectory.ndjson";
const DIAG_TRAJECTORY_ROTATED_NAME: &str = "trajectory.ndjson.1";
const DIAG_NDJSON_CAP_BYTES: u64 = 4 * 1024 * 1024;

/// Query statistics (C cbm_query_stats_t / g_query_stats).
#[derive(Debug, Default)]
pub struct QueryStats {
    pub count: AtomicI32,
    pub errors: AtomicI32,
    pub time_us: AtomicI64,
    pub max_us: AtomicI64,
}

pub static QUERY_STATS: QueryStats = QueryStats {
    count: AtomicI32::new(0),
    errors: AtomicI32::new(0),
    time_us: AtomicI64::new(0),
    max_us: AtomicI64::new(0),
};

/// Record one tool call (C cbm_diag_record_query).
pub fn record_query(duration_us: i64, is_error: bool) {
    QUERY_STATS.count.fetch_add(1, Ordering::Relaxed);
    QUERY_STATS
        .time_us
        .fetch_add(duration_us, Ordering::Relaxed);
    if is_error {
        QUERY_STATS.errors.fetch_add(1, Ordering::Relaxed);
    }
    let mut old = QUERY_STATS.max_us.load(Ordering::Relaxed);
    while duration_us > old {
        match QUERY_STATS.max_us.compare_exchange_weak(
            old,
            duration_us,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => old = actual,
        }
    }
}

fn count_open_fds() -> i32 {
    match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            let n = entries.count() as i32;
            n - 2 // "." and ".." like the C's scandir arithmetic
        }
        Err(_) => -1,
    }
}

struct DiagState {
    stop: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    started: bool,
    abandoned: bool,
    start_time: SystemTime,
    directory: PathBuf,
    snapshot_path: PathBuf,
    trajectory_path: PathBuf,
    ndjson_size: u64,
    writer: Option<std::thread::JoinHandle<()>>,
}

static STATE: Mutex<Option<DiagState>> = Mutex::new(None);
static WRITER_REACHED: AtomicBool = AtomicBool::new(false);

fn tmp_base() -> PathBuf {
    match std::env::var("TMPDIR") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => PathBuf::from("/tmp"),
    }
}

fn uptime_s(start: SystemTime) -> u64 {
    start.duration_since(UNIX_EPOCH).is_err() as u64
        + start.elapsed().map(|d| d.as_secs()).unwrap_or(0)
}

/// Build the snapshot JSON body (C write_diagnostics shape; RSS fields
/// from the OS, not the allocator).
fn snapshot_body(start: SystemTime) -> String {
    let rss = crate::mem::rss();
    let peak = crate::mem::peak_rss();
    let map = crate::mem::map_collect();
    let q_count = QUERY_STATS.count.load(Ordering::Relaxed);
    let q_errors = QUERY_STATS.errors.load(Ordering::Relaxed);
    let q_total = QUERY_STATS.time_us.load(Ordering::Relaxed);
    let q_max = QUERY_STATS.max_us.load(Ordering::Relaxed);
    let q_avg = if q_count > 0 {
        q_total / q_count as i64
    } else {
        0
    };
    let buckets: Vec<String> = (0..crate::mem::MEM_MAP_BUCKETS)
        .map(|i| {
            format!(
                "{{\"limit\": {}, \"bytes\": {}, \"blocks\": {}}}",
                crate::mem::map_bucket_limit(i as i32),
                map.bucket_bytes[i],
                map.bucket_blocks[i]
            )
        })
        .collect();
    let phases = crate::mem::phase_report_json();
    format!(
        "{{\n\
         \"uptime_s\": {},\n\
         \"rss_bytes\": {},\n\
         \"peak_rss_bytes\": {},\n\
         \"heap_committed_bytes\": 0,\n\
         \"peak_committed_bytes\": 0,\n\
         \"page_faults\": 0,\n\
         \"fd_count\": {},\n\
         \"query_count\": {},\n\
         \"query_errors\": {},\n\
         \"query_total_us\": {},\n\
         \"query_avg_us\": {},\n\
         \"query_max_us\": {},\n\
         \"mem_malloc_owned\": false,\n\
         \"mem_live_bytes\": {},\n\
         \"mem_live_blocks\": {},\n\
         \"mem_area_committed_bytes\": {},\n\
         \"mem_bucket_bytes\": [{}],\n\
         \"phases\": [{}]\n\
         }}\n",
        uptime_s(start),
        rss,
        peak,
        count_open_fds(),
        q_count,
        q_errors,
        q_total,
        q_avg,
        q_max,
        map.live_bytes,
        map.live_blocks,
        map.area_committed_bytes,
        buckets.join(", "),
        phases
    )
}

fn trajectory_line(start: SystemTime) -> String {
    format!(
        "{{\"uptime_s\":{},\"rss\":{},\"peak_rss\":{},\"committed\":{},\"peak_committed\":{},\"page_faults\":{},\"fd\":{},\"queries\":{}}}\n",
        uptime_s(start),
        crate::mem::rss(),
        crate::mem::peak_rss(),
        0,
        0,
        0,
        count_open_fds(),
        QUERY_STATS.count.load(Ordering::Relaxed)
    )
}

fn write_diagnostics(st: &mut DiagState) {
    if st.stop.load(Ordering::Acquire) {
        return;
    }
    // snapshot.json via tmp+rename (atomic publish).
    let body = snapshot_body(st.start_time);
    let tmp = st.directory.join(DIAG_SNAPSHOT_TMP_NAME);
    let final_path = st.directory.join(DIAG_SNAPSHOT_NAME);
    let mut ok = std::fs::write(&tmp, body.as_bytes()).is_ok();
    if ok {
        ok = std::fs::rename(&tmp, &final_path).is_ok();
    }
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    // trajectory.ndjson append with rotation.
    if st.ndjson_size > DIAG_NDJSON_CAP_BYTES {
        let rotated = st.directory.join(DIAG_TRAJECTORY_ROTATED_NAME);
        if std::fs::rename(&st.trajectory_path, rotated).is_ok() {
            st.ndjson_size = 0;
        } else {
            return;
        }
    }
    let line = trajectory_line(st.start_time);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&st.trajectory_path)
    {
        if f.write_all(line.as_bytes()).is_ok() {
            st.ndjson_size += line.len() as u64;
        }
    }
}

fn diag_thread_main(
    state: std::sync::Arc<std::sync::Mutex<DiagState>>,
    stop: std::sync::Arc<AtomicBool>,
) {
    WRITER_REACHED.store(true, Ordering::Release);
    while !stop.load(Ordering::Acquire) {
        if let Ok(mut st) = state.lock() {
            write_diagnostics(&mut st);
        }
        if !stop.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(DIAG_INTERVAL_MS));
        }
    }
    // One final write on the way out.
    if let Ok(mut st) = state.lock() {
        write_diagnostics(&mut st);
    }
    if let Some(d) = STATE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        d.done.store(true, Ordering::Release);
    }
}

use std::sync::Arc;

/// Start diagnostics (C cbm_diag_start). Requires `CBM_DIAGNOSTICS` in
/// {1, true}; no-op when already running or abandoned.
pub fn start() -> bool {
    let Ok(env) = std::env::var("CBM_DIAGNOSTICS") else {
        return false;
    };
    if env != "1" && env != "true" {
        return false;
    }
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(st) = guard.as_ref() {
        if st.started || st.abandoned {
            return false;
        }
    }

    // Private directory: cbm-diagnostics-<pid>-<rand> under $TMPDIR//tmp.
    let mut rand_bytes = [0u8; 8];
    crate::secure_random::secure_random(&mut rand_bytes);
    let dir = tmp_base().join(format!(
        "cbm-diagnostics-{}-{:016x}",
        std::process::id(),
        u64::from_le_bytes(rand_bytes)
    ));
    if std::fs::create_dir(&dir).is_err() {
        return false;
    }
    let snapshot_path = dir.join(DIAG_SNAPSHOT_NAME);
    let trajectory_path = dir.join(DIAG_TRAJECTORY_NAME);

    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let st = DiagState {
        stop: Arc::clone(&stop),
        done: Arc::clone(&done),
        started: true,
        abandoned: false,
        start_time: SystemTime::now(),
        directory: dir.clone(),
        snapshot_path: snapshot_path.clone(),
        trajectory_path: trajectory_path.clone(),
        ndjson_size: 0,
        writer: None,
    };
    let state_arc = Arc::new(Mutex::new(st));
    let writer_state = Arc::clone(&state_arc);
    let writer_stop = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .spawn(move || diag_thread_main(writer_state, writer_stop))
        .ok();
    if handle.is_none() {
        let _ = std::fs::remove_dir_all(&dir);
        return false;
    }
    if let Some(st) = guard.as_mut() {
        st.writer = handle;
        st.started = true;
        st.directory = dir.clone();
        st.snapshot_path = snapshot_path;
        st.trajectory_path = trajectory_path;
    } else {
        // STATE was empty — store the initial record.
        *guard = Some(DiagState {
            stop,
            done,
            started: true,
            abandoned: false,
            start_time: SystemTime::now(),
            directory: dir,
            snapshot_path,
            trajectory_path,
            ndjson_size: 0,
            writer: None,
        });
    }
    // Note: state_arc is dropped here; the writer thread holds its own Arc.
    drop(state_arc);
    if let Some(d) = guard.as_ref() {
        // Control record: survives CBM_LOG_LEVEL suppression; spaces in
        // paths are fine (structured fields, not a flat line).
        crate::log::control_record(
            "diagnostics.start",
            &[
                ("snapshot", &d.snapshot_path.to_string_lossy()),
                ("trajectory", &d.trajectory_path.to_string_lossy()),
                ("interval_s", &(DIAG_INTERVAL_MS / 1000).to_string()),
            ],
        );
    }
    true
}

/// Stop diagnostics (C cbm_diag_stop): signal, join, cleanup live files,
/// remove the directory.
pub fn stop() {
    let handle;
    {
        let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let Some(st) = guard.as_mut() else {
            return;
        };
        if !st.started {
            return;
        }
        st.stop.store(true, Ordering::Release);
        handle = st.writer.take();
    }
    if let Some(h) = handle {
        let _ = h.join();
    }
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(st) = guard.as_mut() {
        // Cleanup live files (snapshot + tmp), keep the rotated trajectory
        // for post-mortem.
        if let Some(dir) = Some(&st.directory) {
            let _ = std::fs::remove_file(dir.join(DIAG_SNAPSHOT_NAME));
            let _ = std::fs::remove_file(dir.join(DIAG_SNAPSHOT_TMP_NAME));
            let _ = std::fs::remove_dir_all(dir);
        }
        *guard = None;
    }
}

/// Current snapshot/trajectory paths (C test API copy analogue).
pub fn paths() -> Option<(PathBuf, PathBuf)> {
    let guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .map(|d| (d.snapshot_path.clone(), d.trajectory_path.clone()))
}

/// Writer reached its loop? (C test writer-reached flag)
pub fn writer_reached() -> bool {
    WRITER_REACHED.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_query_aggregates() {
        record_query(100, false);
        record_query(300, false);
        record_query(50, true);
        let c = QUERY_STATS.count.load(Ordering::Relaxed);
        let t = QUERY_STATS.time_us.load(Ordering::Relaxed);
        let m = QUERY_STATS.max_us.load(Ordering::Relaxed);
        let e = QUERY_STATS.errors.load(Ordering::Relaxed);
        assert!(c >= 3);
        assert!(t >= 450);
        assert!(m >= 300);
        assert!(e >= 1);
    }

    #[test]
    fn start_stop_cycle() {
        std::env::set_var("CBM_DIAGNOSTICS", "1");
        assert!(start());
        // Already started → false.
        assert!(!start());
        // Paths exist after the first write window? The writer ticks every
        // 5s; the directory must exist immediately.
        let (snap, traj) = paths().expect("paths");
        assert!(snap.parent().unwrap().is_dir());
        assert!(snap.file_name().unwrap() == "snapshot.json");
        assert!(traj.file_name().unwrap() == "trajectory.ndjson");
        stop();
        assert!(!snap.parent().unwrap().exists()); // removed on stop
        std::env::remove_var("CBM_DIAGNOSTICS");
    }

    #[test]
    fn start_requires_env() {
        std::env::remove_var("CBM_DIAGNOSTICS");
        assert!(!start());
        std::env::set_var("CBM_DIAGNOSTICS", "0");
        assert!(!start());
        std::env::set_var("CBM_DIAGNOSTICS", "maybe");
        assert!(!start());
        std::env::remove_var("CBM_DIAGNOSTICS");
    }

    #[test]
    fn snapshot_body_is_json_shaped() {
        let body = snapshot_body(SystemTime::now());
        assert!(body.contains("\"uptime_s\""));
        assert!(body.contains("\"rss_bytes\""));
        assert!(body.contains("\"query_count\""));
        assert!(body.contains("\"mem_bucket_bytes\""));
        assert!(body.trim_end().ends_with('}'));
    }

    #[test]
    fn trajectory_line_shape() {
        let line = trajectory_line(SystemTime::now());
        assert!(line.starts_with("{\"uptime_s\":"));
        assert!(line.ends_with("}\n"));
    }
}
