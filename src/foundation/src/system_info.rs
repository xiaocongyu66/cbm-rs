//! system_info.rs — 1:1 rewrite of `src/foundation/system_info.c`.
//!
//! CPU core count and RAM detection, Linux path: sysconf + sysinfo host
//! fallbacks, with cgroup-aware overrides (v2 first, v1 fallback) so
//! limits reflect the container's effective quota, capped by host values
//! against mis-mounted cgroups. Results cached after first call.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemInfo {
    /// All cores.
    pub total_cores: i32,
    /// P-cores (Apple) or total_cores (others).
    pub perf_cores: i32,
    /// Total physical RAM in bytes (cgroup-capped when containerized).
    pub total_ram: u64,
}

const DEFAULT_CORES: i32 = 1;

/// Read a small file, trim trailing whitespace. Returns None on any failure.
fn read_small_file(path: &std::path::Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    Some(raw.trim_end_matches(['\n', ' ', '\t']).to_string())
}

/// Effective CPU count from a cgroup file tree.
/// Returns -1 when no quota is discoverable (caller falls back to sysconf).
pub fn detect_cgroup_cpus(cgroup_root: &str) -> i32 {
    // cgroup v2: "<root>/cpu.max" — "<quota> <period>" or "max <period>".
    if let Some(buf) = read_small_file(std::path::Path::new(&format!("{cgroup_root}/cpu.max"))) {
        if buf.starts_with("max") {
            return -1;
        }
        let mut it = buf.split_whitespace();
        if let (Some(q), Some(p)) = (it.next(), it.next()) {
            if let (Ok(quota), Ok(period)) = (q.parse::<i64>(), p.parse::<i64>()) {
                if quota > 0 && period > 0 {
                    let n = (quota + period - 1) / period; // ceil
                    return if n > 0 { n as i32 } else { 1 };
                }
            }
        }
        return -1;
    }

    // cgroup v1: quota of -1 means unlimited.
    let quota: i64 = match read_small_file(std::path::Path::new(&format!(
        "{cgroup_root}/cpu/cpu.cfs_quota_us"
    ))) {
        Some(buf) => match buf.parse::<i64>() {
            Ok(v) if v > 0 => v,
            _ => return -1,
        },
        None => return -1,
    };
    let period: i64 = match read_small_file(std::path::Path::new(&format!(
        "{cgroup_root}/cpu/cpu.cfs_period_us"
    ))) {
        Some(buf) => match buf.parse::<i64>() {
            Ok(v) if v > 0 => v,
            _ => return -1,
        },
        None => return -1,
    };
    let n = (quota + period - 1) / period;
    if n > 0 {
        n as i32
    } else {
        1
    }
}

/// Effective memory limit (bytes) from a cgroup file tree; 0 = unlimited.
pub fn detect_cgroup_mem(cgroup_root: &str) -> u64 {
    // cgroup v2: "max" or integer bytes.
    if let Some(buf) =
        read_small_file(std::path::Path::new(&format!("{cgroup_root}/memory.max")))
    {
        if buf.starts_with("max") {
            return 0;
        }
        return match buf.parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => 0,
        };
    }

    // cgroup v1: sentinel "unlimited" is ~PAGE_COUNTER_MAX; anything past
    // half of u64 max is effectively unlimited.
    if let Some(buf) = read_small_file(std::path::Path::new(&format!(
        "{cgroup_root}/memory/memory.limit_in_bytes"
    ))) {
        if let Ok(n) = buf.parse::<u64>() {
            if n > 0 && n < u64::MAX / 2 {
                return n;
            }
        }
    }
    0
}

fn detect() -> SystemInfo {
    // Host fallbacks.
    let host_cpus = {
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if n > 0 {
            n as i32
        } else {
            DEFAULT_CORES
        }
    };
    let mut host_ram: u64 = 0;
    unsafe {
        let mut si: libc::sysinfo = std::mem::zeroed();
        if libc::sysinfo(&mut si) == 0 {
            host_ram = si.totalram as u64 * si.mem_unit as u64;
        }
    }

    // Cgroup overrides; min(cgroup, host) defends against mis-mounted
    // cgroups reporting values larger than the host.
    let cg_cpus = detect_cgroup_cpus("/sys/fs/cgroup");
    let total_cores = if cg_cpus > 0 && cg_cpus < host_cpus {
        cg_cpus
    } else {
        host_cpus
    };
    let perf_cores = total_cores; // Linux doesn't distinguish P/E
    let cg_ram = detect_cgroup_mem("/sys/fs/cgroup");
    let total_ram = if cg_ram > 0 && (host_ram == 0 || cg_ram < host_ram) {
        cg_ram
    } else {
        host_ram
    };

    SystemInfo {
        total_cores,
        perf_cores,
        total_ram,
    }
}

/// Cached system info (immutable hardware properties).
pub fn system_info() -> &'static SystemInfo {
    static CACHE: OnceLock<SystemInfo> = OnceLock::new();
    CACHE.get_or_init(detect)
}

const MIN_WORKERS: i32 = 1;
const WORKERS_MAX: i32 = 256;

/// Default worker count. `initial=true` uses all cores (user is waiting);
/// incremental leaves one core of headroom. `CBM_WORKERS` overrides,
/// clamped to [MIN_WORKERS, WORKERS_MAX].
pub fn default_worker_count(initial: bool) -> i32 {
    if let Ok(raw) = std::env::var("CBM_WORKERS") {
        if let Ok(n) = raw.parse::<i32>() {
            if (MIN_WORKERS..=WORKERS_MAX).contains(&n) {
                return n;
            }
        }
        crate::log::warn("workers.env.invalid", &[("value", raw.as_str()), ("fallback", "sysconf")]);
    }
    let info = system_info();
    if initial {
        // Use all cores for initial indexing — user is waiting.
        return info.total_cores;
    }
    // Incremental: leave headroom for user's apps.
    let workers = info.perf_cores - 1;
    workers.max(MIN_WORKERS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_is_sane_on_this_host() {
        let info = system_info();
        assert!(info.total_cores >= 1);
        assert_eq!(info.perf_cores, info.total_cores); // Linux
        // This test box has RAM; container cap (if any) must be > 0.
        assert!(info.total_ram > 0, "got {}", info.total_ram);
    }

    #[test]
    fn cgroup_cpu_v2_parsing() {
        let dir = std::env::temp_dir().join(format!("cbm-cg-cpu-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cpu.max"), "200000 100000\n").unwrap();
        assert_eq!(detect_cgroup_cpus(dir.to_str().unwrap()), 2); // ceil(2.0)

        std::fs::write(dir.join("cpu.max"), "max 100000\n").unwrap();
        assert_eq!(detect_cgroup_cpus(dir.to_str().unwrap()), -1);

        std::fs::write(dir.join("cpu.max"), "250000 100000\n").unwrap();
        assert_eq!(detect_cgroup_cpus(dir.to_str().unwrap()), 3); // ceil(2.5)

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cgroup_mem_v2_parsing() {
        let dir = std::env::temp_dir().join(format!("cbm-cg-mem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("memory.max"), "1073741824\n").unwrap();
        assert_eq!(detect_cgroup_mem(dir.to_str().unwrap()), 1 << 30);

        std::fs::write(dir.join("memory.max"), "max\n").unwrap();
        assert_eq!(detect_cgroup_mem(dir.to_str().unwrap()), 0);

        std::fs::write(dir.join("memory.max"), "0\n").unwrap();
        assert_eq!(detect_cgroup_mem(dir.to_str().unwrap()), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cgroup_missing_tree_is_unlimited() {
        assert_eq!(detect_cgroup_cpus("/nonexistent-cbm"), -1);
        assert_eq!(detect_cgroup_mem("/nonexistent-cbm"), 0);
    }
}
