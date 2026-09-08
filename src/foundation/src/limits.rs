//! limits.rs — 1:1 rewrite of `src/foundation/limits.{c,h}`.
//!
//! Generous, env-configurable safety limits. Hitting a limit degrades to a
//! *reported* skip, never a silent drop and never an unbounded read. Every
//! limit is env-overridable so an operator can tune it per-repo without a
//! rebuild.

/// Result of an attempted per-file read, so callers can attribute a skip to
/// the right phase/reason instead of collapsing every failure into
/// "read failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStatus {
    /// File read successfully.
    Ok,
    /// Could not open (missing / permission).
    OpenFail,
    /// Zero/negative size — benign, nothing to index.
    Empty,
    /// Size exceeds [`max_file_bytes`].
    Oversized,
    /// Buffer allocation failed.
    Oom,
}

const MAX_FILE_BYTES_DEFAULT: i64 = 512 * 1024 * 1024; // 512 MiB

/// Maximum size (bytes) of a single source file the indexer will read into
/// memory. Files larger than this are skipped-and-reported (phase
/// "oversized"), never silently dropped. Override with `CBM_MAX_FILE_BYTES`
/// (a positive integer count of bytes).
///
/// The env var is read on each call — intentional: cheap, and reading fresh
/// means a test/operator can change the cap without a process restart or a
/// stale memoized copy leaking across runs.
pub fn max_file_bytes() -> i64 {
    match std::env::var("CBM_MAX_FILE_BYTES") {
        Ok(raw) if !raw.is_empty() => parse_positive(&raw).unwrap_or(MAX_FILE_BYTES_DEFAULT),
        _ => MAX_FILE_BYTES_DEFAULT,
    }
}

const CYPHER_MAX_DEPTH_DEFAULT: i32 = 10;
const MCP_MAX_DEPTH_DEFAULT: i32 = 15;

/// Maximum variable-length path depth for the Cypher engine (the `*min..max`
/// hop ceiling). BOTH the explicit (`*1..N`) and unbounded (`*`, `*..m`)
/// forms are clamped to this, so `[:CALLS*1..1000000]` degrades to a
/// WARN-and-cap rather than an unbounded (cyclic-graph DoS) traversal.
/// Override with `CBM_CYPHER_MAX_DEPTH` (a positive integer). Default 10.
pub fn cypher_max_depth() -> i32 {
    env_positive_int("CBM_CYPHER_MAX_DEPTH", CYPHER_MAX_DEPTH_DEFAULT)
}

/// Maximum traversal depth for client-driven MCP graph tools
/// (trace_call_path, detect_changes): the client `depth` argument is
/// WARN-clamped to this so an arbitrarily large value cannot drive an
/// unbounded BFS over the shared store. Override with `CBM_MCP_MAX_DEPTH`
/// (a positive integer). Default 15.
pub fn mcp_max_depth() -> i32 {
    env_positive_int("CBM_MCP_MAX_DEPTH", MCP_MAX_DEPTH_DEFAULT)
}

/// Shared env parser: a positive integer, else `None`.
fn parse_positive(raw: &str) -> Option<i64> {
    raw.trim().parse::<i64>().ok().filter(|&v| v > 0)
}

fn env_positive_int(name: &str, fallback: i32) -> i32 {
    match std::env::var(name) {
        Ok(raw) if !raw.is_empty() => parse_positive(&raw)
            .filter(|&v| v <= i32::MAX as i64)
            .map(|v| v as i32)
            .unwrap_or(fallback),
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// Serialize env mutations across tests (env is process-global).
    static ENV_LOCK: AtomicU8 = AtomicU8::new(0);

    fn with_env<F: FnOnce()>(k: &str, v: Option<&str>, f: F) {
        while ENV_LOCK.swap(1, Ordering::SeqCst) == 1 {
            std::thread::yield_now();
        }
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
        f();
        std::env::remove_var(k);
        ENV_LOCK.store(0, Ordering::SeqCst);
    }

    #[test]
    fn defaults_when_env_unset() {
        with_env("CBM_MAX_FILE_BYTES", None, || {
            assert_eq!(max_file_bytes(), 512 * 1024 * 1024);
        });
        with_env("CBM_CYPHER_MAX_DEPTH", None, || {
            assert_eq!(cypher_max_depth(), 10)
        });
        with_env("CBM_MCP_MAX_DEPTH", None, || {
            assert_eq!(mcp_max_depth(), 15)
        });
    }

    #[test]
    fn env_overrides() {
        with_env("CBM_MAX_FILE_BYTES", Some("1048576"), || {
            assert_eq!(max_file_bytes(), 1_048_576);
        });
        with_env("CBM_CYPHER_MAX_DEPTH", Some("3"), || {
            assert_eq!(cypher_max_depth(), 3)
        });
        with_env("CBM_MCP_MAX_DEPTH", Some("40"), || {
            assert_eq!(mcp_max_depth(), 40)
        });
    }

    #[test]
    fn invalid_env_falls_back_to_default() {
        with_env("CBM_MAX_FILE_BYTES", Some("not-a-number"), || {
            assert_eq!(max_file_bytes(), 512 * 1024 * 1024);
        });
        with_env("CBM_MAX_FILE_BYTES", Some("-5"), || {
            assert_eq!(max_file_bytes(), 512 * 1024 * 1024);
        });
        with_env("CBM_MAX_FILE_BYTES", Some("0"), || {
            assert_eq!(max_file_bytes(), 512 * 1024 * 1024);
        });
        with_env("CBM_MAX_FILE_BYTES", Some(""), || {
            assert_eq!(max_file_bytes(), 512 * 1024 * 1024);
        });
        with_env("CBM_CYPHER_MAX_DEPTH", Some("99999999999999999999"), || {
            assert_eq!(cypher_max_depth(), 10); // overflows i32 → default
        });
    }
}
