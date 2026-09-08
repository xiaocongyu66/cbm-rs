//! dump_verify.rs — 1:1 rewrite of `src/foundation/dump_verify.{c,h}`.
//!
//! Post-dump plausibility gate (#334): when the persisted node count falls
//! below `ratio` of committed nodes (above a floor), the index is reported
//! as "degraded" instead of silently passing.

pub const MIN_FLOOR: i32 = 50;
pub const DEFAULT_RATIO: f64 = 0.5;

/// Plausibility check. `ratio <= 0` disables the gate entirely.
pub fn is_degraded(committed_nodes: i32, persisted_nodes: i32, ratio: f64, min_floor: i32) -> bool {
    if ratio <= 0.0 {
        return false;
    }
    if committed_nodes < 0 {
        return false;
    }
    if persisted_nodes < 0 {
        return true;
    }
    if committed_nodes > 0 && persisted_nodes == 0 {
        return true;
    }
    if committed_nodes <= min_floor {
        return false;
    }
    (persisted_nodes as f64) < (committed_nodes as f64) * ratio
}

/// Minimum healthy ratio, env-overridable via `CBM_DUMP_VERIFY_MIN_RATIO`
/// (a double in [0, 1]); invalid values warn and fall back to 0.5.
pub fn min_ratio() -> f64 {
    if let Ok(buf) = std::env::var("CBM_DUMP_VERIFY_MIN_RATIO") {
        if let Ok(r) = buf.trim().parse::<f64>() {
            if (0.0..=1.0).contains(&r) {
                return r;
            }
        }
        crate::log::warn(
            "dump_verify.env.invalid",
            &[("value", &buf), ("fallback", "0.5")],
        );
    }
    DEFAULT_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_disabled_with_zero_ratio() {
        assert!(!is_degraded(1000, 0, 0.0, MIN_FLOOR));
    }

    #[test]
    fn negative_inputs() {
        assert!(!is_degraded(-1, 100, 0.5, MIN_FLOOR)); // committed bogus → pass
        assert!(is_degraded(1000, -1, 0.5, MIN_FLOOR)); // persisted bogus → degraded
    }

    #[test]
    fn empty_persisted_is_degraded() {
        assert!(is_degraded(1000, 0, 0.5, MIN_FLOOR));
    }

    #[test]
    fn min_floor_bypasses_check() {
        // persisted == 0 degrades regardless of floor (checked before floor).
        assert!(is_degraded(50, 0, 0.5, MIN_FLOOR));
        // committed <= floor with nonzero persisted: too small to judge.
        assert!(!is_degraded(50, 1, 0.5, MIN_FLOOR));
        assert!(!is_degraded(50, 10, 0.5, MIN_FLOOR));
        // Same ratio just above the floor DOES check.
        assert!(is_degraded(51, 1, 0.5, MIN_FLOOR));
    }

    #[test]
    fn ratio_threshold() {
        // 400/1000 = 0.4 < 0.5 → degraded.
        assert!(is_degraded(1000, 400, 0.5, MIN_FLOOR));
        // 500/1000 = 0.5 → not below ratio → healthy.
        assert!(!is_degraded(1000, 500, 0.5, MIN_FLOOR));
        // 900/1000 → healthy.
        assert!(!is_degraded(1000, 900, 0.5, MIN_FLOOR));
    }

    #[test]
    fn env_override() {
        std::env::set_var("CBM_DUMP_VERIFY_MIN_RATIO", "0.8");
        assert!((min_ratio() - 0.8).abs() < f64::EPSILON);
        // 700/1000=0.7 < 0.8 → degraded under the stricter env ratio.
        assert!(is_degraded(1000, 700, min_ratio(), MIN_FLOOR));
        std::env::set_var("CBM_DUMP_VERIFY_MIN_RATIO", "bogus");
        assert!((min_ratio() - 0.5).abs() < f64::EPSILON);
        std::env::set_var("CBM_DUMP_VERIFY_MIN_RATIO", "1.5"); // out of range
        assert!((min_ratio() - 0.5).abs() < f64::EPSILON);
        std::env::remove_var("CBM_DUMP_VERIFY_MIN_RATIO");
    }
}
