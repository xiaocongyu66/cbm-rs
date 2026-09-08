//! profile.rs — 1:1 rewrite of `src/foundation/profile.{c,h}`.
//!
//! Activatable profiling (`CBM_PROFILE` env or programmatic enable) plus a
//! scaling probe that records timing at total/8, /4, /2, total checkpoints
//! and warns on superlinear growth (k ≥ 1.35) — the alarm an accidental
//! O(n²) regression should trip in an ordinary user's log.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Instant;

pub const SCALE_CHECKPOINTS: usize = 4;
pub const SCALE_WARN_K: f64 = 1.35;

const SCALE_MIN_ITEMS: i64 = 512;
const SCALE_MIN_FIRST_US: i64 = 1000;

static PROFILE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Read `CBM_PROFILE` (non-empty, non-"0" → active).
pub fn init() {
    if let Ok(v) = std::env::var("CBM_PROFILE") {
        if !v.is_empty() && v != "0" {
            PROFILE_ACTIVE.store(true, Ordering::Relaxed);
        }
    }
}

pub fn enable() {
    PROFILE_ACTIVE.store(true, Ordering::Relaxed);
}

pub fn active() -> bool {
    PROFILE_ACTIVE.load(Ordering::Relaxed)
}

pub fn now_ns() -> i64 {
    crate::platform::now_ns() as i64
}

/// Log a phase's elapsed time (optionally with item count and rate).
pub fn log_elapsed(phase: &str, sub: &str, start_ns: i64, items: i64) {
    let us = (now_ns() - start_ns) / 1_000;
    let ms = us / 1_000;
    if items > 0 && us > 0 {
        let rate = (items as f64 * 1_000_000.0 / us as f64) as i64;
        crate::log::info(
            "prof",
            &[
                ("phase", phase),
                ("sub", sub),
                ("ms", &ms.to_string()),
                ("us", &us.to_string()),
                ("items", &items.to_string()),
                ("rate_per_s", &rate.to_string()),
            ],
        );
    } else if items > 0 {
        crate::log::info(
            "prof",
            &[
                ("phase", phase),
                ("sub", sub),
                ("ms", &ms.to_string()),
                ("us", &us.to_string()),
                ("items", &items.to_string()),
            ],
        );
    } else {
        crate::log::info(
            "prof",
            &[
                ("phase", phase),
                ("sub", sub),
                ("ms", &ms.to_string()),
                ("us", &us.to_string()),
            ],
        );
    }
}

/// Scaling probe (C cbm_scale_probe_t).
pub struct ScaleProbe {
    pub phase: &'static str,
    pub total: i64,
    start: Instant,
    next_cp: AtomicI32,
    cp_us: [i64; SCALE_CHECKPOINTS],
    cp_items: [i64; SCALE_CHECKPOINTS],
}

impl ScaleProbe {
    /// Begin probing `phase` over `total` items.
    pub fn begin(phase: &'static str, total: i64) -> ScaleProbe {
        ScaleProbe {
            phase,
            total,
            start: Instant::now(),
            next_cp: AtomicI32::new(0),
            cp_us: [0; SCALE_CHECKPOINTS],
            cp_items: [0; SCALE_CHECKPOINTS],
        }
    }

    fn elapsed_us(&self) -> i64 {
        self.start.elapsed().as_micros() as i64
    }

    /// Record a checkpoint when `done` crosses total/8, /4, /2, total.
    /// Exactly one thread records each checkpoint (CAS, like the C).
    pub fn tick(&mut self, done: i64) {
        if self.total < SCALE_MIN_ITEMS {
            return;
        }
        let cp = self.next_cp.load(Ordering::Relaxed);
        if cp >= SCALE_CHECKPOINTS as i32 {
            return;
        }
        // cp 0..3 -> total/8, total/4, total/2, total
        let threshold = self.total >> (SCALE_CHECKPOINTS as i32 - 1 - cp);
        if done < threshold {
            return;
        }
        if self
            .next_cp
            .compare_exchange(cp, cp + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let cp = cp as usize;
        self.cp_us[cp] = self.elapsed_us();
        self.cp_items[cp] = done;
    }

    /// Fit exponent k = log(T_last/T_first) / log(n_last/n_first).
    /// -1.0 on degenerate inputs.
    pub fn fit_k(first_n: i64, first_us: i64, last_n: i64, last_us: i64) -> f64 {
        if first_n <= 0 || first_us <= 0 || last_us <= 0 || last_n <= first_n {
            return -1.0;
        }
        ((last_us as f64) / (first_us as f64)).ln() / ((last_n as f64) / (first_n as f64)).ln()
    }

    /// Analyze and log; warns on superlinear growth.
    pub fn end(&self) {
        if self.total < SCALE_MIN_ITEMS {
            return;
        }
        let recorded = self.next_cp.load(Ordering::Relaxed) as usize;
        if recorded < 2 {
            return; // need two points to speak about growth
        }
        let first_us = self.cp_us[0];
        let first_n = self.cp_items[0];
        let last_us = self.cp_us[recorded - 1];
        let last_n = self.cp_items[recorded - 1];
        if first_us < SCALE_MIN_FIRST_US || first_n <= 0 || last_n <= first_n || last_us <= 0 {
            return;
        }
        let k = Self::fit_k(first_n, first_us, last_n, last_us);
        if k < 0.0 {
            return;
        }
        let us_per_item = last_us / last_n;
        let k_buf = format!("{k:.2}");
        let n_buf = last_n.to_string();
        let per_buf = us_per_item.to_string();
        let ms_buf = (last_us / 1_000).to_string();
        if k >= SCALE_WARN_K {
            crate::log::warn(
                "scaling.superlinear",
                &[
                    ("phase", self.phase),
                    ("k", &k_buf),
                    ("items", &n_buf),
                    ("elapsed_ms", &ms_buf),
                    ("us_per_item", &per_buf),
                ],
            );
        }
        if !active() {
            return;
        }
        let curve: Vec<String> = (0..recorded)
            .map(|i| format!("{}:{}", self.cp_items[i], self.cp_us[i] / 1_000))
            .collect();
        crate::log::info(
            "scaling",
            &[
                ("phase", self.phase),
                ("k", &k_buf),
                ("items", &n_buf),
                ("elapsed_ms", &ms_buf),
                ("us_per_item", &per_buf),
                ("curve_items_ms", &curve.join(",")),
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_init() {
        std::env::set_var("CBM_PROFILE", "1");
        init();
        assert!(active());
        std::env::remove_var("CBM_PROFILE");
        // init() with no env must not disable once enabled.
        enable();
        init();
        assert!(active());
    }

    #[test]
    fn fit_k_math() {
        // 4x items, 16x time → k = log(16)/log(4) = 2.0 (quadratic).
        assert!((ScaleProbe::fit_k(100, 100, 400, 1600) - 2.0).abs() < 1e-9);
        // Linear: 2x items, 2x time → k = 1.
        assert!((ScaleProbe::fit_k(100, 100, 200, 200) - 1.0).abs() < 1e-9);
        // Degenerate.
        assert_eq!(ScaleProbe::fit_k(0, 100, 400, 1600), -1.0);
        assert_eq!(ScaleProbe::fit_k(100, 0, 400, 1600), -1.0);
        assert_eq!(ScaleProbe::fit_k(400, 100, 400, 1600), -1.0);
    }

    #[test]
    fn probe_checkpoints_recorded() {
        let mut probe = ScaleProbe::begin("test", 1024);
        // Below first checkpoint (128): no-op.
        probe.tick(50);
        assert_eq!(probe.next_cp.load(Ordering::Relaxed), 0);
        probe.tick(128); // cp0 = total/8
        assert_eq!(probe.next_cp.load(Ordering::Relaxed), 1);
        probe.tick(200);
        probe.tick(256); // cp1 = total/4
        assert_eq!(probe.next_cp.load(Ordering::Relaxed), 2);
        probe.tick(512); // cp2
        probe.tick(1024); // cp3
        assert_eq!(probe.next_cp.load(Ordering::Relaxed), 4);
        probe.tick(2000); // saturated
        assert_eq!(probe.next_cp.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn probe_small_totals_skip() {
        let mut probe = ScaleProbe::begin("tiny", 100);
        probe.tick(100);
        assert_eq!(probe.next_cp.load(Ordering::Relaxed), 0); // below min items
    }

    #[test]
    fn log_elapsed_smoke() {
        let start = now_ns();
        log_elapsed("phase", "sub", start, 0);
        log_elapsed("phase", "sub", start, 10);
    }
}
