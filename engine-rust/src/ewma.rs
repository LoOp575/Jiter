//! Formula #2: Scaled Bitwise EWMA / Jacobson's Algorithm (RFC 6298).
//!
//! Uses microsecond fixed-point integer registers scaled BEFORE bit-shifting:
//!   - `srtt_scaled   = SRTT_us   << 3` (alpha = 1/8 = 2^-3)
//!   - `rttvar_scaled = RTTVAR_us << 2` (beta  = 1/4 = 2^-2)

pub const MAX_VALID_RTT_US: u64 = 30_000_000; // 30 seconds sanity bound
pub const DEFAULT_MAX_AGE_MS: i64 = 10_000;

#[derive(Debug, Clone)]
pub struct BitwiseEwmaEstimator {
    initialized: bool,
    srtt_scaled: u64,
    rttvar_scaled: u64,
    min_rtt_us: Option<u64>,
    last_sample_ts_ms: Option<i64>,
    sample_count: u32,
}

impl Default for BitwiseEwmaEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl BitwiseEwmaEstimator {
    pub fn new() -> Self {
        Self {
            initialized: false,
            srtt_scaled: 0,
            rttvar_scaled: 0,
            min_rtt_us: None,
            last_sample_ts_ms: None,
            sample_count: 0,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn sample_count(&self) -> u32 {
        self.sample_count
    }

    pub fn reset(&mut self) {
        self.initialized = false;
        self.srtt_scaled = 0;
        self.rttvar_scaled = 0;
        self.min_rtt_us = None;
        self.last_sample_ts_ms = None;
        self.sample_count = 0;
    }

    pub fn reset_baseline(&mut self, new_min_rtt_ms: Option<f64>) {
        self.min_rtt_us = match new_min_rtt_ms {
            Some(ms) if ms.is_finite() && ms > 0.0 => Some(((ms * 1000.0).round() as u64).max(1)),
            _ => None,
        };
    }

    /// Ingest a new RTT measurement in milliseconds.
    /// Returns `true` if accepted, `false` if invalid, non-finite, or out-of-order.
    pub fn update(&mut self, rtt_ms: f64, timestamp_ms: i64) -> bool {
        if !rtt_ms.is_finite() || rtt_ms <= 0.0 {
            return false;
        }
        let rtt_us_f = (rtt_ms * 1000.0).round();
        if rtt_us_f <= 0.0 || rtt_us_f > (MAX_VALID_RTT_US as f64) {
            return false;
        }
        let rtt_us = rtt_us_f as u64;

        if let Some(prev_ts) = self.last_sample_ts_ms {
            if timestamp_ms < prev_ts {
                return false;
            }
        }

        self.min_rtt_us = Some(match self.min_rtt_us {
            Some(cur) => cur.min(rtt_us),
            None => rtt_us,
        });

        if !self.initialized {
            // RFC 6298 initialization: SRTT <- R, RTTVAR <- R/2
            self.srtt_scaled = rtt_us << 3;
            self.rttvar_scaled = (rtt_us >> 1).max(1) << 2;
            self.initialized = true;
        } else {
            let err = (rtt_us as i64) - ((self.srtt_scaled >> 3) as i64);
            let next_srtt = (self.srtt_scaled as i64).saturating_add(err).max(1) as u64;
            let abs_err = err.unsigned_abs();
            let next_var = (self.rttvar_scaled as i64)
                .saturating_add(abs_err as i64)
                .saturating_sub((self.rttvar_scaled >> 2) as i64)
                .max(0) as u64;
            self.srtt_scaled = next_srtt;
            self.rttvar_scaled = next_var;
        }

        self.last_sample_ts_ms = Some(timestamp_ms);
        self.sample_count = self.sample_count.saturating_add(1);
        true
    }

    pub fn is_stale(&self, now_ms: i64, max_age_ms: i64) -> bool {
        match self.last_sample_ts_ms {
            Some(last_ts) if self.initialized => now_ms.saturating_sub(last_ts) > max_age_ms,
            _ => true,
        }
    }

    pub fn srtt_ms(&self) -> Option<f64> {
        if !self.initialized {
            None
        } else {
            Some((self.srtt_scaled as f64 / 8.0) / 1000.0)
        }
    }

    pub fn jitter_ms(&self) -> Option<f64> {
        if !self.initialized {
            None
        } else {
            Some((self.rttvar_scaled as f64 / 4.0) / 1000.0)
        }
    }

    /// Retransmission Timeout = SRTT + 4 * RTTVAR (without 1s TCP floor).
    pub fn rto_ms(&self) -> Option<f64> {
        if !self.initialized {
            None
        } else {
            let rto_us = (self.srtt_scaled >> 3).saturating_add(self.rttvar_scaled);
            Some(rto_us as f64 / 1000.0)
        }
    }

    pub fn min_rtt_ms(&self) -> Option<f64> {
        self.min_rtt_us.map(|v| v as f64 / 1000.0)
    }

    pub fn bufferbloat_ms(&self) -> Option<f64> {
        if !self.initialized {
            return None;
        }
        let base_us = self.min_rtt_us?;
        let srtt_us = self.srtt_scaled >> 3;
        let bloat_us = srtt_us.saturating_sub(base_us);
        Some(bloat_us as f64 / 1000.0)
    }
}
