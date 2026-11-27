//! Formula #1: Linear Cost Function + Non-Compensatory Hard Veto Guardrails
//! + Anti-Flicker Hysteresis Color State Machine.

pub const RTT_SCALE_MS: f64 = 200.0;
pub const JITTER_SCALE_MS: f64 = 50.0;
pub const LOSS_SCALE_PCT: f64 = 10.0;
pub const BLOAT_SCALE_MS: f64 = 300.0;

pub const REASON_STALE_SAMPLES: u32 = 1 << 0;
pub const REASON_VETO_GAME_LOSS: u32 = 1 << 1;
pub const REASON_VETO_GAME_BLOAT: u32 = 1 << 2;
pub const REASON_VETO_GAME_MIN_BW: u32 = 1 << 3;
pub const REASON_VETO_STREAM_STARVED: u32 = 1 << 4;
pub const REASON_VETO_STREAM_LOSS: u32 = 1 << 5;
pub const REASON_PACER_THROTTLE_BG: u32 = 1 << 6;
pub const REASON_PACER_HEADROOM: u32 = 1 << 7;
pub const REASON_PACER_FULL: u32 = 1 << 8;
pub const REASON_FEC_K4: u32 = 1 << 9;
pub const REASON_FEC_K2: u32 = 1 << 10;
pub const REASON_FEC_STANDBY: u32 = 1 << 11;
pub const REASON_ROUTE_TO_RELAY: u32 = 1 << 12;
pub const REASON_ROUTE_TO_NATIVE: u32 = 1 << 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TrafficProfile {
    Game = 0,
    Browser = 1,
    Download = 2,
    Streaming = 3,
    Social = 4,
    SafeBalanced = 5,
}

impl TrafficProfile {
    pub fn from_u32(id: u32) -> Self {
        match id {
            0 => Self::Game,
            1 => Self::Browser,
            2 => Self::Download,
            3 => Self::Streaming,
            4 => Self::Social,
            _ => Self::SafeBalanced,
        }
    }

    pub const fn weights(self) -> ProfileWeights {
        match self {
            Self::Game => ProfileWeights::new(0.35, 0.30, 0.20, 0.15, 0.00, 2.0),
            Self::Browser => ProfileWeights::new(0.20, 0.15, 0.15, 0.15, 0.35, 5.0),
            Self::Download => ProfileWeights::new(0.10, 0.10, 0.15, 0.25, 0.40, 25.0),
            Self::Streaming => ProfileWeights::new(0.15, 0.25, 0.15, 0.20, 0.25, 15.0),
            Self::Social => ProfileWeights::new(0.20, 0.20, 0.20, 0.20, 0.20, 5.0),
            Self::SafeBalanced => ProfileWeights::new(0.30, 0.25, 0.20, 0.20, 0.05, 5.0),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProfileWeights {
    pub w_rtt: f64,
    pub w_jitter: f64,
    pub w_loss: f64,
    pub w_bloat: f64,
    pub w_bw: f64,
    pub min_bw_mbps: f64,
}

impl ProfileWeights {
    pub const fn new(
        w_rtt: f64,
        w_jitter: f64,
        w_loss: f64,
        w_bloat: f64,
        w_bw: f64,
        min_bw_mbps: f64,
    ) -> Self {
        Self {
            w_rtt,
            w_jitter,
            w_loss,
            w_bloat,
            w_bw,
            min_bw_mbps,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QualityState {
    Unknown = 0,
    Green = 1,
    Yellow = 2,
    Red = 3,
}

#[derive(Debug, Clone, Copy)]
pub struct ScoreResult {
    pub score_q: f64,
    pub cost_c: f64,
    pub confidence: f64,
    pub veto_flags: u32,
    pub r_norm: f64,
    pub j_norm: f64,
    pub p_norm: f64,
    pub b_norm: f64,
    pub w_norm: f64,
}

fn round_to(val: f64, factor: f64) -> f64 {
    (val * factor).round() / factor
}

pub fn evaluate_linear_cost(
    srtt_ms: f64,
    jitter_ms: f64,
    loss_pct: f64,
    bufferbloat_ms: f64,
    bandwidth_mbps: Option<f64>,
    profile: TrafficProfile,
    sample_count: u32,
) -> ScoreResult {
    let w = profile.weights();

    let r_norm = (srtt_ms.max(0.0) / RTT_SCALE_MS).min(1.0);
    let j_norm = (jitter_ms.max(0.0) / JITTER_SCALE_MS).min(1.0);
    let p_norm = (loss_pct.max(0.0) / LOSS_SCALE_PCT).min(1.0);
    let b_norm = (bufferbloat_ms.max(0.0) / BLOAT_SCALE_MS).min(1.0);

    let mut confidence = (sample_count as f64 / 10.0).clamp(0.0, 1.0);
    let w_norm = match bandwidth_mbps {
        Some(bw) if bw.is_finite() && bw >= 0.0 => (1.0 - (bw / w.min_bw_mbps)).clamp(0.0, 1.0),
        _ => {
            confidence *= 0.8;
            0.0
        }
    };

    let cost_c = w.w_rtt * r_norm
        + w.w_jitter * j_norm
        + w.w_loss * p_norm
        + w.w_bloat * b_norm
        + w.w_bw * w_norm;

    let mut score_q = 100.0 * (1.0 - cost_c);
    let mut veto_flags = 0u32;

    match profile {
        TrafficProfile::Game => {
            if loss_pct >= 5.0 {
                score_q = score_q.min(45.0);
                veto_flags |= REASON_VETO_GAME_LOSS;
            }
            if bufferbloat_ms >= 50.0 {
                score_q = score_q.min(49.0);
                veto_flags |= REASON_VETO_GAME_BLOAT;
            }
            if let Some(bw) = bandwidth_mbps {
                if bw.is_finite() && bw < w.min_bw_mbps {
                    score_q = score_q.min(45.0);
                    veto_flags |= REASON_VETO_GAME_MIN_BW;
                }
            }
        }
        TrafficProfile::Streaming => {
            if let Some(bw) = bandwidth_mbps {
                if bw.is_finite() && bw < (w.min_bw_mbps * 0.4) {
                    score_q = score_q.min(45.0);
                    veto_flags |= REASON_VETO_STREAM_STARVED;
                }
            }
            if loss_pct >= 5.0 {
                score_q = score_q.min(49.0);
                veto_flags |= REASON_VETO_STREAM_LOSS;
            }
        }
        _ => {}
    }

    ScoreResult {
        score_q: round_to(score_q, 100.0),
        cost_c: round_to(cost_c, 10_000.0),
        confidence: round_to(confidence, 100.0),
        veto_flags,
        r_norm: round_to(r_norm, 10_000.0),
        j_norm: round_to(j_norm, 10_000.0),
        p_norm: round_to(p_norm, 10_000.0),
        b_norm: round_to(b_norm, 10_000.0),
        w_norm: round_to(w_norm, 10_000.0),
    }
}

#[derive(Debug, Clone)]
pub struct ColorStateMachine {
    min_dwell_ms: i64,
    ewma_alpha: f64,
    smoothed_q: Option<f64>,
    state: QualityState,
    last_transition_ms: i64,
}

impl Default for ColorStateMachine {
    fn default() -> Self {
        Self::new(2_000, 0.35)
    }
}

impl ColorStateMachine {
    pub fn new(min_dwell_ms: i64, ewma_alpha: f64) -> Self {
        Self {
            min_dwell_ms,
            ewma_alpha,
            smoothed_q: None,
            state: QualityState::Unknown,
            last_transition_ms: -min_dwell_ms,
        }
    }

    pub fn state(&self) -> QualityState {
        self.state
    }

    pub fn reset(&mut self) {
        self.smoothed_q = None;
        self.state = QualityState::Unknown;
        self.last_transition_ms = -self.min_dwell_ms;
    }

    pub fn update(&mut self, score_q: Option<f64>, now_ms: i64, is_stale: bool) -> QualityState {
        let raw_q = match score_q {
            Some(q) if !is_stale && q.is_finite() => q,
            _ => {
                self.state = QualityState::Unknown;
                self.smoothed_q = None;
                self.last_transition_ms = now_ms;
                return self.state;
            }
        };

        let q = match self.smoothed_q {
            Some(prev) => self.ewma_alpha * raw_q + (1.0 - self.ewma_alpha) * prev,
            None => raw_q,
        };
        self.smoothed_q = Some(q);

        let dwell_elapsed = now_ms.saturating_sub(self.last_transition_ms) >= self.min_dwell_ms;

        if self.state == QualityState::Unknown {
            self.state = if q >= 80.0 {
                QualityState::Green
            } else if q >= 50.0 {
                QualityState::Yellow
            } else {
                QualityState::Red
            };
            self.last_transition_ms = now_ms;
            return self.state;
        }

        let target = match self.state {
            QualityState::Green => {
                if q < 48.0 {
                    QualityState::Red
                } else if q < 75.0 {
                    QualityState::Yellow
                } else {
                    QualityState::Green
                }
            }
            QualityState::Yellow => {
                if q >= 82.0 {
                    QualityState::Green
                } else if q < 48.0 {
                    QualityState::Red
                } else {
                    QualityState::Yellow
                }
            }
            QualityState::Red => {
                if q >= 82.0 {
                    QualityState::Green
                } else if q >= 55.0 {
                    QualityState::Yellow
                } else {
                    QualityState::Red
                }
            }
            QualityState::Unknown => self.state,
        };

        let severe_drop = target == QualityState::Red && raw_q < 45.0;
        if target != self.state && (dwell_elapsed || severe_drop) {
            self.state = target;
            self.last_transition_ms = now_ms;
        }

        self.state
    }
}
