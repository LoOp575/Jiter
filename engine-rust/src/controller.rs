//! Closed-loop Adaptive Controller coordinating Formulas #2 -> #1 -> #3 + Pacer + Route Selector.

use crate::ewma::{BitwiseEwmaEstimator, DEFAULT_MAX_AGE_MS};
use crate::scoring::{
    evaluate_linear_cost, ColorStateMachine, QualityState, TrafficProfile, REASON_FEC_K2,
    REASON_FEC_K4, REASON_FEC_STANDBY, REASON_PACER_FULL, REASON_PACER_HEADROOM,
    REASON_PACER_THROTTLE_BG, REASON_ROUTE_TO_NATIVE, REASON_ROUTE_TO_RELAY, REASON_STALE_SAMPLES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FecMode {
    Off = 0,
    XorK4Interleaved = 1,
    XorK2Interleaved = 2,
    Duplicate = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RouteChoice {
    Native = 0,
    Relay = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct RouteMetrics {
    pub srtt_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub bufferbloat_ms: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct ControlDecision {
    pub quality_score: Option<f64>,
    pub quality_state: QualityState,
    pub fec_mode: FecMode,
    pub bg_pacer_ratio: f64,
    pub selected_route: RouteChoice,
    pub confidence: f64,
    pub reason_flags: u32,
}

pub struct AdaptiveController {
    color_engine: ColorStateMachine,
    fec_mode: FecMode,
    bg_pacer_ratio: f64,
    selected_route: RouteChoice,
    route_hysteresis_pts: f64,
    route_cooldown_ms: i64,
    last_route_switch_ms: i64,
}

impl Default for AdaptiveController {
    fn default() -> Self {
        Self::new(10.0, 5_000)
    }
}

impl AdaptiveController {
    pub fn new(route_hysteresis_pts: f64, route_cooldown_ms: i64) -> Self {
        Self {
            color_engine: ColorStateMachine::default(),
            fec_mode: FecMode::Off,
            bg_pacer_ratio: 1.0,
            selected_route: RouteChoice::Native,
            route_hysteresis_pts,
            route_cooldown_ms,
            last_route_switch_ms: -route_cooldown_ms,
        }
    }

    pub fn reset(&mut self) {
        self.color_engine.reset();
        self.fec_mode = FecMode::Off;
        self.bg_pacer_ratio = 1.0;
        self.selected_route = RouteChoice::Native;
        self.last_route_switch_ms = -self.route_cooldown_ms;
    }

    pub fn step(
        &mut self,
        now_ms: i64,
        profile: TrafficProfile,
        ewma: &BitwiseEwmaEstimator,
        loss_pct: f64,
        bandwidth_mbps: Option<f64>,
        alternate_route: Option<RouteMetrics>,
    ) -> ControlDecision {
        if ewma.is_stale(now_ms, DEFAULT_MAX_AGE_MS) {
            let q_state = self.color_engine.update(None, now_ms, true);
            self.fec_mode = FecMode::Off;
            self.bg_pacer_ratio = 1.0;
            return ControlDecision {
                quality_score: None,
                quality_state: q_state,
                fec_mode: self.fec_mode,
                bg_pacer_ratio: self.bg_pacer_ratio,
                selected_route: self.selected_route,
                confidence: 0.0,
                reason_flags: REASON_STALE_SAMPLES,
            };
        }

        let srtt_ms = ewma.srtt_ms().unwrap_or(0.0);
        let jitter_ms = ewma.jitter_ms().unwrap_or(0.0);
        let bloat_ms = ewma.bufferbloat_ms().unwrap_or(0.0);

        let score = evaluate_linear_cost(
            srtt_ms,
            jitter_ms,
            loss_pct,
            bloat_ms,
            bandwidth_mbps,
            profile,
            ewma.sample_count(),
        );
        let mut reason_flags = score.veto_flags;
        let q_state = self.color_engine.update(Some(score.score_q), now_ms, false);

        // 1) Anti-Bufferbloat Background Pacer
        if matches!(profile, TrafficProfile::Game | TrafficProfile::Streaming) {
            if bloat_ms > 5.0 || score.score_q < 85.0 {
                self.bg_pacer_ratio = ((self.bg_pacer_ratio * 0.65 * 1000.0).round() / 1000.0).max(0.15);
                reason_flags |= REASON_PACER_THROTTLE_BG;
            } else {
                self.bg_pacer_ratio = (((self.bg_pacer_ratio + 0.03) * 1000.0).round() / 1000.0).min(0.55);
                reason_flags |= REASON_PACER_HEADROOM;
            }
        } else {
            self.bg_pacer_ratio = 1.0;
            reason_flags |= REASON_PACER_FULL;
        }

        // 2) Adaptive Formula #3 (XOR FEC) — ONLY for latency-sensitive profiles
        if profile == TrafficProfile::Game {
            if loss_pct >= 6.0 {
                self.fec_mode = FecMode::XorK2Interleaved;
                reason_flags |= REASON_FEC_K2;
            } else if loss_pct >= 1.0 || jitter_ms >= 8.0 {
                self.fec_mode = FecMode::XorK4Interleaved;
                reason_flags |= REASON_FEC_K4;
            } else if loss_pct < 0.3 && jitter_ms < 4.0 {
                self.fec_mode = FecMode::Off;
                reason_flags |= REASON_FEC_STANDBY;
            }
        } else {
            self.fec_mode = FecMode::Off;
        }

        // 3) Route Intelligence (Active vs Alternate Route with Hysteresis & Cooldown)
        if let Some(alt) = alternate_route {
            if now_ms.saturating_sub(self.last_route_switch_ms) >= self.route_cooldown_ms {
                let alt_score = evaluate_linear_cost(
                    alt.srtt_ms,
                    alt.jitter_ms,
                    alt.loss_pct,
                    alt.bufferbloat_ms,
                    bandwidth_mbps,
                    profile,
                    ewma.sample_count(),
                );
                if alt_score.score_q >= score.score_q + self.route_hysteresis_pts {
                    if self.selected_route == RouteChoice::Native {
                        self.selected_route = RouteChoice::Relay;
                        reason_flags |= REASON_ROUTE_TO_RELAY;
                    } else {
                        self.selected_route = RouteChoice::Native;
                        reason_flags |= REASON_ROUTE_TO_NATIVE;
                    }
                    self.last_route_switch_ms = now_ms;
                }
            }
        }

        ControlDecision {
            quality_score: Some(score.score_q),
            quality_state: q_state,
            fec_mode: self.fec_mode,
            bg_pacer_ratio: self.bg_pacer_ratio,
            selected_route: self.selected_route,
            confidence: score.confidence,
            reason_flags,
        }
    }
}
