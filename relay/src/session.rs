//! Ephemeral RAM-only JITER Relay Session Table.
//!
//! Zero-retention privacy design:
//!   - Sessions exist strictly in memory keyed by random ephemeral `session_id`
//!   - Idle sessions are automatically purged after `session_timeout_ms`
//!   - `FLAG_GOODBYE` triggers immediate removal of all session buffers and telemetry

use std::collections::HashMap;
use std::net::SocketAddr;

use jiter_math::controller::FecMode;
use jiter_math::fec::{FecFrame, InterleavedXorFecDecoder, InterleavedXorFecEncoder};
use jiter_math::scoring::TrafficProfile;

use crate::protocol::{pacer_q8_to_ratio, pacer_ratio_to_q8, TrafficTier};
use crate::scheduler::DownstreamScheduler;

pub fn fec_mode_from_u8(raw: u8) -> FecMode {
    match raw {
        1 => FecMode::XorK4Interleaved,
        2 => FecMode::XorK2Interleaved,
        3 => FecMode::Duplicate,
        _ => FecMode::Off,
    }
}

pub fn fec_mode_to_u8(mode: FecMode) -> u8 {
    match mode {
        FecMode::Off => 0,
        FecMode::XorK4Interleaved => 1,
        FecMode::XorK2Interleaved => 2,
        FecMode::Duplicate => 3,
    }
}

pub struct RelaySession {
    pub session_id: u32,
    pub peer_addr: SocketAddr,
    pub last_seen_ms: i64,
    pub profile: TrafficProfile,
    pub fec_mode: FecMode,
    pub link_hint_mbps: f64,
    pub tx_sequence: u32,
    pub highest_rx_seq: Option<u32>,
    pub rx_received_count: u64,
    pub rx_expected_count: u64,
    pub uplink_fec_decoder: InterleavedXorFecDecoder,
    pub downlink_fec_encoder: Option<InterleavedXorFecEncoder>,
    pub downstream: DownstreamScheduler,
}

impl RelaySession {
    pub fn new(session_id: u32, peer_addr: SocketAddr, now_ms: i64, max_link_mbps: f64) -> Self {
        let mut downstream = DownstreamScheduler::new(128, 128, 64);
        downstream.configure_pacer(1.0, max_link_mbps);
        Self {
            session_id,
            peer_addr,
            last_seen_ms: now_ms,
            profile: TrafficProfile::SafeBalanced,
            fec_mode: FecMode::Off,
            link_hint_mbps: max_link_mbps,
            tx_sequence: 1,
            highest_rx_seq: None,
            rx_received_count: 0,
            rx_expected_count: 0,
            uplink_fec_decoder: InterleavedXorFecDecoder::new(128),
            downlink_fec_encoder: None,
            downstream,
        }
    }

    pub fn next_tx_seq(&mut self) -> u32 {
        let seq = self.tx_sequence;
        self.tx_sequence = self.tx_sequence.wrapping_add(1);
        seq
    }

    pub fn touch(&mut self, peer_addr: SocketAddr, now_ms: i64) {
        self.peer_addr = peer_addr;
        self.last_seen_ms = now_ms;
    }

    /// Observe incoming packet sequence for lightweight uplink loss estimation.
    pub fn observe_rx_sequence(&mut self, seq: u32) {
        self.rx_received_count = self.rx_received_count.saturating_add(1);
        match self.highest_rx_seq {
            None => {
                self.highest_rx_seq = Some(seq);
                self.rx_expected_count = 1;
            }
            Some(high) => {
                let delta = seq.wrapping_sub(high);
                // Ignore huge wraparound jumps or duplicates; only advance forward gaps up to 4096
                if delta > 0 && delta <= 4096 {
                    self.highest_rx_seq = Some(seq);
                    self.rx_expected_count = self.rx_expected_count.saturating_add(delta as u64);
                }
            }
        }
    }

    /// Estimated uplink packet loss in basis points (100 = 1.00%).
    pub fn rx_loss_bps(&self) -> u32 {
        if self.rx_expected_count == 0 || self.rx_received_count >= self.rx_expected_count {
            return 0;
        }
        let lost = self.rx_expected_count - self.rx_received_count;
        let bps = ((lost as f64) / (self.rx_expected_count as f64) * 10_000.0).round();
        bps.clamp(0.0, 10_000.0) as u32
    }

    pub fn update_policy(
        &mut self,
        profile: TrafficProfile,
        fec_mode: FecMode,
        pacer_q8: u8,
        link_mbps_opt: Option<f64>,
    ) {
        self.profile = profile;
        if let Some(mbps) = link_mbps_opt {
            if mbps.is_finite() && mbps > 0.2 {
                self.link_hint_mbps = mbps;
            }
        }
        let ratio = pacer_q8_to_ratio(pacer_q8).clamp(0.15, 1.0);
        self.downstream.configure_pacer(ratio, self.link_hint_mbps);

        if fec_mode != self.fec_mode {
            self.fec_mode = fec_mode;
            self.downlink_fec_encoder = match fec_mode {
                FecMode::Off => None,
                FecMode::XorK4Interleaved => Some(InterleavedXorFecEncoder::new(4, 2)),
                FecMode::XorK2Interleaved => Some(InterleavedXorFecEncoder::new(2, 1)),
                FecMode::Duplicate => Some(InterleavedXorFecEncoder::new(1, 1)),
            };
        }
    }

    pub fn pacer_q8(&self) -> u8 {
        pacer_ratio_to_q8(self.downstream.bg_pacer_ratio())
    }

    pub fn decode_uplink_fec(&mut self, wire_fec_bytes: &[u8]) -> Vec<Vec<u8>> {
        let Some(frame) = FecFrame::from_wire_bytes(wire_fec_bytes) else {
            return Vec::new();
        };
        self.uplink_fec_decoder
            .receive(&frame)
            .into_iter()
            .map(|p| p.payload)
            .collect()
    }

    pub fn encode_downlink_fec(&mut self, tier: TrafficTier, payload: &[u8]) -> Option<Vec<FecFrame>> {
        if tier != TrafficTier::Game {
            return None;
        }
        let enc = self.downlink_fec_encoder.as_mut()?;
        Some(enc.encode_packet(payload))
    }

    pub fn fec_recovered_total(&self) -> u32 {
        self.uplink_fec_decoder
            .recovered_count()
            .min(u32::MAX as u64) as u32
    }
}

pub struct SessionTable {
    sessions: HashMap<u32, RelaySession>,
    max_sessions: usize,
    session_timeout_ms: i64,
    default_link_mbps: f64,
}

impl SessionTable {
    pub fn new(max_sessions: usize, session_timeout_ms: i64, default_link_mbps: f64) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions: max_sessions.max(1),
            session_timeout_ms: session_timeout_ms.max(1_000),
            default_link_mbps,
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn get_or_create(
        &mut self,
        session_id: u32,
        peer_addr: SocketAddr,
        now_ms: i64,
    ) -> Option<&mut RelaySession> {
        if !self.sessions.contains_key(&session_id) {
            if self.sessions.len() >= self.max_sessions {
                self.evict_expired(now_ms);
            }
            if self.sessions.len() >= self.max_sessions {
                return None;
            }
            self.sessions.insert(
                session_id,
                RelaySession::new(session_id, peer_addr, now_ms, self.default_link_mbps),
            );
        }
        let sess = self.sessions.get_mut(&session_id)?;
        sess.touch(peer_addr, now_ms);
        Some(sess)
    }

    pub fn get_mut(&mut self, session_id: u32) -> Option<&mut RelaySession> {
        self.sessions.get_mut(&session_id)
    }

    pub fn remove(&mut self, session_id: u32) -> bool {
        self.sessions.remove(&session_id).is_some()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut RelaySession> {
        self.sessions.values_mut()
    }

    pub fn evict_expired(&mut self, now_ms: i64) -> usize {
        let timeout = self.session_timeout_ms;
        let before = self.sessions.len();
        self.sessions
            .retain(|_, sess| now_ms.saturating_sub(sess.last_seen_ms) <= timeout);
        before - self.sessions.len()
    }
}
