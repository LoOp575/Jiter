//! Relay-side Downstream 3-Tier Strict Priority Queue + Anti-Bufferbloat Background Pacer.
//!
//! Works in lockstep with the Android client's `TrafficScheduler` to eliminate both
//! uplink and downlink bufferbloat so games stay near the physical latency floor
//! while video streaming runs smoothly concurrently.

use std::collections::VecDeque;

use crate::protocol::TrafficTier;

#[derive(Debug, Clone)]
pub struct QueuedPacket {
    pub tier: TrafficTier,
    pub payload: Vec<u8>,
    pub enqueued_ms: i64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DownstreamStats {
    pub enqueued_game: u64,
    pub enqueued_streaming: u64,
    pub enqueued_background: u64,
    pub dropped_queue_full: u64,
    pub dequeued_game: u64,
    pub dequeued_streaming: u64,
    pub dequeued_background: u64,
    pub bg_pacer_deferrals: u64,
}

pub struct DownstreamScheduler {
    max_game: usize,
    max_streaming: usize,
    max_background: usize,
    q_game: VecDeque<QueuedPacket>,
    q_streaming: VecDeque<QueuedPacket>,
    q_background: VecDeque<QueuedPacket>,
    bg_pacer_ratio: f64,
    link_bytes_per_ms: f64,
    bg_tokens_bytes: f64,
    last_token_ms: Option<i64>,
    stats: DownstreamStats,
}

impl DownstreamScheduler {
    pub fn new(max_game: usize, max_streaming: usize, max_background: usize) -> Self {
        Self {
            max_game: max_game.max(1),
            max_streaming: max_streaming.max(1),
            max_background: max_background.max(1),
            q_game: VecDeque::with_capacity(max_game.max(1)),
            q_streaming: VecDeque::with_capacity(max_streaming.max(1)),
            q_background: VecDeque::with_capacity(max_background.max(1)),
            bg_pacer_ratio: 1.0,
            link_bytes_per_ms: 3_125.0, // default 25 Mbps
            bg_tokens_bytes: 4_096.0,
            last_token_ms: None,
            stats: DownstreamStats::default(),
        }
    }

    pub fn configure_pacer(&mut self, bg_pacer_ratio: f64, estimated_link_mbps: f64) {
        if bg_pacer_ratio.is_finite() {
            self.bg_pacer_ratio = bg_pacer_ratio.clamp(0.15, 1.0);
        }
        if estimated_link_mbps.is_finite() && estimated_link_mbps > 0.1 {
            // Reserve ~8% headroom so ISP/BTS downlink buffer remains nearly empty
            let effective_mbps = (estimated_link_mbps * 0.92).max(0.5);
            self.link_bytes_per_ms = (effective_mbps * 1_000_000.0) / 8_000.0;
        }
    }

    pub fn bg_pacer_ratio(&self) -> f64 {
        self.bg_pacer_ratio
    }

    pub fn enqueue(&mut self, tier: TrafficTier, payload: Vec<u8>, now_ms: i64) -> bool {
        let pkt = QueuedPacket {
            tier,
            payload,
            enqueued_ms: now_ms,
        };
        match tier {
            TrafficTier::Game => {
                if self.q_game.len() >= self.max_game {
                    self.stats.dropped_queue_full += 1;
                    return false;
                }
                self.q_game.push_back(pkt);
                self.stats.enqueued_game += 1;
                true
            }
            TrafficTier::Streaming => {
                if self.q_streaming.len() >= self.max_streaming {
                    self.stats.dropped_queue_full += 1;
                    return false;
                }
                self.q_streaming.push_back(pkt);
                self.stats.enqueued_streaming += 1;
                true
            }
            TrafficTier::Background => {
                if self.q_background.len() >= self.max_background {
                    self.stats.dropped_queue_full += 1;
                    return false;
                }
                self.q_background.push_back(pkt);
                self.stats.enqueued_background += 1;
                true
            }
        }
    }

    fn refill_bg_tokens(&mut self, now_ms: i64) {
        if let Some(prev) = self.last_token_ms {
            if now_ms > prev {
                let dt_ms = (now_ms - prev) as f64;
                let bg_rate_bytes_per_ms = self.link_bytes_per_ms * self.bg_pacer_ratio;
                let max_burst = (bg_rate_bytes_per_ms * 12.0).max(2_048.0);
                self.bg_tokens_bytes =
                    (self.bg_tokens_bytes + dt_ms * bg_rate_bytes_per_ms).min(max_burst);
            }
        }
        self.last_token_ms = Some(now_ms);
    }

    pub fn dequeue(&mut self, now_ms: i64) -> Option<QueuedPacket> {
        self.refill_bg_tokens(now_ms);

        // 1. Strict VIP: GAME packets always drain first
        if let Some(pkt) = self.q_game.pop_front() {
            self.stats.dequeued_game += 1;
            return Some(pkt);
        }

        // 2. Bounded STREAMING queue
        if let Some(pkt) = self.q_streaming.pop_front() {
            self.stats.dequeued_streaming += 1;
            return Some(pkt);
        }

        // 3. Anti-Bufferbloat token-bucket paced BACKGROUND queue
        if let Some(front) = self.q_background.front() {
            let cost = front.payload.len().max(64) as f64;
            if self.bg_tokens_bytes >= cost {
                self.bg_tokens_bytes -= cost;
                let pkt = self.q_background.pop_front();
                self.stats.dequeued_background += 1;
                return pkt;
            } else {
                self.stats.bg_pacer_deferrals += 1;
            }
        }

        None
    }

    pub fn estimated_queue_delay_us(&self) -> u32 {
        let queued_bytes: usize = self
            .q_game
            .iter()
            .chain(self.q_streaming.iter())
            .chain(self.q_background.iter())
            .map(|p| p.payload.len())
            .sum();
        if queued_bytes == 0 || self.link_bytes_per_ms <= 0.0 {
            return 0;
        }
        let delay_ms = (queued_bytes as f64) / self.link_bytes_per_ms;
        (delay_ms * 1_000.0).round().clamp(0.0, u32::MAX as f64) as u32
    }

    pub fn stats(&self) -> DownstreamStats {
        self.stats
    }
}
