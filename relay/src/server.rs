//! JITER Stage 3 Edge Relay Server (UDP data-plane + closed-loop two-sided telemetry).

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use jiter_math::scoring::TrafficProfile;

use crate::protocol::{
    HelloAckPayload, HelloReqPayload, MsgType, PolicySyncPayload, ProbeReqPayload,
    ProbeRespPayload, TrafficTier, WireHeader, FLAG_FEC_PARITY, FLAG_GOODBYE, MAX_PAYLOAD_BYTES,
    RELAY_CAP_FORWARD_UDP, RELAY_CAP_PACER_3TIER, RELAY_CAP_XOR_FEC, WIRE_HEADER_BYTES,
    WIRE_VERSION,
};
use crate::session::{fec_mode_from_u8, fec_mode_to_u8, SessionTable};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMode {
    /// Loopback / diagnostic mode: echoes decoded & FEC-recovered frames through the
    /// downstream 3-tier pacer so clients can verify live RTT, loss, FEC, and pacer end-to-end.
    Echo,
    /// Forwards decoded uplink payloads to an upstream UDP endpoint and applies
    /// downstream strict-priority pacing + XOR FEC on return packets.
    Forward(SocketAddr),
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind_addr: SocketAddr,
    pub region_tag: String,
    pub mode: RelayMode,
    pub max_sessions: usize,
    pub session_timeout_secs: u64,
    pub default_link_mbps: f64,
    pub mtu: u16,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:51820".parse().expect("valid default bind"),
            region_tag: "JKT-1".to_string(),
            mode: RelayMode::Echo,
            max_sessions: 4096,
            session_timeout_secs: 60,
            default_link_mbps: 50.0,
            mtu: 1280,
        }
    }
}

#[derive(Debug, Default)]
pub struct RelayCounters {
    pub active_sessions: AtomicUsize,
    pub rx_frames: AtomicU64,
    pub tx_frames: AtomicU64,
    pub probes_served: AtomicU64,
    pub handshakes_served: AtomicU64,
    pub goodbyes_served: AtomicU64,
    pub fec_recovered_packets: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RelayStatsSnapshot {
    pub active_sessions: usize,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub probes_served: u64,
    pub handshakes_served: u64,
    pub goodbyes_served: u64,
    pub fec_recovered_packets: u64,
}

impl RelayCounters {
    pub fn snapshot(&self) -> RelayStatsSnapshot {
        RelayStatsSnapshot {
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            rx_frames: self.rx_frames.load(Ordering::Relaxed),
            tx_frames: self.tx_frames.load(Ordering::Relaxed),
            probes_served: self.probes_served.load(Ordering::Relaxed),
            handshakes_served: self.handshakes_served.load(Ordering::Relaxed),
            goodbyes_served: self.goodbyes_served.load(Ordering::Relaxed),
            fec_recovered_packets: self.fec_recovered_packets.load(Ordering::Relaxed),
        }
    }
}

pub struct RelayServer {
    config: RelayConfig,
    client_socket: UdpSocket,
    upstream_socket: Option<UdpSocket>,
    sessions: SessionTable,
    last_forward_session_id: Option<u32>,
    counters: Arc<RelayCounters>,
    stop_flag: Arc<AtomicBool>,
    started_at: Instant,
    last_evict_ms: i64,
}

impl RelayServer {
    pub fn bind(config: RelayConfig) -> io::Result<Self> {
        let client_socket = UdpSocket::bind(config.bind_addr)?;
        client_socket.set_read_timeout(Some(Duration::from_millis(2)))?;

        let upstream_socket = match config.mode {
            RelayMode::Echo => None,
            RelayMode::Forward(target) => {
                let bind_any: SocketAddr = if target.is_ipv4() {
                    "0.0.0.0:0".parse().expect("valid ipv4 bind")
                } else {
                    "[::]:0".parse().expect("valid ipv6 bind")
                };
                let sock = UdpSocket::bind(bind_any)?;
                sock.set_nonblocking(true)?;
                Some(sock)
            }
        };

        let sessions = SessionTable::new(
            config.max_sessions,
            (config.session_timeout_secs as i64).saturating_mul(1_000),
            config.default_link_mbps,
        );

        Ok(Self {
            config,
            client_socket,
            upstream_socket,
            sessions,
            last_forward_session_id: None,
            counters: Arc::new(RelayCounters::default()),
            stop_flag: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
            last_evict_ms: 0,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.client_socket.local_addr()
    }

    pub fn counters(&self) -> Arc<RelayCounters> {
        Arc::clone(&self.counters)
    }

    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    fn now_ms(&self) -> i64 {
        self.started_at.elapsed().as_millis() as i64
    }

    fn relay_caps(&self) -> u16 {
        let mut caps = RELAY_CAP_XOR_FEC | RELAY_CAP_PACER_3TIER;
        if matches!(self.config.mode, RelayMode::Forward(_)) {
            caps |= RELAY_CAP_FORWARD_UDP;
        }
        caps
    }

    pub fn run(&mut self) -> io::Result<()> {
        let mut rx_buf = [0u8; 2048];
        let mut up_buf = [0u8; 2048];

        while !self.stop_flag.load(Ordering::Relaxed) {
            let now_ms = self.now_ms();

            match self.client_socket.recv_from(&mut rx_buf) {
                Ok((len, peer_addr)) => {
                    self.handle_client_datagram(&rx_buf[..len], peer_addr, now_ms);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }

            // Drain any return packets from upstream in Forward mode
            if let Some(ref up_sock) = self.upstream_socket {
                let mut drained = 0usize;
                while drained < 64 {
                    match up_sock.recv_from(&mut up_buf) {
                        Ok((len, _src)) => {
                            drained += 1;
                            if len > 0 && len <= MAX_PAYLOAD_BYTES {
                                if let Some(sid) = self.last_forward_session_id {
                                    if let Some(sess) = self.sessions.get_mut(sid) {
                                        let tier = if len <= 320 {
                                            TrafficTier::Game
                                        } else {
                                            TrafficTier::Streaming
                                        };
                                        sess.downstream.enqueue(tier, up_buf[..len].to_vec(), now_ms);
                                    }
                                }
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                ErrorKind::WouldBlock
                                    | ErrorKind::TimedOut
                                    | ErrorKind::Interrupted
                            ) =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }

            self.drain_all_downstream(now_ms);

            if now_ms.saturating_sub(self.last_evict_ms) >= 5_000 {
                self.sessions.evict_expired(now_ms);
                self.counters
                    .active_sessions
                    .store(self.sessions.len(), Ordering::Relaxed);
                self.last_evict_ms = now_ms;
            }
        }
        Ok(())
    }

    fn handle_client_datagram(&mut self, data: &[u8], peer_addr: SocketAddr, now_ms: i64) {
        let Some(hdr) = WireHeader::unpack(data) else {
            return;
        };
        let payload_end = WIRE_HEADER_BYTES + (hdr.payload_len as usize);
        if data.len() < payload_end {
            return;
        }
        let payload = &data[WIRE_HEADER_BYTES..payload_end];
        self.counters.rx_frames.fetch_add(1, Ordering::Relaxed);

        // Instant zero-retention session teardown on GOODBYE
        if hdr.msg_type == MsgType::Control && (hdr.flags & FLAG_GOODBYE) != 0 {
            if self.sessions.remove(hdr.session_id) {
                self.counters.goodbyes_served.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .active_sessions
                    .store(self.sessions.len(), Ordering::Relaxed);
            }
            return;
        }

        let relay_caps = self.relay_caps();
        let accepted_mtu = self.config.mtu;
        let region_tag = self.config.region_tag.clone();
        let mode = self.config.mode.clone();

        let Some(sess) = self
            .sessions
            .get_or_create(hdr.session_id, peer_addr, now_ms)
        else {
            return;
        };
        sess.observe_rx_sequence(hdr.sequence);

        // Apply piggybacked pacer/FEC hints immediately on data frames too
        if matches!(hdr.msg_type, MsgType::DataPlain | MsgType::DataFec) {
            let hinted_fec = fec_mode_from_u8(hdr.fec_mode);
            sess.update_policy(sess.profile, hinted_fec, hdr.pacer_q8, None);
        }

        match hdr.msg_type {
            MsgType::HelloReq => {
                if let Some(req) = HelloReqPayload::unpack(payload) {
                    let profile = TrafficProfile::from_u32(req.profile_id as u32);
                    let link_mbps = if req.link_hint_mbps_x10 > 0 {
                        Some((req.link_hint_mbps_x10 as f64) / 10.0)
                    } else {
                        None
                    };
                    let fec = fec_mode_from_u8(hdr.fec_mode);
                    sess.update_policy(profile, fec, hdr.pacer_q8, link_mbps);
                }

                let ack = HelloAckPayload::new(accepted_mtu, relay_caps, &region_tag).pack();
                let resp_hdr = WireHeader {
                    version: WIRE_VERSION,
                    msg_type: MsgType::HelloAck,
                    traffic_tier: TrafficTier::Game,
                    flags: 0,
                    session_id: hdr.session_id,
                    sequence: sess.next_tx_seq(),
                    payload_len: ack.len() as u16,
                    pacer_q8: sess.pacer_q8(),
                    fec_mode: fec_mode_to_u8(sess.fec_mode),
                };
                if let Some(frame) = resp_hdr.frame_bytes(&ack) {
                    if self.client_socket.send_to(&frame, peer_addr).is_ok() {
                        self.counters.tx_frames.fetch_add(1, Ordering::Relaxed);
                        self.counters
                            .handshakes_served
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            MsgType::ProbeReq => {
                let Some(req) = ProbeReqPayload::unpack(payload) else {
                    return;
                };
                let profile = TrafficProfile::from_u32(req.profile_id as u32);
                sess.update_policy(profile, fec_mode_from_u8(hdr.fec_mode), hdr.pacer_q8, None);

                let resp_payload = ProbeRespPayload {
                    echo_tx_us: req.client_tx_us,
                    relay_rx_loss_bps: sess.rx_loss_bps(),
                    relay_queue_us: sess.downstream.estimated_queue_delay_us(),
                    relay_fec_recovered: sess.fec_recovered_total(),
                    relay_pacer_q8: sess.pacer_q8() as u16,
                    relay_fec_mode: fec_mode_to_u8(sess.fec_mode) as u16,
                }
                .pack();

                let resp_hdr = WireHeader {
                    version: WIRE_VERSION,
                    msg_type: MsgType::ProbeResp,
                    traffic_tier: TrafficTier::Game,
                    flags: 0,
                    session_id: hdr.session_id,
                    sequence: sess.next_tx_seq(),
                    payload_len: resp_payload.len() as u16,
                    pacer_q8: sess.pacer_q8(),
                    fec_mode: fec_mode_to_u8(sess.fec_mode),
                };
                if let Some(frame) = resp_hdr.frame_bytes(&resp_payload) {
                    if self.client_socket.send_to(&frame, peer_addr).is_ok() {
                        self.counters.tx_frames.fetch_add(1, Ordering::Relaxed);
                        self.counters.probes_served.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            MsgType::PolicySync => {
                if let Some(sync) = PolicySyncPayload::unpack(payload) {
                    let profile = TrafficProfile::from_u32(sync.profile_id as u32);
                    let fec = fec_mode_from_u8(sync.fec_mode);
                    let link_mbps = if sync.link_mbps_x10 > 0 {
                        Some((sync.link_mbps_x10 as f64) / 10.0)
                    } else {
                        None
                    };
                    sess.update_policy(profile, fec, sync.pacer_q8, link_mbps);
                }
            }
            MsgType::DataPlain => {
                let packets = vec![payload.to_vec()];
                self.dispatch_decoded_uplink(hdr.session_id, hdr.traffic_tier, packets, &mode, now_ms);
            }
            MsgType::DataFec => {
                let before = sess.uplink_fec_decoder.recovered_count();
                let packets = sess.decode_uplink_fec(payload);
                let after = sess.uplink_fec_decoder.recovered_count();
                if after > before {
                    self.counters
                        .fec_recovered_packets
                        .fetch_add(after - before, Ordering::Relaxed);
                }
                if !packets.is_empty() {
                    self.dispatch_decoded_uplink(
                        hdr.session_id,
                        hdr.traffic_tier,
                        packets,
                        &mode,
                        now_ms,
                    );
                }
            }
            MsgType::Control | MsgType::HelloAck | MsgType::ProbeResp => {}
        }

        self.counters
            .active_sessions
            .store(self.sessions.len(), Ordering::Relaxed);
    }

    fn dispatch_decoded_uplink(
        &mut self,
        session_id: u32,
        tier: TrafficTier,
        packets: Vec<Vec<u8>>,
        mode: &RelayMode,
        now_ms: i64,
    ) {
        match mode {
            RelayMode::Echo => {
                if let Some(sess) = self.sessions.get_mut(session_id) {
                    for pkt in packets {
                        sess.downstream.enqueue(tier, pkt, now_ms);
                    }
                }
            }
            RelayMode::Forward(upstream_addr) => {
                self.last_forward_session_id = Some(session_id);
                if let Some(ref up_sock) = self.upstream_socket {
                    for pkt in packets {
                        let _ = up_sock.send_to(&pkt, upstream_addr);
                    }
                }
            }
        }
    }

    fn drain_all_downstream(&mut self, now_ms: i64) {
        let mut to_send: Vec<(SocketAddr, Vec<u8>)> = Vec::new();

        for sess in self.sessions.iter_mut() {
            let mut budget = 32usize;
            while budget > 0 {
                let Some(pkt) = sess.downstream.dequeue(now_ms) else {
                    break;
                };
                budget -= 1;

                if let Some(fec_frames) = sess.encode_downlink_fec(pkt.tier, &pkt.payload) {
                    for fr in fec_frames {
                        let wire_fec = fr.to_wire_bytes();
                        if wire_fec.len() > MAX_PAYLOAD_BYTES {
                            continue;
                        }
                        let hdr = WireHeader {
                            version: WIRE_VERSION,
                            msg_type: MsgType::DataFec,
                            traffic_tier: pkt.tier,
                            flags: if fr.is_parity { FLAG_FEC_PARITY } else { 0 },
                            session_id: sess.session_id,
                            sequence: sess.next_tx_seq(),
                            payload_len: wire_fec.len() as u16,
                            pacer_q8: sess.pacer_q8(),
                            fec_mode: fec_mode_to_u8(sess.fec_mode),
                        };
                        if let Some(bytes) = hdr.frame_bytes(&wire_fec) {
                            to_send.push((sess.peer_addr, bytes));
                        }
                    }
                } else if pkt.payload.len() <= MAX_PAYLOAD_BYTES {
                    let hdr = WireHeader {
                        version: WIRE_VERSION,
                        msg_type: MsgType::DataPlain,
                        traffic_tier: pkt.tier,
                        flags: 0,
                        session_id: sess.session_id,
                        sequence: sess.next_tx_seq(),
                        payload_len: pkt.payload.len() as u16,
                        pacer_q8: sess.pacer_q8(),
                        fec_mode: fec_mode_to_u8(sess.fec_mode),
                    };
                    if let Some(bytes) = hdr.frame_bytes(&pkt.payload) {
                        to_send.push((sess.peer_addr, bytes));
                    }
                }
            }
        }

        for (addr, frame) in to_send {
            if self.client_socket.send_to(&frame, addr).is_ok() {
                self.counters.tx_frames.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
