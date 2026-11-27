//! JITER Stage 4 Edge Relay Server:
//!   - ECDHE P-256 + PSK mutual auth + HKDF-SHA256 + ChaCha20-Poly1305 AEAD (`FLAG_ENCRYPTED`)
//!   - 64-packet sliding Anti-Replay Window
//!   - Real Linux `/dev/net/tun` NAT Gateway (`--mode tun`) + `--mode echo` + `--mode forward`
//!   - Downstream 3-Tier Strict Priority Queue + Anti-Bufferbloat Pacer + GF(2) XOR FEC

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use jiter_math::scoring::TrafficProfile;

use crate::crypto::{
    compute_hello_ack_tag, compute_hello_req_tag, constant_time_eq_16, derive_psk_key,
    derive_session_keys, random_nonce_16, EphemeralP256KeyPair, SessionCipher, AEAD_TAG_BYTES,
};
use crate::protocol::{
    EncryptedHelloAckPayload, EncryptedHelloReqPayload, HelloAckPayload, HelloReqPayload, MsgType,
    PolicySyncPayload, ProbeReqPayload, ProbeRespPayload, TrafficTier, WireHeader, FLAG_ENCRYPTED,
    FLAG_FEC_PARITY, FLAG_GOODBYE, MAX_PAYLOAD_BYTES, RELAY_CAP_AEAD_CHACHA20,
    RELAY_CAP_FORWARD_UDP, RELAY_CAP_PACER_3TIER, RELAY_CAP_TUN_NAT, RELAY_CAP_XOR_FEC,
    WIRE_HEADER_BYTES, WIRE_VERSION,
};
use crate::session::{fec_mode_from_u8, fec_mode_to_u8, SessionTable};
use crate::tun::{parse_ipv4_summary, LinuxTunDevice, TunIpPool};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMode {
    /// Loopback / diagnostic mode: echoes decoded & FEC-recovered frames through the
    /// downstream 3-tier pacer so clients can verify live RTT, loss, FEC, and AEAD end-to-end.
    Echo,
    /// Forwards decoded uplink payloads to a single upstream UDP target.
    Forward(SocketAddr),
    /// Full-internet VPN Gateway via Linux `/dev/net/tun` (e.g. `jiter0` with NAT MASQUERADE).
    Tun { tun_name: String },
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind_addr: SocketAddr,
    pub region_tag: String,
    pub mode: RelayMode,
    pub psk: Option<String>,
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
            psk: None,
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
    pub auth_or_replay_drops: AtomicU64,
    pub tun_rx_packets: AtomicU64,
    pub tun_tx_packets: AtomicU64,
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
    pub auth_or_replay_drops: u64,
    pub tun_rx_packets: u64,
    pub tun_tx_packets: u64,
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
            auth_or_replay_drops: self.auth_or_replay_drops.load(Ordering::Relaxed),
            tun_rx_packets: self.tun_rx_packets.load(Ordering::Relaxed),
            tun_tx_packets: self.tun_tx_packets.load(Ordering::Relaxed),
        }
    }
}

fn build_wire_frame(
    cipher: Option<&SessionCipher>,
    mut hdr: WireHeader,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    if let Some(c) = cipher {
        let ct_len = plaintext.len().checked_add(AEAD_TAG_BYTES)?;
        if ct_len > MAX_PAYLOAD_BYTES {
            return None;
        }
        hdr.flags |= FLAG_ENCRYPTED;
        hdr.payload_len = ct_len as u16;
        let aad = hdr.pack()?;
        let ciphertext = c.encrypt(hdr.session_id, hdr.sequence, &aad, plaintext)?;
        let mut out = Vec::with_capacity(WIRE_HEADER_BYTES + ciphertext.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext);
        Some(out)
    } else {
        if plaintext.len() > MAX_PAYLOAD_BYTES {
            return None;
        }
        hdr.flags &= !FLAG_ENCRYPTED;
        hdr.payload_len = plaintext.len() as u16;
        hdr.frame_bytes(plaintext)
    }
}

pub struct RelayServer {
    config: RelayConfig,
    psk_key: Option<[u8; 32]>,
    client_socket: UdpSocket,
    upstream_socket: Option<UdpSocket>,
    tun_device: Option<LinuxTunDevice>,
    ip_pool: TunIpPool,
    sessions: SessionTable,
    last_forward_session_id: Option<u32>,
    counters: Arc<RelayCounters>,
    stop_flag: Arc<AtomicBool>,
    started_at: Instant,
    last_evict_ms: i64,
}

impl RelayServer {
    pub fn bind(config: RelayConfig) -> io::Result<Self> {
        let psk_key = config
            .psk
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(derive_psk_key);

        if matches!(config.mode, RelayMode::Tun { .. }) && psk_key.is_none() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "--mode tun requires --psk (or JITER_PSK) for mandatory ChaCha20-Poly1305 AEAD encryption",
            ));
        }

        let client_socket = UdpSocket::bind(config.bind_addr)?;
        client_socket.set_read_timeout(Some(Duration::from_millis(2)))?;

        let mut upstream_socket = None;
        let mut tun_device = None;

        match &config.mode {
            RelayMode::Echo => {}
            RelayMode::Forward(target) => {
                let bind_any: SocketAddr = if target.is_ipv4() {
                    "0.0.0.0:0".parse().expect("valid ipv4 bind")
                } else {
                    "[::]:0".parse().expect("valid ipv6 bind")
                };
                let sock = UdpSocket::bind(bind_any)?;
                sock.set_nonblocking(true)?;
                upstream_socket = Some(sock);
            }
            RelayMode::Tun { tun_name } => {
                let dev = LinuxTunDevice::open(tun_name)?;
                tun_device = Some(dev);
            }
        }

        let sessions = SessionTable::new(
            config.max_sessions,
            (config.session_timeout_secs as i64).saturating_mul(1_000),
            config.default_link_mbps,
        );

        Ok(Self {
            config,
            psk_key,
            client_socket,
            upstream_socket,
            tun_device,
            ip_pool: TunIpPool::new([10, 77, 0]),
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

    pub fn tun_name(&self) -> Option<&str> {
        self.tun_device.as_ref().map(|d| d.name())
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
        if self.psk_key.is_some() {
            caps |= RELAY_CAP_AEAD_CHACHA20;
        }
        match self.config.mode {
            RelayMode::Forward(_) => caps |= RELAY_CAP_FORWARD_UDP,
            RelayMode::Tun { .. } => caps |= RELAY_CAP_TUN_NAT,
            RelayMode::Echo => {}
        }
        caps
    }

    pub fn run(&mut self) -> io::Result<()> {
        let mut rx_buf = [0u8; 2048];
        let mut up_buf = [0u8; 2048];
        let mut tun_buf = [0u8; 2048];

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

            // Drain return packets from upstream UDP socket (Forward mode)
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
                                        sess.downstream.enqueue(
                                            tier,
                                            up_buf[..len].to_vec(),
                                            now_ms,
                                        );
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

            // Drain return IPv4 internet packets from Linux /dev/net/tun (Tun NAT mode)
            if let Some(ref mut tun_dev) = self.tun_device {
                let mut drained = 0usize;
                while drained < 64 {
                    match tun_dev.read_packet(&mut tun_buf) {
                        Ok(len) if len >= 20 && len <= MAX_PAYLOAD_BYTES => {
                            drained += 1;
                            self.counters.tun_rx_packets.fetch_add(1, Ordering::Relaxed);
                            if let Some(summary) = parse_ipv4_summary(&tun_buf[..len]) {
                                if let Some(sid) = self.ip_pool.lookup_session_by_ip(summary.dst_ip)
                                {
                                    if let Some(sess) = self.sessions.get_mut(sid) {
                                        sess.downstream.enqueue(
                                            summary.traffic_tier,
                                            tun_buf[..len].to_vec(),
                                            now_ms,
                                        );
                                    }
                                }
                            }
                        }
                        Ok(_) => break,
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
                let expired = self.sessions.evict_expired(now_ms);
                for sid in expired {
                    self.ip_pool.release_session(sid);
                }
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
        let header_bytes = &data[..WIRE_HEADER_BYTES];
        let raw_payload = &data[WIRE_HEADER_BYTES..payload_end];
        self.counters.rx_frames.fetch_add(1, Ordering::Relaxed);

        let is_encrypted_frame = (hdr.flags & FLAG_ENCRYPTED) != 0;

        // Handle HELLO_REQ separately (establishes or authenticates session)
        if hdr.msg_type == MsgType::HelloReq {
            self.handle_hello_req(hdr, raw_payload, is_encrypted_frame, peer_addr, now_ms);
            return;
        }

        // Handle authenticated or plaintext GOODBYE
        if hdr.msg_type == MsgType::Control && (hdr.flags & FLAG_GOODBYE) != 0 {
            if self.psk_key.is_some() {
                if !is_encrypted_frame {
                    self.counters
                        .auth_or_replay_drops
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let auth_ok = match self.sessions.get_mut(hdr.session_id) {
                    Some(sess) => match sess.cipher.as_mut() {
                        Some(cipher) => cipher
                            .decrypt_and_check_replay(
                                hdr.session_id,
                                hdr.sequence,
                                header_bytes,
                                raw_payload,
                            )
                            .is_some(),
                        None => false,
                    },
                    None => false,
                };
                if !auth_ok {
                    self.counters
                        .auth_or_replay_drops
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
            if self.sessions.remove(hdr.session_id) {
                self.ip_pool.release_session(hdr.session_id);
                self.counters.goodbyes_served.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .active_sessions
                    .store(self.sessions.len(), Ordering::Relaxed);
            }
            return;
        }

        // Enforce mandatory AEAD encryption when PSK is configured
        let decrypted_buf: Option<Vec<u8>>;
        let payload: &[u8] = if self.psk_key.is_some() {
            if !is_encrypted_frame {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            let Some(sess) = self.sessions.get_mut(hdr.session_id) else {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            let Some(cipher) = sess.cipher.as_mut() else {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            let Some(plain) = cipher.decrypt_and_check_replay(
                hdr.session_id,
                hdr.sequence,
                header_bytes,
                raw_payload,
            ) else {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            sess.touch(peer_addr, now_ms);
            decrypted_buf = Some(plain);
            decrypted_buf.as_deref().unwrap()
        } else {
            if self
                .sessions
                .get_or_create(hdr.session_id, peer_addr, now_ms)
                .is_none()
            {
                return;
            }
            decrypted_buf = None;
            let _ = &decrypted_buf;
            raw_payload
        };

        let mode = self.config.mode.clone();

        let Some(sess) = self.sessions.get_mut(hdr.session_id) else {
            return;
        };
        sess.observe_rx_sequence(hdr.sequence);

        if matches!(hdr.msg_type, MsgType::DataPlain | MsgType::DataFec) {
            let hinted_fec = fec_mode_from_u8(hdr.fec_mode);
            sess.update_policy(sess.profile, hinted_fec, hdr.pacer_q8, None);
        }

        match hdr.msg_type {
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
                if let Some(frame) = build_wire_frame(sess.cipher.as_ref(), resp_hdr, &resp_payload)
                {
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
                let assigned_ip = sess.assigned_ipv4;
                let packets = vec![payload.to_vec()];
                self.dispatch_decoded_uplink(
                    hdr.session_id,
                    hdr.traffic_tier,
                    assigned_ip,
                    packets,
                    &mode,
                    now_ms,
                );
            }
            MsgType::DataFec => {
                let assigned_ip = sess.assigned_ipv4;
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
                        assigned_ip,
                        packets,
                        &mode,
                        now_ms,
                    );
                }
            }
            MsgType::HelloReq | MsgType::Control | MsgType::HelloAck | MsgType::ProbeResp => {}
        }

        self.counters
            .active_sessions
            .store(self.sessions.len(), Ordering::Relaxed);
    }

    fn handle_hello_req(
        &mut self,
        hdr: WireHeader,
        raw_payload: &[u8],
        is_encrypted_frame: bool,
        peer_addr: SocketAddr,
        now_ms: i64,
    ) {
        let relay_caps = self.relay_caps();
        let accepted_mtu = self.config.mtu;
        let region_tag = self.config.region_tag.clone();

        if let Some(psk_key) = self.psk_key {
            if !is_encrypted_frame {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            let Some(enc_req) = EncryptedHelloReqPayload::unpack(raw_payload) else {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            let expected_tag = compute_hello_req_tag(
                &psk_key,
                hdr.session_id,
                &raw_payload[..EncryptedHelloReqPayload::BODY_BEFORE_TAG],
            );
            if !constant_time_eq_16(&expected_tag, &enc_req.auth_tag) {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }

            let server_kp = EphemeralP256KeyPair::generate();
            let server_pub = server_kp.public_bytes();
            let Some(ecdh_shared) = server_kp.diffie_hellman(&enc_req.client_pub) else {
                self.counters
                    .auth_or_replay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };

            let server_nonce = random_nonce_16();
            let keys = derive_session_keys(
                &ecdh_shared,
                &psk_key,
                &enc_req.client_nonce,
                &server_nonce,
                hdr.session_id,
            );

            let Some(assigned_ipv4) = self.ip_pool.allocate(hdr.session_id) else {
                return;
            };
            let Some(sess) = self
                .sessions
                .get_or_create(hdr.session_id, peer_addr, now_ms)
            else {
                self.ip_pool.release_session(hdr.session_id);
                return;
            };

            let profile = TrafficProfile::from_u32(enc_req.base.profile_id as u32);
            let link_mbps = if enc_req.base.link_hint_mbps_x10 > 0 {
                Some((enc_req.base.link_hint_mbps_x10 as f64) / 10.0)
            } else {
                None
            };
            sess.update_policy(profile, fec_mode_from_u8(hdr.fec_mode), hdr.pacer_q8, link_mbps);
            sess.cipher = Some(SessionCipher::for_server(&keys));
            sess.assigned_ipv4 = Some(assigned_ipv4);

            let ack = EncryptedHelloAckPayload {
                base: HelloAckPayload::new(accepted_mtu, relay_caps, &region_tag),
                assigned_ipv4,
                server_pub,
                server_nonce,
                auth_tag: [0u8; 16],
            };
            let mut ack_bytes = ack.pack();
            let server_tag = compute_hello_ack_tag(
                &psk_key,
                hdr.session_id,
                &enc_req.client_nonce,
                &ack_bytes[..EncryptedHelloAckPayload::BODY_BEFORE_TAG],
            );
            ack_bytes[EncryptedHelloAckPayload::BODY_BEFORE_TAG..].copy_from_slice(&server_tag);

            let resp_hdr = WireHeader {
                version: WIRE_VERSION,
                msg_type: MsgType::HelloAck,
                traffic_tier: TrafficTier::Game,
                flags: FLAG_ENCRYPTED,
                session_id: hdr.session_id,
                sequence: sess.next_tx_seq(),
                payload_len: ack_bytes.len() as u16,
                pacer_q8: sess.pacer_q8(),
                fec_mode: fec_mode_to_u8(sess.fec_mode),
            };
            if let Some(frame) = resp_hdr.frame_bytes(&ack_bytes) {
                if self.client_socket.send_to(&frame, peer_addr).is_ok() {
                    self.counters.tx_frames.fetch_add(1, Ordering::Relaxed);
                    self.counters
                        .handshakes_served
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            // Legacy Stage 3 plaintext diagnostic handshake (when --psk is omitted)
            let Some(sess) = self
                .sessions
                .get_or_create(hdr.session_id, peer_addr, now_ms)
            else {
                return;
            };
            if let Some(req) = HelloReqPayload::unpack(raw_payload) {
                let profile = TrafficProfile::from_u32(req.profile_id as u32);
                let link_mbps = if req.link_hint_mbps_x10 > 0 {
                    Some((req.link_hint_mbps_x10 as f64) / 10.0)
                } else {
                    None
                };
                sess.update_policy(profile, fec_mode_from_u8(hdr.fec_mode), hdr.pacer_q8, link_mbps);
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

        self.counters
            .active_sessions
            .store(self.sessions.len(), Ordering::Relaxed);
    }

    fn dispatch_decoded_uplink(
        &mut self,
        session_id: u32,
        tier: TrafficTier,
        assigned_ipv4: Option<[u8; 4]>,
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
            RelayMode::Tun { .. } => {
                if let Some(ref mut tun_dev) = self.tun_device {
                    for pkt in packets {
                        let Some(summary) = parse_ipv4_summary(&pkt) else {
                            continue;
                        };
                        // Anti-spoofing: source IP must match this session's assigned IPv4
                        if let Some(expected_ip) = assigned_ipv4 {
                            if summary.src_ip != expected_ip {
                                continue;
                            }
                        }
                        if tun_dev.write_packet(&pkt).is_ok() {
                            self.counters.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
                        }
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
                        let hdr = WireHeader {
                            version: WIRE_VERSION,
                            msg_type: MsgType::DataFec,
                            traffic_tier: pkt.tier,
                            flags: if fr.is_parity { FLAG_FEC_PARITY } else { 0 },
                            session_id: sess.session_id,
                            sequence: sess.next_tx_seq(),
                            payload_len: 0,
                            pacer_q8: sess.pacer_q8(),
                            fec_mode: fec_mode_to_u8(sess.fec_mode),
                        };
                        if let Some(bytes) = build_wire_frame(sess.cipher.as_ref(), hdr, &wire_fec)
                        {
                            to_send.push((sess.peer_addr, bytes));
                        }
                    }
                } else {
                    let hdr = WireHeader {
                        version: WIRE_VERSION,
                        msg_type: MsgType::DataPlain,
                        traffic_tier: pkt.tier,
                        flags: 0,
                        session_id: sess.session_id,
                        sequence: sess.next_tx_seq(),
                        payload_len: 0,
                        pacer_q8: sess.pacer_q8(),
                        fec_mode: fec_mode_to_u8(sess.fec_mode),
                    };
                    if let Some(bytes) = build_wire_frame(sess.cipher.as_ref(), hdr, &pkt.payload) {
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
