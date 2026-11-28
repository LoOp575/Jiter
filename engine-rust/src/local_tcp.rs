//! Stage 6 Transparent User-Space TCP Stack (`smoltcp`) for JITER Local Traffic Shaper.
//!
//! Enables JITER to intercept and shape IPv4 TCP traffic (`0.0.0.0/0`) directly on Android
//! without requiring a remote VPS relay:
//!   - Full RFC-compliant TCP state machine (3-way handshake, SACK/retransmission,
//!     out-of-order reassembly, window management, graceful FIN & RST).
//!   - `any_ip = true` transparent destination routing so every outbound destination IP:port
//!     from Android apps is accepted cleanly without NAT collisions.
//!   - Per-flow RX/TX buffers allow Kotlin's `LocalTrafficShaper` to smoothly throttle
//!     Tier-2 Background TCP downloads via backpressure (`rwnd` flow control) without
//!     dropping packets or breaking HTTPS / Play Store / m-banking sessions.

use std::collections::{HashMap, VecDeque};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, State as TcpState};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

pub const MAX_LOCAL_TCP_FLOWS: usize = 256;
const TCP_RX_BUF_BYTES: usize = 32 * 1024;
const TCP_TX_BUF_BYTES: usize = 64 * 1024;
const FLOW_IDLE_TIMEOUT_MS: i64 = 120_000;
const CLOSED_RETENTION_MS: i64 = 15_000;
const MAX_TX_QUEUE_PKTS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
}

struct FlowEntry {
    id: u64,
    key: TcpFlowKey,
    handle: SocketHandle,
    #[allow(dead_code)]
    tier: u8,
    last_active_ms: i64,
    remote_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Ignored,
    ExistingFlow,
    NewFlow {
        flow_id: u64,
        dst_ipv4_be: u32,
        dst_port: u16,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LocalTcpStats {
    pub active_flows: u32,
    pub total_flows: u64,
    pub app_rx_bytes: u64,
    pub app_tx_bytes: u64,
}

struct VirtualTunDevice {
    mtu: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualTunDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu: mtu.clamp(576, 1500),
            rx_queue: VecDeque::with_capacity(64),
            tx_queue: VecDeque::with_capacity(128),
        }
    }
}

struct VirtualRxToken {
    packet: Vec<u8>,
}

struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        if self.tx_queue.len() < MAX_TX_QUEUE_PKTS {
            self.tx_queue.push_back(buf);
        }
        res
    }
}

impl Device for VirtualTunDevice {
    type RxToken<'a> = VirtualRxToken where Self: 'a;
    type TxToken<'a> = VirtualTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            VirtualRxToken { packet },
            VirtualTxToken {
                tx_queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

/// Transparent IPv4 TCP stack powered by `smoltcp` with `any_ip = true`.
pub struct LocalTcpStack {
    device: VirtualTunDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows_by_id: HashMap<u64, FlowEntry>,
    id_by_key: HashMap<TcpFlowKey, u64>,
    next_flow_id: u64,
    total_flows: u64,
    app_rx_bytes: u64,
    app_tx_bytes: u64,
    last_gc_ms: i64,
}

impl LocalTcpStack {
    pub fn new(mtu: u16, seed: u64) -> Self {
        let mut device = VirtualTunDevice::new(mtu as usize);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = if seed == 0 { 0x4A49_5445_5236_0001 } else { seed };

        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        let gw = Ipv4Address::new(10, 77, 0, 1);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(gw), 32));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(gw);
        iface.set_any_ip(true);

        Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows_by_id: HashMap::with_capacity(64),
            id_by_key: HashMap::with_capacity(64),
            next_flow_id: 1,
            total_flows: 0,
            app_rx_bytes: 0,
            app_tx_bytes: 0,
            last_gc_ms: 0,
        }
    }

    /// Feeds one raw IPv4 TCP packet captured from the Android TUN fd into `smoltcp`.
    /// Immediately polls so any new listening socket binds to the client 4-tuple right away,
    /// preventing collisions when multiple connections target the same `(dst_ip, dst_port)`.
    pub fn ingest_ipv4(&mut self, packet: &[u8], tier: u8, now_ms: i64) -> IngestOutcome {
        let Some((key, tcp_flags)) = parse_ipv4_tcp_header(packet) else {
            return IngestOutcome::Ignored;
        };

        // Ignore broadcast / multicast / unspecified destinations
        if key.dst_ip[0] >= 224 || key.dst_ip == [0, 0, 0, 0] || key.dst_ip == [255, 255, 255, 255] {
            return IngestOutcome::Ignored;
        }

        let is_pure_syn = (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0 && (tcp_flags & 0x04) == 0;

        if let Some(&existing_id) = self.id_by_key.get(&key) {
            let needs_replace = if is_pure_syn {
                self.flows_by_id.get(&existing_id).map_or(true, |e| {
                    let s = self.sockets.get::<tcp::Socket>(e.handle);
                    matches!(s.state(), TcpState::Closed | TcpState::TimeWait)
                })
            } else {
                false
            };

            if needs_replace {
                self.remove_flow_internal(existing_id);
            } else {
                if let Some(entry) = self.flows_by_id.get_mut(&existing_id) {
                    entry.last_active_ms = now_ms;
                }
                self.device.rx_queue.push_back(packet.to_vec());
                self.iface.poll(Instant::from_millis(now_ms), &mut self.device, &mut self.sockets);
                return IngestOutcome::ExistingFlow;
            }
        }

        if !is_pure_syn {
            // Packet for an unknown/expired flow (e.g. stray ACK/FIN): let smoltcp reply RST if appropriate.
            self.device.rx_queue.push_back(packet.to_vec());
            self.iface.poll(Instant::from_millis(now_ms), &mut self.device, &mut self.sockets);
            return IngestOutcome::Ignored;
        }

        if self.flows_by_id.len() >= MAX_LOCAL_TCP_FLOWS {
            self.gc_flows(now_ms, true);
            if self.flows_by_id.len() >= MAX_LOCAL_TCP_FLOWS {
                return IngestOutcome::Ignored;
            }
        }

        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_BYTES]),
            tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_BYTES]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        socket.set_timeout(Some(Duration::from_secs(45)));
        socket.set_keep_alive(Some(Duration::from_secs(25)));

        let dst_addr = Ipv4Address::from_bytes(&key.dst_ip);
        if socket.listen(IpEndpoint::new(IpAddress::Ipv4(dst_addr), key.dst_port)).is_err() {
            return IngestOutcome::Ignored;
        }

        let handle = self.sockets.add(socket);
        let flow_id = self.next_flow_id;
        self.next_flow_id = self.next_flow_id.wrapping_add(1).max(1);
        self.total_flows += 1;

        self.flows_by_id.insert(
            flow_id,
            FlowEntry {
                id: flow_id,
                key,
                handle,
                tier,
                last_active_ms: now_ms,
                remote_closed: false,
            },
        );
        self.id_by_key.insert(key, flow_id);

        // Immediately poll so smoltcp transitions this socket from Listen -> SynReceived
        // bound to the exact client `(src_ip, src_port)`.
        self.device.rx_queue.push_back(packet.to_vec());
        self.iface.poll(Instant::from_millis(now_ms), &mut self.device, &mut self.sockets);

        let dst_ipv4_be = u32::from_be_bytes(key.dst_ip);
        IngestOutcome::NewFlow {
            flow_id,
            dst_ipv4_be,
            dst_port: key.dst_port,
        }
    }

    /// Drives smoltcp timers (retransmits, keepalives, ACKs) and periodic stale flow GC.
    pub fn poll(&mut self, now_ms: i64) {
        self.iface
            .poll(Instant::from_millis(now_ms), &mut self.device, &mut self.sockets);
        if now_ms - self.last_gc_ms >= 2_000 {
            self.gc_flows(now_ms, false);
            self.last_gc_ms = now_ms;
        }
    }

    /// Pops the next generated IPv4 packet destined back to the Android TUN interface.
    pub fn pop_tx_packet(&mut self) -> Option<Vec<u8>> {
        self.device.tx_queue.pop_front()
    }

    /// Reads plaintext application bytes sent by the Android app on `flow_id`.
    /// Returns:
    ///   - `> 0`: bytes copied into `out`
    ///   - `0`: no bytes ready yet, flow still open
    ///   - `-1`: app half-closed (`FIN` received and RX buffer drained)
    ///   - `-2`: flow does not exist or already closed/aborted
    pub fn recv_from_app(&mut self, flow_id: u64, out: &mut [u8], now_ms: i64) -> i32 {
        let Some(entry) = self.flows_by_id.get_mut(&flow_id) else {
            return -2;
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(entry.handle);
        if socket.recv_queue() > 0 && !out.is_empty() {
            match socket.recv_slice(out) {
                Ok(n) if n > 0 => {
                    entry.last_active_ms = now_ms;
                    self.app_rx_bytes += n as u64;
                    return n as i32;
                }
                _ => {}
            }
        }
        match socket.state() {
            TcpState::Closed | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => -2,
            TcpState::CloseWait => -1,
            _ => {
                if !socket.may_recv() && socket.recv_queue() == 0 {
                    -1
                } else {
                    0
                }
            }
        }
    }

    /// Writes plaintext downlink bytes received from the remote internet server into `smoltcp`.
    /// Returns `>= 0` bytes accepted, or `-1` if the flow is closed/cannot accept more data.
    pub fn send_to_app(&mut self, flow_id: u64, data: &[u8], now_ms: i64) -> i32 {
        let Some(entry) = self.flows_by_id.get_mut(&flow_id) else {
            return -1;
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(entry.handle);
        if !socket.may_send() {
            return -1;
        }
        if data.is_empty() {
            return 0;
        }
        match socket.send_slice(data) {
            Ok(n) => {
                if n > 0 {
                    entry.last_active_ms = now_ms;
                    self.app_tx_bytes += n as u64;
                }
                n as i32
            }
            Err(_) => -1,
        }
    }

    /// Returns free TX buffer space toward the Android app (`>= 0`), or `-1` if flow cannot send.
    pub fn can_send_to_app(&self, flow_id: u64) -> i32 {
        let Some(entry) = self.flows_by_id.get(&flow_id) else {
            return -1;
        };
        let socket = self.sockets.get::<tcp::Socket>(entry.handle);
        if !socket.may_send() {
            return -1;
        }
        socket.send_capacity().saturating_sub(socket.send_queue()) as i32
    }

    /// Closes (`abort = false` -> graceful FIN) or resets (`abort = true` -> immediate RST) a flow.
    pub fn close_flow(&mut self, flow_id: u64, abort: bool) {
        if let Some(entry) = self.flows_by_id.get_mut(&flow_id) {
            entry.remote_closed = true;
            let socket = self.sockets.get_mut::<tcp::Socket>(entry.handle);
            if abort {
                socket.abort();
            } else {
                socket.close();
            }
        }
    }

    pub fn stats(&self) -> LocalTcpStats {
        LocalTcpStats {
            active_flows: self.flows_by_id.len() as u32,
            total_flows: self.total_flows,
            app_rx_bytes: self.app_rx_bytes,
            app_tx_bytes: self.app_tx_bytes,
        }
    }

    fn gc_flows(&mut self, now_ms: i64, aggressive: bool) {
        let to_remove: Vec<u64> = self
            .flows_by_id
            .values()
            .filter_map(|entry| {
                let s = self.sockets.get::<tcp::Socket>(entry.handle);
                let idle_ms = now_ms.saturating_sub(entry.last_active_ms);
                let state = s.state();
                let dead = state == TcpState::Closed
                    && (entry.remote_closed || s.recv_queue() == 0 || idle_ms >= CLOSED_RETENTION_MS);
                let time_wait_stale =
                    state == TcpState::TimeWait && (aggressive || idle_ms >= CLOSED_RETENTION_MS);
                let idle_expired = idle_ms >= FLOW_IDLE_TIMEOUT_MS
                    || (aggressive && idle_ms >= 30_000 && entry.remote_closed);
                if dead || time_wait_stale || idle_expired {
                    Some(entry.id)
                } else {
                    None
                }
            })
            .collect();

        for id in to_remove {
            self.remove_flow_internal(id);
        }
    }

    fn remove_flow_internal(&mut self, flow_id: u64) {
        if let Some(entry) = self.flows_by_id.remove(&flow_id) {
            if self.id_by_key.get(&entry.key) == Some(&flow_id) {
                self.id_by_key.remove(&entry.key);
            }
            self.sockets.remove(entry.handle);
        }
    }
}

fn parse_ipv4_tcp_header(pkt: &[u8]) -> Option<(TcpFlowKey, u8)> {
    if pkt.len() < 40 {
        return None;
    }
    if (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 20 {
        return None;
    }
    if pkt[9] != 6 {
        return None; // Not TCP
    }
    let src_ip = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dst_ip = [pkt[16], pkt[17], pkt[18], pkt[19]];
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let tcp_flags = pkt[ihl + 13];
    Some((
        TcpFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        },
        tcp_flags,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: builds a simulated Android client IPv4 stack (`10.77.0.2/24`, default gw `10.77.0.1`)
    /// to test real TCP 3-way handshake, multi-KB bidirectional transfer, concurrent flows to the
    /// same destination IP:port, graceful FIN, and RST abort through `LocalTcpStack`.
    fn make_client_stack() -> (VirtualTunDevice, Interface, SocketSet<'static>) {
        let mut dev = VirtualTunDevice::new(1280);
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = 0xCAFE_BABE_1234_5678;
        let mut iface = Interface::new(cfg, &mut dev, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 77, 0, 2), 24));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 77, 0, 1));
        (dev, iface, SocketSet::new(Vec::new()))
    }

    fn pump_packets(
        c_dev: &mut VirtualTunDevice,
        c_iface: &mut Interface,
        c_socks: &mut SocketSet<'static>,
        proxy: &mut LocalTcpStack,
        now_ms: i64,
        new_flows: &mut Vec<(u64, u32, u16)>,
    ) {
        c_iface.poll(Instant::from_millis(now_ms), c_dev, c_socks);
        while let Some(pkt) = c_dev.tx_queue.pop_front() {
            if let IngestOutcome::NewFlow {
                flow_id,
                dst_ipv4_be,
                dst_port,
            } = proxy.ingest_ipv4(&pkt, 0, now_ms)
            {
                new_flows.push((flow_id, dst_ipv4_be, dst_port));
            }
        }
        proxy.poll(now_ms);
        while let Some(pkt) = proxy.pop_tx_packet() {
            c_dev.rx_queue.push_back(pkt);
        }
        c_iface.poll(Instant::from_millis(now_ms), c_dev, c_socks);
    }

    #[test]
    fn transparent_tcp_handshake_bidirectional_and_concurrent_same_dst() {
        let (mut c_dev, mut c_iface, mut c_socks) = make_client_stack();
        let mut proxy = LocalTcpStack::new(1280, 99);

        let dst_ip = IpAddress::v4(93, 184, 216, 34);
        let dst_ep = IpEndpoint::new(dst_ip, 443);

        // Open TWO concurrent TCP flows to the EXACT SAME destination IP:port (like Chrome / Play Store)
        let mut s1 = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 32768]),
            tcp::SocketBuffer::new(vec![0u8; 32768]),
        );
        let mut s2 = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 32768]),
            tcp::SocketBuffer::new(vec![0u8; 32768]),
        );
        s1.connect(c_iface.context(), dst_ep, 51001).unwrap();
        s2.connect(c_iface.context(), dst_ep, 51002).unwrap();
        let h1 = c_socks.add(s1);
        let h2 = c_socks.add(s2);

        let mut new_flows = Vec::new();
        let mut now_ms = 10;
        for _ in 0..8 {
            pump_packets(&mut c_dev, &mut c_iface, &mut c_socks, &mut proxy, now_ms, &mut new_flows);
            now_ms += 10;
        }

        assert_eq!(new_flows.len(), 2, "Expected 2 distinct transparent flows");
        assert_eq!(new_flows[0].1, u32::from_be_bytes([93, 184, 216, 34]));
        assert_eq!(new_flows[0].2, 443);
        assert_ne!(new_flows[0].0, new_flows[1].0);
        assert_eq!(c_socks.get::<tcp::Socket>(h1).state(), TcpState::Established);
        assert_eq!(c_socks.get::<tcp::Socket>(h2).state(), TcpState::Established);

        // Send distinct multi-KB payloads on BOTH flows simultaneously
        let req1: Vec<u8> = (0..4096).map(|i| ((i * 7) & 0xFF) as u8).collect();
        let req2: Vec<u8> = (0..3072).map(|i| ((i * 13 + 5) & 0xFF) as u8).collect();
        let resp1: Vec<u8> = (0..5000).map(|i| ((i * 3 + 1) & 0xFF) as u8).collect();

        let mut sent1 = 0;
        let mut sent2 = 0;
        let mut got_req1 = Vec::new();
        let mut got_req2 = Vec::new();
        let mut proxy_sent1 = 0;
        let mut client_got1 = Vec::new();
        let mut tmp = [0u8; 4096];

        let f1 = new_flows[0].0;
        let f2 = new_flows[1].0;

        for _ in 0..40 {
            if sent1 < req1.len() {
                if let Ok(n) = c_socks.get_mut::<tcp::Socket>(h1).send_slice(&req1[sent1..]) {
                    sent1 += n;
                }
            }
            if sent2 < req2.len() {
                if let Ok(n) = c_socks.get_mut::<tcp::Socket>(h2).send_slice(&req2[sent2..]) {
                    sent2 += n;
                }
            }

            pump_packets(&mut c_dev, &mut c_iface, &mut c_socks, &mut proxy, now_ms, &mut new_flows);

            let r1 = proxy.recv_from_app(f1, &mut tmp, now_ms);
            if r1 > 0 {
                got_req1.extend_from_slice(&tmp[..r1 as usize]);
            }
            let r2 = proxy.recv_from_app(f2, &mut tmp, now_ms);
            if r2 > 0 {
                got_req2.extend_from_slice(&tmp[..r2 as usize]);
            }

            if proxy_sent1 < resp1.len() && proxy.can_send_to_app(f1) > 0 {
                let w = proxy.send_to_app(f1, &resp1[proxy_sent1..], now_ms);
                if w > 0 {
                    proxy_sent1 += w as usize;
                }
            }

            pump_packets(&mut c_dev, &mut c_iface, &mut c_socks, &mut proxy, now_ms, &mut new_flows);

            if let Ok(n) = c_socks.get_mut::<tcp::Socket>(h1).recv_slice(&mut tmp) {
                if n > 0 {
                    client_got1.extend_from_slice(&tmp[..n]);
                }
            }

            now_ms += 10;
            if got_req1.len() == req1.len()
                && got_req2.len() == req2.len()
                && client_got1.len() == resp1.len()
            {
                break;
            }
        }

        // Verify bit-exact delivery without cross-talk between flow 1 & flow 2
        assert_eq!(got_req1, req1);
        assert_eq!(got_req2, req2);
        assert_eq!(client_got1, resp1);

        // Test graceful FIN on f1 and immediate RST abort on f2
        proxy.close_flow(f1, false);
        proxy.close_flow(f2, true);
        for _ in 0..6 {
            pump_packets(&mut c_dev, &mut c_iface, &mut c_socks, &mut proxy, now_ms, &mut new_flows);
            now_ms += 20;
        }
        assert_eq!(c_socks.get::<tcp::Socket>(h1).state(), TcpState::CloseWait);
        assert_eq!(c_socks.get::<tcp::Socket>(h2).state(), TcpState::Closed);

        let st = proxy.stats();
        assert_eq!(st.total_flows, 2);
        assert_eq!(st.app_rx_bytes, (req1.len() + req2.len()) as u64);
        assert_eq!(st.app_tx_bytes, resp1.len() as u64);
    }
}
