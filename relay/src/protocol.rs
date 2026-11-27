//! JITER Relay Wire Protocol v1 (`JT`) — 16-byte fixed big-endian header.
//!
//! Byte-for-byte compatible with:
//!   - C11 Packet Engine (`engine-native/c/src/jiter_packet.c`)
//!   - Android Kotlin Client (`android/.../relay/RelayProtocol.kt`)

pub const WIRE_HEADER_BYTES: usize = 16;
pub const WIRE_MAGIC_0: u8 = b'J';
pub const WIRE_MAGIC_1: u8 = b'T';
pub const WIRE_VERSION: u8 = 1;
pub const MAX_PAYLOAD_BYTES: usize = 1440;

pub const FLAG_GOODBYE: u8 = 0x01;
pub const FLAG_FEC_PARITY: u8 = 0x02;
pub const FLAG_ENCRYPTED: u8 = 0x04;

pub const RELAY_CAP_XOR_FEC: u16 = 1 << 0;
pub const RELAY_CAP_PACER_3TIER: u16 = 1 << 1;
pub const RELAY_CAP_FORWARD_UDP: u16 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrafficTier {
    Game = 0,
    Streaming = 1,
    Background = 2,
}

impl TrafficTier {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Game),
            1 => Some(Self::Streaming),
            2 => Some(Self::Background),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    ProbeReq = 1,
    ProbeResp = 2,
    HelloReq = 3,
    HelloAck = 4,
    DataPlain = 5,
    DataFec = 6,
    PolicySync = 7,
    Control = 8,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ProbeReq),
            2 => Some(Self::ProbeResp),
            3 => Some(Self::HelloReq),
            4 => Some(Self::HelloAck),
            5 => Some(Self::DataPlain),
            6 => Some(Self::DataFec),
            7 => Some(Self::PolicySync),
            8 => Some(Self::Control),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireHeader {
    pub version: u8,
    pub msg_type: MsgType,
    pub traffic_tier: TrafficTier,
    pub flags: u8,
    pub session_id: u32,
    pub sequence: u32,
    pub payload_len: u16,
    pub pacer_q8: u8,
    pub fec_mode: u8,
}

impl WireHeader {
    pub fn pack(&self) -> Option<[u8; WIRE_HEADER_BYTES]> {
        if self.version != WIRE_VERSION || (self.payload_len as usize) > MAX_PAYLOAD_BYTES {
            return None;
        }
        let mut out = [0u8; WIRE_HEADER_BYTES];
        out[0] = WIRE_MAGIC_0;
        out[1] = WIRE_MAGIC_1;
        out[2] = ((self.version & 0x0F) << 4) | ((self.msg_type as u8) & 0x0F);
        out[3] = (((self.traffic_tier as u8) & 0x03) << 6) | (self.flags & 0x3F);
        out[4..8].copy_from_slice(&self.session_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.sequence.to_be_bytes());
        out[12..14].copy_from_slice(&self.payload_len.to_be_bytes());
        out[14] = self.pacer_q8;
        out[15] = self.fec_mode;
        Some(out)
    }

    pub fn unpack(buf: &[u8]) -> Option<Self> {
        if buf.len() < WIRE_HEADER_BYTES {
            return None;
        }
        if buf[0] != WIRE_MAGIC_0 || buf[1] != WIRE_MAGIC_1 {
            return None;
        }
        let version = buf[2] >> 4;
        if version != WIRE_VERSION {
            return None;
        }
        let msg_type = MsgType::from_u8(buf[2] & 0x0F)?;
        let traffic_tier = TrafficTier::from_u8(buf[3] >> 6)?;
        let flags = buf[3] & 0x3F;
        let session_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let sequence = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let payload_len = u16::from_be_bytes([buf[12], buf[13]]);
        if (payload_len as usize) > MAX_PAYLOAD_BYTES {
            return None;
        }
        Some(Self {
            version,
            msg_type,
            traffic_tier,
            flags,
            session_id,
            sequence,
            payload_len,
            pacer_q8: buf[14],
            fec_mode: buf[15],
        })
    }

    pub fn frame_bytes(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() != self.payload_len as usize {
            return None;
        }
        let hdr = self.pack()?;
        let mut buf = Vec::with_capacity(WIRE_HEADER_BYTES + payload.len());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(payload);
        Some(buf)
    }
}

pub fn pacer_ratio_to_q8(ratio: f64) -> u8 {
    if !ratio.is_finite() || ratio <= 0.0 {
        return 0;
    }
    if ratio >= 1.0 {
        return 255;
    }
    let scaled = (ratio * 255.0 + 0.5).floor();
    if scaled >= 255.0 {
        255
    } else {
        scaled as u8
    }
}

pub fn pacer_q8_to_ratio(q8: u8) -> f64 {
    (q8 as f64) / 255.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeReqPayload {
    pub client_tx_us: u64,
    pub profile_id: u16,
    pub reserved: u16,
}

impl ProbeReqPayload {
    pub const BYTES: usize = 12;

    pub fn pack(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..8].copy_from_slice(&self.client_tx_us.to_be_bytes());
        out[8..10].copy_from_slice(&self.profile_id.to_be_bytes());
        out[10..12].copy_from_slice(&self.reserved.to_be_bytes());
        out
    }

    pub fn unpack(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::BYTES {
            return None;
        }
        Some(Self {
            client_tx_us: u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            profile_id: u16::from_be_bytes([buf[8], buf[9]]),
            reserved: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRespPayload {
    pub echo_tx_us: u64,
    pub relay_rx_loss_bps: u32,
    pub relay_queue_us: u32,
    pub relay_fec_recovered: u32,
    pub relay_pacer_q8: u16,
    pub relay_fec_mode: u16,
}

impl ProbeRespPayload {
    pub const BYTES: usize = 24;

    pub fn pack(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..8].copy_from_slice(&self.echo_tx_us.to_be_bytes());
        out[8..12].copy_from_slice(&self.relay_rx_loss_bps.to_be_bytes());
        out[12..16].copy_from_slice(&self.relay_queue_us.to_be_bytes());
        out[16..20].copy_from_slice(&self.relay_fec_recovered.to_be_bytes());
        out[20..22].copy_from_slice(&self.relay_pacer_q8.to_be_bytes());
        out[22..24].copy_from_slice(&self.relay_fec_mode.to_be_bytes());
        out
    }

    pub fn unpack(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::BYTES {
            return None;
        }
        Some(Self {
            echo_tx_us: u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            relay_rx_loss_bps: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            relay_queue_us: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            relay_fec_recovered: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            relay_pacer_q8: u16::from_be_bytes([buf[20], buf[21]]),
            relay_fec_mode: u16::from_be_bytes([buf[22], buf[23]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloReqPayload {
    pub profile_id: u8,
    pub routing_mode: u8,
    pub fec_policy: u8,
    pub reserved: u8,
    pub mtu: u16,
    pub link_hint_mbps_x10: u16,
}

impl HelloReqPayload {
    pub const BYTES: usize = 8;

    pub fn pack(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0] = self.profile_id;
        out[1] = self.routing_mode;
        out[2] = self.fec_policy;
        out[3] = self.reserved;
        out[4..6].copy_from_slice(&self.mtu.to_be_bytes());
        out[6..8].copy_from_slice(&self.link_hint_mbps_x10.to_be_bytes());
        out
    }

    pub fn unpack(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::BYTES {
            return None;
        }
        Some(Self {
            profile_id: buf[0],
            routing_mode: buf[1],
            fec_policy: buf[2],
            reserved: buf[3],
            mtu: u16::from_be_bytes([buf[4], buf[5]]),
            link_hint_mbps_x10: u16::from_be_bytes([buf[6], buf[7]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloAckPayload {
    pub accepted_mtu: u16,
    pub relay_caps: u16,
    pub region_tag: [u8; 8],
}

impl HelloAckPayload {
    pub const BYTES: usize = 12;

    pub fn new(accepted_mtu: u16, relay_caps: u16, region: &str) -> Self {
        let mut tag = [0u8; 8];
        let bytes = region.as_bytes();
        let n = bytes.len().min(8);
        tag[..n].copy_from_slice(&bytes[..n]);
        Self {
            accepted_mtu,
            relay_caps,
            region_tag: tag,
        }
    }

    pub fn region_str(&self) -> String {
        let end = self
            .region_tag
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.region_tag.len());
        String::from_utf8_lossy(&self.region_tag[..end]).to_string()
    }

    pub fn pack(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..2].copy_from_slice(&self.accepted_mtu.to_be_bytes());
        out[2..4].copy_from_slice(&self.relay_caps.to_be_bytes());
        out[4..12].copy_from_slice(&self.region_tag);
        out
    }

    pub fn unpack(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::BYTES {
            return None;
        }
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&buf[4..12]);
        Some(Self {
            accepted_mtu: u16::from_be_bytes([buf[0], buf[1]]),
            relay_caps: u16::from_be_bytes([buf[2], buf[3]]),
            region_tag: tag,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySyncPayload {
    pub profile_id: u8,
    pub fec_mode: u8,
    pub pacer_q8: u8,
    pub reserved: u8,
    pub link_mbps_x10: u16,
    pub reserved2: u16,
}

impl PolicySyncPayload {
    pub const BYTES: usize = 8;

    pub fn pack(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0] = self.profile_id;
        out[1] = self.fec_mode;
        out[2] = self.pacer_q8;
        out[3] = self.reserved;
        out[4..6].copy_from_slice(&self.link_mbps_x10.to_be_bytes());
        out[6..8].copy_from_slice(&self.reserved2.to_be_bytes());
        out
    }

    pub fn unpack(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::BYTES {
            return None;
        }
        Some(Self {
            profile_id: buf[0],
            fec_mode: buf[1],
            pacer_q8: buf[2],
            reserved: buf[3],
            link_mbps_x10: u16::from_be_bytes([buf[4], buf[5]]),
            reserved2: u16::from_be_bytes([buf[6], buf[7]]),
        })
    }
}
