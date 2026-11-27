//! Linux `/dev/net/tun` interface + ephemeral VPN IPv4 address pool (`10.77.0.2..254`)
//! + zero-allocation IPv4 endpoint extractor & 3-tier packet classifier.

use std::collections::HashMap;
use std::io;

use crate::protocol::TrafficTier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4PacketSummary {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub protocol: u8,
    pub traffic_tier: TrafficTier,
}

/// Zero-allocation IPv4 header parser & tier classifier matching `engine-native/c/src/jiter_packet.c`.
pub fn parse_ipv4_summary(raw: &[u8]) -> Option<Ipv4PacketSummary> {
    if raw.len() < 20 {
        return None;
    }
    let version = raw[0] >> 4;
    let ihl = (raw[0] & 0x0F) as usize * 4;
    if version != 4 || ihl < 20 || ihl > raw.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if total_len < ihl || total_len > raw.len() {
        return None;
    }

    let dscp = raw[1] >> 2;
    let protocol = raw[9];
    let src_ip = [raw[12], raw[13], raw[14], raw[15]];
    let dst_ip = [raw[16], raw[17], raw[18], raw[19]];

    let mut dst_port = 0u16;
    let mut src_port = 0u16;
    if (protocol == 17 && ihl + 8 <= total_len) || (protocol == 6 && ihl + 20 <= total_len) {
        src_port = u16::from_be_bytes([raw[ihl], raw[ihl + 1]]);
        dst_port = u16::from_be_bytes([raw[ihl + 2], raw[ihl + 3]]);
    }

    let tier = if dscp == 46 || dscp == 32 || protocol == 1 {
        TrafficTier::Game
    } else if protocol == 17 {
        if total_len <= 320 || dst_port == 53 || src_port == 53 {
            TrafficTier::Game
        } else {
            TrafficTier::Streaming
        }
    } else if protocol == 6 {
        if total_len <= 96 {
            TrafficTier::Game
        } else if dst_port == 443 || dst_port == 80 || src_port == 443 || src_port == 80 {
            TrafficTier::Streaming
        } else {
            TrafficTier::Background
        }
    } else {
        TrafficTier::Background
    };

    Some(Ipv4PacketSummary {
        src_ip,
        dst_ip,
        protocol,
        traffic_tier: tier,
    })
}

/// Ephemeral RAM-only IPv4 pool for `10.77.0.2` .. `10.77.0.254` (gateway `10.77.0.1/24`).
pub struct TunIpPool {
    subnet_prefix: [u8; 3],
    ip_to_session: HashMap<[u8; 4], u32>,
    session_to_ip: HashMap<u32, [u8; 4]>,
    next_host: u8,
}

impl TunIpPool {
    pub fn new(subnet_prefix: [u8; 3]) -> Self {
        Self {
            subnet_prefix,
            ip_to_session: HashMap::new(),
            session_to_ip: HashMap::new(),
            next_host: 2,
        }
    }

    pub fn allocate(&mut self, session_id: u32) -> Option<[u8; 4]> {
        if let Some(&existing) = self.session_to_ip.get(&session_id) {
            return Some(existing);
        }
        for _ in 0..253 {
            let host = self.next_host;
            self.next_host = if self.next_host >= 254 {
                2
            } else {
                self.next_host + 1
            };
            let candidate = [
                self.subnet_prefix[0],
                self.subnet_prefix[1],
                self.subnet_prefix[2],
                host,
            ];
            if !self.ip_to_session.contains_key(&candidate) {
                self.ip_to_session.insert(candidate, session_id);
                self.session_to_ip.insert(session_id, candidate);
                return Some(candidate);
            }
        }
        None
    }

    pub fn release_session(&mut self, session_id: u32) {
        if let Some(ip) = self.session_to_ip.remove(&session_id) {
            self.ip_to_session.remove(&ip);
        }
    }

    pub fn lookup_session_by_ip(&self, ip: [u8; 4]) -> Option<u32> {
        self.ip_to_session.get(&ip).copied()
    }

    pub fn assigned_ip(&self, session_id: u32) -> Option<[u8; 4]> {
        self.session_to_ip.get(&session_id).copied()
    }

    pub fn active_leases(&self) -> usize {
        self.session_to_ip.len()
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxTunDevice {
    file: std::fs::File,
    name: String,
}

#[cfg(target_os = "linux")]
impl LinuxTunDevice {
    pub fn open(dev_name: &str) -> io::Result<Self> {
        use std::fs::OpenOptions;
        use std::os::unix::io::AsRawFd;

        #[repr(C)]
        struct IfReq {
            ifr_name: [libc::c_char; libc::IFNAMSIZ],
            ifr_flags: libc::c_short,
            _pad: [u8; 22],
        }

        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        const TUNSETIFF: u64 = 0x4004_54CA;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr = IfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        let bytes = dev_name.as_bytes();
        let copy_len = bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, &b) in bytes[..copy_len].iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        let fd = file.as_raw_fd();
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Enable non-blocking I/O so UDP loop and TUN loop interleave cleanly with <2ms latency
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc_nb = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc_nb < 0 {
            return Err(io::Error::last_os_error());
        }

        let actual_name_bytes: Vec<u8> = ifr
            .ifr_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        let name = String::from_utf8_lossy(&actual_name_bytes).to_string();

        Ok(Self { file, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.file.read(buf)
    }

    pub fn write_packet(&mut self, pkt: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        self.file.write(pkt)
    }
}

#[cfg(not(target_os = "linux"))]
pub struct LinuxTunDevice;

#[cfg(not(target_os = "linux"))]
impl LinuxTunDevice {
    pub fn open(_dev_name: &str) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "--mode tun requires Linux /dev/net/tun",
        ))
    }

    pub fn name(&self) -> &str {
        "unsupported"
    }

    pub fn read_packet(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "non-Linux"))
    }

    pub fn write_packet(&mut self, _pkt: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "non-Linux"))
    }
}
