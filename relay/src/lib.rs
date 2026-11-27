//! JITER Stage 4 Edge Relay library (`jiter-relay`).
//!
//! Coordinates:
//!   - ECDHE P-256 + PSK mutual auth + HKDF-SHA256 + ChaCha20-Poly1305 AEAD (`crypto`)
//!   - Linux `/dev/net/tun` NAT Gateway & ephemeral IPv4 pool (`tun`)
//!   - Two-sided anti-bufferbloat 3-tier strict-priority pacing (`scheduler`)
//!   - GF(2) XOR Parity FEC recovery (`session`, via `jiter-math`)

pub mod crypto;
pub mod protocol;
pub mod scheduler;
pub mod server;
pub mod session;
pub mod tun;
