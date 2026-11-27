//! JITER Stage 3 Edge Relay library (`jiter-relay`).
//!
//! Coordinates two-sided anti-bufferbloat pacing, strict 3-tier downstream scheduling,
//! and GF(2) XOR Parity FEC recovery with the JITER Android client.

pub mod protocol;
pub mod scheduler;
pub mod server;
pub mod session;
