# JITER Relay Wire Protocol v1 (`JT`)

This document locks the binary UDP wire contract shared identically across:

- **C11 Packet Engine** (`engine-native/c/include/jiter_packet.h`, `jiter_packet.c`)
- **Rust JITER Relay Edge** (`relay/src/protocol.rs`)
- **Android Client** (`android/app/src/main/java/com/jiter/app/relay/RelayProtocol.kt`)

---

## 1. Fixed 16-Byte Wire Header (Big-Endian)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Magic 'J'   |   Magic 'T'   |  Ver (4)|Typ  |Tier|Flags     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        session_id (u32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        sequence (u32)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       payload_len (u16)       |  pacer_q8 (u8)| fec_mode (u8) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    payload (payload_len bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Field Definitions

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| `0..1` | 2 B | `magic` | ASCII `'J'` (`0x4A`), `'T'` (`0x54`) |
| `2` | 1 B | `ver_type` | High 4 bits = version (`1`), Low 4 bits = `msg_type` (`1..8`) |
| `3` | 1 B | `tier_flags` | High 2 bits = `traffic_tier` (`0=GAME, 1=STREAMING, 2=BACKGROUND`), Low 6 bits = `flags` |
| `4..7` | 4 B | `session_id` | Ephemeral random per-GO session ID (never linked to user account; wiped on `GOODBYE`) |
| `8..11` | 4 B | `sequence` | Monotonic per-session frame sequence number (used for loss estimation) |
| `12..13` | 2 B | `payload_len` | Payload byte length (`0..1440`) |
| `14` | 1 B | `pacer_q8` | Quantized `bg_pacer_ratio` (`round(clamp(ratio, 0.0, 1.0) * 255)`) |
| `15` | 1 B | `fec_mode` | `0=OFF`, `1=XOR_K4`, `2=XOR_K2`, `3=DUPLICATE` |

### Message Types (`msg_type`)

| Value | Name | Direction | Payload Layout |
|---:|---|---|---|
| `1` | `PROBE_REQ` | Client → Relay | `client_tx_us: u64` (8B) + `profile_id: u16` (2B) + `reserved: u16` (2B) = **12 bytes** |
| `2` | `PROBE_RESP` | Relay → Client | `echo_tx_us: u64` (8B) + `relay_rx_loss_bps: u32` (4B, loss% × 100) + `relay_queue_us: u32` (4B) + `relay_fec_recovered: u32` (4B) + `relay_pacer_q8: u16` (2B) + `relay_fec_mode: u16` (2B) = **24 bytes** |
| `3` | `HELLO_REQ` | Client → Relay | `profile_id: u8` + `routing_mode: u8` + `fec_policy: u8` + `reserved: u8` + `mtu: u16` + `link_hint_mbps_x10: u16` = **8 bytes** |
| `4` | `HELLO_ACK` | Relay → Client | `accepted_mtu: u16` + `relay_caps: u16` + `region_tag: [u8; 8]` (UTF-8 zero-padded, e.g. `"JKT-1\0\0\0"`) = **12 bytes** |
| `5` | `DATA_PLAIN` | Bidirectional | Raw IPv4 packet bytes (max 1440 bytes) |
| `6` | `DATA_FEC` | Bidirectional | 8-byte `JiterFecHeader` (Formula #3) + FEC data or XOR parity bytes |
| `7` | `POLICY_SYNC` | Client → Relay | `profile_id: u8` + `fec_mode: u8` + `pacer_q8: u8` + `reserved: u8` + `link_mbps_x10: u16` + `reserved2: u16` = **8 bytes** |
| `8` | `CONTROL` | Bidirectional | 0 bytes; `flags & 0x01` (`FLAG_GOODBYE`) triggers immediate RAM wipe of session state |

### Header Flags (`tier_flags & 0x3F`)
- `0x01`: `FLAG_GOODBYE` — Clean session teardown & RAM wipe
- `0x02`: `FLAG_FEC_PARITY` — Fast-path hint indicating `DATA_FEC` payload carries a parity frame
- `0x04`: `FLAG_ENCRYPTED` — Reserved for Stage 4 Noise_IK / WireGuard outer AEAD transport wrapper

---

## 2. Golden Interoperability Test Vector

Verified identically in C (`test_native_engine.cpp`), Rust (`relay/tests/integration_relay.rs`), and Kotlin (`JiterEngineTest.kt`):

- `version = 1`, `msg_type = 6 (DATA_FEC)`, `tier = 0 (GAME)`, `flags = 0x02 (FLAG_FEC_PARITY)`
- `session_id = 0x11223344`, `sequence = 0x0000002A (42)`, `payload_len = 128 (0x0080)`
- `pacer_q8 = 89 (~0.35)`, `fec_mode = 2 (XOR_K2)`

Exact 16 wire bytes (hex):
```text
4A 54 16 02 11 22 33 44 00 00 00 2A 00 80 59 02
```

---

## 3. Privacy & Zero-Retention Guarantee

- `session_id` is randomly generated in RAM when the user taps **GO** and destroyed on **STOP**.
- The Relay stores active sessions strictly in an in-memory `HashMap` with idle TTL expiration (default 60s) and immediate deletion upon receiving `FLAG_GOODBYE`.
- No user accounts, no IP-to-history database, and no disk packet logs are written.
