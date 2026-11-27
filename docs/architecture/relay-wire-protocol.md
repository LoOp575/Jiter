# JITER Relay Wire Protocol v1 (`JT`) — Stage 4 Encrypted Spec

This document locks the binary UDP wire contract & AEAD transport security shared identically across:

- **C11 Packet Engine** (`engine-native/c/include/jiter_packet.h`, `jiter_packet.c`)
- **Rust JITER Relay Edge** (`relay/src/protocol.rs`, `relay/src/crypto.rs`, `relay/src/tun.rs`)
- **Android Client** (`android/app/src/main/java/com/jiter/app/relay/{RelayProtocol,RelayCrypto,RelayTunnelClient}.kt`)

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
|            payload / AEAD ciphertext + 16B Poly1305 tag       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Flags (`tier_flags & 0x3F`)
- `0x01`: `FLAG_GOODBYE` — Clean session teardown & RAM wipe
- `0x02`: `FLAG_FEC_PARITY` — Fast-path hint indicating `DATA_FEC` payload carries a parity frame
- `0x04`: `FLAG_ENCRYPTED` — Stage 4 ECDHE P-256 handshake / ChaCha20-Poly1305 AEAD encrypted payload

### Relay Capability Bitmask (`HelloAckPayload.relay_caps`)
- `1 << 0`: `RELAY_CAP_XOR_FEC` — GF(2) Interleaved XOR Parity FEC
- `1 << 1`: `RELAY_CAP_PACER_3TIER` — Downstream 3-tier Strict Priority + Anti-Bufferbloat Pacer
- `1 << 2`: `RELAY_CAP_FORWARD_UDP` — Upstream single-target UDP forwarding (`--mode forward`)
- `1 << 3`: `RELAY_CAP_AEAD_CHACHA20` — Stage 4 ECDHE P-256 + HKDF-SHA256 + ChaCha20-Poly1305 AEAD
- `1 << 4`: `RELAY_CAP_TUN_NAT` — Stage 4 Linux `/dev/net/tun` full-internet NAT gateway (`--mode tun`)

---

## 2. Stage 4 Standard Transport Security (ECDHE P-256 + PSK + ChaCha20-Poly1305)

Uses **zero custom cryptography** — strictly standard audited primitives:
- **Rust Relay (`relay/`)**: RustCrypto `p256` (ECDH), `hkdf` + `sha2` + `hmac`, `chacha20poly1305` (RFC 8439), `subtle` constant-time MAC compare.
- **Android Client (`android/`)**: Built-in JCA/Conscrypt `EC` (`secp256r1` ECDH), `HmacSHA256` (RFC 5869 HKDF), `ChaCha20-Poly1305` (RFC 8439), `MessageDigest.isEqual` (available natively on Android API 29–35 and JDK 17 with zero APK bloat).

### Key Derivation
1. `psk_key (32B) = SHA-256("jiter-psk-v1:" || trim(psk_string))`
2. **Encrypted `HELLO_REQ` (`msg_type = 3`, `flags = FLAG_ENCRYPTED`, 105 bytes):**
   - `0..8`: Base `HelloReqPayload` (8B)
   - `8..73`: `client_ephem_pub` — 65B uncompressed SEC1 P-256 public key (`0x04 || X(32) || Y(32)`)
   - `73..89`: `client_nonce` — 16B CSPRNG random bytes
   - `89..105`: `client_auth_tag` — first 16B of `HMAC-SHA256(psk_key, "jiter-hello-req-v1" || session_id_be4 || payload[0..89])`
3. **Encrypted `HELLO_ACK` (`msg_type = 4`, `flags = FLAG_ENCRYPTED`, 113 bytes):**
   - `0..12`: Base `HelloAckPayload` (12B: `accepted_mtu`, `relay_caps`, `region_tag[8]`)
   - `12..16`: `assigned_ipv4` (4B, e.g., `10.77.0.2` allocated from relay RAM pool)
   - `16..81`: `server_ephem_pub` — 65B uncompressed SEC1 P-256 public key (`0x04 || X(32) || Y(32)`)
   - `81..97`: `server_nonce` — 16B CSPRNG random bytes
   - `97..113`: `server_auth_tag` — first 16B of `HMAC-SHA256(psk_key, "jiter-hello-ack-v1" || session_id_be4 || client_nonce(16) || payload[0..97])`
4. **Forward-Secret Directional Keys (RFC 5869 HKDF-SHA256):**
   - `ecdh_shared (32B)` = raw X-coordinate from ECDH(`secp256r1`)
   - `ikm (64B) = ecdh_shared || psk_key`
   - `salt (36B) = client_nonce(16) || server_nonce(16) || session_id_be4(4)`
   - `c2s_key (32B) = HKDF-Expand(PRK, "jiter-v1-c2s-key", 32)`
   - `s2c_key (32B) = HKDF-Expand(PRK, "jiter-v1-s2c-key", 32)`
   - `c2s_iv  (4B)  = HKDF-Expand(PRK, "jiter-v1-c2s-iv", 4)`
   - `s2c_iv  (4B)  = HKDF-Expand(PRK, "jiter-v1-s2c-iv", 4)`

### Per-Packet AEAD Framing & Anti-Replay
- **Nonce (12B):** `dir_iv(4B) || session_id_be4(4B) || sequence_be4(4B)` (zero extra wire bytes; monotonic `sequence` guarantees uniqueness).
- **AAD (16B):** Exact packed 16-byte `WireHeader` (`payload_len` includes the 16-byte Poly1305 tag).
- **Anti-Replay:** 64-packet sliding bitmap window checked before decryption and updated **only after** Poly1305 tag verification succeeds.
- When the relay runs with `--psk` or `--mode tun`, unauthenticated/unencrypted packets are strictly dropped.

---

## 3. Golden Interoperability Test Vector (16-Byte Header)

- `version = 1`, `msg_type = 6 (DATA_FEC)`, `tier = 0 (GAME)`, `flags = 0x02 (FLAG_FEC_PARITY)`
- `session_id = 0x11223344`, `sequence = 42`, `payload_len = 128`, `pacer_q8 = 89`, `fec_mode = 2`

```text
4A 54 16 02 11 22 33 44 00 00 00 2A 00 80 59 02
```

Cryptographic interoperability is additionally locked across Rust and Kotlin via official **IETF RFC 5869 (HKDF-SHA256)**, **IETF RFC 8439 (ChaCha20-Poly1305)**, and **SEC1 P-256 Generator `G`** golden vectors.
