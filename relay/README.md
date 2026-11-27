# JITER Stage 4 Edge Relay Gateway (`relay/`)

Memory-safe Rust UDP Relay Edge designed for **Jakarta (`JKT-1`)** and **Singapore (`SG-1`)** Linux VPS deployments.

## Stage 4 Capabilities (Complete Two-Sided Real-Internet Tunnel)

1. **Standard Transport Cryptography (`crypto.rs` — Zero Custom Crypto)**:
   - Per-session **ECDHE P-256** (`p256`) for Perfect Forward Secrecy
   - Mutual PSK authentication (`HMAC-SHA256` + constant-time `subtle` verification)
   - Directional keys derived via **RFC 5869 HKDF-SHA256** (`hkdf` + `sha2`)
   - Per-packet **RFC 8439 ChaCha20-Poly1305 AEAD** (`chacha20poly1305`) binding the 16-byte wire header as AAD
   - **64-packet sliding Anti-Replay Window** updated strictly after Poly1305 verification
2. **Real Linux `/dev/net/tun` NAT Gateway (`--mode tun`, `tun.rs`)**:
   - Ephemeral RAM-only IPv4 pool (`10.77.0.2..254`, anti-spoofing source IP check)
   - Routes real Android game + YouTube + browser traffic to the internet through Linux NAT `MASQUERADE`
   - Applies **Downstream 3-Tier Strict Priority Queue (`GAME > STREAMING > BACKGROUND`) + Anti-Bufferbloat Background Pacer** (`scheduler.rs`) on every returning internet packet
3. **Adaptive GF(2) XOR Parity FEC (`jiter-math`)**:
   - Recovers lost uplink Game UDP packets bit-exact before injecting into `jiter0`, and protects downlink Game packets across wireless last-mile legs.
4. **Zero-Retention RAM-Only Privacy**:
   - Random ephemeral `session_id`, auto-expiring idle leases, instant wipe on authenticated `GOODBYE`, zero disk logs.

---

## Quick Start on a Jakarta / Singapore Linux VPS (Full Internet Gateway)

```bash
# 1. Build release binary
cd relay
cargo test -- --nocapture
cargo build --release
sudo install -m 0755 target/release/jiter-relay /usr/local/bin/jiter-relay

# 2. Configure Linux jiter0 TUN, BBR, FQ, NAT MASQUERADE & generate a 256-bit JITER_PSK
sudo chmod +x deploy/setup-vps.sh
sudo ./deploy/setup-vps.sh

# 3. Launch encrypted TUN gateway (using the printed JITER_PSK)
export JITER_PSK="<printed-psk>"
sudo -E /usr/local/bin/jiter-relay \
  --bind 0.0.0.0:51820 \
  --region JKT-1 \
  --mode tun \
  --tun-name jiter0 \
  --max-link-mbps 100
```

### Diagnostic / Echo Mode (No Root / No TUN Required)

```bash
cargo run --release -- \
  --bind 0.0.0.0:51820 \
  --region JKT-1 \
  --mode echo \
  --psk "my-test-secret"
```

Then open **Configure Backend / Relay** in the JITER Android app, enter your VPS IP, port `51820`, `Relay PSK (AEAD)`, switch **Tunnel Scope** to **Full Internet Tunnel (0.0.0.0/0)**, tap **Save**, and tap **GO**.
