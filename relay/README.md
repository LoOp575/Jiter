# JITER Stage 3 Edge Relay Server (`relay/`)

Memory-safe, zero-dependency Rust UDP Relay Edge designed for **Jakarta (`JKT-1`)** and **Singapore (`SG-1`)** VPS deployments.

## What the Relay Does (Two-Sided Actuation)

1. **Zero-Retention Ephemeral Sessions**: Sessions live strictly in RAM keyed by random per-session IDs, auto-expire after `--session-timeout-secs`, and wipe immediately on `GOODBYE`. No disk logs, no accounts.
2. **Low-Latency Probe & Telemetry (`PROBE_REQ → PROBE_RESP`)**: Measures real relay-side RTT, uplink sequence-gap loss, downstream queue delay, and recovered FEC packet counts — fed straight into Formula #1 on the Android client for live **Native vs Relay** route selection.
3. **Downstream 3-Tier Strict Priority + Anti-Bufferbloat Pacer (`scheduler.rs`)**: Mirrors the Android client's `bg_pacer_ratio` (via `POLICY_SYNC` and piggybacked header `pacer_q8`) and reserves ~8% downlink headroom so ISP/BTS downlink buffers stay nearly empty while gaming + streaming run concurrently.
4. **Adaptive GF(2) XOR Parity FEC (`jiter-math`)**: Decodes & recovers dropped uplink Game UDP packets bit-exact via `InterleavedXorFecDecoder`, and protects downlink Game packets via `InterleavedXorFecEncoder`.

---

## Build & Run Locally

```bash
cd relay
cargo test -- --nocapture
cargo run --release -- --bind 0.0.0.0:51820 --region JKT-1 --mode echo --max-link-mbps 50
```

### Forward Mode (Game / Upstream UDP Target)

```bash
cargo run --release -- \
  --bind 0.0.0.0:51820 \
  --region SG-1 \
  --mode forward \
  --upstream 10.0.0.10:30001 \
  --max-link-mbps 100
```

---

## Docker Build (From Repository Root)

```bash
docker build -f relay/Dockerfile -t jiter-relay:stage3 .
docker run -d --name jiter-relay --restart unless-stopped \
  -p 51820:51820/udp \
  jiter-relay:stage3 --bind 0.0.0.0:51820 --region JKT-1 --mode echo
```

## Recommended Linux VPS Kernel Tuning (Jakarta / Singapore Edge)

```bash
sudo sysctl -w net.core.default_qdisc=fq
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

Then open **Configure Backend / Relay** in the JITER Android app, enter your VPS IP in **JITER Relay Host / IP** and port `51820`, tap **Save**, and tap **GO**.
