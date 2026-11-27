# JITER Core Engine Specification (v2.0)

This specification locks the mathematical contracts, fixed-point register layout, wire frame format, and closed-loop actuator rules shared across:

1. **Python Verification Lab** (`test-lab/simulations/jiter_formulas.py`) — implemented & unit-tested
2. **Android Client (Kotlin PoC → Rust FFI)** — Stage 2
3. **JITER Relay Edge (Jakarta / Singapore)** — Stage 3

---

## 1. Closed-Loop Signal Flow (Every 250 ms)

```text
Raw Probe / Packet RTT (microseconds)
        │
        ▼
[Formula #2] BitwiseEwmaEstimator (RFC 6298 Scaled Integer)
  • Outputs: srtt_us, jitter_us, rto_us, min_rtt_us, bufferbloat_us
  • Guard: invalid / NaN / out-of-order / stale -> UNKNOWN (never 0)
        │
        ▼
[Formula #1] LinearCostScorer + Hard Veto Guardrails
  • Outputs: score_q (0..100), cost_c (0..1), confidence, veto_reasons[]
  • ColorStateMachine: EWMA smoothing + asymmetric hysteresis + 2000ms min dwell
        │
        ▼
[Actuators] AdaptiveController Policy Output
  ├─ 1. Strict Priority Queue + Anti-Bufferbloat Background Pacer (bg_pacer_ratio: 0.15..1.0)
  ├─ 2. [Formula #3] Adaptive Interleaved XOR Parity FEC (GF(2)) for latency-sensitive UDP
  └─ 3. Route Intelligence (Active vs Alternate path with +10pt hysteresis & cooldown)
```

---

## 2. Formula #2 — Scaled Bitwise EWMA Registers (RFC 6298)

To run identically on ARM64 Android CPUs, Rust, and Linux relays with zero floating-point drift and zero small-delta truncation:

- **Input:** `rtt_us: u64` (1 ≤ `rtt_us` ≤ 30,000,000), monotonic `timestamp_ms: i64`.
- **Registers:**
  - `srtt_scaled: u64` = $\text{SRTT}_{\mu\text{s}} \ll 3$ (represents $\alpha = \frac{1}{8} = 2^{-3}$)
  - `rttvar_scaled: u64` = $\text{RTTVAR}_{\mu\text{s}} \ll 2$ (represents $\beta = \frac{1}{4} = 2^{-2}$)
  - `min_rtt_us: u64` = lowest valid RTT on current route (explicitly reset on interface/route switch)
- **Initialization (first valid sample):**
  ```text
  srtt_scaled   = rtt_us << 3
  rttvar_scaled = max(1, rtt_us >> 1) << 2
  min_rtt_us    = rtt_us
  ```
- **Update (subsequent valid samples):**
  ```text
  err           = (rtt_us as i64) - ((srtt_scaled >> 3) as i64)
  srtt_scaled   = (srtt_scaled as i64 + err) as u64
  rttvar_scaled = (rttvar_scaled as i64 + abs(err) - ((rttvar_scaled >> 2) as i64)) as u64
  ```
- **Derived outputs:**
  - `srtt_us = srtt_scaled >> 3`
  - `jitter_us = rttvar_scaled >> 2`
  - `rto_us = (srtt_scaled >> 3) + rttvar_scaled` ($\text{SRTT} + 4 \times \text{RTTVAR}$)
  - `bufferbloat_us = max(0, srtt_us - min_rtt_us)`

> **Why scaling BEFORE shifting is mandatory:** Naive unscaled `srtt += (rtt - srtt) >> 3` truncates any delta smaller than 8 units to `0`, causing estimator lockup. Microsecond fixed-point scaling reproduces RFC 6298 floating-point output to within `< 0.05 ms` using 4 integer instructions.

---

## 3. Formula #1 — Linear Cost Function & Hard Veto Guardrails

### Normalization (0.0 = best, 1.0 = worst)
```text
R   = min(srtt_ms / 200.0, 1.0)
J   = min(jitter_ms / 50.0, 1.0)
P   = min(loss_pct / 10.0, 1.0)
B_n = min(max(bufferbloat_ms, 0.0) / 300.0, 1.0)
W   = clamp(1.0 - (bandwidth_mbps / profile.min_bw_mbps), 0.0, 1.0)   // 0.0 + lower confidence if unknown
```

### Weighted Cost & Quality Score
```text
C = w_R * R + w_J * J + w_P * P + w_B * B_n + w_W * W
Q = 100.0 * (1.0 - C)
```

### Profile Table (Weights Sum to 100%)

| Profile | RTT | Jitter | Loss | Bufferbloat | Bandwidth | `min_bw_mbps` |
|---|---:|---:|---:|---:|---:|---:|
| `Game` | 35% | 30% | 20% | 15% | 0%* | 2.0 Mbps |
| `Browser` | 20% | 15% | 15% | 15% | 35% | 5.0 Mbps |
| `Download` | 10% | 10% | 15% | 25% | 40% | 25.0 Mbps |
| `Streaming` | 15% | 25% | 15% | 20% | 25% | 15.0 Mbps |
| `Social` | 20% | 20% | 20% | 20% | 20% | 5.0 Mbps |
| `SafeBalanced` | 30% | 25% | 20% | 20% | 5% | 5.0 Mbps |

### Non-Compensatory Hard Veto Guardrails
Pure linear scoring suffers from a *compensation trap* (e.g., 20 ms RTT + 10% packet loss still yields `Q = 75.0` under linear weights even though gameplay is broken). Therefore:

| Profile | Fatal Condition | Score Cap | Reason Code |
|---|---|---:|---|
| `Game` | `loss_pct >= 5.0` | `Q <= 45.0` | `VETO_GAME_CRITICAL_LOSS` |
| `Game` | `bufferbloat_ms >= 50.0` | `Q <= 49.0` | `VETO_GAME_BUFFERBLOAT` |
| `Game` | `bandwidth_mbps < 2.0` | `Q <= 45.0` | `VETO_GAME_BELOW_MIN_BW` |
| `Streaming` | `bandwidth_mbps < 6.0` | `Q <= 45.0` | `VETO_STREAMING_STARVED` |
| `Streaming` | `loss_pct >= 5.0` | `Q <= 49.0` | `VETO_STREAMING_LOSS` |

### Anti-Flicker Hysteresis (`ColorStateMachine`)
- Score smoothing: EWMA ($\alpha = 0.35$).
- Transitions require `min_dwell_ms = 2000` (except immediate downgrade to `RED` on `raw Q < 45` or immediate `UNKNOWN` on stale samples):
  - `GREEN → YELLOW`: `< 75.0` | `YELLOW → GREEN`: `>= 82.0`
  - `YELLOW → RED`: `< 48.0` | `RED → YELLOW`: `>= 55.0`

---

## 4. Formula #3 — Interleaved Bitwise XOR Parity FEC ($\text{GF}(2)$)

Operates **inside** the authenticated encrypted tunnel (WireGuard / Noise Protocol) strictly on small latency-sensitive UDP packets (e.g., Game / Voice), never on bulk downloads.

### Wire Frame Layout (8-Byte Header)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          group_id (u32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       orig_len (u16)          |  slot_index   | F |   block_k |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     payload (variable bytes) ...              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- `group_id`: 32-bit wrapping parity group identifier.
- `orig_len`: original payload byte length; XORed across slots inside the parity buffer so variable-length UDP payloads recover **100% bit-exact**.
- `slot_index`: `0 .. block_k - 1` for data packets; `block_k` for parity packet.
- `F` (bit 7): `0 = DATA`, `1 = PARITY`; low 4 bits = `block_k` (`1..15`).

### Latency vs Burst-Resistance Modes
| Mode | `block_k` | `stride` | Bandwidth Overhead | Max Recovery Wait (at 60 pkt/s) | Best Use Case |
|---|---:|---:|---:|---:|---|
| `OFF` | - | - | 0% | 0 ms | Clean link (`loss < 0.3%`) or Bulk Download |
| `XOR_K2_LOW_LAT` | 2 | 1 | +50% (~30 Kbps on Game) | ~16 ms | Ultra-low-latency Game UDP under random loss |
| `XOR_K4_INTERLEAVED` | 4 | 4 | +25% | ~192 ms | Higher-rate streams or bursty 4G/Wi-Fi |
| `DUPLICATE` | 1 | 1 | +100% (~60 Kbps on Game) | 0 ms | Severe burst loss on tiny critical game packets |

---

## 5. Two-Sided Actuation Requirement (Maintaining 5–20 ms)

Because bufferbloat occurs on **both** upload (phone modem/Wi-Fi TX queue) and download (ISP/BTS downlink buffer), maintaining 5–20 ms during concurrent gaming + 1080p streaming requires both endpoints:

1. **Android Client (`JiterVpnService` + TUN):**
   - Classifies flows by UID (`ConnectivityManager.getConnectionOwnerUid` on API 29+) + foreground app profile.
   - Enforces Strict Priority Queue (`GAME > STREAMING > BACKGROUND`) and paces background upload using `bg_pacer_ratio`.
   - Encodes/decodes Adaptive XOR FEC frames for game UDP.
2. **JITER Relay Edge (Jakarta / Singapore VPS):**
   - Applies matching downstream Strict Priority Queue and paces total downlink to ~90–92% of estimated link capacity so ISP/router buffers remain nearly empty.
   - Runs BBR congestion control on TCP/QUIC transport and encodes/decodes Adaptive XOR FEC on the wireless last-mile leg.
3. **Physical Latency Floor (Non-Negotiable):**
   - **Wi-Fi Fiber → Jakarta / Singapore:** 5–20 ms is physically achievable and maintainable under concurrent streaming.
   - **4G LTE:** Radio access floor is ~25–40 ms; JITER locks latency near the ~30 ms floor instead of spiking to 200+ ms.
   - **Distant regions (JP/EU/US):** Speed-of-light fiber propagation (65–180 ms) cannot be broken by any software.
