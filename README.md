# JITER
## Full Technical Blueprint v2.0

**Platform:** Android (Client: Kotlin + C++ + C + Rust) + Swappable Edge Relay (Jakarta / Singapore) + Zero-Config Control Plane (Vercel / Supabase / Node.js)  
**Status:** Blueprint v2.0 + Stage 1–4 + **Stage 5 One-Tap GO UX, Packet-Driven Auto-Detection & Zero-Config Control Plane**  
**Initial release:** No login, zero-config one-tap GO for users, developer-managed Control Plane & hidden 5-tap diagnostics console

JITER is an Android network stability, low-latency, and privacy engine. Its primary interaction stays radically simple: **GO** starts a protected adaptive session and **STOP** ends it. While GO is active, JITER keeps an encrypted tunnel alive, monitors real-time link health via integer bitwise math, classifies active traffic (Game, Streaming, Download, Browser), and applies two-sided queue pacing and adaptive error recovery **without restarting the tunnel**.

> **Engineering honesty:** JITER cannot break the speed of light or cellular radio physics. Maintaining **5–20 ms** is physically achievable on Fiber Wi-Fi to Jakarta/Singapore servers by eliminating *bufferbloat*, *retransmit spikes*, and *suboptimal ISP routing*. On 4G LTE (~25–40 ms radio floor) or distant overseas regions (65–180 ms fiber floor), JITER locks latency near the physical floor instead of letting concurrent streaming/downloads spike ping to 200+ ms.

---

## 1. Product decisions (v2.0)

| Area | v2.0 decision |
|---|---|
| Product name | JITER (formerly NEXUS) |
| Platform | Android 10–16 (API 29+ for UID flow classification) |
| Core mission | Maintain low latency & zero bufferbloat so **Game** and **Streaming** run smoothly together |
| Main controls | **GO / STOP** (idempotent single-tap lifecycle) |
| Login | None in Phase 1 (stateless client; ephemeral WireGuard/Noise key registration with rate limits) |
| Tunnel | Always active while GO is on (Privacy mode); profile switches update policy only, never restart tunnel |
| Routing modes | Explicit user-visible mode: **Privacy Always-Encrypted** vs **Hybrid Adaptive** (compare Native ISP via `VpnService.protect()` vs JITER Relay) |
| Foreground context | Automatic via Android Usage Access (`UsageStatsManager`), never Accessibility Service |
| Android service model | **Single merged `JiterVpnService`** calling `startForeground()` (avoids dual-service lifecycle bugs on Android 14–16) |
| Relay infrastructure | Real UDP VPS in **Jakarta / Singapore** (HTTP-only PaaS free tiers cannot run WireGuard/UDP relays) |
| APK target | ≤15 MB for an ARM64 per-ABI release APK |
| RAM target | ≤60 MB PSS during active session, measured on target device |

---

## 2. Core Technology: 3 Cooperating Mathematical Engines

JITER is built on **three real, industry-proven algorithms** working together in a 250 ms closed loop — separating the **Observer (Eye & Brain)** from the **Actuator (Muscle)**:

```text
[Raw Packet / Probe RTT (µs)]
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. EYE — Formula #2: Scaled Bitwise EWMA (RFC 6298)         │
│    • Jacobson's Algorithm (Linux/Windows/Android kernel)    │
│    • Pure integer bit-shifts (srtt << 3, rttvar << 2)       │
│    • Tracks SRTT, Jitter, RTO, min_RTT, and Bufferbloat     │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. BRAIN — Formula #1: Linear Cost Function + Hard Veto     │
│    • Composite weighted routing metric (EIGRP / SD-WAN)     │
│    • Profile-specific weights (Game / Stream / Download)    │
│    • Non-compensatory Veto caps score on fatal loss/bloat   │
│    • Anti-flicker hysteresis + dwell color state machine    │
└───────┬──────────────────────┬──────────────────────┬───────┘
        │                      │                      │
        ▼                      ▼                      ▼
 [ACTUATOR A]           [ACTUATOR B]           [ACTUATOR C]
 Strict Priority Queue  Formula #3: Adaptive   Smart Route Switch
 + Anti-Bufferbloat     Interleaved XOR FEC    (Native vs Relay)
 Pacer (90-92% link     (Galois Field GF(2))   Switches only on
 pacing keeps ISP       Recovers lost Game     >= +10pt score gain
 queues empty!)         UDP in 0-RTT!          + cooldown window
```

### Formula #1 — Linear Cost Function + Hard Veto Guardrails
Normalizes heterogeneous metrics into unitless costs (`0.0` best → `1.0` worst):

```text
R   = min(SRTT / 200, 1.0)
J   = min(Jitter / 50, 1.0)
P   = min(PacketLoss / 10, 1.0)
B_n = min(max(Bufferbloat, 0) / 300, 1.0)
W   = clamp(1.0 - (Bandwidth_Mbps / Profile_Min_Mbps), 0.0, 1.0)

C   = w_R*R + w_J*J + w_P*P + w_B*B_n + w_W*W
Q   = 100 * (1 - C)
```

- **Hard Veto Guardrail (v2.0 fix):** Pure linear scoring suffers from a *compensation trap* (e.g., 20 ms ping + 10% packet loss still scores `75.0` despite broken gameplay). JITER applies hard score caps when fatal thresholds trip (e.g., `Loss >= 5%` or `Bufferbloat >= 50 ms` in Game mode caps `Q <= 45–49`).

| Parameter | Game | Browser | Download | Streaming | Social | Safe Balanced |
|---|---:|---:|---:|---:|---:|---:|
| RTT | 35% | 20% | 10% | 15% | 20% | 30% |
| Jitter | 30% | 15% | 10% | 25% | 20% | 25% |
| Packet loss | 20% | 15% | 15% | 15% | 20% | 20% |
| Bufferbloat | 15% | 15% | 25% | 20% | 20% | 20% |
| Bandwidth (`W`) | 0%* | 35% | 40% | 25% | 20% | 5% |
| Min BW (`min_bw_mbps`) | 2.0 | 5.0 | 25.0 | 15.0 | 5.0 | 5.0 |

*\*Game assigns 0% linear bandwidth weight but enforces a hard eligibility veto below 2.0 Mbps.*

### Formula #2 — Scaled Bitwise EWMA / Jacobson's Algorithm (RFC 6298)
Uses integer microsecond registers scaled **before** bit-shifting (`<< 3` for $\alpha = \frac{1}{8}$, `<< 2` for $\beta = \frac{1}{4}$), matching Linux kernel `tcp_rtt_estimator`:

```text
err           = rtt_us - (srtt_scaled >> 3)
srtt_scaled  += err
rttvar_scaled += abs(err) - (rttvar_scaled >> 2)
RTO           = (srtt_scaled >> 3) + rttvar_scaled
Bufferbloat   = max(0, (srtt_scaled >> 3) - min_rtt_us)
```

- Prevents naive unscaled bit-shift truncation (`delta < 8` locking at 0).
- Runs in ~4 integer CPU instructions (~1–2 ns in native ARM64) and matches floating-point RFC 6298 to `< 0.05 ms`.

### Formula #3 — Interleaved Bitwise XOR Parity FEC (Galois Field $\text{GF}(2)$)
Protects latency-sensitive Game/Voice UDP packets inside the encrypted tunnel by computing XOR parity across $k$ length-prefixed packets ($P_{\text{xor}} = P_1 \oplus \dots \oplus P_k$).
- If any 1 packet in a group drops on Wi-Fi/4G, the receiver reconstructs it **100% bit-exact without waiting 1 RTT for retransmission**.
- **Adaptive tuning:** Disabled (`OFF`) on clean links and bulk downloads; uses low-wait `k=2` for ultra-low-latency game UDP (~30 Kbps overhead) or **interleaved `stride=4..6`** to survive consecutive wireless burst drops (improving burst recovery from ~19% → ~70% at the same +25% overhead).

Full mathematical & binary framing contract: see [`docs/architecture/core-engine-spec.md`](docs/architecture/core-engine-spec.md).

---

## 3. Realistic Capabilities per Profile (No Mitos)

| Profile | What JITER Actually Does at the Network Layer | Explicit Limitation |
|---|---|---|
| **Game** | Strict Priority Queue (`GAME > STREAM > BG`), anti-bufferbloat background pacing, Adaptive XOR FEC on small UDP, and smart local Relay routing (JKT/SG). | Cannot break speed of light or 4G LTE radio floor (~25–40 ms). |
| **Streaming** | Encrypted tunnel bypasses ISP DPI video throttling; anti-jitter pacing keeps ABR stable at 1080p while preventing background sync spikes. | Cannot increase physical ISP subscription cap. |
| **Download** | Releases background pacer (`bg_pacer_ratio = 1.0`), disables XOR FEC overhead, uses full-throughput queues & BBR congestion control on Relay. | Cannot automatically split HTTPS downloads inside Chrome/Play Store like IDM (TLS end-to-end encryption). Multi-thread HTTP-Range downloading requires a separate optional in-app download module. |

---

## 4. Verified Simulation Benchmark Results (Stage 1 Lab)

Reproducible via `python3 test-lab/simulations/run_experiments.py` (simultaneous **Game 60 pkt/s + 1080p Streaming 8 Mbps + Background Download burst 24 Mbps** + 2.5–3% wireless packet loss):

| Scenario | Mode | Median Game RTT | P95 Game RTT | Final Loss | Streaming 1080p |
|---|---|---:|---:|---:|---:|
| **Wi-Fi Fiber → Jakarta** (11 ms physical floor) | No JITER | 208.2 ms | 210.7 ms | 1.54% | 8.0 Mbps |
| | **With JITER** | **11.0 ms** | **13.0 ms** | **0.64%** | **8.0 Mbps** |
| **Wi-Fi Fiber → Singapore** (16 ms physical floor) | No JITER | 213.2 ms | 215.7 ms | 1.54% | 8.0 Mbps |
| | **With JITER** | **16.0 ms** | **18.0 ms** | **0.64%** | **8.0 Mbps** |
| **Bad ISP Route (65 ms) → Relay SG (17 ms)** | No JITER | 262.2 ms | 264.8 ms | 2.75% | 8.0 Mbps |
| | **With JITER** | **17.1 ms** | 64.1 ms* | **0.70%** | **8.0 Mbps** |
| **4G LTE → Jakarta** (32 ms radio floor) | No JITER | 195.2 ms | 197.8 ms | 2.75% | 8.0 Mbps |
| | **With JITER** | **32.0 ms** | **34.2 ms** | **0.70%** | **8.0 Mbps** |

*\*P95 in Scenario 3 reflects the brief initial warmup window before hysteresis switches from ISP to Relay; post-switch steady-state latency stays locked near 17 ms.*

---

## 5. Android 14–16 Engineering Realities & UX

- **Status-bar indicator (`|`):** Android enforces monochrome tinting on status-bar `smallIcon` across Android 5–16, so arbitrary RGB green/yellow/red status-bar lines are unsupported. JITER uses **distinct icon shapes** in the status bar (solid line = GOOD, dashed = MODERATE, exclamation = DEGRADED) and displays **full Green/Yellow/Red color + Relay RTT + Jitter + Loss + Profile** in the expanded notification and app UI.
- **Single VPN Foreground Service:** `JiterVpnService` owns both the `TUN` interface and `startForeground()` lifecycle, with idempotent `GO`/`STOP` transitions and explicit Android 14+ foreground service types.
- **Mobile battery safety:** Active probing (500 ms–2 s) runs **only when the screen is interactive and traffic is flowing**. When idle or screen-off, probing backs off (30–60 s or passive) to avoid keeping the cellular modem stuck in `RRC_CONNECTED` tail-energy drain.
- **Sideload & Usage Access:** On Android 13+, sideloaded APKs require enabling *Allow restricted settings* in App Info before granting Usage Access. JITER handles missing Usage Access gracefully by falling back to `SafeBalanced` (plus optional manual profile override).
- **Single-runtime discipline:** Phase 1–2 implements the mathematical engine directly in Kotlin (zero JNI/multi-runtime bloat). Rust (`engine-rust/`) is introduced once packet-level TUN scheduling and WireGuard/Noise integration (e.g., BoringTun/GotaTun) justify native zero-copy throughput without stacking Go + Rust runtimes together.

---

## 6. Polyglot Native Stack & Repository Structure

| Language | Responsibility | Characteristics | Location |
|---|---|---|---|
| **C (C11)** | Network engine, zero-copy IPv4/UDP/TCP packet parsing, 8-byte FEC header framing, 64-bit GF(2) XOR kernel | Ultra-lightweight & fast, zero heap allocation | `engine-native/c/` |
| **C++ (C++17)** | Network engine memory management (`PacketPool` slab allocator), 3-tier Strict Priority `TrafficScheduler`, anti-bufferbloat pacer, Android JNI bridge | High performance, flexible, bounded RAM (~384 KB pool) | `engine-native/cpp/`, `android/app/src/main/cpp/` |
| **Rust (2021)** | Mathematical engine (Formulas #1, #2, #3), Hard Veto guardrails, hysteresis, `AdaptiveController`, versioned C-ABI FFI (`jiter_math_ffi.h`) | High performance & memory safety | `engine-rust/` |
| **Kotlin** | Android UI, merged `JiterVpnService`, notifications, Usage Access detector, swappable `BackendConfigStore` & pluggable `EngineAdapter` | Native Android integration | `android/app/src/main/java/com/jiter/app/` |

```text
Jiter/
├── README.md                                 # Blueprint v2.0 & Polyglot Architecture
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml                            # CI: Python + C + C++ + Rust + Cross-compiled Android APK
├── docs/
│   └── architecture/
│       ├── core-engine-spec.md               # Fixed-point, Veto, Hysteresis & XOR FEC wire spec
│       └── relay-wire-protocol.md            # Stage 4 Encrypted Wire Protocol v1 (ECDHE P-256 + ChaCha20-Poly1305)
├── scripts/
│   └── build-rust-android.sh                 # Cross-compiles engine-rust -> libjiter_math.a (arm64-v8a, x86_64)
├── engine-rust/                              # Rust Mathematical Engine + C-ABI FFI
│   ├── Cargo.toml
│   ├── include/jiter_math_ffi.h
│   └── src/{lib,ewma,scoring,fec,controller,ffi}.rs
├── engine-native/                            # C + C++ Native Network Engine
│   ├── Makefile
│   ├── c/{include/jiter_packet.h, src/jiter_packet.c}
│   ├── cpp/{include/jiter_packet_pool.hpp, include/jiter_scheduler.hpp, src/jiter_scheduler.cpp}
│   └── tests/test_native_engine.cpp
├── test-lab/
│   └── simulations/                          # Python Reference Lab & 4 Experiments
├── android/                                  # Kotlin Android App + NDK CMake JNI (libjiter_native.so)
│   ├── app/src/main/cpp/{CMakeLists.txt, jiter_jni.cpp}
│   └── app/src/main/java/com/jiter/app/
│       ├── MainActivity.kt                   # One-Tap GO minimalist UI + 5-tap Hidden Developer Console
│       ├── bridge/{EngineAdapter,NativeEngineBridge}.kt
│       ├── config/{BackendConfig,BackendConfigStore,LanguageManager}.kt
│       ├── relay/{ControlPlaneClient,RelayCrypto,RelayProtocol,RelayTunnelClient}.kt
│       ├── engine/                           # Pure Kotlin fallback implementation
│       ├── vpn/JiterVpnService.kt            # Zero-config bootstrap + Full Internet TUN + Packet Auto-Profile + AEAD
│       ├── context/{AppContextDetector,TrafficAutoProfileDetector,UidFlowClassifier}.kt
│       ├── network/NetworkMonitor.kt
│       ├── notification/StatusNotification.kt
│       └── state/SessionStore.kt
├── control-plane/                            # Stage 5 Zero-Config Control Plane (Vercel / Supabase / Node.js)
│   ├── api/v1/{health.js, session/bootstrap.js}
│   ├── lib/bootstrap-core.js
│   ├── supabase/schema.sql
│   ├── server.js
│   └── test/bootstrap.test.js
└── relay/                                    # Stage 4 JKT/SG Rust Edge Relay (AEAD + Linux /dev/net/tun NAT + XOR FEC)
    ├── Cargo.toml
    ├── Dockerfile
    ├── deploy/{setup-vps.sh, jiter-relay.service}
    ├── src/{lib,main,crypto,tun,protocol,scheduler,session,server}.rs
    └── tests/integration_relay.rs
```

### Run Local Verification

```bash
# 1. C11 + C++17 Native Network Engine tests (gcc / g++)
make -C engine-native clean test

# 2. Rust Mathematical Engine & C-ABI FFI tests (cargo)
(cd engine-rust && cargo test)

# 3. Stage 3 Rust Edge Relay Server & real UDP integration tests
(cd relay && cargo test -- --nocapture)

# 4. Stage 5 Zero-Config Control Plane tests (Node.js >= 18)
npm --prefix control-plane test

# 5. Python Reference Lab unit tests & 4 experiments
python3 -m unittest discover -s test-lab/simulations -p "test_*.py" -v
python3 test-lab/simulations/run_experiments.py
```

---

## 7. Security, Privacy & Threat Model

- **Cryptography:** Use maintained WireGuard / Noise Protocol implementations only — **never custom cryptography**.
- **Leak protection:** Explicit DNS policy and IPv4/IPv6 tunnel routing, tested against DNS/IPv6 leaks before claiming privacy protection.
- **Fail-closed vs fail-open:** User-selectable and explicitly disclosed in UI.
- **Honest privacy boundary:** No-login stateless operation avoids accounts and local history databases, but a relay still observes source IP, session timing, and traffic volume. When Hybrid Native probing (`VpnService.protect()`) is enabled, probe packets reach the probe endpoint over the ISP directly and are disclosed to the user.

---

## 8. Staged Implementation Roadmap

| Stage | Deliverable | Status |
|---|---|---|
| **Stage 1: Blueprint & Math Lab** | Blueprint v2.0, Core Engine Spec, Python reference implementation (#1, #2, #3 + Closed-Loop Controller), unit tests, 4 experiments | **Done** |
| **Stage 2: Polyglot Native Android PoC** | Native **C** packet engine + **C++** slab `PacketPool` & `TrafficScheduler` + **Rust** math engine (`jiter_math_ffi.h`) linked into `libjiter_native.so` + **Kotlin** Android UI/VpnService/Notifications + **Swappable Backend Config** + **Bahasa Indonesia / English live language switcher** + GitHub Actions CI APK build | **Done** |
| **Stage 3: Edge Relay & Live TUN Data-Plane** | Unified 16-byte JITER Wire Protocol v1 (`docs/architecture/relay-wire-protocol.md`) + **Rust JITER Relay Edge (`relay/`)** with RAM-only ephemeral sessions, downstream 3-tier strict-priority pacer, GF(2) XOR FEC recovery, Docker/systemd VPS deploy kit + Android protected UDP `RelayTunnelClient`, live TUN→C/C++→Relay pump, and Formula #1 Native-vs-Relay switching | **Done** |
| **Stage 4: AEAD Encryption, Linux `/dev/net/tun` NAT & Full Internet Tunnel** | Standard **ECDHE P-256 + PSK + HKDF-SHA256 + ChaCha20-Poly1305 AEAD + 64-pkt Anti-Replay** (`FLAG_ENCRYPTED`, verified byte-for-byte between Rust & Android JCA), real Linux `/dev/net/tun` + `TunIpPool` + NAT VPS setup (`relay/deploy/setup-vps.sh`), Android **Full Internet Tunnel (`0.0.0.0/0` + DNS `1.1.1.1`/`8.8.8.8` + IPv6 leak shield `::/0`)**, and API 29+ **UID App Flow Classifier** (`getConnectionOwnerUid`) | **Done** |
| **Stage 5: One-Tap GO UX, Smart Packet Detection & Zero-Config Control Plane** | Ultra-minimalist **One-Tap GO** home screen (all diagnostics & swappable backend controls tucked inside a **5-tap Hidden Developer Console**), **Android OS `ApplicationInfo.category` UID + TUN Packet Auto-Profile Detector** with sticky windows (detects Game, Streaming, Game+Streaming, and Download automatically without Usage Access), and swappable **Control Plane (`control-plane/`)** ready for Vercel/Supabase/Node.js with automatic multi-node failover | **Done** |
| **Stage 6: Device Hardware Profiling & Release Hardening** | Real-device ARM64 release APK profiling (≤15 MB APK, ≤60 MB PSS RAM), Wi-Fi ↔ 4G/5G handoff soak tests, external DNS/IPv6 leak test validation, and signed Play Store / sideload release bundle | Next |
