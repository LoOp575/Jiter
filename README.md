# JITER
## Full Technical Blueprint v1.2

**Platform:** Android  
**Status:** Product and engineering blueprint  
**Initial release:** No login, stateless client

JITER is an Android application concept for network stability and privacy. Its primary interaction is simple: **GO** starts a session and **STOP** ends it. While GO is active, an encrypted tunnel remains active. JITER detects the foreground app (with user-granted permission) and adapts its profile without restarting the tunnel.

> **Important:** Formula weights, thresholds, and performance figures below are engineering hypotheses or acceptance targets, not proven results. JITER cannot guarantee lower ping. A tunnel can improve or worsen latency depending on ISP routing, relay location/load, destination, radio conditions, and congestion.

---

## 1. Product decisions

| Area | v1 decision |
|---|---|
| Product name | JITER (NEXUS is the former name) |
| Platform | Android |
| Focus | Network stability and privacy |
| Main controls | GO / STOP |
| Login | None in phase one |
| Client | Stateless; temporary session state in RAM |
| Tunnel | Always active while GO is on; app-context changes must not restart it |
| Context detection | Automatic, with explicit Android permission |
| Routing | Hybrid: native route and encrypted relay, selected only when measurements justify it |
| APK target | ≤15 MB for an ARM64 per-ABI release APK |
| RAM target | ≤60 MB PSS during active session, measured on target device |
| Backend | Start with low-cost/free infrastructure after verifying limits and availability |

## 2. User experience and status indicator

### GO / STOP flow

1. User taps GO.
2. Android displays VPN consent when required.
3. JITER starts its foreground service, network sensors, and tunnel.
4. If Usage Access is granted, JITER detects the foreground app and chooses a profile.
5. Profile changes update engine policy without restarting the tunnel.
6. STOP closes the tunnel, stops session sensors, and clears session state.

### Single-line indicator

The agreed visual is one vertical line, |, not multiple signal bars:

- **Green:** good / stable.
- **Yellow:** moderate / changing.
- **Red:** poor / unstable.

Android and OEM skins do not consistently allow arbitrary custom colored status-bar icons. The collapsed notification area is constrained. The exact one-line indicator must be prototyped on the target Android device. If unsupported, use the closest reliable notification icon and show details in the expanded notification.

### Notification information

- Tunnel state: CONNECTED, CONNECTING, DEGRADED, or DISCONNECTED.
- **Relay RTT**, explicitly distinguished from game/server ping.
- Jitter, packet loss, active foreground profile, and sample freshness.
- A small sparkline may appear in the expanded notification if supported. Do not depend on a graph in the status bar.

## 3. Architecture

| Layer | Technology | Responsibilities |
|---|---|---|
| Android Core | Kotlin | UI, GO/STOP, VpnService, foreground service, notification, permissions, lifecycle, foreground-app detection |
| Network Engine | Rust | Sample validation, estimators, scoring, route intelligence, adaptive controller |
| Tunnel | WireGuard | Established encrypted tunnel and cryptographic protocol |
| Test Lab | Python | Formula simulation, data replay, benchmark analysis |
| Build/configuration | Gradle Kotlin DSL, XML | Android build, manifest, permissions, resources |

**Data flow:** Android Network Monitor → Sensor / Processor → Mathematical Engine → Route Intelligence → Adaptive Controller → Android / tunnel policy. The Privacy Engine enforces tunnel, DNS, IPv6, and configuration-security policy.

### Suggested repository structure

    jiter/
    ├── android/
    │   └── app/src/main/
    │       ├── java/.../jiter/
    │       │   ├── MainActivity.kt
    │       │   ├── service/JiterForegroundService.kt
    │       │   ├── vpn/JiterVpnService.kt
    │       │   ├── notification/StatusIndicator.kt
    │       │   ├── context/AppContextDetector.kt
    │       │   ├── network/NetworkMonitor.kt
    │       │   └── bridge/EngineBridge.kt
    │       ├── res/
    │       └── AndroidManifest.xml
    ├── engine-rust/
    │   ├── src/lib.rs
    │   ├── src/sensor/
    │   ├── src/processor/
    │   ├── src/scoring/
    │   ├── src/route/
    │   ├── src/controller/
    │   └── Cargo.toml
    ├── tunnel/integration-notes/
    ├── test-lab/simulations/
    ├── test-lab/benchmark/
    ├── docs/architecture/
    ├── docs/threat-model/
    └── scripts/

This is a proposed layout, not a claim that these source files already exist. Package namespace, application ID, relay domain, API endpoints, and server identity remain undecided.

## 4. Languages and tools

| Language / technology | Extension | Role |
|---|---|---|
| Kotlin | .kt | Native Android app, services, VPN lifecycle, notifications, permissions |
| Rust | .rs | Network engine, estimators, scoring, adaptive controller |
| WireGuard | Library integration | Encrypted tunnel; do not invent cryptography |
| C/C++ (optional) | .c, .cpp, .h | NDK/JNI only if a dependency requires it |
| Gradle Kotlin DSL | .gradle.kts | Build and dependency configuration |
| XML | .xml | Manifest, permissions, resources |
| Python | .py | Offline simulation and benchmark analysis; not shipped in APK |
| Shell | .sh | Build and test automation |

**Implementation recommendation:** prove Android VPN service, notification, lifecycle, and resource use in Kotlin first. Add Rust after the engine contract and performance need are clear. Keep JNI/FFI narrow and versioned.

## 5. Foreground app detection and adaptive profiles

Use Android Usage Access / UsageStatsManager where supported, with clear user explanation and consent. Do not use Accessibility Service solely to detect the foreground app.

| Foreground category | Profile | Priority |
|---|---|---|
| Game | Low Latency | RTT, jitter, loss; still enforce minimum bandwidth eligibility |
| Browser | Responsive | Responsiveness and adequate throughput |
| Download | High Throughput | Capacity and transfer stability |
| Streaming | Stable Throughput | Low jitter and sufficient throughput |
| Social | Balanced | General-purpose balance |
| Unknown | Safe Balanced | Conservative fallback |

Changing profile changes policy only. It must not restart the tunnel.

## 6. Network sensing and data processing

### N01: Network Sensor

Collect, when available and appropriate:

- RTT to a controlled probe endpoint or relay.
- Jitter / RTT variation.
- Packet loss from sent and missing probes.
- Throughput or capacity estimates without disruptive background tests.
- DNS lookup latency.
- Idle RTT and loaded RTT for bufferbloat estimation.
- Network type, relay health, and timestamps.

### N02: Data Processor

- Every sample carries timestamp, unit, source, and validity.
- Reject invalid, non-finite, duplicate, or out-of-range values.
- Missing or stale data is UNKNOWN, never silently treated as zero.
- Keep Wi-Fi and mobile baselines separate.
- Apply bounded timeouts and retries.
- Adapt sampling interval to network state.

Suggested initial sampling: stable 2 s, changing 1 s, unstable 500 ms, idle 5 s. These are test parameters, not fixed truths. Notification refresh should be slower than sensor sampling.

## 7. Mathematical engine (initial model)

The engine normalizes metrics with different units into costs. Lower cost means better conditions. Constants and weights require empirical calibration.

### 7.1 Smoothed RTT

    SRTT_t = 0.875 × SRTT_(t-1) + 0.125 × RTT_t

Initialize from a valid measurement, not an artificial zero.

### 7.2 Jitter estimator

    D_t = |RTT_t - SRTT_(t-1)|
    J_t = 0.75 × J_(t-1) + 0.25 × D_t

This is a deviation-based RTT variation estimator. Document probe interval and outlier handling.

### 7.3 Packet loss

    PacketLoss(%) = (lost probes / sent probes) × 100

Use a defined measurement window and minimum sample count. Low sample counts should carry low confidence.

### 7.4 Bufferbloat estimate

    B = RTT_loaded - RTT_idle

A large positive value indicates latency growth under load. Loaded tests must be bounded so they do not consume excessive data or disrupt the user.

### 7.5 Initial normalization

    R   = min(SRTT / 200, 1)
    J   = min(Jitter / 50, 1)
    P   = min(PacketLoss / 10, 1)
    B_n = min(max(B, 0) / 300, 1)

The 200 ms, 50 ms, 10%, and 300 ms scales are starting assumptions and must be calibrated.

### 7.6 JITER ARC v1 score

    C = 0.30R + 0.25J + 0.20P + 0.20B_n + 0.05W
    Q = 100 × (1 - C)

W is a normalized bandwidth penalty based on each profile's minimum throughput requirement. More bandwidth is not always better; model whether the connection meets the use-case requirement. A Game profile may assign bandwidth zero weight in the score while still enforcing a minimum feasibility threshold.

### 7.7 Illustrative profile weights

| Parameter | Game | Browser | Download | Streaming |
|---|---:|---:|---:|---:|
| RTT | 35% | 20% | 10% | 15% |
| Jitter | 30% | 15% | 10% | 25% |
| Packet loss | 20% | 15% | 15% | 15% |
| Bufferbloat | 15% | 15% | 25% | 20% |
| Bandwidth | 0%* | 35% | 40% | 25% |

*Game still requires a minimum bandwidth eligibility check. Weights per profile must total 100%.

## 8. Color engine and anti-flicker

- Smooth input score using moving average or EWMA.
- Use hysteresis so entering a poor state and recovering do not share an identical threshold.
- Apply minimum dwell time before changing color.
- If samples become stale, show UNKNOWN or DEGRADED; do not leave a misleading green state.
- Keep diagnostic reasons in temporary session memory only unless a separately consented diagnostic feature is introduced.

## 9. Route intelligence

Compare only routes that are actually available and measurable:

1. Native ISP route as baseline.
2. Alternative Wi-Fi or mobile network when permitted by the system and user.
3. Encrypted JITER relay route.

Do not select a relay based on geographic distance alone. Compare device-to-relay RTT, relay health and load, packet loss, capacity, and destination-relevant measurements where possible.

Android and the ISP do not give an app unrestricted control over arbitrary native internet routes. VpnService controls traffic included in the VPN; it does not grant universal control over carrier routing.

## 10. Adaptive controller and traffic scheduler

### N05: Adaptive Controller

- Consume score, confidence, sample age, tunnel state, and foreground context.
- Select policy using hysteresis and cooldown.
- Avoid rapid oscillation.
- Expose stable reason codes for decisions.
- Fall back to Safe Balanced when measurements are insufficient or the engine fails.

### N07: Traffic Scheduler constraints

The scheduler can shape queues and traffic JITER actually controls. VpnService does not automatically provide per-packet QoS for every application UID. A TUN interface does not trivially expose the originating UID for each packet.

Do not promise universal app prioritization. Limit claims to tested policy changes, internal queue management, and traffic JITER demonstrably controls.

## 11. Privacy engine and tunnel

Basic topology:

    Android JITER Client
            |
        VPNService / TUN
            |
     Encrypted WireGuard Tunnel
            |
         JITER Relay
            |
          Internet

Security requirements:

- Use a maintained WireGuard implementation and authenticated peers.
- Do not create custom encryption or cryptographic protocols.
- Define DNS policy and explicitly handle IPv4 and IPv6.
- Test DNS and IPv6 leaks for every configuration claimed as protected.
- Validate relay configuration and protect keys.
- Minimize diagnostic logs and retention.
- Make tunnel failure behavior explicit.

**Privacy limitation:** no-login does not mean total anonymity. A relay may see source IP, connection time, traffic volume, and DNS/destination metadata depending on configuration. HTTPS protects application payload end-to-end, but does not hide all metadata.

### Fail-closed vs fail-open

- **Fail-closed / lockdown:** can prevent traffic escaping outside the tunnel, but may leave the user without internet while the tunnel recovers.
- **Fail-open:** may preserve connectivity but can allow traffic outside the tunnel.

The selected behavior must be disclosed, user-approved, and tested.

## 12. Stateless client and data handling

- No account, password, or server-side user profile.
- No persistent local usage-history database.
- Current session metrics and context remain in RAM.
- STOP ends probes, closes the tunnel, and clears session state.
- Keep required non-personal technical configuration minimal and documented.

Android, the operating system, or relay operator may retain operational metadata outside the app's direct control. Distinguish between data JITER itself does not store and metadata the OS or relay may process.

## 13. Android services and lifecycle

- VpnService owns the TUN and VPN lifecycle.
- A foreground service maintains an active session with a persistent notification, subject to Android version requirements.
- Handle permission revocation, process death, Wi-Fi/mobile changes, relay loss, and recovery.
- Avoid permanent wakelocks; use only when measured necessity justifies them.
- Make GO and STOP idempotent: repeated GO must not create duplicate services, and STOP must be safe after an unexpected disconnect.
- Rate-limit notification updates independently of sensor sampling.

## 14. State machine

| State | Meaning | Expected behavior |
|---|---|---|
| STOPPED | Inactive | No session tunnel or sensors |
| STARTING | Initializing | Request consent and prepare service |
| CONNECTING | Tunnel setup | Validate peer and handshake |
| ACTIVE | Normal operation | Sensors and engine active |
| DEGRADED | Quality degraded | Report state and evaluate fallback |
| RECOVERING | Recovery attempt | Bounded retries; no infinite loop |
| STOPPING | Ending session | Close tunnel and clear state |
| ERROR | Failed | Explain reason and return safely to STOPPED |

All transitions should be idempotent and have explicit timeout/error behavior.

## 15. Performance targets and acceptance criteria

These are goals to test, not achieved results.

| Metric | Initial target | Verification |
|---|---|---|
| APK size | ≤15 MB, ARM64 per-ABI | Release APK size |
| RAM | ≤60 MB PSS while active | Android Profiler / dumpsys meminfo |
| Cold start | ≤3 s | Repeated cold-start measurements |
| Throughput | ≥90% of baseline under equivalent conditions | Repeated baseline vs tunnel tests |
| Stability | 1 h without crash; 8 h without sustained memory growth | Soak test |
| Network switching | Recover without crash | Wi-Fi ↔ mobile test |
| Privacy | DNS/IPv6 leak tests pass for claimed configuration | Dedicated leak tests |
| Battery | No aggressive idle polling | Energy use per hour |

APK size depends on ABI, native libraries, symbols, and packaging. PSS depends on OS and device. Neither target should be claimed until measured.

## 16. Benchmark plan

Compare three modes:

1. **Baseline:** JITER off.
2. **Monitoring only:** sensors active, no tunnel.
3. **Tunnel active:** tunnel and engine active.

Test Wi-Fi and mobile separately across idle, browsing, streaming, download, and game-like traffic. Include weak signal, congestion, and controlled packet loss. Record RTT, jitter, packet loss, throughput, bufferbloat, CPU, PSS, battery, device, Android version, operator, relay, and test conditions.

Report median and p95, not only the best run. A single session is not sufficient evidence.

## 17. Kotlin ↔ Rust interface contract

Use a small, versioned JNI/FFI boundary. Do not pass complex Android objects into Rust.

| Direction | Example fields | Rules |
|---|---|---|
| Kotlin → Rust | timestamp_ms, network_type, rtt_ms, jitter_ms, loss_pct, relay_state, foreground_profile | Explicit units; nullable when unavailable |
| Rust → Kotlin | quality_score, quality_state, selected_policy, confidence, reason_code, engine_version | Validated values and stable reason codes |
| Lifecycle | start_session, submit_sample, update_context, stop_session | Idempotent operations and defined errors |

Every metric needs a timestamp or age. Missing data must never be silently converted to zero. Contract changes require a version update.

## 18. Threat model

| Threat | Primary mitigation |
|---|---|
| Untrusted relay / peer | WireGuard peer authentication and configuration validation |
| DNS or IPv6 leak | Explicit DNS policy, IPv6 routing, leak tests |
| Modified configuration | Integrity checks and schema validation |
| Excessive metadata logging | Data minimization and short retention |
| Tunnel failure | Explicit fail-open/closed policy and recovery states |
| Permission misuse | Minimum permissions and clear user explanation |

The threat model must state what JITER protects, against whom, and what it cannot protect. Avoid claims such as “100% anonymous” or “impossible to intercept.”

## 19. Implementation roadmap

| Phase | Work | Exit criteria |
|---|---|---|
| 0. Specification | Freeze requirements, permissions, threat model, notification design | No critical ambiguity |
| 1. Android PoC | GO/STOP, basic VpnService, foreground notification | Lifecycle works on target device |
| 2. Sensor baseline | RTT, jitter, loss, timestamps, validation | Repeatable measurements |
| 3. Tunnel PoC | WireGuard with one relay, DNS/IPv6 policy | Stable tunnel and leak tests pass |
| 4. Engine | Scoring, hysteresis, profiles, fallback | Unit and replay tests pass |
| 5. ACD | Usage Access and profile mapping | Profile changes without tunnel restart |
| 6. Optimization | APK, RAM, CPU, battery | Targets measured |
| 7. Beta | Soak tests across devices/networks | No critical defects; limitations documented |

## 20. Main technical risks

- Custom colored status-bar line may be restricted by Android/OEM; prototype early and provide a notification fallback.
- A relay adds a network hop and may increase RTT; compare with native route and avoid forcing a worse route.
- Foreground-app detection depends on permission and OS behavior; provide a safe Unknown profile.
- VpnService does not automatically provide per-UID QoS; keep scheduler claims narrow and testable.
- Free cloud tiers can have quotas, sleep, or policy changes; do not treat free infrastructure as an always-on SLA.
- Native libraries may exceed APK/RAM goals; profile actual release builds.

## 21. Open engineering decisions

- Can the single-line colored indicator be rendered consistently on the target Android device?
- Where will the first relay run, and who operates it?
- How will peer configuration be provisioned, rotated, and revoked without user accounts?
- Will initial route selection be automatic or advisory?
- Which profile weights and thresholds correlate with real user experience?
- Which tunnel failure policy (fail-closed or fail-open) will be selected?
- Can the selected WireGuard integration meet the APK and PSS targets?

## 22. Recommended build order

1. Build a minimal Kotlin prototype for GO/STOP, VpnService, and notification lifecycle.
2. Measure APK size, PSS, CPU, battery, and Android 13 behavior on the target device.
3. Add RTT sensing and timestamp validation; build baseline datasets.
4. Integrate one WireGuard relay and run DNS/IPv6 leak tests.
5. Implement and calibrate formulas in Python replay tests before porting selected logic to Rust.
6. Add Rust through a narrow JNI contract.
7. Add foreground-app detection and verify profile changes do not restart the tunnel.
8. Run comparative benchmarks and revise targets based on evidence.

## 23. Technical references to consult

- Android Developers: VpnService API and VPN implementation guidance.
- Android Developers: foreground services and notification channels.
- Android Developers: UsageStatsManager and Usage Access.
- WireGuard official protocol and implementation documentation.
- Rust FFI / JNI integration and memory-safety documentation.
- Android Studio Profiler, Memory Profiler, Network Inspector, and device testing tools.

Re-check official documentation during implementation because Android permissions, foreground-service requirements, target SDK rules, and distribution policies can change.

---

## Project status

This README is the **JITER v1.2 blueprint**, not a statement that the Android app, relay, API, or source-code modules have already been implemented. The next engineering milestone is the Kotlin Android proof of concept.
