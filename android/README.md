# JITER Android PoC (Stage 2)

Minimalist native Kotlin Android application (`minSdk 29`, `targetSdk 35`, package `com.jiter.app`) implementing:

- **GO / STOP** idempotent session lifecycle in a single merged `JiterVpnService` + Foreground Service (Android 14/15 `specialUse` compliant)
- **Pure Kotlin Core Engine** (`com.jiter.app.engine`):
  - `BitwiseEwmaEstimator` — Formula #2 (RFC 6298 scaled microsecond integer registers)
  - `LinearCostScorer` + `ColorStateMachine` — Formula #1 + Hard Veto guardrails + anti-flicker hysteresis
  - `InterleavedXorFecEncoder` / `InterleavedXorFecDecoder` — Formula #3 ($\text{GF}(2)$ XOR parity with interleaved stride & 8-byte wire framing)
  - `AdaptiveController` — closed-loop coordinator
- **Signature Vertical-Line Indicator (`|`):** Green/Yellow/Red in-app indicator + monochrome shape-coded status-bar icons + rich expanded notification with direct STOP action
- **Foreground App Detection:** `AppContextDetector` via `UsageStatsManager` (never Accessibility Service) with safe `SafeBalanced` fallback and manual profile chips (`Auto` / `Game` / `Streaming` / `Download`) that switch policy **without restarting the tunnel**
- **Battery-Safe Network Monitor:** Bounded probe RTT + rolling packet loss + passive `TrafficStats` throughput + 30 s screen-off cellular backoff

> **Stage 2 PoC Safety Note:** `JiterVpnService` establishes a real Android TUN interface scoped to the diagnostic virtual subnet (`10.77.0.0/24`) so device internet stays unaffected while validating VPN consent, TUN lifecycle, notifications, and live scoring on physical phones prior to Stage 3 WireGuard/Noise relay forwarding.

## Build & Test

### Option A — GitHub Actions (No Local Android Studio Required)
Push or open a PR and download the compiled `jiter-stage2-poc-debug-apk` artifact from the **Actions** tab (`.github/workflows/ci.yml`).

### Option B — Android Studio / Local Gradle
1. Open the `android/` directory in Android Studio (JDK 17, Android SDK 35).
2. Run unit tests:
   ```bash
   cd android
   gradle testDebugUnitTest
   ```
3. Build Debug APK:
   ```bash
   gradle assembleDebug
   # Output: android/app/build/outputs/apk/debug/app-debug.apk
   ```

## Sideloading on Android 13–16
If installing the APK manually outside Play Store, Android restricts Usage Access by default:
1. Open **Settings → Apps → JITER → ⋮ (top right) → Allow restricted settings**.
2. Tap **Grant Usage Access** inside JITER and toggle it on.
