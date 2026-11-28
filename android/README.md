# JITER Android PoC (Polyglot Native: Kotlin + C++ + C + Rust)

Native Android application (`minSdk 29`, `targetSdk 35`, package `com.jiter.app`) combining all four layers cleanly:

- **Kotlin (`com.jiter.app`):** Ultra-minimalist **One-Tap GO** UI with live Bahasa Indonesia / English switcher (`ID`/`EN`), signature vertical-line `|` indicator, **5-tap Hidden Developer Console** (`JITER` title) containing full live telemetry and runtime-swappable `BackendConfigStore`, zero-config `ControlPlaneClient` bootstrap with multi-node failover, **Packet-Driven `TrafficAutoProfileDetector`** + Android OS Category `UidFlowClassifier` (zero Usage Access required to detect Game/Streaming/Download!), and **Stage 6 Hybrid `JiterVpnService`** supporting both **Mode A: Full AEAD Relay (`0.0.0.0/0` + DNS/IPv6 shield + ChaCha20-Poly1305)** and **Mode B: `LocalTrafficShaper` (`0.0.0.0/0` non-blocking UDP NAT + Rust `smoltcp` TCP + TCP Background Pacer, zero VPS required!)**.
- **C (`engine-native/c/`):** Zero-copy IPv4/UDP/TCP packet parser, traffic-tier classifier, 16-byte JITER Relay Wire Protocol v1 codec, 8-byte XOR FEC wire header pack/unpack, and 64-bit aligned GF(2) XOR kernel.
- **C++ (`engine-native/cpp/`, `src/main/cpp/jiter_jni.cpp`):** Fixed-capacity slab `PacketPool` (~384 KB bounded RAM, zero heap allocations on hot path), 3-tier Strict Priority `TrafficScheduler` + anti-bufferbloat background pacer wired live to the TUN pump via JNI.
- **Rust (`engine-rust/` & `relay/`):** Memory-safe Formulas #1, #2, #3 + `AdaptiveController` + **Stage 6 transparent user-space TCP stack (`smoltcp`, `any_ip = true`)** linked into `libjiter_native.so` via C-ABI FFI (`jiter_math_ffi.h`), plus the standalone Stage 4 **JITER Edge Relay Server** (`relay/`).

## Build & Test

### Option A — GitHub Actions (Full C + C++ + Rust + Kotlin APK Automatically)
Push or open a PR and download `jiter-native-polyglot-debug-apk` from the **Actions** tab (`.github/workflows/ci.yml`). It cross-compiles Rust (`arm64-v8a`, `x86_64`), links C + C++ + Rust into `libjiter_native.so`, runs all unit tests, and packages `app-debug.apk`.

### Option B — Local Android Studio / CLI
1. *(Optional, to enable native Rust math inside `libjiter_native.so`)*:
   ```bash
   rustup target add aarch64-linux-android x86_64-linux-android
   ./scripts/build-rust-android.sh arm64-v8a,x86_64
   ```
   *(If skipped, CMake still builds the C + C++ network engine and the app automatically uses pure Kotlin math fallback).*
2. Build & test Android app:
   ```bash
   cd android
   gradle testDebugUnitTest assembleDebug
   # Output: android/app/build/outputs/apk/debug/app-debug.apk
   ```

## Sideloading on Android 13–16
If installing manually outside Play Store:
1. Open **Settings → Apps → JITER → ⋮ → Allow restricted settings**.
2. Tap **Grant Usage Access** inside JITER and toggle it on.
3. Tap **Configure Backend / Relay** anytime in JITER to swap Relay Host/Port, Control Plane URL, Probe Host, or Engine Backend without reinstalling.
