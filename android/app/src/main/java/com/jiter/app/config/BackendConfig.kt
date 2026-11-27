package com.jiter.app.config

enum class RoutingMode(val label: String) {
    PRIVACY_ALWAYS_TUNNEL("Privacy (Always Tunnel)"),
    HYBRID_ADAPTIVE("Hybrid (Native vs Relay)"),
}

enum class FailurePolicy(val label: String) {
    FAIL_OPEN("Fail-Open (Keep Internet)"),
    FAIL_CLOSED("Fail-Closed (Lockdown)"),
}

enum class FecPolicy(val label: String) {
    AUTO_ADAPTIVE("Auto Adaptive"),
    FORCE_OFF("Force OFF"),
    FORCE_K2_LOW_LAT("Force XOR k=2 (Game)"),
}

enum class EngineRuntimePreference(val label: String) {
    AUTO_NATIVE_FIRST("Auto (Rust + C++ + C)"),
    KOTLIN_PURE("Kotlin Pure"),
}

/**
 * Pluggable, non-personal technical backend & engine configuration.
 * All relay, control-plane, probe, and runtime engine settings can be swapped
 * at runtime without hardcoding a single infrastructure provider.
 */
data class BackendConfig(
    val controlPlaneUrl: String = DEFAULT_CONTROL_PLANE_URL,
    val relayHost: String = DEFAULT_RELAY_HOST,
    val relayPort: Int = DEFAULT_RELAY_PORT,
    val probeHost: String = DEFAULT_PROBE_HOST,
    val probePort: Int = DEFAULT_PROBE_PORT,
    val routingMode: RoutingMode = RoutingMode.HYBRID_ADAPTIVE,
    val failurePolicy: FailurePolicy = FailurePolicy.FAIL_OPEN,
    val fecPolicy: FecPolicy = FecPolicy.AUTO_ADAPTIVE,
    val enginePreference: EngineRuntimePreference = EngineRuntimePreference.AUTO_NATIVE_FIRST,
) {
    fun sanitized(): BackendConfig {
        val cleanControl = controlPlaneUrl.trim()
        val cleanRelayHost = relayHost.trim()
        val cleanProbeHost = probeHost.trim().ifEmpty { DEFAULT_PROBE_HOST }
        val cleanRelayPort = relayPort.coerceIn(1, 65535)
        val cleanProbePort = probePort.coerceIn(1, 65535)
        return copy(
            controlPlaneUrl = cleanControl,
            relayHost = cleanRelayHost,
            relayPort = cleanRelayPort,
            probeHost = cleanProbeHost,
            probePort = cleanProbePort,
        )
    }

    fun hasCustomRelay(): Boolean = relayHost.isNotBlank()

    fun summaryLabel(): String = buildString {
        if (hasCustomRelay()) {
            append("Relay: $relayHost:$relayPort")
        } else {
            append("Probe: $probeHost:$probePort")
        }
        append(" · ")
        append(if (routingMode == RoutingMode.PRIVACY_ALWAYS_TUNNEL) "Privacy" else "Hybrid")
    }

    companion object {
        const val DEFAULT_CONTROL_PLANE_URL = ""
        const val DEFAULT_RELAY_HOST = ""
        const val DEFAULT_RELAY_PORT = 51820
        const val DEFAULT_PROBE_HOST = "1.1.1.1"
        const val DEFAULT_PROBE_PORT = 443
    }
}
