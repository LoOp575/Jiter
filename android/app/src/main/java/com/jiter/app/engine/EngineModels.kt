package com.jiter.app.engine

import kotlin.math.abs

enum class TrafficProfile(
    val displayName: String,
    val weights: ProfileWeights,
) {
    GAME("Game", ProfileWeights(0.35, 0.30, 0.20, 0.15, 0.00, 2.0)),
    BROWSER("Browser", ProfileWeights(0.20, 0.15, 0.15, 0.15, 0.35, 5.0)),
    DOWNLOAD("Download", ProfileWeights(0.10, 0.10, 0.15, 0.25, 0.40, 25.0)),
    STREAMING("Streaming", ProfileWeights(0.15, 0.25, 0.15, 0.20, 0.25, 15.0)),
    SOCIAL("Social", ProfileWeights(0.20, 0.20, 0.20, 0.20, 0.20, 5.0)),
    SAFE_BALANCED("Safe Balanced", ProfileWeights(0.30, 0.25, 0.20, 0.20, 0.05, 5.0)),
}

data class ProfileWeights(
    val wRtt: Double,
    val wJitter: Double,
    val wLoss: Double,
    val wBloat: Double,
    val wBw: Double,
    val minBwMbps: Double,
) {
    init {
        val total = wRtt + wJitter + wLoss + wBloat + wBw
        require(abs(total - 1.0) <= 1e-6) { "Profile weights must sum to 1.0, got $total" }
        require(minBwMbps > 0.0) { "minBwMbps must be positive" }
    }
}

enum class QualityState {
    UNKNOWN,
    GREEN,
    YELLOW,
    RED,
}

enum class FecMode(val label: String) {
    OFF("OFF"),
    XOR_K4_INTERLEAVED("XOR k=4"),
    XOR_K2_INTERLEAVED("XOR k=2"),
    DUPLICATE("DUP x2"),
}

enum class RouteChoice(val label: String) {
    NATIVE("Native ISP"),
    RELAY("JITER Relay"),
}

enum class SessionState(val label: String) {
    STOPPED("STOPPED"),
    STARTING("STARTING"),
    CONNECTING("CONNECTING"),
    ACTIVE("CONNECTED"),
    DEGRADED("DEGRADED"),
    RECOVERING("RECOVERING"),
    STOPPING("STOPPING"),
    ERROR("ERROR"),
}

data class RouteMetrics(
    val srttMs: Double,
    val jitterMs: Double,
    val lossPct: Double,
    val bufferbloatMs: Double,
)

data class ScoreResult(
    val scoreQ: Double,
    val costC: Double,
    val confidence: Double,
    val vetoReasons: List<String>,
    val componentR: Double,
    val componentJ: Double,
    val componentP: Double,
    val componentB: Double,
    val componentW: Double,
)

data class ControlDecision(
    val qualityScore: Double?,
    val qualityState: QualityState,
    val fecMode: FecMode,
    val bgPacerRatio: Double,
    val selectedRoute: RouteChoice,
    val confidence: Double,
    val reasonCodes: List<String>,
)

data class SessionSnapshot(
    val sessionState: SessionState = SessionState.STOPPED,
    val qualityState: QualityState = QualityState.UNKNOWN,
    val qualityScore: Double? = null,
    val srttMs: Double? = null,
    val jitterMs: Double? = null,
    val bufferbloatMs: Double? = null,
    val rtoMs: Double? = null,
    val lossPct: Double? = null,
    val estimatedThroughputMbps: Double? = null,
    val activeProfile: TrafficProfile = TrafficProfile.SAFE_BALANCED,
    val manualProfileOverride: TrafficProfile? = null,
    val detectionSource: String = "Standby",
    val concurrentStreamingDetected: Boolean = false,
    val foregroundPackage: String? = null,
    val networkType: String = "Unknown",
    val fecMode: FecMode = FecMode.OFF,
    val bgPacerRatio: Double = 1.0,
    val selectedRoute: RouteChoice = RouteChoice.NATIVE,
    val engineRuntimeLabel: String = "Auto (Rust + C++ + C)",
    val backendSummary: String = "Probe: 1.1.1.1:443 · Hybrid TUN",
    val controlPlaneActive: Boolean = false,
    val localShaperActive: Boolean = false,
    val localActiveFlows: Int = 0,
    val localPacedBytes: Long = 0L,
    val relayConnected: Boolean = false,
    val relayEncrypted: Boolean = false,
    val fullInternetTunnelActive: Boolean = false,
    val assignedTunnelIp: String? = null,
    val relayRegion: String? = null,
    val relayRttMs: Double? = null,
    val tunTxPackets: Long = 0L,
    val tunRxPackets: Long = 0L,
    val fecRecoveredPackets: Long = 0L,
    val rttHistoryMs: List<Double> = emptyList(),
    val lastSampleTimestampMs: Long? = null,
    val statusDetail: String = "Idle — tap GO to start JITER session",
    val reasonCodes: List<String> = emptyList(),
)
