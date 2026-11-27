package com.jiter.app.vpn

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.app.ServiceCompat
import com.jiter.app.context.AppContextDetector
import com.jiter.app.engine.AdaptiveController
import com.jiter.app.engine.BitwiseEwmaEstimator
import com.jiter.app.engine.QualityState
import com.jiter.app.engine.SessionSnapshot
import com.jiter.app.engine.SessionState
import com.jiter.app.engine.TrafficProfile
import com.jiter.app.network.NetworkMonitor
import com.jiter.app.notification.StatusNotification
import com.jiter.app.state.SessionStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Single merged VpnService + Foreground Service owning TUN lifecycle,
 * network sensing, foreground-app profile detection, and the 3-formula engine.
 *
 * Stage 2 PoC note: establishes a real Android TUN interface scoped to the
 * diagnostic virtual subnet (10.77.0.0/24) so VPN consent, TUN lifecycle,
 * foreground notification, and live telemetry can be verified on real Android
 * devices without blackholing internet traffic before the Stage 3 Relay exists.
 */
class JiterVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var statusNotification: StatusNotification
    private lateinit var networkMonitor: NetworkMonitor
    private lateinit var appContextDetector: AppContextDetector

    private val ewma = BitwiseEwmaEstimator()
    private val controller = AdaptiveController()

    private var tunInterface: ParcelFileDescriptor? = null
    private var monitorJob: Job? = null

    @Volatile
    private var isRunning: Boolean = false

    @Volatile
    private var manualProfileOverride: TrafficProfile? = null

    override fun onCreate() {
        super.onCreate()
        statusNotification = StatusNotification(this).apply { ensureChannel() }
        networkMonitor = NetworkMonitor(this)
        appContextDetector = AppContextDetector(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopSession()
                return START_NOT_STICKY
            }
            ACTION_SET_PROFILE_OVERRIDE -> {
                val rawName = intent.getStringExtra(EXTRA_PROFILE_NAME)
                manualProfileOverride = rawName?.let { name ->
                    TrafficProfile.entries.firstOrNull { it.name == name }
                }
                // Policy-only update: NEVER restarts the tunnel!
                SessionStore.update { current ->
                    val effective = manualProfileOverride ?: current.activeProfile
                    current.copy(
                        manualProfileOverride = manualProfileOverride,
                        activeProfile = effective,
                    )
                }
                if (isRunning) {
                    statusNotification.updateIfAllowed(SessionStore.snapshot.value, force = true)
                }
                return START_STICKY
            }
            ACTION_START, null -> {
                val rawName = intent?.getStringExtra(EXTRA_PROFILE_NAME)
                if (rawName != null) {
                    manualProfileOverride = TrafficProfile.entries.firstOrNull { it.name == rawName }
                }
                startSessionIdempotent()
                return START_STICKY
            }
            else -> return START_STICKY
        }
    }

    override fun onRevoke() {
        super.onRevoke()
        stopSession()
    }

    override fun onDestroy() {
        stopSessionInternal(callStopSelf = false)
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startSessionIdempotent() {
        if (isRunning) {
            // Idempotent GO: do not spawn duplicate TUN or loops
            statusNotification.updateIfAllowed(SessionStore.snapshot.value, force = true)
            return
        }

        val startingSnapshot = SessionSnapshot(
            sessionState = SessionState.STARTING,
            qualityState = QualityState.UNKNOWN,
            manualProfileOverride = manualProfileOverride,
            activeProfile = manualProfileOverride ?: TrafficProfile.SAFE_BALANCED,
            networkType = networkMonitor.getNetworkType(),
            statusDetail = "Initializing TUN interface and sensors...",
        )
        SessionStore.update { startingSnapshot }
        promoteToForeground(startingSnapshot)

        val pfd = establishPocTun()
        if (pfd == null) {
            val errorSnapshot = startingSnapshot.copy(
                sessionState = SessionState.ERROR,
                statusDetail = "VPN permission revoked or TUN interface unavailable",
            )
            SessionStore.update { errorSnapshot }
            stopSessionInternal(callStopSelf = true)
            return
        }

        tunInterface = pfd
        isRunning = true
        ewma.reset()
        controller.reset()

        val activeInit = startingSnapshot.copy(
            sessionState = SessionState.ACTIVE,
            statusDetail = "TUN active (Stage 2 PoC monitor · Relay wired in Stage 3)",
        )
        SessionStore.update { activeInit }
        statusNotification.updateIfAllowed(activeInit, force = true)

        networkMonitor.startObservingNetwork { newType ->
            // Separate Wi-Fi and mobile baselines cleanly when interface changes
            ewma.resetBaseline(null)
            SessionStore.update { current ->
                current.copy(
                    networkType = newType,
                    statusDetail = "Network switched to $newType — recalibrating baseline",
                )
            }
        }

        monitorJob?.cancel()
        monitorJob = serviceScope.launch {
            runClosedLoopMonitor()
        }
    }

    private fun establishPocTun(): ParcelFileDescriptor? {
        return try {
            Builder()
                .setSession("JITER PoC")
                .setMtu(1280)
                .addAddress("10.77.0.2", 32)
                // Diagnostic virtual subnet only in Stage 2 so device internet stays unaffected
                // until the Stage 3 WireGuard/Noise relay forwarding path is integrated.
                .addRoute("10.77.0.0", 24)
                .establish()
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun runClosedLoopMonitor() {
        while (serviceScope.isActive && isRunning) {
            val sample = networkMonitor.runProbe(socketProtector = { sock -> protect(sock) })

            if (sample.rttMs != null) {
                ewma.update(sample.rttMs, sample.timestampMs)
            }

            val detected = appContextDetector.detect()
            val effectiveProfile = manualProfileOverride ?: detected.profile

            val decision = controller.step(
                nowMs = sample.timestampMs,
                profile = effectiveProfile,
                ewma = ewma,
                lossPct = sample.lossPct,
                bandwidthMbps = sample.estimatedThroughputMbps,
                alternateRouteMetrics = null, // Relay candidate probes plugged in Stage 3
            )

            val sessionState = when {
                sample.networkType == "Offline" -> SessionState.DEGRADED
                decision.qualityState == QualityState.RED -> SessionState.DEGRADED
                else -> SessionState.ACTIVE
            }

            val detail = buildString {
                if (sample.networkType == "Offline") {
                    append("No active internet connection")
                } else if (!detected.hasUsagePermission && manualProfileOverride == null) {
                    append("Usage Access not granted · using Safe Balanced")
                } else if (manualProfileOverride != null) {
                    append("Manual profile lock · tunnel uninterrupted")
                } else {
                    append("Auto profile active · tunnel uninterrupted")
                }
            }

            val updated = SessionSnapshot(
                sessionState = sessionState,
                qualityState = decision.qualityState,
                qualityScore = decision.qualityScore,
                srttMs = ewma.srttMs,
                jitterMs = ewma.jitterMs,
                bufferbloatMs = ewma.bufferbloatMs,
                rtoMs = ewma.rtoMs,
                lossPct = sample.lossPct,
                estimatedThroughputMbps = sample.estimatedThroughputMbps,
                activeProfile = effectiveProfile,
                manualProfileOverride = manualProfileOverride,
                foregroundPackage = detected.foregroundPackage,
                networkType = sample.networkType,
                fecMode = decision.fecMode,
                bgPacerRatio = decision.bgPacerRatio,
                selectedRoute = decision.selectedRoute,
                lastSampleTimestampMs = SystemClock.elapsedRealtime(),
                statusDetail = detail,
                reasonCodes = decision.reasonCodes,
            )

            SessionStore.update { updated }
            statusNotification.updateIfAllowed(updated)

            val nextDelayMs = computeAdaptiveProbeDelayMs(
                screenInteractive = networkMonitor.isScreenInteractive(),
                qualityState = decision.qualityState,
            )
            delay(nextDelayMs)
        }
    }

    private fun computeAdaptiveProbeDelayMs(
        screenInteractive: Boolean,
        qualityState: QualityState,
    ): Long {
        if (!screenInteractive) {
            // Cellular radio battery backoff when screen is off
            return 30_000L
        }
        return when (qualityState) {
            QualityState.GREEN -> 2_000L
            QualityState.YELLOW -> 1_000L
            QualityState.RED, QualityState.UNKNOWN -> 750L
        }
    }

    private fun promoteToForeground(snapshot: SessionSnapshot) {
        val notification = statusNotification.build(snapshot)
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(
            this,
            StatusNotification.NOTIFICATION_ID,
            notification,
            fgsType,
        )
    }

    private fun stopSession() {
        stopSessionInternal(callStopSelf = true)
    }

    private fun stopSessionInternal(callStopSelf: Boolean) {
        isRunning = false
        monitorJob?.cancel()
        monitorJob = null
        networkMonitor.stopObservingNetwork()

        try {
            tunInterface?.close()
        } catch (_: Exception) {
            // Safe idempotent close
        }
        tunInterface = null

        ewma.reset()
        controller.reset()
        manualProfileOverride = null

        // Stateless client: wipe all in-RAM session telemetry on STOP
        SessionStore.clear()
        statusNotification.cancel()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)

        if (callStopSelf) {
            stopSelf()
        }
    }

    companion object {
        const val ACTION_START = "com.jiter.app.action.START"
        const val ACTION_STOP = "com.jiter.app.action.STOP"
        const val ACTION_SET_PROFILE_OVERRIDE = "com.jiter.app.action.SET_PROFILE_OVERRIDE"
        const val EXTRA_PROFILE_NAME = "extra_profile_name"
    }
}
