package com.jiter.app.vpn

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.app.ServiceCompat
import com.jiter.app.bridge.EngineAdapter
import com.jiter.app.bridge.NativeEngineBridge
import com.jiter.app.config.BackendConfig
import com.jiter.app.config.BackendConfigStore
import com.jiter.app.config.FecPolicy
import com.jiter.app.context.AppContextDetector
import com.jiter.app.engine.FecMode
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
 * network sensing, foreground-app profile detection, and the pluggable
 * Rust/C++/C/Kotlin core engine.
 *
 * All backend/relay endpoints, probe hosts, and runtime engine preferences are
 * loaded dynamically from `BackendConfigStore` so operators can swap backends
 * without modifying or recompiling the app.
 */
class JiterVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var statusNotification: StatusNotification
    private lateinit var networkMonitor: NetworkMonitor
    private lateinit var appContextDetector: AppContextDetector

    private val engineLock = Any()
    private var engineAdapter: EngineAdapter? = null

    private var tunInterface: ParcelFileDescriptor? = null
    private var monitorJob: Job? = null

    @Volatile
    private var isRunning: Boolean = false

    @Volatile
    private var manualProfileOverride: TrafficProfile? = null

    @Volatile
    private var activeConfig: BackendConfig = BackendConfig()

    override fun onCreate() {
        super.onCreate()
        activeConfig = BackendConfigStore.ensureLoaded(this)
        statusNotification = StatusNotification(this).apply { ensureChannel() }
        networkMonitor = NetworkMonitor(
            context = this,
            initialProbeHost = activeConfig.probeHost,
            initialProbePort = activeConfig.probePort,
        )
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
            ACTION_RELOAD_CONFIG -> {
                applyBackendConfigLive(BackendConfigStore.ensureLoaded(this))
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

    private fun applyBackendConfigLive(newConfig: BackendConfig) {
        val prevPref = activeConfig.enginePreference
        val prevProbeHost = activeConfig.probeHost
        val prevProbePort = activeConfig.probePort
        activeConfig = newConfig
        networkMonitor.updateProbeEndpoint(newConfig.probeHost, newConfig.probePort)

        val engineLabel = synchronized(engineLock) {
            if (isRunning && prevPref != newConfig.enginePreference) {
                engineAdapter?.close()
                engineAdapter = NativeEngineBridge.createAdapter(newConfig.enginePreference)
            } else if (isRunning && (prevProbeHost != newConfig.probeHost || prevProbePort != newConfig.probePort)) {
                engineAdapter?.resetBaseline(null)
            }
            engineAdapter?.engineLabel ?: newConfig.enginePreference.label
        }

        SessionStore.update { current ->
            current.copy(
                engineRuntimeLabel = engineLabel,
                backendSummary = newConfig.summaryLabel(),
            )
        }
        if (isRunning) {
            statusNotification.updateIfAllowed(SessionStore.snapshot.value, force = true)
        }
    }

    private fun startSessionIdempotent() {
        val cfg = BackendConfigStore.ensureLoaded(this)
        activeConfig = cfg
        networkMonitor.updateProbeEndpoint(cfg.probeHost, cfg.probePort)

        if (isRunning) {
            // Idempotent GO: do not spawn duplicate TUN or loops
            statusNotification.updateIfAllowed(SessionStore.snapshot.value, force = true)
            return
        }

        val adapter = synchronized(engineLock) {
            engineAdapter?.close()
            NativeEngineBridge.createAdapter(cfg.enginePreference).also { engineAdapter = it }
        }

        val startingSnapshot = SessionSnapshot(
            sessionState = SessionState.STARTING,
            qualityState = QualityState.UNKNOWN,
            manualProfileOverride = manualProfileOverride,
            activeProfile = manualProfileOverride ?: TrafficProfile.SAFE_BALANCED,
            networkType = networkMonitor.getNetworkType(),
            engineRuntimeLabel = adapter.engineLabel,
            backendSummary = cfg.summaryLabel(),
            statusDetail = "Initializing TUN interface and ${adapter.engineLabel}...",
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

        val activeInit = startingSnapshot.copy(
            sessionState = SessionState.ACTIVE,
            statusDetail = "TUN active · ${adapter.engineLabel}",
        )
        SessionStore.update { activeInit }
        statusNotification.updateIfAllowed(activeInit, force = true)

        networkMonitor.startObservingNetwork { newType ->
            // Separate Wi-Fi and mobile baselines cleanly when interface changes
            synchronized(engineLock) {
                engineAdapter?.resetBaseline(null)
            }
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
                // Diagnostic virtual subnet only until Stage 3 full-tunnel WireGuard/Noise relay
                // forwarding is connected, keeping normal device connectivity intact during testing.
                .addRoute("10.77.0.0", 24)
                .establish()
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun runClosedLoopMonitor() {
        while (serviceScope.isActive && isRunning) {
            val cfg = activeConfig
            val sample = networkMonitor.runProbe(socketProtector = { sock -> protect(sock) })

            val detected = appContextDetector.detect()
            val effectiveProfile = manualProfileOverride ?: detected.profile

            val stepOut = synchronized(engineLock) {
                val adapter = engineAdapter ?: return@synchronized null
                if (sample.rttMs != null) {
                    adapter.submitRtt(sample.rttMs, sample.timestampMs)
                }
                val res = adapter.step(
                    nowMs = sample.timestampMs,
                    profile = effectiveProfile,
                    lossPct = sample.lossPct,
                    bandwidthMbps = sample.estimatedThroughputMbps,
                    alternateRoute = null, // Swappable relay candidate probes plugged in Stage 3
                )
                Pair(adapter.engineLabel, res)
            } ?: break

            val (runtimeLabel, engineOut) = stepOut
            val baseDecision = engineOut.decision

            // Apply explicit operator FEC policy override from BackendConfig
            val effectiveFec = when (cfg.fecPolicy) {
                FecPolicy.AUTO_ADAPTIVE -> baseDecision.fecMode
                FecPolicy.FORCE_OFF -> FecMode.OFF
                FecPolicy.FORCE_K2_LOW_LAT -> {
                    if (effectiveProfile == TrafficProfile.GAME) FecMode.XOR_K2_INTERLEAVED
                    else FecMode.OFF
                }
            }

            val sessionState = when {
                sample.networkType == "Offline" -> SessionState.DEGRADED
                baseDecision.qualityState == QualityState.RED -> SessionState.DEGRADED
                else -> SessionState.ACTIVE
            }

            val detail = buildString {
                if (sample.networkType == "Offline") {
                    append("No active internet (${cfg.failurePolicy.label})")
                } else if (!detected.hasUsagePermission && manualProfileOverride == null) {
                    append("Usage Access off · Safe Balanced · ${cfg.routingMode.label}")
                } else if (manualProfileOverride != null) {
                    append("Manual profile lock · tunnel uninterrupted")
                } else {
                    append("Auto profile active · tunnel uninterrupted")
                }
            }

            val updated = SessionSnapshot(
                sessionState = sessionState,
                qualityState = baseDecision.qualityState,
                qualityScore = baseDecision.qualityScore,
                srttMs = engineOut.srttMs,
                jitterMs = engineOut.jitterMs,
                bufferbloatMs = engineOut.bufferbloatMs,
                rtoMs = engineOut.rtoMs,
                lossPct = sample.lossPct,
                estimatedThroughputMbps = sample.estimatedThroughputMbps,
                activeProfile = effectiveProfile,
                manualProfileOverride = manualProfileOverride,
                foregroundPackage = detected.foregroundPackage,
                networkType = sample.networkType,
                fecMode = effectiveFec,
                bgPacerRatio = baseDecision.bgPacerRatio,
                selectedRoute = baseDecision.selectedRoute,
                engineRuntimeLabel = runtimeLabel,
                backendSummary = cfg.summaryLabel(),
                lastSampleTimestampMs = SystemClock.elapsedRealtime(),
                statusDetail = detail,
                reasonCodes = baseDecision.reasonCodes,
            )

            SessionStore.update { updated }
            statusNotification.updateIfAllowed(updated)

            val nextDelayMs = computeAdaptiveProbeDelayMs(
                screenInteractive = networkMonitor.isScreenInteractive(),
                qualityState = baseDecision.qualityState,
            )
            delay(nextDelayMs)
        }
    }

    private fun computeAdaptiveProbeDelayMs(
        screenInteractive: Boolean,
        qualityState: QualityState,
    ): Long {
        if (!screenInteractive) {
            return 30_000L // Cellular radio battery backoff when screen is off
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

        synchronized(engineLock) {
            engineAdapter?.close()
            engineAdapter = null
        }
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
        const val ACTION_RELOAD_CONFIG = "com.jiter.app.action.RELOAD_CONFIG"
        const val EXTRA_PROFILE_NAME = "extra_profile_name"
    }
}
