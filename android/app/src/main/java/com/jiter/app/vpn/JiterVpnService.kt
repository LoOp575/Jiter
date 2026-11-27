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
import com.jiter.app.config.FailurePolicy
import com.jiter.app.config.FecPolicy
import com.jiter.app.config.RoutingMode
import com.jiter.app.context.AppContextDetector
import com.jiter.app.engine.FecMode
import com.jiter.app.engine.QualityState
import com.jiter.app.engine.RouteChoice
import com.jiter.app.engine.SessionSnapshot
import com.jiter.app.engine.SessionState
import com.jiter.app.engine.TrafficProfile
import com.jiter.app.network.NetworkMonitor
import com.jiter.app.notification.StatusNotification
import com.jiter.app.relay.RelayTunnelClient
import com.jiter.app.state.SessionStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Single merged VpnService + Foreground Service owning:
 *  - TUN lifecycle & live IPv4 data-plane pump (C parser + C++ slab pool/scheduler)
 *  - Stage 3 Protected UDP JITER Relay Client (HELLO, PROBE, POLICY_SYNC, XOR FEC DATA)
 *  - Network sensing, foreground-app profile detection, and Rust/C++/C/Kotlin engine
 *
 * All backend/relay endpoints, probe hosts, and runtime engine preferences are
 * loaded dynamically from `BackendConfigStore` so operators can swap backends
 * at runtime without restarting the TUN interface.
 */
class JiterVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var statusNotification: StatusNotification
    private lateinit var networkMonitor: NetworkMonitor
    private lateinit var appContextDetector: AppContextDetector
    private lateinit var relayClient: RelayTunnelClient

    private val engineLock = Any()
    private val tunWriteLock = Any()

    private var engineAdapter: EngineAdapter? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var tunOutStream: FileOutputStream? = null

    private var monitorJob: Job? = null
    private var tunPumpJob: Job? = null

    private val relayReconnectNeeded = AtomicBoolean(false)
    private val localTunTxCount = AtomicLong(0L)

    @Volatile
    private var isRunning: Boolean = false

    @Volatile
    private var manualProfileOverride: TrafficProfile? = null

    @Volatile
    private var activeConfig: BackendConfig = BackendConfig()

    @Volatile
    private var currentFecMode: FecMode = FecMode.OFF

    @Volatile
    private var currentBgPacerRatio: Double = 1.0

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
        relayClient = RelayTunnelClient(
            onDownlinkPacket = { payload -> writeDownlinkPacketToTun(payload) },
        )
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
        val prevRelayHost = activeConfig.relayHost
        val prevRelayPort = activeConfig.relayPort

        activeConfig = newConfig
        networkMonitor.updateProbeEndpoint(newConfig.probeHost, newConfig.probePort)

        if (prevRelayHost != newConfig.relayHost || prevRelayPort != newConfig.relayPort) {
            relayReconnectNeeded.set(true)
        }

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
            statusNotification.updateIfAllowed(SessionStore.snapshot.value, force = true)
            return
        }

        val adapter = synchronized(engineLock) {
            engineAdapter?.close()
            NativeEngineBridge.createAdapter(cfg.enginePreference).also { engineAdapter = it }
        }

        localTunTxCount.set(0L)
        currentFecMode = FecMode.OFF
        currentBgPacerRatio = 1.0
        relayReconnectNeeded.set(cfg.hasCustomRelay())

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

        val pfd = establishTun()
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
        synchronized(tunWriteLock) {
            tunOutStream = FileOutputStream(pfd.fileDescriptor)
        }
        isRunning = true

        val activeInit = startingSnapshot.copy(
            sessionState = SessionState.ACTIVE,
            statusDetail = "TUN active · ${adapter.engineLabel}",
        )
        SessionStore.update { activeInit }
        statusNotification.updateIfAllowed(activeInit, force = true)

        networkMonitor.startObservingNetwork { newType ->
            synchronized(engineLock) {
                engineAdapter?.resetBaseline(null)
            }
            if (activeConfig.hasCustomRelay()) {
                relayReconnectNeeded.set(true)
            }
            SessionStore.update { current ->
                current.copy(
                    networkType = newType,
                    statusDetail = "Network switched to $newType — recalibrating baseline",
                )
            }
        }

        tunPumpJob?.cancel()
        tunPumpJob = serviceScope.launch {
            runTunDataPlanePump(pfd)
        }

        monitorJob?.cancel()
        monitorJob = serviceScope.launch {
            runClosedLoopMonitor()
        }
    }

    private fun establishTun(): ParcelFileDescriptor? {
        return try {
            Builder()
                .setSession("JITER Stage 3 Tunnel")
                .setMtu(1280)
                .addAddress("10.77.0.2", 32)
                // Virtual JITER tunnel subnet keeps regular host internet safe while
                // routing 10.77.0.0/24 diagnostic & relay packets through C/C++ scheduler + XOR FEC.
                .addRoute("10.77.0.0", 24)
                .establish()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Stage 3 Real TUN Data-Plane Loop:
     *   TUN fd -> C IPv4 parser -> C++ slab PacketPool + 3-tier TrafficScheduler
     *          -> Protected UDP Relay (DATA_PLAIN or GF(2) XOR DATA_FEC)
     */
    private fun runTunDataPlanePump(pfd: ParcelFileDescriptor) {
        val inStream = FileInputStream(pfd.fileDescriptor)
        val rxBuf = ByteArray(2048)
        val txBuf = ByteArray(2048)
        val outTierAndLen = IntArray(2)

        try {
            while (serviceScope.isActive && isRunning) {
                val readLen = inStream.read(rxBuf)
                if (readLen <= 0) {
                    if (!isRunning) break
                    continue
                }
                val nowMs = SystemClock.elapsedRealtime()

                synchronized(engineLock) {
                    val adapter = engineAdapter ?: return@synchronized
                    adapter.enqueueTunPacket(rxBuf, readLen, nowMs, tierOverride = -1)
                    while (adapter.dequeueScheduledPacket(nowMs, txBuf, outTierAndLen)) {
                        val tier = outTierAndLen[0]
                        val pktLen = outTierAndLen[1]
                        if (pktLen > 0) {
                            localTunTxCount.incrementAndGet()
                            if (relayClient.isConnected) {
                                relayClient.sendDataPacket(
                                    trafficTier = tier,
                                    rawIpv4 = txBuf,
                                    length = pktLen,
                                    fecMode = currentFecMode,
                                    bgPacerRatio = currentBgPacerRatio,
                                )
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Normal exit when tunInterface is closed on STOP
        }
    }

    private fun writeDownlinkPacketToTun(payload: ByteArray) {
        if (!isRunning || payload.isEmpty()) return
        synchronized(tunWriteLock) {
            try {
                tunOutStream?.write(payload)
            } catch (_: Exception) {
                // Ignore write failure during teardown
            }
        }
    }

    private suspend fun runClosedLoopMonitor() {
        while (serviceScope.isActive && isRunning) {
            val cfg = activeConfig
            val detected = appContextDetector.detect()
            val effectiveProfile = manualProfileOverride ?: detected.profile

            // Handle dynamic Relay connect / live endpoint swap / disconnect without TUN restart
            if (cfg.hasCustomRelay()) {
                val shouldReconnect = relayReconnectNeeded.getAndSet(false) ||
                    !relayClient.matchesEndpoint(cfg.relayHost, cfg.relayPort) ||
                    !relayClient.isConnected
                if (shouldReconnect) {
                    relayClient.connect(
                        config = cfg,
                        profile = effectiveProfile,
                        socketProtector = { sock -> protect(sock) },
                    )
                }
            } else if (relayClient.isConnected || relayReconnectNeeded.getAndSet(false)) {
                relayClient.disconnect(sendGoodbye = true)
            }

            val sample = networkMonitor.runProbe(socketProtector = { sock -> protect(sock) })

            val relayProbe = if (cfg.hasCustomRelay()) {
                relayClient.probeRelay(
                    profile = effectiveProfile,
                    fecMode = currentFecMode,
                    bgPacerRatio = currentBgPacerRatio,
                )
            } else {
                null
            }

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
                    alternateRoute = relayProbe?.routeMetrics,
                )
                Pair(adapter.engineLabel, res)
            } ?: break

            val (runtimeLabel, engineOut) = stepOut
            val baseDecision = engineOut.decision

            val effectiveFec = when (cfg.fecPolicy) {
                FecPolicy.AUTO_ADAPTIVE -> baseDecision.fecMode
                FecPolicy.FORCE_OFF -> FecMode.OFF
                FecPolicy.FORCE_K2_LOW_LAT -> {
                    if (effectiveProfile == TrafficProfile.GAME) FecMode.XOR_K2_INTERLEAVED
                    else FecMode.OFF
                }
            }

            currentFecMode = effectiveFec
            currentBgPacerRatio = baseDecision.bgPacerRatio

            // Two-sided actuation: mirror active profile, BG pacer, and XOR FEC onto Relay Edge
            if (relayClient.isConnected) {
                relayClient.syncPolicy(
                    profile = effectiveProfile,
                    fecMode = effectiveFec,
                    bgPacerRatio = baseDecision.bgPacerRatio,
                    estimatedLinkMbps = sample.estimatedThroughputMbps,
                )
            }

            val effectiveRoute = when {
                cfg.routingMode == RoutingMode.PRIVACY_ALWAYS_TUNNEL && relayClient.isConnected ->
                    RouteChoice.RELAY
                !cfg.hasCustomRelay() -> RouteChoice.NATIVE
                else -> baseDecision.selectedRoute
            }

            val relayDownLockdown = cfg.hasCustomRelay() &&
                cfg.routingMode == RoutingMode.PRIVACY_ALWAYS_TUNNEL &&
                cfg.failurePolicy == FailurePolicy.FAIL_CLOSED &&
                !relayClient.isConnected

            val sessionState = when {
                sample.networkType == "Offline" -> SessionState.DEGRADED
                relayDownLockdown -> SessionState.DEGRADED
                baseDecision.qualityState == QualityState.RED -> SessionState.DEGRADED
                else -> SessionState.ACTIVE
            }

            val relayStats = relayClient.stats()

            val detail = buildString {
                if (sample.networkType == "Offline") {
                    append("No active internet (${cfg.failurePolicy.label})")
                } else if (relayDownLockdown) {
                    append("Relay unreachable · Fail-Closed lockdown active")
                } else if (relayStats.connected && relayStats.region != null) {
                    append("Relay ${relayStats.region} linked · ${effectiveRoute.label}")
                } else if (cfg.hasCustomRelay()) {
                    append("Relay standby (${cfg.failurePolicy.label}) · Native fallback")
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
                selectedRoute = effectiveRoute,
                engineRuntimeLabel = runtimeLabel,
                backendSummary = cfg.summaryLabel(),
                relayConnected = relayStats.connected,
                relayRegion = relayStats.region,
                relayRttMs = relayProbe?.rttMs ?: relayStats.relayRttMs,
                tunTxPackets = maxOf(localTunTxCount.get(), relayStats.txPackets),
                tunRxPackets = relayStats.rxPackets,
                fecRecoveredPackets = relayStats.fecRecoveredTotal,
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
        tunPumpJob?.cancel()
        tunPumpJob = null
        networkMonitor.stopObservingNetwork()

        // Send GOODBYE so the Relay Edge immediately wipes RAM session state
        relayClient.disconnect(sendGoodbye = true)

        synchronized(tunWriteLock) {
            try {
                tunOutStream?.close()
            } catch (_: Exception) {
                // Ignore close error
            }
            tunOutStream = null
        }

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
