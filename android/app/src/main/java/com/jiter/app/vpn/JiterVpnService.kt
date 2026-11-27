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
import com.jiter.app.config.TunnelScope
import com.jiter.app.context.AppContextDetector
import com.jiter.app.context.UidFlowClassifier
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
 *  - Stage 4 Full Internet Tunnel (`0.0.0.0/0` + DNS + IPv6 leak shield) & Diagnostic TUN modes
 *  - Live IPv4 data-plane pump (Android UID classifier -> C IPv4 parser -> C++ slab Pool/Scheduler)
 *  - Stage 4 Protected UDP Relay Client (ECDHE P-256 + PSK + ChaCha20-Poly1305 AEAD + XOR FEC)
 *  - Network sensing, foreground-app profile detection, and Rust/C++/C/Kotlin closed-loop engine
 */
class JiterVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var statusNotification: StatusNotification
    private lateinit var networkMonitor: NetworkMonitor
    private lateinit var appContextDetector: AppContextDetector
    private lateinit var uidFlowClassifier: UidFlowClassifier
    private lateinit var relayClient: RelayTunnelClient

    private val engineLock = Any()
    private val tunWriteLock = Any()

    private var engineAdapter: EngineAdapter? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var tunOutStream: FileOutputStream? = null

    private var sessionJob: Job? = null
    private var tunPumpJob: Job? = null

    private val relayReconnectNeeded = AtomicBoolean(false)
    private val localTunTxCount = AtomicLong(0L)

    @Volatile
    private var isRunning: Boolean = false

    @Volatile
    private var fullInternetTunnelActive: Boolean = false

    @Volatile
    private var activeTunnelIp: String = DEFAULT_TUN_IPV4

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
        uidFlowClassifier = UidFlowClassifier(this)
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
        val relayChanged = activeConfig.relayHost != newConfig.relayHost ||
            activeConfig.relayPort != newConfig.relayPort ||
            activeConfig.relayPsk != newConfig.relayPsk

        activeConfig = newConfig
        networkMonitor.updateProbeEndpoint(newConfig.probeHost, newConfig.probePort)

        if (relayChanged) {
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

        isRunning = true
        fullInternetTunnelActive = false
        activeTunnelIp = DEFAULT_TUN_IPV4
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
            statusDetail = "Initializing tunnel and ${adapter.engineLabel}...",
        )
        SessionStore.update { startingSnapshot }
        promoteToForeground(startingSnapshot)

        sessionJob?.cancel()
        sessionJob = serviceScope.launch {
            bootstrapTunnelAndRunLoop(cfg, adapter.engineLabel)
        }
    }

    private suspend fun bootstrapTunnelAndRunLoop(
        cfg: BackendConfig,
        runtimeLabel: String,
    ) {
        val wantFullTunnel = cfg.tunnelScope == TunnelScope.FULL_INTERNET_TUNNEL
        var useFullInternetTun = false
        var tunnelIp = DEFAULT_TUN_IPV4
        var tunnelMtu = 1280
        var startupNote: String? = null

        // For Full Internet Tunnel, perform ECDHE P-256 + PSK handshake first so we get
        // the dynamic assigned IPv4 and confirm AEAD encryption before routing 0.0.0.0/0.
        if (wantFullTunnel) {
            if (!cfg.hasCustomRelay() || !cfg.hasRelayPsk()) {
                if (cfg.failurePolicy == FailurePolicy.FAIL_CLOSED) {
                    useFullInternetTun = true
                    startupNote = "Full Tunnel requires Relay + PSK · Fail-Closed lockdown"
                } else {
                    useFullInternetTun = false
                    startupNote = "Full Tunnel requires Relay Host + PSK · safe diagnostic fallback"
                }
            } else {
                SessionStore.update {
                    it.copy(
                        sessionState = SessionState.CONNECTING,
                        statusDetail = "Performing ECDHE P-256 + AEAD handshake with ${cfg.relayHost}...",
                    )
                }
                val initialProfile = manualProfileOverride ?: TrafficProfile.SAFE_BALANCED
                val connected = relayClient.connect(
                    config = cfg,
                    profile = initialProfile,
                    socketProtector = { sock -> protect(sock) },
                )
                relayReconnectNeeded.set(false)
                if (connected && relayClient.isEncrypted) {
                    useFullInternetTun = true
                    tunnelIp = relayClient.assignedIpv4 ?: DEFAULT_TUN_IPV4
                    tunnelMtu = relayClient.acceptedMtu
                } else if (cfg.failurePolicy == FailurePolicy.FAIL_CLOSED) {
                    useFullInternetTun = true
                    startupNote = "Relay handshake failed · Fail-Closed lockdown active"
                } else {
                    useFullInternetTun = false
                    startupNote = "Relay unreachable/PSK mismatch · Fail-Open diagnostic fallback"
                }
            }
        }

        if (!isRunning) return

        val pfd = establishTun(
            localIpv4 = tunnelIp,
            mtu = tunnelMtu,
            fullInternetRoute = useFullInternetTun,
        )
        if (pfd == null) {
            SessionStore.update {
                it.copy(
                    sessionState = SessionState.ERROR,
                    statusDetail = "VPN permission revoked or TUN interface unavailable",
                )
            }
            stopSessionInternal(callStopSelf = true)
            return
        }

        tunInterface = pfd
        fullInternetTunnelActive = useFullInternetTun
        activeTunnelIp = tunnelIp
        synchronized(tunWriteLock) {
            tunOutStream = FileOutputStream(pfd.fileDescriptor)
        }

        val activeInit = SessionStore.snapshot.value.copy(
            sessionState = SessionState.ACTIVE,
            relayConnected = relayClient.isConnected,
            relayEncrypted = relayClient.isEncrypted,
            fullInternetTunnelActive = useFullInternetTun,
            assignedTunnelIp = tunnelIp,
            relayRegion = relayClient.stats().region,
            statusDetail = startupNote ?: if (useFullInternetTun) {
                "Full Tunnel AEAD active ($tunnelIp) · $runtimeLabel"
            } else {
                "TUN active · $runtimeLabel"
            },
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

        runClosedLoopMonitor(startupNote)
    }

    private fun establishTun(
        localIpv4: String,
        mtu: Int,
        fullInternetRoute: Boolean,
    ): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
                .setSession(if (fullInternetRoute) "JITER Full AEAD Tunnel" else "JITER Diagnostic Tunnel")
                .setMtu(mtu.coerceIn(576, 1400))
                .setBlocking(true)
                .addAddress(localIpv4, 32)

            // Exclude JITER's own process so relay UDP sockets & probes never loop into TUN
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Exception) {
                // VpnService.protect() still shields every socket
            }

            if (fullInternetRoute) {
                builder
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    // IPv6 leak shield: prevents unencrypted IPv6 DNS/traffic bypassing IPv4 tunnel
                    .addAddress("fd77:0:0:1::2", 128)
                    .addRoute("::", 0)
            } else {
                builder.addRoute("10.77.0.0", 24)
            }

            builder.establish()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Stage 4 Real TUN Data-Plane Loop:
     *   TUN fd -> Android UID classifier (API 29+) -> C IPv4 parser
     *          -> C++ slab PacketPool + 3-tier TrafficScheduler
     *          -> Protected UDP Relay (ChaCha20-Poly1305 AEAD + GF(2) XOR FEC)
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
                val uidTierOverride = uidFlowClassifier.classifyIpv4Packet(rxBuf, readLen)

                synchronized(engineLock) {
                    val adapter = engineAdapter ?: return@synchronized
                    adapter.enqueueTunPacket(rxBuf, readLen, nowMs, tierOverride = uidTierOverride)
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

    private suspend fun runClosedLoopMonitor(initialFallbackWarning: String?) {
        var persistentWarning = initialFallbackWarning

        while (serviceScope.isActive && isRunning) {
            val cfg = activeConfig
            val detected = appContextDetector.detect()
            val effectiveProfile = manualProfileOverride ?: detected.profile

            // Handle dynamic Relay connect / live endpoint or PSK hot-swap / disconnect
            if (cfg.hasCustomRelay()) {
                val shouldReconnect = relayReconnectNeeded.getAndSet(false) ||
                    !relayClient.matchesConfig(cfg) ||
                    !relayClient.isConnected
                if (shouldReconnect) {
                    val ok = relayClient.connect(
                        config = cfg,
                        profile = effectiveProfile,
                        socketProtector = { sock -> protect(sock) },
                    )
                    if (ok) {
                        persistentWarning = null
                    }
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

            if (relayClient.isConnected) {
                relayClient.syncPolicy(
                    profile = effectiveProfile,
                    fecMode = effectiveFec,
                    bgPacerRatio = baseDecision.bgPacerRatio,
                    estimatedLinkMbps = sample.estimatedThroughputMbps,
                )
            }

            val effectiveRoute = when {
                fullInternetTunnelActive && relayClient.isConnected -> RouteChoice.RELAY
                cfg.routingMode == RoutingMode.PRIVACY_ALWAYS_TUNNEL && relayClient.isConnected ->
                    RouteChoice.RELAY
                !cfg.hasCustomRelay() -> RouteChoice.NATIVE
                else -> baseDecision.selectedRoute
            }

            val relayDownLockdown = cfg.hasCustomRelay() &&
                (cfg.routingMode == RoutingMode.PRIVACY_ALWAYS_TUNNEL || fullInternetTunnelActive) &&
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
                } else if (persistentWarning != null && !relayStats.connected) {
                    append(persistentWarning)
                } else if (relayStats.connected && relayStats.region != null) {
                    if (fullInternetTunnelActive && relayStats.encrypted) {
                        append("AEAD Full Tunnel · ${relayStats.region} (${activeTunnelIp})")
                    } else if (relayStats.encrypted) {
                        append("AEAD Relay ${relayStats.region} · ${effectiveRoute.label}")
                    } else {
                        append("Relay ${relayStats.region} (Diag) · ${effectiveRoute.label}")
                    }
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
                relayEncrypted = relayStats.encrypted,
                fullInternetTunnelActive = fullInternetTunnelActive,
                assignedTunnelIp = if (fullInternetTunnelActive) activeTunnelIp else relayStats.assignedIpv4,
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
        fullInternetTunnelActive = false
        sessionJob?.cancel()
        sessionJob = null
        tunPumpJob?.cancel()
        tunPumpJob = null
        networkMonitor.stopObservingNetwork()

        // Send authenticated/plain GOODBYE so the Relay Edge wipes RAM session immediately
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
        private const val DEFAULT_TUN_IPV4 = "10.77.0.2"
    }
}
