package com.jiter.app.vpn

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import androidx.core.app.ServiceCompat
import com.jiter.app.BuildConfig
import com.jiter.app.bridge.EngineAdapter
import com.jiter.app.bridge.NativeEngineBridge
import com.jiter.app.config.BackendConfig
import com.jiter.app.config.BackendConfigStore
import com.jiter.app.config.FailurePolicy
import com.jiter.app.config.FecPolicy
import com.jiter.app.config.RoutingMode
import com.jiter.app.config.TunnelScope
import com.jiter.app.context.AppContextDetector
import com.jiter.app.context.AutoProfileAssessment
import com.jiter.app.context.DetectedContext
import com.jiter.app.context.TrafficAutoProfileDetector
import com.jiter.app.context.UidFlowClassifier
import com.jiter.app.engine.FecMode
import com.jiter.app.engine.QualityState
import com.jiter.app.engine.RouteChoice
import com.jiter.app.engine.SessionSnapshot
import com.jiter.app.engine.SessionState
import com.jiter.app.engine.TrafficProfile
import com.jiter.app.local.LocalTcpNativeBridge
import com.jiter.app.local.LocalTrafficShaper
import com.jiter.app.network.NetworkMonitor
import com.jiter.app.notification.StatusNotification
import com.jiter.app.relay.ControlPlaneClient
import com.jiter.app.relay.RelayProtocol
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
 *  - Stage 6 Hybrid Auto-Selection:
 *      Mode A — Full AEAD Relay (`0.0.0.0/0` + DNS + IPv6 shield + ChaCha20-Poly1305 + XOR FEC)
 *               when a healthy Control Plane or manual Relay VPS is available.
 *      Mode B — Local Traffic Shaper (`0.0.0.0/0` + Native Rust `smoltcp` TCP + Non-blocking UDP
 *               NAT + DNS Tier-0 Fast-Path + TCP Background Pacer) with zero VPS required!
 *  - Stage 5 Packet-Driven Auto-Profile Engine (Android OS Category UID + TUN traffic flow)
 *  - Live IPv4 data-plane pump (UID classifier -> C IPv4 parser -> C++ slab Pool/Scheduler)
 *  - Network sensing and Rust/C++/C/Kotlin closed-loop adaptive controller
 */
class JiterVpnService : VpnService() {

    private enum class ActiveTunMode {
        DIAGNOSTIC,
        LOCAL_SHAPER,
        FULL_AEAD_RELAY,
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var statusNotification: StatusNotification
    private lateinit var networkMonitor: NetworkMonitor
    private lateinit var appContextDetector: AppContextDetector
    private lateinit var uidFlowClassifier: UidFlowClassifier
    private lateinit var trafficAutoProfileDetector: TrafficAutoProfileDetector
    private lateinit var relayClient: RelayTunnelClient
    private lateinit var localShaper: LocalTrafficShaper

    private val engineLock = Any()
    private val tunWriteLock = Any()

    private var engineAdapter: EngineAdapter? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var tunOutStream: FileOutputStream? = null

    private var sessionJob: Job? = null
    @Volatile
    private var tunPumpThread: Thread? = null

    private val relayReconnectNeeded = AtomicBoolean(false)
    private val baselineResetRequested = AtomicBoolean(false)
    private val localTunTxCount = AtomicLong(0L)
    private val rttHistoryLock = Any()
    private val rttHistoryWindow = ArrayDeque<Double>(64)

    @Volatile
    private var isRunning: Boolean = false

    @Volatile
    private var fullInternetTunnelActive: Boolean = false

    @Volatile
    private var localShaperActive: Boolean = false

    @Volatile
    private var controlPlaneActive: Boolean = false

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
        trafficAutoProfileDetector = TrafficAutoProfileDetector()
        relayClient = RelayTunnelClient(
            onDownlinkPacket = { payload -> writeDownlinkPacketToTun(payload, payload.size) },
        )
        localShaper = LocalTrafficShaper(
            protectDatagram = { sock -> protect(sock) },
            protectStream = { sock -> protect(sock) },
            onDownlinkPacket = { buf, len -> writeDownlinkPacketToTun(buf, len) },
            onDownlinkActivity = { tier, bytes, isUdp ->
                trafficAutoProfileDetector.recordDownlinkBytes(
                    tier = tier,
                    byteLength = bytes,
                    isUdp = isUdp,
                    nowMs = SystemClock.elapsedRealtime(),
                )
            },
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
                if (localShaperActive &&
                    (manualProfileOverride == null || manualProfileOverride == TrafficProfile.DOWNLOAD)
                ) {
                    localShaper.updatePacer(1.0, null)
                }
                // Policy-only update: NEVER restarts the tunnel!
                SessionStore.update { current ->
                    val effective = manualProfileOverride ?: current.activeProfile
                    current.copy(
                        manualProfileOverride = manualProfileOverride,
                        activeProfile = effective,
                        detectionSource = if (manualProfileOverride != null) "Manual" else current.detectionSource,
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
        uidFlowClassifier.shutdown()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun applyBackendConfigLive(newConfig: BackendConfig) {
        val prevPref = activeConfig.enginePreference
        val prevProbeHost = activeConfig.probeHost
        val prevProbePort = activeConfig.probePort
        val relayChanged = activeConfig.relayHost != newConfig.relayHost ||
            activeConfig.relayPort != newConfig.relayPort ||
            activeConfig.relayPsk != newConfig.relayPsk ||
            activeConfig.controlPlaneUrl != newConfig.controlPlaneUrl

        activeConfig = newConfig
        networkMonitor.updateProbeEndpoint(newConfig.probeHost, newConfig.probePort)

        if (relayChanged && !localShaperActive) {
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
        localShaperActive = false
        controlPlaneActive = false
        activeTunnelIp = DEFAULT_TUN_IPV4
        localTunTxCount.set(0L)
        synchronized(rttHistoryLock) { rttHistoryWindow.clear() }
        trafficAutoProfileDetector.reset()
        uidFlowClassifier.clearCache()
        appContextDetector.reset()
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
            statusDetail = "Starting JITER...",
        )
        SessionStore.update { startingSnapshot }
        promoteToForeground(startingSnapshot)

        sessionJob?.cancel()
        sessionJob = serviceScope.launch {
            bootstrapTunnelAndRunLoop(cfg, adapter.engineLabel)
        }
    }

    private suspend fun bootstrapTunnelAndRunLoop(
        storedCfg: BackendConfig,
        runtimeLabel: String,
    ) {
        var cfg = storedCfg
        var tunMode = ActiveTunMode.DIAGNOSTIC
        var tunnelIp = DEFAULT_TUN_IPV4
        var tunnelMtu = 1280
        var startupNote: String? = null
        val initialProfile = manualProfileOverride ?: TrafficProfile.SAFE_BALANCED

        val allowRelayAttempt = cfg.tunnelScope == TunnelScope.HYBRID_AUTO ||
            cfg.tunnelScope == TunnelScope.FULL_INTERNET_TUNNEL

        // 1. Try Mode A: Full AEAD Relay via Zero-Config Control Plane or Manual Relay + PSK
        if (allowRelayAttempt && cfg.hasControlPlane() && !cfg.hasCustomRelay()) {
            SessionStore.update {
                it.copy(
                    sessionState = SessionState.CONNECTING,
                    statusDetail = "Selecting best server...",
                )
            }
            val boot = ControlPlaneClient.bootstrap(
                baseUrl = cfg.controlPlaneUrl,
                appKey = cfg.controlPlaneAppKey,
                preferredRegion = "",
                networkType = networkMonitor.getNetworkType(),
                appVersion = BuildConfig.VERSION_NAME,
            )
            if (boot != null && boot.nodes.isNotEmpty()) {
                for (node in boot.nodes) {
                    val candidateCfg = ControlPlaneClient.applyToConfig(cfg, node, boot.policy)
                    val ok = relayClient.connect(
                        config = candidateCfg,
                        profile = initialProfile,
                        socketProtector = { sock -> protect(sock) },
                    )
                    if (ok) {
                        cfg = candidateCfg
                        activeConfig = candidateCfg
                        networkMonitor.updateProbeEndpoint(cfg.probeHost, cfg.probePort)
                        controlPlaneActive = true
                        relayReconnectNeeded.set(false)
                        if (relayClient.isEncrypted &&
                            (cfg.tunnelScope == TunnelScope.FULL_INTERNET_TUNNEL ||
                                cfg.tunnelScope == TunnelScope.HYBRID_AUTO)
                        ) {
                            tunMode = ActiveTunMode.FULL_AEAD_RELAY
                            tunnelIp = relayClient.assignedIpv4 ?: DEFAULT_TUN_IPV4
                            tunnelMtu = relayClient.acceptedMtu
                        }
                        break
                    }
                }
                if (!relayClient.isConnected) {
                    startupNote = "Relay nodes busy · smart local shaper active"
                }
            } else {
                startupNote = "Auto server standby · smart local shaper active"
            }
        } else if (allowRelayAttempt && cfg.hasCustomRelay() && cfg.hasRelayPsk()) {
            SessionStore.update {
                it.copy(
                    sessionState = SessionState.CONNECTING,
                    statusDetail = "Connecting encrypted tunnel...",
                )
            }
            val connected = relayClient.connect(
                config = cfg,
                profile = initialProfile,
                socketProtector = { sock -> protect(sock) },
            )
            relayReconnectNeeded.set(false)
            if (connected && relayClient.isEncrypted) {
                tunMode = ActiveTunMode.FULL_AEAD_RELAY
                tunnelIp = relayClient.assignedIpv4 ?: DEFAULT_TUN_IPV4
                tunnelMtu = relayClient.acceptedMtu
            } else if (cfg.tunnelScope == TunnelScope.FULL_INTERNET_TUNNEL &&
                cfg.failurePolicy == FailurePolicy.FAIL_CLOSED
            ) {
                tunMode = ActiveTunMode.FULL_AEAD_RELAY
                startupNote = "Relay handshake failed · Fail-Closed lockdown active"
            } else {
                startupNote = "Relay unreachable · smart local shaper fallback"
            }
        } else if (cfg.tunnelScope == TunnelScope.FULL_INTERNET_TUNNEL) {
            if (cfg.failurePolicy == FailurePolicy.FAIL_CLOSED) {
                tunMode = ActiveTunMode.FULL_AEAD_RELAY
                startupNote = "Full Tunnel requires Relay + PSK · Fail-Closed lockdown"
            } else {
                startupNote = "Full Tunnel requires Relay + PSK · safe diagnostic fallback"
            }
        }

        // 2. Mode B (Stage 6 Hybrid Fallback / Local Shaper):
        //    Whenever no VPS AEAD tunnel is active and scope allows Hybrid/Local, start the
        //    native smoltcp + non-blocking UDP Local Traffic Shaper (0.0.0.0/0, zero VPS needed!)
        val wantsLocalShaper = tunMode != ActiveTunMode.FULL_AEAD_RELAY &&
            (cfg.tunnelScope == TunnelScope.HYBRID_AUTO ||
                cfg.tunnelScope == TunnelScope.LOCAL_SHAPER_ONLY)

        if (wantsLocalShaper) {
            // Mode B has zero UDP/AEAD encapsulation overhead -> full 1500 MTU boosts TCP payload +18%
            val localMtu = LOCAL_SHAPER_MTU
            if (LocalTcpNativeBridge.isSupported() && localShaper.start(mtu = localMtu)) {
                tunMode = ActiveTunMode.LOCAL_SHAPER
                tunnelMtu = localMtu
                localShaperActive = true
                relayReconnectNeeded.set(false)
            } else {
                tunMode = ActiveTunMode.DIAGNOSTIC
                localShaperActive = false
                startupNote = startupNote ?: "Native local stack unavailable · diagnostic fallback"
            }
        }

        if (!isRunning) {
            localShaper.stop()
            return
        }

        val pfd = establishTun(
            localIpv4 = tunnelIp,
            mtu = tunnelMtu,
            mode = tunMode,
        )
        if (pfd == null) {
            localShaper.stop()
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
        fullInternetTunnelActive = (tunMode == ActiveTunMode.FULL_AEAD_RELAY)
        localShaperActive = (tunMode == ActiveTunMode.LOCAL_SHAPER)
        activeTunnelIp = tunnelIp
        synchronized(tunWriteLock) {
            tunOutStream = FileOutputStream(pfd.fileDescriptor)
        }

        val activeInit = SessionStore.snapshot.value.copy(
            sessionState = SessionState.ACTIVE,
            controlPlaneActive = controlPlaneActive,
            localShaperActive = localShaperActive,
            relayConnected = relayClient.isConnected,
            relayEncrypted = relayClient.isEncrypted,
            fullInternetTunnelActive = fullInternetTunnelActive,
            assignedTunnelIp = tunnelIp,
            relayRegion = relayClient.stats().region,
            backendSummary = cfg.summaryLabel(),
            statusDetail = startupNote ?: when (tunMode) {
                ActiveTunMode.FULL_AEAD_RELAY ->
                    "Full Tunnel AEAD active ($tunnelIp) · $runtimeLabel"
                ActiveTunMode.LOCAL_SHAPER ->
                    "Local Traffic Shaper active (No-VPS) · $runtimeLabel"
                ActiveTunMode.DIAGNOSTIC ->
                    "Diagnostic TUN active · $runtimeLabel"
            },
        )
        SessionStore.update { activeInit }
        statusNotification.updateIfAllowed(activeInit, force = true)

        networkMonitor.startObservingNetwork { newType ->
            synchronized(engineLock) {
                engineAdapter?.resetBaseline(null)
            }
            baselineResetRequested.set(true)
            if (!localShaperActive && activeConfig.hasCustomRelay()) {
                relayReconnectNeeded.set(true)
            }
            SessionStore.update { current ->
                current.copy(
                    networkType = newType,
                    statusDetail = "Network switched to $newType — recalibrating baseline",
                )
            }
        }

        startTunDataPlaneThread(pfd)

        runClosedLoopMonitor(startupNote)
    }

    private fun startTunDataPlaneThread(pfd: ParcelFileDescriptor) {
        stopTunDataPlaneThread()
        val thread = Thread({
            try {
                Process.setThreadPriority(Process.THREAD_PRIORITY_DISPLAY)
            } catch (_: Throwable) {
                // Best-effort OS priority boost
            }
            runTunDataPlanePump(pfd)
        }, "jiter-tun-pump").apply {
            isDaemon = true
            priority = (Thread.MAX_PRIORITY - 1).coerceIn(Thread.NORM_PRIORITY, Thread.MAX_PRIORITY)
            start()
        }
        tunPumpThread = thread
    }

    private fun stopTunDataPlaneThread() {
        val thread = tunPumpThread ?: return
        tunPumpThread = null
        thread.interrupt()
        try {
            thread.join(800L)
        } catch (_: InterruptedException) {
            // Ignore interrupt during teardown
        }
    }

    private fun establishTun(
        localIpv4: String,
        mtu: Int,
        mode: ActiveTunMode,
    ): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
                .setSession(
                    when (mode) {
                        ActiveTunMode.FULL_AEAD_RELAY -> "JITER Full AEAD Tunnel"
                        ActiveTunMode.LOCAL_SHAPER -> "JITER Local Traffic Shaper"
                        ActiveTunMode.DIAGNOSTIC -> "JITER Diagnostic Monitor"
                    },
                )
                .setMtu(mtu.coerceIn(576, 1500))
                .setBlocking(true)
                .addAddress(localIpv4, 32)

            // Exclude JITER's own process so outbound sockets & probes never loop into TUN
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Exception) {
                // VpnService.protect() still shields every socket
            }

            when (mode) {
                ActiveTunMode.FULL_AEAD_RELAY -> {
                    builder
                        .addRoute("0.0.0.0", 0)
                        .addDnsServer("1.1.1.1")
                        .addDnsServer("8.8.8.8")
                        // IPv6 leak shield: prevents unencrypted IPv6 DNS/traffic bypassing IPv4 tunnel
                        .addAddress("fd77:0:0:1::2", 128)
                        .addRoute("::", 0)
                }
                ActiveTunMode.LOCAL_SHAPER -> {
                    // Captures all IPv4 app traffic for local 3-tier priority shaping & TCP BG pacing
                    // while leaving carrier IPv6/VoLTE/IMS untouched.
                    builder
                        .addRoute("0.0.0.0", 0)
                        .addDnsServer("1.1.1.1")
                        .addDnsServer("8.8.8.8")
                }
                ActiveTunMode.DIAGNOSTIC -> {
                    builder.addRoute("10.77.0.0", 24)
                }
            }

            builder.establish()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Stage 6 Real TUN Data-Plane Loop:
     *   TUN fd -> Android OS Category UID classifier -> C IPv4 parser
     *          -> C++ slab PacketPool + 3-tier TrafficScheduler
     *          -> Live TrafficAutoProfileDetector (zero Usage Access needed!)
     *          -> Mode A: Protected UDP Relay (AEAD + XOR FEC)
     *          -> Mode B: Local Traffic Shaper (Rust smoltcp TCP + Non-blocking UDP + TCP BG Pacer)
     */
    private fun runTunDataPlanePump(pfd: ParcelFileDescriptor) {
        val inStream = FileInputStream(pfd.fileDescriptor)
        val rxBuf = ByteArray(2048)
        val txBuf = ByteArray(2048)
        val outTierAndLen = IntArray(2)

        try {
            while (isRunning && !Thread.currentThread().isInterrupted) {
                val readLen = inStream.read(rxBuf)
                if (readLen <= 0) {
                    if (!isRunning) break
                    continue
                }
                val nowMs = SystemClock.elapsedRealtime()
                val flowClass = uidFlowClassifier.classifyFlow(rxBuf, readLen, nowMs)

                // Record activity directly from the current incoming packet (never on unrelated
                // dequeued packets) while flagging DNS / ICMP / TCP ACK control frames so they
                // keep VIP queue priority without false-triggering GAME mode!
                recordPacketActivity(rxBuf, readLen, flowClass, nowMs)

                synchronized(engineLock) {
                    val adapter = engineAdapter ?: return@synchronized
                    adapter.enqueueTunPacket(rxBuf, readLen, nowMs, tierOverride = flowClass.qosTier)
                    while (adapter.dequeueScheduledPacket(nowMs, txBuf, outTierAndLen)) {
                        val tier = outTierAndLen[0]
                        val pktLen = outTierAndLen[1]
                        if (pktLen > 0) {
                            localTunTxCount.incrementAndGet()
                            if (localShaperActive) {
                                localShaper.submitScheduledPacket(txBuf, pktLen, tier)
                            } else if (relayClient.isConnected) {
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

    private fun recordPacketActivity(
        rawIpv4: ByteArray,
        length: Int,
        flowClass: com.jiter.app.context.FlowClassification,
        nowMs: Long,
    ) {
        if (length < 20) return
        val version = (rawIpv4[0].toInt() ushr 4) and 0x0F
        val ihl = (rawIpv4[0].toInt() and 0x0F) * 4
        if (version != 4 || ihl < 20 || ihl > length) return

        val proto = rawIpv4[9].toInt() and 0xFF
        val dstPort = if ((proto == 6 || proto == 17) && ihl + 4 <= length) {
            ((rawIpv4[ihl + 2].toInt() and 0xFF) shl 8) or (rawIpv4[ihl + 3].toInt() and 0xFF)
        } else {
            0
        }
        val isControl = proto == 1 ||
            dstPort == 53 ||
            dstPort == 853 ||
            (proto == 6 && length <= 96)

        val inferredTier = when {
            flowClass.qosTier in 0..2 -> flowClass.qosTier
            proto == 1 -> RelayProtocol.TIER_GAME
            proto == 17 && (dstPort == 53 || length <= 320) -> RelayProtocol.TIER_GAME
            proto == 17 -> RelayProtocol.TIER_STREAMING
            proto == 6 && length <= 96 -> RelayProtocol.TIER_GAME
            proto == 6 && (dstPort == 443 || dstPort == 80) -> RelayProtocol.TIER_STREAMING
            else -> RelayProtocol.TIER_BACKGROUND
        }

        trafficAutoProfileDetector.recordPacket(
            tier = inferredTier,
            byteLength = length,
            uidMatched = flowClass.uidMatched,
            nowMs = nowMs,
            protocol = proto,
            dstPort = dstPort,
            uidProfile = flowClass.appProfile,
            isControlPacket = isControl,
        )
    }

    private fun writeDownlinkPacketToTun(payload: ByteArray, length: Int) {
        if (!isRunning || length <= 0 || length > payload.size) return
        synchronized(tunWriteLock) {
            try {
                tunOutStream?.write(payload, 0, length)
            } catch (_: Exception) {
                // Ignore write failure during teardown
            }
        }
    }

    private suspend fun runClosedLoopMonitor(initialFallbackWarning: String?) {
        var persistentWarning = initialFallbackWarning
        var didStartupWarmup = false
        val baselineWindow = ArrayDeque<Pair<Long, Double>>(64)
        var steadyLowJitterStreak = 0

        while (serviceScope.isActive && isRunning) {
            if (baselineResetRequested.getAndSet(false)) {
                baselineWindow.clear()
                steadyLowJitterStreak = 0
            }

            val cfg = activeConfig
            val nowElapsedMs = SystemClock.elapsedRealtime()
            val packetAssessment = trafficAutoProfileDetector.evaluate(nowElapsedMs)
            val usageDetected = appContextDetector.detect()

            val (effectiveProfile, detectionSource) = resolveEffectiveProfile(
                manualOverride = manualProfileOverride,
                usageDetected = usageDetected,
                packetAssessment = packetAssessment,
            )

            // Handle dynamic Relay connect / live endpoint or PSK hot-swap when not in Local Shaper mode
            if (!localShaperActive && cfg.hasCustomRelay()) {
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
            } else if (!localShaperActive && (relayClient.isConnected || relayReconnectNeeded.getAndSet(false))) {
                relayClient.disconnect(sendGoodbye = true)
            }

            var sample = networkMonitor.runProbe(socketProtector = { sock -> protect(sock) })
            val firstRtt = sample.rttMs
            if (!didStartupWarmup && firstRtt != null && isRunning) {
                didStartupWarmup = true
                // Warm up 2 extra fast probes (150 ms apart) on session start so RFC 6298 initial
                // RTTVAR (R/2) settles to true network jitter instead of flashing YELLOW on healthy 4G.
                synchronized(engineLock) {
                    engineAdapter?.submitRtt(firstRtt, sample.timestampMs)
                }
                recordBaselineSample(baselineWindow, sample.timestampMs, firstRtt)
                repeat(STARTUP_WARMUP_EXTRA_PROBES) {
                    if (!isRunning) return@repeat
                    delay(STARTUP_WARMUP_INTERVAL_MS)
                    val warm = networkMonitor.runProbe(socketProtector = { sock -> protect(sock) })
                    val warmRtt = warm.rttMs
                    if (warmRtt != null) {
                        synchronized(engineLock) {
                            engineAdapter?.submitRtt(warmRtt, warm.timestampMs)
                        }
                        recordBaselineSample(baselineWindow, warm.timestampMs, warmRtt)
                        sample = warm
                    }
                }
            } else if (firstRtt != null) {
                didStartupWarmup = true
                synchronized(engineLock) {
                    engineAdapter?.submitRtt(firstRtt, sample.timestampMs)
                }
                recordBaselineSample(baselineWindow, sample.timestampMs, firstRtt)
            }

            val observedThroughputMbps = maxOf(
                sample.estimatedThroughputMbps ?: 0.0,
                packetAssessment.observedGoodputMbps ?: 0.0,
            ).takeIf { it > 0.0 }
            val scorerBandwidthMbps = resolveScorerBandwidthMbps(
                linkCapacityMbps = sample.linkCapacityMbps,
                observedThroughputMbps = observedThroughputMbps,
            )
            val pacerLinkMbps = scorerBandwidthMbps ?: observedThroughputMbps
            val displayThroughputMbps = observedThroughputMbps ?: sample.linkCapacityMbps

            val relayProbe = if (!localShaperActive && cfg.hasCustomRelay()) {
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
                val res = adapter.step(
                    nowMs = sample.timestampMs,
                    profile = effectiveProfile,
                    lossPct = sample.lossPct,
                    bandwidthMbps = scorerBandwidthMbps,
                    alternateRoute = relayProbe?.routeMetrics,
                )
                val srtt = res.srttMs
                val jit = res.jitterMs
                val bloat = res.bufferbloatMs
                if (srtt != null && jit != null && bloat != null &&
                    jit < STEADY_BASELINE_MAX_JITTER_MS && sample.lossPct == 0.0
                ) {
                    steadyLowJitterStreak += 1
                } else {
                    steadyLowJitterStreak = 0
                }
                if (srtt != null && jit != null && bloat != null && baselineWindow.size >= 2) {
                    val spanMs = baselineWindow.last().first - baselineWindow.first().first
                    val windowMinRtt = baselineWindow.minOf { it.second }
                    if (shouldRecalibrateSteadyBaseline(
                            bloatMs = bloat,
                            srttMs = srtt,
                            jitterMs = jit,
                            lossPct = sample.lossPct,
                            steadyStreak = steadyLowJitterStreak,
                            windowSpanMs = spanMs,
                            windowMinRttMs = windowMinRtt,
                        )
                    ) {
                        adapter.resetBaseline(windowMinRtt)
                        steadyLowJitterStreak = 0
                    }
                }
                if (localShaperActive) {
                    // In Mode B Local Shaper, LocalTrafficShaper handles smooth 50 ms TCP rwnd
                    // downlink pacing. Keep the C++ scheduler's outbound queue unthrottled so
                    // outbound TCP ACKs never stall behind a blocking TUN read().
                    adapter.configureSchedulerPacer(1.0, pacerLinkMbps ?: 25.0)
                }
                Pair(adapter.engineLabel, res)
            } ?: break

            val (runtimeLabel, engineOut) = stepOut
            val baseDecision = engineOut.decision

            val effectiveFec = when {
                localShaperActive -> FecMode.OFF // XOR FEC requires remote jiter-relay endpoint
                cfg.fecPolicy == FecPolicy.AUTO_ADAPTIVE -> baseDecision.fecMode
                cfg.fecPolicy == FecPolicy.FORCE_OFF -> FecMode.OFF
                cfg.fecPolicy == FecPolicy.FORCE_K2_LOW_LAT -> {
                    if (effectiveProfile == TrafficProfile.GAME) FecMode.XOR_K2_INTERLEAVED
                    else FecMode.OFF
                }
                else -> baseDecision.fecMode
            }

            currentFecMode = effectiveFec
            currentBgPacerRatio = baseDecision.bgPacerRatio

            if (localShaperActive) {
                localShaper.updatePacer(baseDecision.bgPacerRatio, pacerLinkMbps)
            } else if (relayClient.isConnected) {
                relayClient.syncPolicy(
                    profile = effectiveProfile,
                    fecMode = effectiveFec,
                    bgPacerRatio = baseDecision.bgPacerRatio,
                    estimatedLinkMbps = pacerLinkMbps,
                )
            }

            val effectiveRoute = when {
                localShaperActive -> RouteChoice.NATIVE
                fullInternetTunnelActive && relayClient.isConnected -> RouteChoice.RELAY
                cfg.routingMode == RoutingMode.PRIVACY_ALWAYS_TUNNEL && relayClient.isConnected ->
                    RouteChoice.RELAY
                !cfg.hasCustomRelay() -> RouteChoice.NATIVE
                else -> baseDecision.selectedRoute
            }

            val relayDownLockdown = !localShaperActive && cfg.hasCustomRelay() &&
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
            val localStats = localShaper.stats()

            val totalTx = if (localShaperActive) {
                maxOf(localTunTxCount.get(), localStats.txPackets)
            } else {
                maxOf(localTunTxCount.get(), relayStats.txPackets)
            }
            val totalRx = if (localShaperActive) localStats.rxPackets else relayStats.rxPackets

            val latestRttForChart = sample.rttMs ?: engineOut.srttMs
            val historySnapshot = synchronized(rttHistoryLock) {
                if (latestRttForChart != null && latestRttForChart.isFinite() && latestRttForChart > 0.0) {
                    if (rttHistoryWindow.size >= 60) {
                        rttHistoryWindow.removeFirst()
                    }
                    rttHistoryWindow.addLast(latestRttForChart)
                }
                rttHistoryWindow.toList()
            }

            val detail = buildString {
                if (sample.networkType == "Offline") {
                    append("No active internet (${cfg.failurePolicy.label})")
                } else if (relayDownLockdown) {
                    append("Relay unreachable · Fail-Closed lockdown active")
                } else if (localShaperActive) {
                    append("Local Shaper (${localStats.activeUdpFlows}u/${localStats.activeTcpFlows}t) · $detectionSource")
                } else if (persistentWarning != null && !relayStats.connected) {
                    append(persistentWarning)
                } else if (relayStats.connected && relayStats.region != null) {
                    if (fullInternetTunnelActive && relayStats.encrypted) {
                        append("AEAD Full Tunnel · ${relayStats.region} ($activeTunnelIp)")
                    } else if (relayStats.encrypted) {
                        append("AEAD Relay ${relayStats.region} · ${effectiveRoute.label}")
                    } else {
                        append("Relay ${relayStats.region} (Diag) · ${effectiveRoute.label}")
                    }
                } else if (cfg.hasCustomRelay()) {
                    append("Relay standby (${cfg.failurePolicy.label}) · Native fallback")
                } else {
                    append("Auto detection ($detectionSource) · ${effectiveProfile.displayName}")
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
                estimatedThroughputMbps = displayThroughputMbps,
                activeProfile = effectiveProfile,
                manualProfileOverride = manualProfileOverride,
                detectionSource = detectionSource,
                concurrentStreamingDetected = packetAssessment.concurrentStreaming,
                foregroundPackage = usageDetected.foregroundPackage,
                networkType = sample.networkType,
                fecMode = effectiveFec,
                bgPacerRatio = baseDecision.bgPacerRatio,
                selectedRoute = effectiveRoute,
                engineRuntimeLabel = runtimeLabel,
                backendSummary = cfg.summaryLabel(),
                controlPlaneActive = controlPlaneActive,
                localShaperActive = localShaperActive,
                localActiveFlows = localStats.activeFlows,
                localPacedBytes = localStats.pacedBackgroundBytes,
                relayConnected = relayStats.connected,
                relayEncrypted = relayStats.encrypted,
                fullInternetTunnelActive = fullInternetTunnelActive,
                assignedTunnelIp = if (fullInternetTunnelActive) activeTunnelIp else relayStats.assignedIpv4,
                relayRegion = relayStats.region,
                relayRttMs = relayProbe?.rttMs ?: relayStats.relayRttMs,
                tunTxPackets = totalTx,
                tunRxPackets = totalRx,
                fecRecoveredPackets = relayStats.fecRecoveredTotal,
                rttHistoryMs = historySnapshot,
                lastSampleTimestampMs = SystemClock.elapsedRealtime(),
                statusDetail = detail,
                reasonCodes = baseDecision.reasonCodes,
            )

            SessionStore.update { updated }
            statusNotification.updateIfAllowed(updated)

            val screenInteractive = networkMonitor.isScreenInteractive()
            val nextDelayMs = computeAdaptiveProbeDelayMs(
                screenInteractive = screenInteractive,
                qualityState = baseDecision.qualityState,
            )
            if (screenInteractive) {
                delay(nextDelayMs)
            } else {
                // Sleep in 1 s slices when screen is off so unlocking resumes live probing promptly
                // while keeping background wakeups inside the 10 s EWMA freshness window.
                var remainingMs = nextDelayMs
                while (remainingMs > 0L && serviceScope.isActive && isRunning) {
                    val slice = minOf(remainingMs, SCREEN_OFF_WAKE_CHECK_MS)
                    delay(slice)
                    remainingMs -= slice
                    if (networkMonitor.isScreenInteractive()) {
                        break
                    }
                }
            }
        }
    }

    private fun recordBaselineSample(
        window: ArrayDeque<Pair<Long, Double>>,
        timestampMs: Long,
        rttMs: Double,
    ) {
        if (!rttMs.isFinite() || rttMs <= 0.0) return
        window.addLast(timestampMs to rttMs)
        val cutoff = timestampMs - BASELINE_ROLLING_WINDOW_MS
        while (window.isNotEmpty() && window.first().first < cutoff) {
            window.removeFirst()
        }
    }

    private fun computeAdaptiveProbeDelayMs(
        screenInteractive: Boolean,
        qualityState: QualityState,
    ): Long {
        if (!screenInteractive) {
            return 8_000L
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
        localShaperActive = false
        controlPlaneActive = false
        sessionJob?.cancel()
        sessionJob = null
        networkMonitor.stopObservingNetwork()
        trafficAutoProfileDetector.reset()
        uidFlowClassifier.clearCache()
        appContextDetector.reset()
        synchronized(rttHistoryLock) { rttHistoryWindow.clear() }

        localShaper.stop()

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

        stopTunDataPlaneThread()

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
        private const val LOCAL_SHAPER_MTU = 1500
        private const val STARTUP_WARMUP_EXTRA_PROBES = 2
        private const val STARTUP_WARMUP_INTERVAL_MS = 150L
        private const val SCREEN_OFF_WAKE_CHECK_MS = 1_000L
        private const val HIGH_THROUGHPUT_PROOF_MBPS = 25.0
        private const val BASELINE_ROLLING_WINDOW_MS = 90_000L
        private const val STEADY_BASELINE_MIN_SPAN_MS = 30_000L
        private const val STEADY_BASELINE_MIN_STREAK = 15
        private const val STEADY_BASELINE_MAX_JITTER_MS = 6.0
        private const val STEADY_BASELINE_MIN_BLOAT_MS = 10.0
        private const val STEADY_BASELINE_MAX_WINDOW_SPREAD_MS = 6.0

        /**
         * Stage 6.3 Link-Capacity Resolver for Formula #1 Quality Scoring:
         * Separates actual physical link capacity (`NetworkCapabilities.linkDownstreamBandwidthKbps`)
         * from low passive app usage (online gaming ~0.15 Mbps, browsing ~0.2 Mbps, YouTube 1080p ~3 Mbps)
         * so healthy Wi-Fi/4G links NEVER get falsely penalized as congested or starved!
         *
         * Observed throughput is only used as a proven LOWER BOUND (raising capacity upward if real
         * transfers exceed the OS estimate, or proving a >= 25 Mbps link when OS capacity is unavailable).
         */
        internal fun resolveScorerBandwidthMbps(
            linkCapacityMbps: Double?,
            observedThroughputMbps: Double?,
        ): Double? {
            val cleanCap = linkCapacityMbps?.takeIf { it.isFinite() && it > 0.0 }
            val cleanObs = observedThroughputMbps?.takeIf { it.isFinite() && it > 0.0 }
            return when {
                cleanCap != null -> if (cleanObs != null) maxOf(cleanCap, cleanObs) else cleanCap
                cleanObs != null && cleanObs >= HIGH_THROUGHPUT_PROOF_MBPS -> cleanObs
                else -> null
            }
        }

        /**
         * Detects permanent calm ISP route / 4G cell-tower baseline shifts (low jitter, 0% loss,
         * and tight RTT spread across the rolling window for >= 30 s) so `min_rtt` recalibrates
         * cleanly without ever masking real active bufferbloat.
         */
        internal fun shouldRecalibrateSteadyBaseline(
            bloatMs: Double,
            srttMs: Double,
            jitterMs: Double,
            lossPct: Double,
            steadyStreak: Int,
            windowSpanMs: Long,
            windowMinRttMs: Double,
        ): Boolean =
            bloatMs >= STEADY_BASELINE_MIN_BLOAT_MS &&
                jitterMs < STEADY_BASELINE_MAX_JITTER_MS &&
                lossPct == 0.0 &&
                steadyStreak >= STEADY_BASELINE_MIN_STREAK &&
                windowSpanMs >= STEADY_BASELINE_MIN_SPAN_MS &&
                windowMinRttMs.isFinite() &&
                windowMinRttMs > 0.0 &&
                (srttMs - windowMinRttMs) <= STEADY_BASELINE_MAX_WINDOW_SPREAD_MS

        /**
         * Stage 6.2 Auto-Profile Precedence:
         *   1. Manual pill / Developer override
         *   2. Foreground app (`UsageStats`) when recognized — immediately follows the app
         *      actually on screen (`Browser`, `Social`, `Streaming`, `Download`, `Game`) without
         *      being hijacked by minimized background apps, while upgrading `Browser` -> `Download`
         *      during sustained in-browser bulk file downloads.
         *   3. Zero-permission live packet/UID activity fallback (for users without Usage Access
         *      or unrecognized foreground apps — immune to DNS/TCP-ACK `GAME` false positives).
         *   4. Safe Balanced standby
         */
        internal fun resolveEffectiveProfile(
            manualOverride: TrafficProfile?,
            usageDetected: DetectedContext,
            packetAssessment: AutoProfileAssessment,
        ): Pair<TrafficProfile, String> = when {
            manualOverride != null -> manualOverride to "Manual"
            usageDetected.hasUsagePermission &&
                usageDetected.profile != TrafficProfile.SAFE_BALANCED -> {
                if (usageDetected.profile == TrafficProfile.BROWSER &&
                    packetAssessment.detectedFromPackets &&
                    packetAssessment.profile == TrafficProfile.DOWNLOAD
                ) {
                    TrafficProfile.DOWNLOAD to "Packet UID"
                } else {
                    usageDetected.profile to "App Usage"
                }
            }
            packetAssessment.detectedFromPackets ->
                packetAssessment.profile to "Packet UID"
            else -> TrafficProfile.SAFE_BALANCED to "Standby"
        }
    }
}
