package com.jiter.app.relay

import com.jiter.app.config.BackendConfig
import com.jiter.app.engine.BitwiseEwmaEstimator
import com.jiter.app.engine.FecFrame
import com.jiter.app.engine.FecMode
import com.jiter.app.engine.InterleavedXorFecDecoder
import com.jiter.app.engine.InterleavedXorFecEncoder
import com.jiter.app.engine.RouteMetrics
import com.jiter.app.engine.TrafficProfile
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

data class RelayProbeResult(
    val reachable: Boolean,
    val rttMs: Double?,
    val routeMetrics: RouteMetrics?,
    val relayRegion: String?,
    val relayFecRecovered: Long,
)

data class RelayDataStats(
    val connected: Boolean,
    val region: String?,
    val relayRttMs: Double?,
    val txPackets: Long,
    val rxPackets: Long,
    val fecRecoveredTotal: Long,
)

/**
 * Stage 3 Protected UDP JITER Relay Client.
 *
 * Uses a single dedicated reader thread to demultiplex incoming UDP datagrams cleanly
 * (`HELLO_ACK`, `PROBE_RESP`, `DATA_PLAIN`, `DATA_FEC`) without socket read contention.
 *
 * All UDP sockets pass through `VpnService.protect(DatagramSocket)` so tunnel traffic
 * never loops back into the local Android TUN interface.
 */
class RelayTunnelClient(
    private val onDownlinkPacket: (ByteArray) -> Unit,
    private val clockMs: () -> Long = { System.nanoTime() / 1_000_000L },
) {
    private val secureRandom = SecureRandom()
    private val running = AtomicBoolean(false)
    private val connectedFlag = AtomicBoolean(false)

    private val txSeq = AtomicInteger(1)
    private val txPacketsCounter = AtomicLong(0L)
    private val rxPacketsCounter = AtomicLong(0L)
    private val remoteFecRecovered = AtomicLong(0L)

    @Volatile
    private var sessionId: Int = 0

    @Volatile
    private var remoteAddr: InetSocketAddress? = null

    @Volatile
    private var activeHost: String = ""

    @Volatile
    private var activePort: Int = 0

    @Volatile
    private var relayRegion: String? = null

    @Volatile
    private var socket: DatagramSocket? = null

    @Volatile
    private var readerThread: Thread? = null

    private val sendLock = Any()
    private val fecLock = Any()
    private var activeUplinkFecMode: FecMode = FecMode.OFF
    private var uplinkFecEncoder: InterleavedXorFecEncoder? = null
    private val downlinkFecDecoder = InterleavedXorFecDecoder(maxTrackedGroups = 96)

    private val relayEwmaLock = Any()
    private val relayEwma = BitwiseEwmaEstimator()

    private class PendingHello {
        val latch = CountDownLatch(1)

        @Volatile
        var ack: HelloAckPayload? = null
    }

    private class PendingProbe(val txUs: Long, val sentNs: Long) {
        val latch = CountDownLatch(1)

        @Volatile
        var resp: ProbeRespPayload? = null

        @Volatile
        var recvNs: Long = 0L
    }

    @Volatile
    private var pendingHello: PendingHello? = null

    @Volatile
    private var pendingProbe: PendingProbe? = null

    val isConnected: Boolean
        get() = connectedFlag.get() && running.get()

    fun matchesEndpoint(host: String, port: Int): Boolean =
        activeHost == host.trim() && activePort == port

    /**
     * Opens a protected UDP socket to `host:port`, launches the demuxing reader thread,
     * and performs the ephemeral `HELLO_REQ -> HELLO_ACK` handshake.
     */
    fun connect(
        config: BackendConfig,
        profile: TrafficProfile,
        socketProtector: (DatagramSocket) -> Boolean,
    ): Boolean {
        disconnect(sendGoodbye = true)
        if (!config.hasCustomRelay()) return false

        val host = config.relayHost.trim()
        val port = config.relayPort.coerceIn(1, 65535)

        return try {
            val resolved = InetAddress.getByName(host)
            val target = InetSocketAddress(resolved, port)

            val sock = DatagramSocket()
            sock.soTimeout = 250
            socketProtector(sock)

            var sid = secureRandom.nextInt()
            if (sid == 0) sid = 0x10A7_7701

            sessionId = sid
            remoteAddr = target
            activeHost = host
            activePort = port
            socket = sock
            txSeq.set(1)
            txPacketsCounter.set(0L)
            rxPacketsCounter.set(0L)
            remoteFecRecovered.set(0L)
            synchronized(relayEwmaLock) { relayEwma.reset() }
            synchronized(fecLock) {
                downlinkFecDecoder.reset()
                activeUplinkFecMode = FecMode.OFF
                uplinkFecEncoder = null
            }

            running.set(true)
            startReaderLoop(sock)

            val helloWait = PendingHello()
            pendingHello = helloWait

            val helloPayload = HelloReqPayload(
                profileId = profile.ordinal,
                routingMode = config.routingMode.ordinal,
                fecPolicy = config.fecPolicy.ordinal,
                mtu = 1280,
                linkHintMbpsX10 = 300,
            ).pack()
            val hdr = WireHeader(
                msgType = RelayProtocol.MSG_HELLO_REQ,
                trafficTier = RelayProtocol.TIER_GAME,
                sessionId = sid,
                sequence = txSeq.getAndIncrement(),
                payloadLen = helloPayload.size,
                pacerQ8 = 255,
                fecMode = 0,
            )
            sendRawFrame(hdr.frameBytes(helloPayload))

            val gotAck = helloWait.latch.await(700L, TimeUnit.MILLISECONDS)
            pendingHello = null

            val ack = helloWait.ack
            if (gotAck && ack != null) {
                relayRegion = ack.regionTag
                connectedFlag.set(true)
                true
            } else {
                connectedFlag.set(false)
                relayRegion = null
                false
            }
        } catch (_: Exception) {
            disconnect(sendGoodbye = false)
            false
        }
    }

    /**
     * Measures real Relay RTT, uplink loss, queue delay, and recovered FEC packets
     * via `PROBE_REQ -> PROBE_RESP`, returning `RouteMetrics` for Formula #1 route selection.
     */
    fun probeRelay(
        profile: TrafficProfile,
        fecMode: FecMode,
        bgPacerRatio: Double,
    ): RelayProbeResult {
        if (!running.get() || socket == null || remoteAddr == null) {
            return RelayProbeResult(false, null, null, relayRegion, remoteFecRecovered.get())
        }

        val nowMs = clockMs()
        val txUs = System.nanoTime() / 1_000L
        val sentNs = System.nanoTime()
        val waiter = PendingProbe(txUs = txUs, sentNs = sentNs)
        pendingProbe = waiter

        val reqPayload = ProbeReqPayload(
            clientTxUs = txUs,
            profileId = profile.ordinal,
        ).pack()
        val hdr = WireHeader(
            msgType = RelayProtocol.MSG_PROBE_REQ,
            trafficTier = RelayProtocol.TIER_GAME,
            sessionId = sessionId,
            sequence = txSeq.getAndIncrement(),
            payloadLen = reqPayload.size,
            pacerQ8 = RelayProtocol.pacerRatioToQ8(bgPacerRatio),
            fecMode = RelayProtocol.fecModeToWireByte(fecMode),
        )

        if (!sendRawFrame(hdr.frameBytes(reqPayload))) {
            pendingProbe = null
            connectedFlag.set(false)
            return RelayProbeResult(false, null, null, relayRegion, remoteFecRecovered.get())
        }

        val gotResp = try {
            waiter.latch.await(800L, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            false
        }
        pendingProbe = null

        val resp = waiter.resp
        if (!gotResp || resp == null) {
            connectedFlag.set(false)
            return RelayProbeResult(false, null, null, relayRegion, remoteFecRecovered.get())
        }

        connectedFlag.set(true)
        val rttMs = ((waiter.recvNs - waiter.sentNs).coerceAtLeast(100_000L)) / 1_000_000.0
        remoteFecRecovered.set(resp.relayFecRecovered)

        val metrics = synchronized(relayEwmaLock) {
            relayEwma.update(rttMs, nowMs)
            val srtt = relayEwma.srttMs ?: rttMs
            val jitter = relayEwma.jitterMs ?: 0.0
            val bloat = maxOf(relayEwma.bufferbloatMs ?: 0.0, resp.relayQueueMs)
            RouteMetrics(
                srttMs = srtt,
                jitterMs = jitter,
                lossPct = resp.relayRxLossPct,
                bufferbloatMs = bloat,
            )
        }

        return RelayProbeResult(
            reachable = true,
            rttMs = rttMs,
            routeMetrics = metrics,
            relayRegion = relayRegion,
            relayFecRecovered = resp.relayFecRecovered,
        )
    }

    /**
     * Synchronizes active profile, pacer ratio, FEC mode, and estimated bandwidth
     * to the Relay Edge for two-sided downstream anti-bufferbloat actuation.
     */
    fun syncPolicy(
        profile: TrafficProfile,
        fecMode: FecMode,
        bgPacerRatio: Double,
        estimatedLinkMbps: Double?,
    ) {
        if (!isConnected) return
        val linkX10 = ((estimatedLinkMbps ?: 25.0).coerceIn(1.0, 5000.0) * 10.0).toInt()
        val payload = PolicySyncPayload(
            profileId = profile.ordinal,
            fecMode = RelayProtocol.fecModeToWireByte(fecMode),
            pacerQ8 = RelayProtocol.pacerRatioToQ8(bgPacerRatio),
            linkMbpsX10 = linkX10,
        ).pack()
        val hdr = WireHeader(
            msgType = RelayProtocol.MSG_POLICY_SYNC,
            trafficTier = RelayProtocol.TIER_GAME,
            sessionId = sessionId,
            sequence = txSeq.getAndIncrement(),
            payloadLen = payload.size,
            pacerQ8 = RelayProtocol.pacerRatioToQ8(bgPacerRatio),
            fecMode = RelayProtocol.fecModeToWireByte(fecMode),
        )
        sendRawFrame(hdr.frameBytes(payload))
    }

    /**
     * Transmits one prioritized TUN IPv4 packet to the Relay.
     * Applies GF(2) XOR Parity FEC automatically on `TIER_GAME` packets when `fecMode != OFF`.
     */
    fun sendDataPacket(
        trafficTier: Int,
        rawIpv4: ByteArray,
        length: Int,
        fecMode: FecMode,
        bgPacerRatio: Double,
    ): Boolean {
        if (!isConnected || length <= 0 || length > RelayProtocol.MAX_PAYLOAD_BYTES) {
            return false
        }
        val pacerQ8 = RelayProtocol.pacerRatioToQ8(bgPacerRatio)
        val wireFecMode = RelayProtocol.fecModeToWireByte(fecMode)

        if (trafficTier == RelayProtocol.TIER_GAME && fecMode != FecMode.OFF) {
            val frames: List<FecFrame> = synchronized(fecLock) {
                if (activeUplinkFecMode != fecMode || uplinkFecEncoder == null) {
                    activeUplinkFecMode = fecMode
                    uplinkFecEncoder = when (fecMode) {
                        FecMode.XOR_K2_INTERLEAVED -> InterleavedXorFecEncoder(blockK = 2, stride = 1)
                        FecMode.XOR_K4_INTERLEAVED -> InterleavedXorFecEncoder(blockK = 4, stride = 2)
                        FecMode.DUPLICATE -> InterleavedXorFecEncoder(blockK = 1, stride = 1)
                        FecMode.OFF -> null
                    }
                }
                val enc = uplinkFecEncoder
                if (enc != null) enc.encodePacket(rawIpv4.copyOf(length)) else emptyList()
            }
            if (frames.isNotEmpty()) {
                var allSent = true
                for (fr in frames) {
                    val fecWire = fr.toWireBytes()
                    if (fecWire.size > RelayProtocol.MAX_PAYLOAD_BYTES) continue
                    val hdr = WireHeader(
                        msgType = RelayProtocol.MSG_DATA_FEC,
                        trafficTier = trafficTier,
                        flags = if (fr.isParity) RelayProtocol.FLAG_FEC_PARITY else 0,
                        sessionId = sessionId,
                        sequence = txSeq.getAndIncrement(),
                        payloadLen = fecWire.size,
                        pacerQ8 = pacerQ8,
                        fecMode = wireFecMode,
                    )
                    if (!sendRawFrame(hdr.frameBytes(fecWire))) {
                        allSent = false
                    }
                }
                if (allSent) txPacketsCounter.incrementAndGet()
                return allSent
            }
        }

        val hdr = WireHeader(
            msgType = RelayProtocol.MSG_DATA_PLAIN,
            trafficTier = trafficTier,
            sessionId = sessionId,
            sequence = txSeq.getAndIncrement(),
            payloadLen = length,
            pacerQ8 = pacerQ8,
            fecMode = wireFecMode,
        )
        val ok = sendRawFrame(hdr.frameBytes(rawIpv4, length))
        if (ok) txPacketsCounter.incrementAndGet()
        return ok
    }

    fun stats(): RelayDataStats {
        val localRecovered = synchronized(fecLock) { downlinkFecDecoder.recoveredCount.toLong() }
        val srtt = synchronized(relayEwmaLock) { relayEwma.srttMs }
        return RelayDataStats(
            connected = isConnected,
            region = relayRegion,
            relayRttMs = srtt,
            txPackets = txPacketsCounter.get(),
            rxPackets = rxPacketsCounter.get(),
            fecRecoveredTotal = localRecovered + remoteFecRecovered.get(),
        )
    }

    fun disconnect(sendGoodbye: Boolean = true) {
        if (sendGoodbye && running.get() && sessionId != 0) {
            val byeHdr = WireHeader(
                msgType = RelayProtocol.MSG_CONTROL,
                trafficTier = RelayProtocol.TIER_GAME,
                flags = RelayProtocol.FLAG_GOODBYE,
                sessionId = sessionId,
                sequence = txSeq.getAndIncrement(),
                payloadLen = 0,
                pacerQ8 = 255,
                fecMode = 0,
            )
            sendRawFrame(byeHdr.frameBytes(ByteArray(0), 0))
        }

        running.set(false)
        connectedFlag.set(false)
        pendingHello?.latch?.countDown()
        pendingProbe?.latch?.countDown()
        pendingHello = null
        pendingProbe = null

        val sock = socket
        socket = null
        try {
            sock?.close()
        } catch (_: Exception) {
            // Ignore close error
        }

        val t = readerThread
        readerThread = null
        if (t != null && t !== Thread.currentThread()) {
            try {
                t.join(350L)
            } catch (_: InterruptedException) {
                // Ignore interrupt
            }
        }

        remoteAddr = null
        activeHost = ""
        activePort = 0
        relayRegion = null
        sessionId = 0
    }

    private fun sendRawFrame(bytes: ByteArray): Boolean {
        val sock = socket ?: return false
        val target = remoteAddr ?: return false
        return try {
            synchronized(sendLock) {
                val pkt = DatagramPacket(bytes, bytes.size, target)
                sock.send(pkt)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun startReaderLoop(sock: DatagramSocket) {
        val thread = Thread({
            val buf = ByteArray(2048)
            val pkt = DatagramPacket(buf, buf.size)
            while (running.get() && !sock.isClosed) {
                try {
                    pkt.length = buf.size
                    sock.receive(pkt)
                    val len = pkt.length
                    if (len < RelayProtocol.WIRE_HEADER_BYTES) continue
                    handleIncomingDatagram(buf, len)
                } catch (_: SocketTimeoutException) {
                    // Normal periodic wakeup to check `running`
                } catch (_: Exception) {
                    if (!running.get() || sock.isClosed) break
                }
            }
        }, "jiter-relay-rx").apply {
            isDaemon = true
            start()
        }
        readerThread = thread
    }

    private fun handleIncomingDatagram(buf: ByteArray, len: Int) {
        val hdr = WireHeader.unpack(buf, len) ?: return
        if (hdr.sessionId != sessionId) return
        val payloadEnd = RelayProtocol.WIRE_HEADER_BYTES + hdr.payloadLen
        if (len < payloadEnd) return

        when (hdr.msgType) {
            RelayProtocol.MSG_HELLO_ACK -> {
                val ack = HelloAckPayload.unpack(buf, RelayProtocol.WIRE_HEADER_BYTES, hdr.payloadLen)
                if (ack != null) {
                    pendingHello?.let { waiter ->
                        waiter.ack = ack
                        waiter.latch.countDown()
                    }
                }
            }
            RelayProtocol.MSG_PROBE_RESP -> {
                val resp = ProbeRespPayload.unpack(buf, RelayProtocol.WIRE_HEADER_BYTES, hdr.payloadLen)
                if (resp != null) {
                    pendingProbe?.let { waiter ->
                        if (waiter.txUs == resp.echoTxUs) {
                            waiter.recvNs = System.nanoTime()
                            waiter.resp = resp
                            waiter.latch.countDown()
                        }
                    }
                }
            }
            RelayProtocol.MSG_DATA_PLAIN -> {
                if (hdr.payloadLen > 0) {
                    val payload = buf.copyOfRange(RelayProtocol.WIRE_HEADER_BYTES, payloadEnd)
                    rxPacketsCounter.incrementAndGet()
                    onDownlinkPacket(payload)
                }
            }
            RelayProtocol.MSG_DATA_FEC -> {
                if (hdr.payloadLen >= FecFrame.HEADER_SIZE) {
                    val wireFec = buf.copyOfRange(RelayProtocol.WIRE_HEADER_BYTES, payloadEnd)
                    val delivered = try {
                        val fecFrame = FecFrame.fromWireBytes(wireFec)
                        synchronized(fecLock) {
                            downlinkFecDecoder.receive(fecFrame)
                        }
                    } catch (_: Exception) {
                        emptyList()
                    }
                    for (pkt in delivered) {
                        rxPacketsCounter.incrementAndGet()
                        onDownlinkPacket(pkt.payload)
                    }
                }
            }
        }
    }
}
