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
    val encrypted: Boolean,
    val assignedIpv4: String?,
    val region: String?,
    val relayRttMs: Double?,
    val txPackets: Long,
    val rxPackets: Long,
    val fecRecoveredTotal: Long,
)

/**
 * Stage 4 Protected UDP JITER Relay Client.
 *
 * Security & Concurrency:
 *   - Supports Stage 4 ECDHE P-256 + PSK mutual auth + HKDF-SHA256 + ChaCha20-Poly1305 AEAD
 *     with 16-byte WireHeader bound as AAD and 64-packet Anti-Replay Window
 *   - Uses a single dedicated reader thread to demultiplex incoming UDP datagrams cleanly
 *   - Protects every socket via `VpnService.protect(DatagramSocket)` so tunnel traffic never loops
 */
class RelayTunnelClient(
    private val onDownlinkPacket: (ByteArray) -> Unit,
    private val clockMs: () -> Long = { System.nanoTime() / 1_000_000L },
) {
    private val secureRandom = SecureRandom()
    private val running = AtomicBoolean(false)
    private val connectedFlag = AtomicBoolean(false)
    private val encryptedFlag = AtomicBoolean(false)

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
    private var activePsk: String = ""

    @Volatile
    private var relayRegion: String? = null

    @Volatile
    private var assignedIpv4Internal: String? = null

    @Volatile
    private var acceptedMtuInternal: Int = 1280

    @Volatile
    private var relayCapsInternal: Int = 0

    @Volatile
    private var sessionCipher: SessionCipher? = null

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

    private class PendingHello(val expectEncrypted: Boolean) {
        val latch = CountDownLatch(1)

        @Volatile
        var plainAck: HelloAckPayload? = null

        @Volatile
        var encryptedAck: EncryptedHelloAckPayload? = null
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

    val isEncrypted: Boolean
        get() = encryptedFlag.get() && sessionCipher != null

    val assignedIpv4: String?
        get() = assignedIpv4Internal

    val acceptedMtu: Int
        get() = acceptedMtuInternal

    val relayCaps: Int
        get() = relayCapsInternal

    fun matchesConfig(config: BackendConfig): Boolean =
        activeHost == config.relayHost.trim() &&
            activePort == config.relayPort &&
            activePsk == config.relayPsk.trim()

    /**
     * Opens a protected UDP socket to `host:port`, launches the demuxing reader thread,
     * and performs either:
     *   - Stage 4 ECDHE P-256 + PSK mutual auth handshake (when `config.hasRelayPsk()`), or
     *   - Plaintext diagnostic `HELLO_REQ -> HELLO_ACK` (when PSK is blank).
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
        val psk = config.relayPsk.trim()
        val useEncryption = psk.isNotEmpty()

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
            activePsk = psk
            socket = sock
            sessionCipher = null
            encryptedFlag.set(false)
            assignedIpv4Internal = null
            acceptedMtuInternal = 1280
            relayCapsInternal = 0
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

            val baseHello = HelloReqPayload(
                profileId = profile.ordinal,
                routingMode = config.routingMode.ordinal,
                fecPolicy = config.fecPolicy.ordinal,
                mtu = 1280,
                linkHintMbpsX10 = 300,
            )

            if (useEncryption) {
                val pskKey = RelayCrypto.derivePskKey(psk)
                val clientKp = EphemeralP256KeyPair.generate()
                val clientNonce = RelayCrypto.randomNonce16()

                val helloWait = PendingHello(expectEncrypted = true)
                pendingHello = helloWait

                val encPayload = EncryptedHelloReqPayload.buildSigned(
                    base = baseHello,
                    clientPub = clientKp.publicUncompressed,
                    clientNonce = clientNonce,
                    pskKey = pskKey,
                    sessionId = sid,
                )
                val hdr = WireHeader(
                    msgType = RelayProtocol.MSG_HELLO_REQ,
                    trafficTier = RelayProtocol.TIER_GAME,
                    flags = RelayProtocol.FLAG_ENCRYPTED,
                    sessionId = sid,
                    sequence = txSeq.getAndIncrement(),
                    payloadLen = encPayload.size,
                    pacerQ8 = 255,
                    fecMode = 0,
                )
                sendRawFrame(hdr.frameBytes(encPayload))

                val gotAck = helloWait.latch.await(1_000L, TimeUnit.MILLISECONDS)
                pendingHello = null

                val encAck = helloWait.encryptedAck
                if (!gotAck || encAck == null) {
                    disconnect(sendGoodbye = false)
                    return false
                }

                // Verify server mutual auth MAC in constant time
                val expectedServerTag = RelayCrypto.computeHelloAckTag(
                    pskKey = pskKey,
                    sessionId = sid,
                    clientNonce = clientNonce,
                    bodyBeforeTag = encAck.bodyBeforeTag,
                )
                if (!RelayCrypto.constantTimeEquals(expectedServerTag, encAck.authTag)) {
                    disconnect(sendGoodbye = false)
                    return false
                }

                val ecdhShared = clientKp.diffieHellman(encAck.serverPub)
                if (ecdhShared == null) {
                    disconnect(sendGoodbye = false)
                    return false
                }

                val keys = RelayCrypto.deriveSessionKeys(
                    ecdhShared = ecdhShared,
                    pskKey = pskKey,
                    clientNonce = clientNonce,
                    serverNonce = encAck.serverNonce,
                    sessionId = sid,
                )
                sessionCipher = SessionCipher.forClient(keys)
                encryptedFlag.set(true)
                relayRegion = encAck.base.regionTag
                acceptedMtuInternal = encAck.base.acceptedMtu.coerceIn(576, 1400)
                relayCapsInternal = encAck.base.relayCaps
                assignedIpv4Internal = encAck.assignedIpv4String
                connectedFlag.set(true)
                true
            } else {
                val helloWait = PendingHello(expectEncrypted = false)
                pendingHello = helloWait

                val helloPayload = baseHello.pack()
                val hdr = WireHeader(
                    msgType = RelayProtocol.MSG_HELLO_REQ,
                    trafficTier = RelayProtocol.TIER_GAME,
                    flags = 0,
                    sessionId = sid,
                    sequence = txSeq.getAndIncrement(),
                    payloadLen = helloPayload.size,
                    pacerQ8 = 255,
                    fecMode = 0,
                )
                sendRawFrame(hdr.frameBytes(helloPayload))

                val gotAck = helloWait.latch.await(700L, TimeUnit.MILLISECONDS)
                pendingHello = null

                val ack = helloWait.plainAck
                if (gotAck && ack != null) {
                    relayRegion = ack.regionTag
                    acceptedMtuInternal = ack.acceptedMtu.coerceIn(576, 1400)
                    relayCapsInternal = ack.relayCaps
                    connectedFlag.set(true)
                    true
                } else {
                    connectedFlag.set(false)
                    relayRegion = null
                    false
                }
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

        val frame = buildOutgoingFrame(
            msgType = RelayProtocol.MSG_PROBE_REQ,
            tier = RelayProtocol.TIER_GAME,
            extraFlags = 0,
            pacerQ8 = RelayProtocol.pacerRatioToQ8(bgPacerRatio),
            wireFecMode = RelayProtocol.fecModeToWireByte(fecMode),
            plaintext = reqPayload,
        )

        if (frame == null || !sendRawFrame(frame)) {
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
        val frame = buildOutgoingFrame(
            msgType = RelayProtocol.MSG_POLICY_SYNC,
            tier = RelayProtocol.TIER_GAME,
            extraFlags = 0,
            pacerQ8 = RelayProtocol.pacerRatioToQ8(bgPacerRatio),
            wireFecMode = RelayProtocol.fecModeToWireByte(fecMode),
            plaintext = payload,
        ) ?: return
        sendRawFrame(frame)
    }

    /**
     * Transmits one prioritized TUN IPv4 packet to the Relay.
     * Applies GF(2) XOR Parity FEC automatically on `TIER_GAME` packets when `fecMode != OFF`,
     * and ChaCha20-Poly1305 AEAD encryption whenever a PSK session cipher is active.
     */
    fun sendDataPacket(
        trafficTier: Int,
        rawIpv4: ByteArray,
        length: Int,
        fecMode: FecMode,
        bgPacerRatio: Double,
    ): Boolean {
        val maxPlain = if (sessionCipher != null) {
            RelayProtocol.MAX_PAYLOAD_BYTES - RelayCrypto.AEAD_TAG_BYTES
        } else {
            RelayProtocol.MAX_PAYLOAD_BYTES
        }
        if (!isConnected || length <= 0 || length > maxPlain) {
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
                    if (fecWire.size > maxPlain) continue
                    val wire = buildOutgoingFrame(
                        msgType = RelayProtocol.MSG_DATA_FEC,
                        tier = trafficTier,
                        extraFlags = if (fr.isParity) RelayProtocol.FLAG_FEC_PARITY else 0,
                        pacerQ8 = pacerQ8,
                        wireFecMode = wireFecMode,
                        plaintext = fecWire,
                    )
                    if (wire == null || !sendRawFrame(wire)) {
                        allSent = false
                    }
                }
                if (allSent) txPacketsCounter.incrementAndGet()
                return allSent
            }
        }

        val wire = buildOutgoingFrame(
            msgType = RelayProtocol.MSG_DATA_PLAIN,
            tier = trafficTier,
            extraFlags = 0,
            pacerQ8 = pacerQ8,
            wireFecMode = wireFecMode,
            plaintext = rawIpv4,
            plainLen = length,
        ) ?: return false

        val ok = sendRawFrame(wire)
        if (ok) txPacketsCounter.incrementAndGet()
        return ok
    }

    fun stats(): RelayDataStats {
        val localRecovered = synchronized(fecLock) { downlinkFecDecoder.recoveredCount.toLong() }
        val srtt = synchronized(relayEwmaLock) { relayEwma.srttMs }
        return RelayDataStats(
            connected = isConnected,
            encrypted = isEncrypted,
            assignedIpv4 = assignedIpv4Internal,
            region = relayRegion,
            relayRttMs = srtt,
            txPackets = txPacketsCounter.get(),
            rxPackets = rxPacketsCounter.get(),
            fecRecoveredTotal = localRecovered + remoteFecRecovered.get(),
        )
    }

    fun disconnect(sendGoodbye: Boolean = true) {
        if (sendGoodbye && running.get() && sessionId != 0) {
            val byeFrame = buildOutgoingFrame(
                msgType = RelayProtocol.MSG_CONTROL,
                tier = RelayProtocol.TIER_GAME,
                extraFlags = RelayProtocol.FLAG_GOODBYE,
                pacerQ8 = 255,
                wireFecMode = 0,
                plaintext = ByteArray(0),
                plainLen = 0,
            )
            if (byeFrame != null) {
                sendRawFrame(byeFrame)
            }
        }

        running.set(false)
        connectedFlag.set(false)
        encryptedFlag.set(false)
        sessionCipher = null
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
        activePsk = ""
        relayRegion = null
        assignedIpv4Internal = null
        relayCapsInternal = 0
        sessionId = 0
    }

    private fun buildOutgoingFrame(
        msgType: Int,
        tier: Int,
        extraFlags: Int,
        pacerQ8: Int,
        wireFecMode: Int,
        plaintext: ByteArray,
        plainLen: Int = plaintext.size,
    ): ByteArray? {
        val seq = txSeq.getAndIncrement()
        val cipher = sessionCipher
        return if (cipher != null) {
            val ctLen = plainLen + RelayCrypto.AEAD_TAG_BYTES
            if (ctLen > RelayProtocol.MAX_PAYLOAD_BYTES) return null
            val hdr = WireHeader(
                msgType = msgType,
                trafficTier = tier,
                flags = extraFlags or RelayProtocol.FLAG_ENCRYPTED,
                sessionId = sessionId,
                sequence = seq,
                payloadLen = ctLen,
                pacerQ8 = pacerQ8,
                fecMode = wireFecMode,
            )
            val aad = hdr.pack()
            val ct = cipher.encrypt(sessionId, seq, aad, plaintext, plainLen) ?: return null
            val out = ByteArray(RelayProtocol.WIRE_HEADER_BYTES + ct.size)
            System.arraycopy(aad, 0, out, 0, RelayProtocol.WIRE_HEADER_BYTES)
            System.arraycopy(ct, 0, out, RelayProtocol.WIRE_HEADER_BYTES, ct.size)
            out
        } else {
            if (plainLen > RelayProtocol.MAX_PAYLOAD_BYTES) return null
            val hdr = WireHeader(
                msgType = msgType,
                trafficTier = tier,
                flags = extraFlags and RelayProtocol.FLAG_ENCRYPTED.inv(),
                sessionId = sessionId,
                sequence = seq,
                payloadLen = plainLen,
                pacerQ8 = pacerQ8,
                fecMode = wireFecMode,
            )
            hdr.frameBytes(plaintext, plainLen)
        }
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

        val isEncFrame = (hdr.flags and RelayProtocol.FLAG_ENCRYPTED) != 0

        if (hdr.msgType == RelayProtocol.MSG_HELLO_ACK) {
            val waiter = pendingHello ?: return
            if (waiter.expectEncrypted) {
                if (!isEncFrame) return
                val encAck = EncryptedHelloAckPayload.unpack(
                    buf,
                    RelayProtocol.WIRE_HEADER_BYTES,
                    hdr.payloadLen,
                )
                if (encAck != null) {
                    waiter.encryptedAck = encAck
                    waiter.latch.countDown()
                }
            } else {
                if (isEncFrame) return
                val plainAck = HelloAckPayload.unpack(
                    buf,
                    RelayProtocol.WIRE_HEADER_BYTES,
                    hdr.payloadLen,
                )
                if (plainAck != null) {
                    waiter.plainAck = plainAck
                    waiter.latch.countDown()
                }
            }
            return
        }

        // Decrypt & check Anti-Replay Window if AEAD cipher is active
        val cipher = sessionCipher
        val plainBytes: ByteArray
        val plainOff: Int
        val plainLen: Int
        if (cipher != null) {
            if (!isEncFrame) return
            val aad = buf.copyOfRange(0, RelayProtocol.WIRE_HEADER_BYTES)
            val decrypted = cipher.decryptAndCheckReplay(
                sessionId = hdr.sessionId,
                sequence = hdr.sequence,
                aadHeader = aad,
                ciphertext = buf,
                offset = RelayProtocol.WIRE_HEADER_BYTES,
                length = hdr.payloadLen,
            ) ?: return
            plainBytes = decrypted
            plainOff = 0
            plainLen = decrypted.size
        } else {
            if (isEncFrame) return
            plainBytes = buf
            plainOff = RelayProtocol.WIRE_HEADER_BYTES
            plainLen = hdr.payloadLen
        }

        when (hdr.msgType) {
            RelayProtocol.MSG_PROBE_RESP -> {
                val resp = ProbeRespPayload.unpack(plainBytes, plainOff, plainLen)
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
                if (plainLen > 0) {
                    val payload = plainBytes.copyOfRange(plainOff, plainOff + plainLen)
                    rxPacketsCounter.incrementAndGet()
                    onDownlinkPacket(payload)
                }
            }
            RelayProtocol.MSG_DATA_FEC -> {
                if (plainLen >= FecFrame.HEADER_SIZE) {
                    val wireFec = plainBytes.copyOfRange(plainOff, plainOff + plainLen)
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
