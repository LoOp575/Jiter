package com.jiter.app.engine

import android.content.pm.ApplicationInfo
import com.jiter.app.bridge.KotlinEngineAdapter
import com.jiter.app.bridge.NativeEngineBridge
import com.jiter.app.config.AppLanguage
import com.jiter.app.config.BackendConfig
import com.jiter.app.config.LanguageManager
import com.jiter.app.config.RoutingMode
import com.jiter.app.config.TunnelScope
import com.jiter.app.context.TrafficAutoProfileDetector
import com.jiter.app.context.UidFlowClassifier
import com.jiter.app.relay.ControlPlaneClient
import com.jiter.app.relay.EncryptedHelloAckPayload
import com.jiter.app.relay.EncryptedHelloReqPayload
import com.jiter.app.relay.EphemeralP256KeyPair
import com.jiter.app.relay.HelloAckPayload
import com.jiter.app.relay.HelloReqPayload
import com.jiter.app.relay.RelayCrypto
import com.jiter.app.relay.RelayProtocol
import com.jiter.app.relay.RelayTunnelClient
import com.jiter.app.relay.ReplayWindow
import com.jiter.app.relay.SessionCipher
import com.jiter.app.relay.WireHeader
import com.sun.net.httpserver.HttpServer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.abs

class JiterEngineTest {

    // ------------------------------------------------------------------------
    // Formula #2: Scaled Bitwise EWMA / Jacobson's Algorithm (RFC 6298)
    // ------------------------------------------------------------------------

    @Test
    fun ewmaRejectsInvalidAndOutOfOrderSamples() {
        val est = BitwiseEwmaEstimator()
        assertFalse(est.update(0.0, 1_000L))
        assertFalse(est.update(-5.0, 1_000L))
        assertFalse(est.update(Double.NaN, 1_000L))
        assertFalse(est.update(Double.POSITIVE_INFINITY, 1_000L))
        assertFalse(est.update(40_000.0, 1_000L))
        assertFalse(est.isInitialized)
        assertNull(est.srttMs)

        assertTrue(est.update(20.0, 2_000L))
        assertFalse(est.update(22.0, 1_500L)) // out-of-order timestamp
        assertEquals(1, est.sampleCount)
    }

    @Test
    fun ewmaScaledBitwiseMatchesRfc6298FloatWithoutTruncation() {
        val samples = doubleArrayOf(30.0, 32.0, 29.0, 31.0, 30.0, 120.0, 31.0, 29.0, 30.0)
        val est = BitwiseEwmaEstimator()
        var srttF = samples[0]
        var varF = samples[0] / 2.0

        samples.forEachIndexed { idx, rtt ->
            assertTrue(est.update(rtt, idx * 1_000L))
            if (idx > 0) {
                val err = rtt - srttF
                varF = 0.75 * varF + 0.25 * abs(err)
                srttF = 0.875 * srttF + 0.125 * rtt
            }
        }

        val srtt = requireNotNull(est.srttMs)
        val jitter = requireNotNull(est.jitterMs)
        val bloat = requireNotNull(est.bufferbloatMs)
        assertTrue("SRTT drift too high: $srtt vs $srttF", abs(srtt - srttF) < 0.05)
        assertTrue("Jitter drift too high: $jitter vs $varF", abs(jitter - varF) < 0.05)
        assertTrue("Expected positive bufferbloat after 120ms spike", bloat > 0.0)
    }

    @Test
    fun ewmaDetectsStaleSamples() {
        val est = BitwiseEwmaEstimator()
        assertTrue(est.isStale(1_000L))
        est.update(15.0, 1_000L)
        assertFalse(est.isStale(5_000L, maxAgeMs = 10_000L))
        assertTrue(est.isStale(12_000L, maxAgeMs = 10_000L))
    }

    // ------------------------------------------------------------------------
    // Formula #1: Linear Cost Function + Hard Veto Guardrails + Hysteresis
    // ------------------------------------------------------------------------

    @Test
    fun allProfileWeightsSumToOne() {
        for (profile in TrafficProfile.entries) {
            val w = profile.weights
            val total = w.wRtt + w.wJitter + w.wLoss + w.wBloat + w.wBw
            assertEquals("Weights for $profile must sum to 1.0", 1.0, total, 1e-6)
        }
    }

    @Test
    fun gameHardVetoPreventsLossCompensationTrap() {
        val res = LinearCostScorer.evaluate(
            srttMs = 20.0,
            jitterMs = 2.0,
            lossPct = 10.0,
            bufferbloatMs = 0.0,
            bandwidthMbps = 40.0,
            profile = TrafficProfile.GAME,
        )
        assertTrue(res.vetoReasons.contains("VETO_GAME_CRITICAL_LOSS"))
        assertTrue("Expected Q <= 45.0, got ${res.scoreQ}", res.scoreQ <= 45.0)
    }

    @Test
    fun missingBandwidthReducesConfidenceInsteadOfZeroingThroughput() {
        val res = LinearCostScorer.evaluate(
            srttMs = 15.0,
            jitterMs = 2.0,
            lossPct = 0.0,
            bufferbloatMs = 2.0,
            bandwidthMbps = null,
            profile = TrafficProfile.DOWNLOAD,
            sampleCount = 20,
        )
        assertEquals(0.0, res.componentW, 1e-6)
        assertTrue(res.confidence < 1.0)
    }

    @Test
    fun colorStateMachineEnforcesHysteresisAndStaleUnknown() {
        val cm = ColorStateMachine(minDwellMs = 2_000L, ewmaAlpha = 1.0)
        assertEquals(QualityState.GREEN, cm.update(90.0, nowMs = 0L))
        // Mild drop to 76 stays GREEN (needs < 75 to leave GREEN)
        assertEquals(QualityState.GREEN, cm.update(76.0, nowMs = 3_000L))
        // Drop to 70 after dwell -> YELLOW
        assertEquals(QualityState.YELLOW, cm.update(70.0, nowMs = 3_500L))
        // Recovery to 79 stays YELLOW (needs >= 82 to re-enter GREEN)
        assertEquals(QualityState.YELLOW, cm.update(79.0, nowMs = 6_000L))
        // Recovery to 84 after dwell -> GREEN
        assertEquals(QualityState.GREEN, cm.update(84.0, nowMs = 6_500L))
        // Stale -> UNKNOWN immediately
        assertEquals(QualityState.UNKNOWN, cm.update(null, nowMs = 7_000L, isStale = true))
    }

    // ------------------------------------------------------------------------
    // Formula #3: Bitwise XOR Parity FEC (GF(2)) + Interleaved Stride + Framing
    // ------------------------------------------------------------------------

    @Test
    fun xorFecRecoversVariableLengthPayloadsBitExact() {
        val enc = InterleavedXorFecEncoder(blockK = 4, stride = 1)
        val payloads = listOf(
            "A".toByteArray(),
            "short_pkt".toByteArray(),
            ("LONG_GAME_STATE_UPDATE:" + (0 until 100).joinToString(",")).toByteArray(),
            ByteArray(0), // empty payload edge case
        )

        val frames = mutableListOf<FecFrame>()
        for (p in payloads) {
            frames.addAll(enc.encodePacket(p))
        }
        assertEquals(5, frames.size) // 4 data + 1 parity

        // Verify wire serialization round-trip on all frames
        val roundTripped = frames.map { FecFrame.fromWireBytes(it.toWireBytes()) }
        assertEquals(frames, roundTripped)

        // Drop each data slot independently and prove 100% bit-exact recovery
        for (dropIdx in 0 until 4) {
            val dec = InterleavedXorFecDecoder()
            val got = mutableMapOf<Int, ByteArray>()
            roundTripped.forEachIndexed { idx, frame ->
                if (idx != dropIdx) {
                    for (pkt in dec.receive(frame)) {
                        got[pkt.slotIndex] = pkt.payload
                    }
                }
            }
            assertEquals(1, dec.recoveredCount)
            assertEquals(4, got.size)
            for (slot in 0 until 4) {
                assertArrayEquals(payloads[slot], got[slot])
            }
        }
    }

    @Test
    fun interleavedStrideRecoversConsecutiveBurstLoss() {
        val enc = InterleavedXorFecEncoder(blockK = 4, stride = 4)
        val dec = InterleavedXorFecDecoder()
        val sent = (0 until 16).map { String.format(Locale.US, "burst_test_%02d", it).toByteArray() }
        val wire = mutableListOf<FecFrame>()
        for (p in sent) {
            wire.addAll(enc.encodePacket(p))
        }
        assertEquals(20, wire.size) // 16 data + 4 parity

        // Drop 4 consecutive wire packets (indices 4, 5, 6, 7) -> 100% recoverable!
        val dropSet = setOf(4, 5, 6, 7)
        val recoveredStrings = mutableSetOf<String>()
        wire.forEachIndexed { idx, frame ->
            if (idx !in dropSet) {
                for (pkt in dec.receive(frame)) {
                    recoveredStrings.add(String(pkt.payload))
                }
            }
        }

        assertEquals(4, dec.recoveredCount)
        assertEquals(sent.map { String(it) }.toSet(), recoveredStrings)
    }

    @Test
    fun twoDropsInSameGroupAreNotFalselyRecovered() {
        val enc = InterleavedXorFecEncoder(blockK = 4, stride = 1)
        val dec = InterleavedXorFecDecoder()
        val frames = mutableListOf<FecFrame>()
        for (i in 0 until 4) {
            frames.addAll(enc.encodePacket("pkt$i".toByteArray()))
        }

        val delivered = mutableListOf<RecoveredPacket>()
        frames.forEachIndexed { idx, frame ->
            if (idx != 0 && idx != 1) {
                delivered.addAll(dec.receive(frame))
            }
        }
        assertEquals(0, dec.recoveredCount)
        assertEquals(2, delivered.size)
    }

    // ------------------------------------------------------------------------
    // Closed-Loop Adaptive Controller
    // ------------------------------------------------------------------------

    @Test
    fun adaptiveControllerCoordinatesFecPacerAndRouteHysteresis() {
        val ewma = BitwiseEwmaEstimator()
        doubleArrayOf(60.0, 115.0, 130.0, 125.0, 140.0, 135.0).forEachIndexed { i, rtt ->
            ewma.update(rtt, i * 500L)
        }

        val ctrl = AdaptiveController(routeHysteresisPts = 10.0, routeCooldownMs = 2_000L)
        val dec = ctrl.step(
            nowMs = 3_000L,
            profile = TrafficProfile.GAME,
            ewma = ewma,
            lossPct = 3.0,
            bandwidthMbps = 20.0,
            alternateRouteMetrics = RouteMetrics(18.0, 2.0, 0.2, 2.0),
        )
        assertEquals(FecMode.XOR_K4_INTERLEAVED, dec.fecMode)
        assertTrue(dec.bgPacerRatio < 1.0)
        assertEquals(RouteChoice.RELAY, dec.selectedRoute)
        assertTrue(dec.reasonCodes.contains("ROUTE_SWITCH_TO_RELAY"))

        // Within cooldown: must NOT flap back
        val duringCooldown = ctrl.step(
            nowMs = 4_000L,
            profile = TrafficProfile.GAME,
            ewma = ewma,
            lossPct = 3.0,
            bandwidthMbps = 20.0,
            alternateRouteMetrics = RouteMetrics(10.0, 1.0, 0.0, 0.0),
        )
        assertEquals(RouteChoice.RELAY, duringCooldown.selectedRoute)

        // After cooldown: switch back if alternate beats active by hysteresis margin
        val afterCooldown = ctrl.step(
            nowMs = 5_500L,
            profile = TrafficProfile.GAME,
            ewma = ewma,
            lossPct = 3.0,
            bandwidthMbps = 20.0,
            alternateRouteMetrics = RouteMetrics(10.0, 1.0, 0.0, 0.0),
        )
        assertEquals(RouteChoice.NATIVE, afterCooldown.selectedRoute)
        assertTrue(afterCooldown.reasonCodes.contains("ROUTE_SWITCH_TO_NATIVE"))
    }

    @Test
    fun fecDisabledForDownloadProfile() {
        val ewma = BitwiseEwmaEstimator()
        ewma.update(30.0, 1_000L)
        val ctrl = AdaptiveController()
        val dec = ctrl.step(
            nowMs = 1_500L,
            profile = TrafficProfile.DOWNLOAD,
            ewma = ewma,
            lossPct = 3.0,
            bandwidthMbps = 30.0,
        )
        assertEquals(FecMode.OFF, dec.fecMode)
        assertEquals(1.0, dec.bgPacerRatio, 1e-6)
    }

    // ------------------------------------------------------------------------
    // Swappable BackendConfig & Pluggable EngineAdapter / Reason Flags
    // ------------------------------------------------------------------------

    @Test
    fun backendConfigSanitizesPortsAndHostsCleanly() {
        val raw = BackendConfig(
            controlPlaneUrl = "  https://api.example.com/v1  ",
            relayHost = "  sg-edge.jiter.net ",
            relayPort = 99999,
            probeHost = "   ",
            probePort = 0,
            routingMode = RoutingMode.PRIVACY_ALWAYS_TUNNEL,
        )
        val clean = raw.sanitized()
        assertEquals("https://api.example.com/v1", clean.controlPlaneUrl)
        assertEquals("sg-edge.jiter.net", clean.relayHost)
        assertEquals(65535, clean.relayPort)
        assertEquals(BackendConfig.DEFAULT_PROBE_HOST, clean.probeHost)
        assertEquals(1, clean.probePort)
        assertTrue(clean.hasCustomRelay())
    }

    @Test
    fun kotlinEngineAdapterAndReasonFlagDecoderMatchContract() {
        val adapter = KotlinEngineAdapter()
        assertTrue(adapter.submitRtt(14.0, 1_000L))
        assertTrue(adapter.submitRtt(15.0, 2_000L))
        val out = adapter.step(2_500L, TrafficProfile.GAME, lossPct = 0.0, bandwidthMbps = 30.0)
        assertEquals(QualityState.GREEN, out.decision.qualityState)
        assertTrue((out.decision.qualityScore ?: 0.0) > 90.0)

        val decoded = NativeEngineBridge.decodeReasonFlags((1 shl 1) or (1 shl 6) or (1 shl 9) or (1 shl 12))
        assertTrue(decoded.contains("VETO_GAME_CRITICAL_LOSS"))
        assertTrue(decoded.contains("PACER_THROTTLE_BG"))
        assertTrue(decoded.contains("FEC_ACTIVE_K4"))
        assertTrue(decoded.contains("ROUTE_SWITCH_TO_RELAY"))
    }

    @Test
    fun languageManagerNormalizesIndonesianAndEnglishCodes() {
        assertEquals(AppLanguage.INDONESIAN, LanguageManager.fromLanguageCode("id"))
        assertEquals(AppLanguage.INDONESIAN, LanguageManager.fromLanguageCode("in"))
        assertEquals(AppLanguage.INDONESIAN, LanguageManager.fromLanguageCode("id-ID"))
        assertEquals(AppLanguage.ENGLISH, LanguageManager.fromLanguageCode("en-US"))
        assertEquals(AppLanguage.SYSTEM, LanguageManager.fromLanguageCode(""))

        assertEquals(
            AppLanguage.ENGLISH,
            LanguageManager.toggleIndonesianEnglish(AppLanguage.INDONESIAN, "en"),
        )
        assertEquals(
            AppLanguage.INDONESIAN,
            LanguageManager.toggleIndonesianEnglish(AppLanguage.ENGLISH, "id"),
        )
        assertEquals(
            AppLanguage.ENGLISH,
            LanguageManager.toggleIndonesianEnglish(AppLanguage.SYSTEM, "in"),
        )
        assertEquals(
            AppLanguage.INDONESIAN,
            LanguageManager.toggleIndonesianEnglish(AppLanguage.SYSTEM, "en"),
        )
    }

    // ------------------------------------------------------------------------
    // Stage 3: Relay Wire Protocol v1, Local UDP Handshake/Probe & TUN Queue
    // ------------------------------------------------------------------------

    @Test
    fun relayWireHeaderMatchesCAndRustGoldenBytes() {
        val hdr = WireHeader(
            version = RelayProtocol.WIRE_VERSION,
            msgType = RelayProtocol.MSG_DATA_FEC,
            trafficTier = RelayProtocol.TIER_GAME,
            flags = RelayProtocol.FLAG_FEC_PARITY,
            sessionId = 0x11223344,
            sequence = 42,
            payloadLen = 128,
            pacerQ8 = RelayProtocol.pacerRatioToQ8(0.35),
            fecMode = 2,
        )
        val packed = hdr.pack()
        val expected = byteArrayOf(
            0x4A, 0x54, 0x16, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x00, 0x00, 0x00, 0x2A,
            0x00, 0x80.toByte(), 0x59, 0x02,
        )
        assertArrayEquals(expected, packed)
        assertEquals(hdr, WireHeader.unpack(packed))

        // Corrupt magic rejected
        val bad = packed.copyOf()
        bad[0] = 0x00
        assertNull(WireHeader.unpack(bad))
    }

    @Test
    fun kotlinAdapterPrioritizesGamePacketsAheadOfBackground() {
        val adapter = KotlinEngineAdapter()
        val bgTcp = ByteArray(1200).apply {
            this[0] = 0x45 // IPv4
            this[9] = 6 // TCP bulk -> BACKGROUND
        }
        val gameUdp = ByteArray(96).apply {
            this[0] = 0x45 // IPv4
            this[9] = 17 // Small UDP -> GAME
        }
        assertTrue(adapter.enqueueTunPacket(bgTcp, bgTcp.size, 1_000L))
        assertTrue(adapter.enqueueTunPacket(gameUdp, gameUdp.size, 1_000L))

        val outBuf = ByteArray(2048)
        val outMeta = IntArray(2)
        assertTrue(adapter.dequeueScheduledPacket(1_000L, outBuf, outMeta))
        assertEquals(RelayProtocol.TIER_GAME, outMeta[0])
        assertEquals(gameUdp.size, outMeta[1])

        assertTrue(adapter.dequeueScheduledPacket(1_000L, outBuf, outMeta))
        assertEquals(RelayProtocol.TIER_BACKGROUND, outMeta[0])
        assertEquals(bgTcp.size, outMeta[1])
    }

    @Test
    fun relayTunnelClientConnectProbeAndEchoOverLocalUdp() {
        val serverSock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        serverSock.soTimeout = 200
        val stopServer = AtomicBoolean(false)
        val gotGoodbye = CountDownLatch(1)

        val serverThread = Thread({
            val rx = ByteArray(2048)
            val pkt = DatagramPacket(rx, rx.size)
            while (!stopServer.get() && !serverSock.isClosed) {
                try {
                    pkt.length = rx.size
                    serverSock.receive(pkt)
                    val hdr = WireHeader.unpack(rx, pkt.length) ?: continue
                    val payloadStart = RelayProtocol.WIRE_HEADER_BYTES
                    when (hdr.msgType) {
                        RelayProtocol.MSG_HELLO_REQ -> {
                            val ackPayload = ByteArray(RelayProtocol.HELLO_ACK_BYTES)
                            RelayProtocol.putU16(ackPayload, 0, 1280)
                            RelayProtocol.putU16(ackPayload, 2, 0x03)
                            "JKT-1".toByteArray(Charsets.UTF_8).copyInto(ackPayload, 4)
                            val resp = WireHeader(
                                msgType = RelayProtocol.MSG_HELLO_ACK,
                                sessionId = hdr.sessionId,
                                sequence = 1,
                                payloadLen = ackPayload.size,
                            ).frameBytes(ackPayload)
                            serverSock.send(DatagramPacket(resp, resp.size, pkt.address, pkt.port))
                        }
                        RelayProtocol.MSG_PROBE_REQ -> {
                            val txUs = RelayProtocol.getU64(rx, payloadStart)
                            val respPayload = ByteArray(RelayProtocol.PROBE_RESP_BYTES)
                            RelayProtocol.putU64(respPayload, 0, txUs)
                            RelayProtocol.putU32(respPayload, 8, 50) // 0.50% loss
                            RelayProtocol.putU32(respPayload, 12, 1_500) // 1.5ms queue
                            RelayProtocol.putU32(respPayload, 16, 3) // 3 FEC recoveries
                            RelayProtocol.putU16(respPayload, 20, hdr.pacerQ8)
                            RelayProtocol.putU16(respPayload, 22, hdr.fecMode)
                            val resp = WireHeader(
                                msgType = RelayProtocol.MSG_PROBE_RESP,
                                sessionId = hdr.sessionId,
                                sequence = 2,
                                payloadLen = respPayload.size,
                            ).frameBytes(respPayload)
                            serverSock.send(DatagramPacket(resp, resp.size, pkt.address, pkt.port))
                        }
                        RelayProtocol.MSG_DATA_PLAIN -> {
                            val body = rx.copyOfRange(payloadStart, payloadStart + hdr.payloadLen)
                            val resp = WireHeader(
                                msgType = RelayProtocol.MSG_DATA_PLAIN,
                                trafficTier = hdr.trafficTier,
                                sessionId = hdr.sessionId,
                                sequence = 3,
                                payloadLen = body.size,
                            ).frameBytes(body)
                            serverSock.send(DatagramPacket(resp, resp.size, pkt.address, pkt.port))
                        }
                        RelayProtocol.MSG_CONTROL -> {
                            if ((hdr.flags and RelayProtocol.FLAG_GOODBYE) != 0) {
                                gotGoodbye.countDown()
                            }
                        }
                    }
                } catch (_: Exception) {
                    // Timeout or closed
                }
            }
        }, "test-mock-relay").apply { start() }

        try {
            val echoedPayload = AtomicReference<ByteArray?>(null)
            val echoLatch = CountDownLatch(1)
            val client = RelayTunnelClient(
                onDownlinkPacket = { data ->
                    echoedPayload.set(data)
                    echoLatch.countDown()
                },
            )

            val cfg = BackendConfig(
                relayHost = "127.0.0.1",
                relayPort = serverSock.localPort,
            )
            assertTrue(client.connect(cfg, TrafficProfile.GAME) { true })
            assertTrue(client.isConnected)

            val probe = client.probeRelay(TrafficProfile.GAME, FecMode.XOR_K2_INTERLEAVED, 0.35)
            assertTrue(probe.reachable)
            assertEquals("JKT-1", probe.relayRegion)
            assertEquals(3L, probe.relayFecRecovered)
            assertNotNull(probe.routeMetrics)
            assertEquals(0.5, probe.routeMetrics!!.lossPct, 1e-6)

            val samplePkt = "JITER_STAGE3_UDP_TEST".toByteArray(Charsets.UTF_8)
            assertTrue(
                client.sendDataPacket(
                    trafficTier = RelayProtocol.TIER_STREAMING,
                    rawIpv4 = samplePkt,
                    length = samplePkt.size,
                    fecMode = FecMode.OFF,
                    bgPacerRatio = 0.5,
                ),
            )
            assertTrue(echoLatch.await(1, TimeUnit.SECONDS))
            assertArrayEquals(samplePkt, echoedPayload.get())

            client.disconnect(sendGoodbye = true)
            assertFalse(client.isConnected)
            assertTrue(gotGoodbye.await(1, TimeUnit.SECONDS))
        } finally {
            stopServer.set(true)
            serverSock.close()
            serverThread.join(1_000L)
        }
    }

    // ------------------------------------------------------------------------
    // Stage 4: Cross-Language AEAD Golden Vector, ECDHE P-256, Replay & UID
    // ------------------------------------------------------------------------

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }

    @Test
    fun stage4CryptoGoldenVectorMatchesRustByteForByte() {
        val pskKey = RelayCrypto.derivePskKey("jiter-golden-psk-2026")
        assertArrayEquals(
            hexToBytes("9716cac97a20451428ec0851a9cf6292a73eb7be982935df53a64205f0a36c96"),
            pskKey,
        )

        val ecdhShared = ByteArray(32) { 0x42 }
        val cNonce = ByteArray(16) { 0x11 }
        val sNonce = ByteArray(16) { 0x22 }
        val sessionId = 0x11223344

        val keys = RelayCrypto.deriveSessionKeys(ecdhShared, pskKey, cNonce, sNonce, sessionId)
        assertArrayEquals(
            hexToBytes("f300fec671057d5c58611466e5a64277de822f4eb866a5d5b56ee2e4b13ca99b"),
            keys.c2sKey,
        )
        assertArrayEquals(
            hexToBytes("072a0d8ed9b240be40601291e593b2a6d1a5de5ae97b4bef54d171979a665bd4"),
            keys.s2cKey,
        )
        assertArrayEquals(hexToBytes("8266924c"), keys.c2sIv)
        assertArrayEquals(hexToBytes("e64d89ea"), keys.s2cIv)

        val clientCipher = SessionCipher.forClient(keys)
        val serverCipher = SessionCipher.forServer(keys)

        val aadHdr = WireHeader(
            version = RelayProtocol.WIRE_VERSION,
            msgType = RelayProtocol.MSG_DATA_PLAIN,
            trafficTier = RelayProtocol.TIER_GAME,
            flags = RelayProtocol.FLAG_ENCRYPTED,
            sessionId = sessionId,
            sequence = 7,
            payloadLen = 16 + RelayCrypto.AEAD_TAG_BYTES,
            pacerQ8 = 89,
            fecMode = 2,
        ).pack()

        val plaintext = "JITER_AEAD_CHECK".toByteArray(Charsets.UTF_8)
        val ct = requireNotNull(clientCipher.encrypt(sessionId, 7, aadHdr, plaintext))
        assertArrayEquals(
            hexToBytes("6352f703709ce93a8853ee5804a31ac16f9e112af1230e8aa353a3f6c0e2d361"),
            ct,
        )

        // Tampering 1 bit of AAD header must fail Poly1305 verification
        val badAad = aadHdr.copyOf()
        badAad[14] = (badAad[14].toInt() xor 0x01).toByte()
        assertNull(serverCipher.decryptAndCheckReplay(sessionId, 7, badAad, ct))

        // Valid decryption succeeds bit-exact
        val decrypted = requireNotNull(serverCipher.decryptAndCheckReplay(sessionId, 7, aadHdr, ct))
        assertArrayEquals(plaintext, decrypted)

        // Exact replay must be dropped
        assertNull(serverCipher.decryptAndCheckReplay(sessionId, 7, aadHdr, ct))

        // Empty plaintext (e.g. encrypted GOODBYE) works cleanly with 16B Poly1305 tag
        val byeAad = WireHeader(
            msgType = RelayProtocol.MSG_CONTROL,
            flags = RelayProtocol.FLAG_GOODBYE or RelayProtocol.FLAG_ENCRYPTED,
            sessionId = sessionId,
            sequence = 8,
            payloadLen = RelayCrypto.AEAD_TAG_BYTES,
        ).pack()
        val byeCt = requireNotNull(clientCipher.encrypt(sessionId, 8, byeAad, ByteArray(0), 0))
        assertEquals(RelayCrypto.AEAD_TAG_BYTES, byeCt.size)
        val byePlain = requireNotNull(serverCipher.decryptAndCheckReplay(sessionId, 8, byeAad, byeCt))
        assertEquals(0, byePlain.size)
    }

    @Test
    fun stage4EcdheP256ReplayWindowAndEncryptedPayloads() {
        val clientKp = EphemeralP256KeyPair.generate()
        val serverKp = EphemeralP256KeyPair.generate()
        assertEquals(RelayCrypto.P256_UNCOMPRESSED_PUB_BYTES, clientKp.publicUncompressed.size)
        assertEquals(0x04.toByte(), clientKp.publicUncompressed[0])

        val sharedA = requireNotNull(clientKp.diffieHellman(serverKp.publicUncompressed))
        val sharedB = requireNotNull(serverKp.diffieHellman(clientKp.publicUncompressed))
        assertEquals(32, sharedA.size)
        assertArrayEquals(sharedA, sharedB)

        // Encrypted HELLO_REQ & HELLO_ACK round-trip
        val pskKey = RelayCrypto.derivePskKey("stage4-test-psk")
        val cNonce = RelayCrypto.randomNonce16()
        val sNonce = RelayCrypto.randomNonce16()
        val sid = 0x55AA1234

        val reqRaw = EncryptedHelloReqPayload.buildSigned(
            base = HelloReqPayload(0, 0, 0, 1280, 450),
            clientPub = clientKp.publicUncompressed,
            clientNonce = cNonce,
            pskKey = pskKey,
            sessionId = sid,
        )
        val expectedReqTag = RelayCrypto.computeHelloReqTag(
            pskKey,
            sid,
            reqRaw.copyOfRange(0, RelayProtocol.ENCRYPTED_HELLO_REQ_BODY_BEFORE_TAG),
        )
        val unpackedReq = requireNotNull(EncryptedHelloReqPayload.unpack(reqRaw))
        assertArrayEquals(clientKp.publicUncompressed, unpackedReq.clientPub)
        assertTrue(RelayCrypto.constantTimeEquals(expectedReqTag, unpackedReq.authTag))

        val ackRaw = EncryptedHelloAckPayload.buildSigned(
            base = HelloAckPayload(
                acceptedMtu = 1280,
                relayCaps = RelayProtocol.RELAY_CAP_AEAD_CHACHA20 or RelayProtocol.RELAY_CAP_TUN_NAT,
                regionTag = "JKT-TUN",
            ),
            assignedIpv4 = byteArrayOf(10, 77, 0, 42),
            serverPub = serverKp.publicUncompressed,
            serverNonce = sNonce,
            clientNonce = cNonce,
            pskKey = pskKey,
            sessionId = sid,
        )
        val unpackedAck = requireNotNull(EncryptedHelloAckPayload.unpack(ackRaw))
        assertEquals("10.77.0.42", unpackedAck.assignedIpv4String)
        assertEquals("JKT-TUN", unpackedAck.base.regionTag)
        val expectedAckTag = RelayCrypto.computeHelloAckTag(
            pskKey,
            sid,
            cNonce,
            unpackedAck.bodyBeforeTag,
        )
        assertTrue(RelayCrypto.constantTimeEquals(expectedAckTag, unpackedAck.authTag))

        // ReplayWindow boundary cases
        val rw = ReplayWindow()
        assertFalse(rw.wouldAccept(0))
        assertTrue(rw.wouldAccept(10))
        rw.markAccepted(10)
        assertFalse(rw.wouldAccept(10))
        assertTrue(rw.wouldAccept(5))
        rw.markAccepted(5)
        assertFalse(rw.wouldAccept(5))
        rw.markAccepted(100)
        assertFalse(rw.wouldAccept(36)) // 100 - 36 == 64 -> outside window
        assertTrue(rw.wouldAccept(37))  // 100 - 37 == 63 -> inside window
    }

    @Test
    fun stage4EncryptedUdpHandshakeProbeEchoAndGoodbye() {
        val psk = "unit-test-aead-psk-2026"
        val pskKey = RelayCrypto.derivePskKey(psk)

        val serverSock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        serverSock.soTimeout = 200
        val stopServer = AtomicBoolean(false)
        val gotEncryptedGoodbye = CountDownLatch(1)

        val serverThread = Thread({
            val rx = ByteArray(2048)
            val pkt = DatagramPacket(rx, rx.size)
            var serverCipher: SessionCipher? = null
            var txSeq = 0

            while (!stopServer.get() && !serverSock.isClosed) {
                try {
                    pkt.length = rx.size
                    serverSock.receive(pkt)
                    val hdr = WireHeader.unpack(rx, pkt.length) ?: continue
                    if ((hdr.flags and RelayProtocol.FLAG_ENCRYPTED) == 0) continue

                    val payloadStart = RelayProtocol.WIRE_HEADER_BYTES
                    val payloadEnd = payloadStart + hdr.payloadLen
                    if (payloadEnd > pkt.length) continue

                    if (hdr.msgType == RelayProtocol.MSG_HELLO_REQ) {
                        val reqBytes = rx.copyOfRange(payloadStart, payloadEnd)
                        val req = EncryptedHelloReqPayload.unpack(reqBytes) ?: continue
                        val expectedTag = RelayCrypto.computeHelloReqTag(
                            pskKey,
                            hdr.sessionId,
                            reqBytes.copyOfRange(0, RelayProtocol.ENCRYPTED_HELLO_REQ_BODY_BEFORE_TAG),
                        )
                        if (!RelayCrypto.constantTimeEquals(expectedTag, req.authTag)) continue

                        val serverKp = EphemeralP256KeyPair.generate()
                        val serverNonce = RelayCrypto.randomNonce16()
                        val shared = serverKp.diffieHellman(req.clientPub) ?: continue
                        val keys = RelayCrypto.deriveSessionKeys(
                            shared,
                            pskKey,
                            req.clientNonce,
                            serverNonce,
                            hdr.sessionId,
                        )
                        serverCipher = SessionCipher.forServer(keys)

                        val ackBytes = EncryptedHelloAckPayload.buildSigned(
                            base = HelloAckPayload(
                                acceptedMtu = 1280,
                                relayCaps = RelayProtocol.RELAY_CAP_AEAD_CHACHA20 or RelayProtocol.RELAY_CAP_TUN_NAT,
                                regionTag = "SG-AEAD",
                            ),
                            assignedIpv4 = byteArrayOf(10, 77, 0, 9),
                            serverPub = serverKp.publicUncompressed,
                            serverNonce = serverNonce,
                            clientNonce = req.clientNonce,
                            pskKey = pskKey,
                            sessionId = hdr.sessionId,
                        )

                        txSeq += 1
                        val resp = WireHeader(
                            msgType = RelayProtocol.MSG_HELLO_ACK,
                            flags = RelayProtocol.FLAG_ENCRYPTED,
                            sessionId = hdr.sessionId,
                            sequence = txSeq,
                            payloadLen = ackBytes.size,
                        ).frameBytes(ackBytes)
                        serverSock.send(DatagramPacket(resp, resp.size, pkt.address, pkt.port))
                        continue
                    }

                    val cipher = serverCipher ?: continue
                    val aad = rx.copyOfRange(0, RelayProtocol.WIRE_HEADER_BYTES)
                    val plain = cipher.decryptAndCheckReplay(
                        hdr.sessionId,
                        hdr.sequence,
                        aad,
                        rx,
                        payloadStart,
                        hdr.payloadLen,
                    ) ?: continue

                    fun sendEnc(msgType: Int, tier: Int, body: ByteArray) {
                        txSeq += 1
                        val respHdr = WireHeader(
                            msgType = msgType,
                            trafficTier = tier,
                            flags = RelayProtocol.FLAG_ENCRYPTED,
                            sessionId = hdr.sessionId,
                            sequence = txSeq,
                            payloadLen = body.size + RelayCrypto.AEAD_TAG_BYTES,
                        ).pack()
                        val ct = cipher.encrypt(hdr.sessionId, txSeq, respHdr, body) ?: return
                        val wire = ByteArray(respHdr.size + ct.size)
                        respHdr.copyInto(wire, 0)
                        ct.copyInto(wire, respHdr.size)
                        serverSock.send(DatagramPacket(wire, wire.size, pkt.address, pkt.port))
                    }

                    when (hdr.msgType) {
                        RelayProtocol.MSG_PROBE_REQ -> {
                            val txUs = RelayProtocol.getU64(plain, 0)
                            val respPayload = ByteArray(RelayProtocol.PROBE_RESP_BYTES)
                            RelayProtocol.putU64(respPayload, 0, txUs)
                            RelayProtocol.putU32(respPayload, 8, 25)
                            RelayProtocol.putU32(respPayload, 12, 800)
                            RelayProtocol.putU32(respPayload, 16, 4)
                            RelayProtocol.putU16(respPayload, 20, hdr.pacerQ8)
                            RelayProtocol.putU16(respPayload, 22, hdr.fecMode)
                            sendEnc(RelayProtocol.MSG_PROBE_RESP, hdr.trafficTier, respPayload)
                        }
                        RelayProtocol.MSG_DATA_PLAIN -> {
                            sendEnc(RelayProtocol.MSG_DATA_PLAIN, hdr.trafficTier, plain)
                        }
                        RelayProtocol.MSG_CONTROL -> {
                            if ((hdr.flags and RelayProtocol.FLAG_GOODBYE) != 0) {
                                gotEncryptedGoodbye.countDown()
                            }
                        }
                    }
                } catch (_: Exception) {
                    // Timeout or closed
                }
            }
        }, "test-mock-aead-relay").apply { start() }

        try {
            val echoedPayload = AtomicReference<ByteArray?>(null)
            val echoLatch = CountDownLatch(1)
            val client = RelayTunnelClient(
                onDownlinkPacket = { data ->
                    echoedPayload.set(data)
                    echoLatch.countDown()
                },
            )

            // Wrong PSK must fail handshake cleanly
            val badCfg = BackendConfig(
                relayHost = "127.0.0.1",
                relayPort = serverSock.localPort,
                relayPsk = "wrong-psk",
                tunnelScope = TunnelScope.FULL_INTERNET_TUNNEL,
            )
            assertFalse(client.connect(badCfg, TrafficProfile.GAME) { true })
            assertFalse(client.isEncrypted)

            // Valid PSK succeeds with AEAD + dynamic assigned IPv4
            val goodCfg = badCfg.copy(relayPsk = psk)
            assertTrue(client.connect(goodCfg, TrafficProfile.GAME) { true })
            assertTrue(client.isConnected)
            assertTrue(client.isEncrypted)
            assertEquals("10.77.0.9", client.assignedIpv4)

            val probe = client.probeRelay(TrafficProfile.GAME, FecMode.XOR_K2_INTERLEAVED, 0.30)
            assertTrue(probe.reachable)
            assertEquals("SG-AEAD", probe.relayRegion)
            assertEquals(4L, probe.relayFecRecovered)

            val secretPkt = "JITER_STAGE4_AEAD_UDP_PAYLOAD".toByteArray(Charsets.UTF_8)
            assertTrue(
                client.sendDataPacket(
                    trafficTier = RelayProtocol.TIER_GAME,
                    rawIpv4 = secretPkt,
                    length = secretPkt.size,
                    fecMode = FecMode.OFF,
                    bgPacerRatio = 0.30,
                ),
            )
            assertTrue(echoLatch.await(1, TimeUnit.SECONDS))
            assertArrayEquals(secretPkt, echoedPayload.get())

            client.disconnect(sendGoodbye = true)
            assertFalse(client.isConnected)
            assertFalse(client.isEncrypted)
            assertTrue(gotEncryptedGoodbye.await(1, TimeUnit.SECONDS))
        } finally {
            stopServer.set(true)
            serverSock.close()
            serverThread.join(1_000L)
        }
    }

    @Test
    fun stage4UidFlowClassifierAndBackendConfigTunnelScope() {
        assertEquals(
            RelayProtocol.TIER_GAME,
            UidFlowClassifier.classifyPackages(arrayOf("com.mobile.legends")),
        )
        assertEquals(
            RelayProtocol.TIER_STREAMING,
            UidFlowClassifier.classifyPackages(arrayOf("com.google.android.youtube")),
        )
        assertEquals(
            RelayProtocol.TIER_BACKGROUND,
            UidFlowClassifier.classifyPackages(arrayOf("com.android.providers.downloads")),
        )
        assertEquals(
            -1,
            UidFlowClassifier.classifyPackages(arrayOf("com.example.notepad")),
        )

        val cfg = BackendConfig(
            relayHost = "  jkt-vps.jiter.net ",
            relayPsk = "  my-secret-psk  ",
            tunnelScope = TunnelScope.FULL_INTERNET_TUNNEL,
        ).sanitized()
        assertEquals("my-secret-psk", cfg.relayPsk)
        assertTrue(cfg.hasRelayPsk())
        assertEquals(TunnelScope.FULL_INTERNET_TUNNEL, cfg.tunnelScope)
        assertTrue(cfg.summaryLabel().contains("Full TUN"))
        assertTrue(cfg.summaryLabel().contains("AEAD"))
    }

    // ------------------------------------------------------------------------
    // Stage 5: OS Category UID Detection, Packet Auto-Profile & Control Plane
    // ------------------------------------------------------------------------

    @Test
    fun stage5UidFlowClassifierUsesAndroidOsCategoryAndLegacyGameFlag() {
        // Brand-new Play Store game NOT in any hardcoded allowlist -> detected via CATEGORY_GAME!
        assertEquals(
            RelayProtocol.TIER_GAME,
            UidFlowClassifier.classifyAppMetadata(
                category = ApplicationInfo.CATEGORY_GAME,
                isLegacyGameFlag = false,
                packages = arrayOf("com.brandnew.indie.arena2026"),
            ),
        )
        // Legacy game flag fallback
        assertEquals(
            RelayProtocol.TIER_GAME,
            UidFlowClassifier.classifyAppMetadata(
                category = ApplicationInfo.CATEGORY_UNDEFINED,
                isLegacyGameFlag = true,
                packages = arrayOf("com.old.game"),
            ),
        )
        // Video / Audio OS category -> STREAMING
        assertEquals(
            RelayProtocol.TIER_STREAMING,
            UidFlowClassifier.classifyAppMetadata(
                category = ApplicationInfo.CATEGORY_VIDEO,
                isLegacyGameFlag = false,
                packages = arrayOf("com.newvideo.player"),
            ),
        )
        assertEquals(
            RelayProtocol.TIER_STREAMING,
            UidFlowClassifier.classifyAppMetadata(
                category = ApplicationInfo.CATEGORY_AUDIO,
                isLegacyGameFlag = false,
                packages = arrayOf("com.newmusic.stream"),
            ),
        )
        // Uncategorized sideloaded game falls back to curated package hints
        assertEquals(
            RelayProtocol.TIER_GAME,
            UidFlowClassifier.classifyAppMetadata(
                category = ApplicationInfo.CATEGORY_UNDEFINED,
                isLegacyGameFlag = false,
                packages = arrayOf("com.mobile.legends"),
            ),
        )
    }

    @Test
    fun stage5TrafficAutoProfileDetectorHandlesGameStreamingConcurrentAndStickyWindows() {
        val detector = TrafficAutoProfileDetector(
            gameStickyMs = 15_000L,
            streamingStickyMs = 10_000L,
            downloadStickyMs = 8_000L,
            burstWindowMs = 3_000L,
        )

        // Initially idle -> Safe Balanced
        val init = detector.evaluate(1_000L)
        assertEquals(TrafficProfile.SAFE_BALANCED, init.profile)
        assertFalse(init.detectedFromPackets)

        // 1 UID-confirmed Game packet activates GAME immediately
        detector.recordPacket(RelayProtocol.TIER_GAME, 96, uidMatched = true, nowMs = 2_000L)
        val gameState = detector.evaluate(2_500L)
        assertEquals(TrafficProfile.GAME, gameState.profile)
        assertTrue(gameState.detectedFromPackets)
        assertFalse(gameState.concurrentStreaming)

        // Concurrent Streaming arrives while Game is still sticky (e.g. PiP YouTube during game)
        detector.recordPacket(RelayProtocol.TIER_STREAMING, 1200, uidMatched = true, nowMs = 10_000L)
        val concurrent = detector.evaluate(10_500L)
        assertEquals(TrafficProfile.GAME, concurrent.profile)
        assertTrue(concurrent.concurrentStreaming)

        // After Game sticky window expires (> 2_000 + 15_000), transitions cleanly to STREAMING
        val streamOnly = detector.evaluate(18_000L)
        assertEquals(TrafficProfile.STREAMING, streamOnly.profile)
        assertFalse(streamOnly.concurrentStreaming)

        // After Streaming expires (> 10_000 + 10_000), heavy Background bulk triggers DOWNLOAD
        for (i in 0 until 60) {
            detector.recordPacket(RelayProtocol.TIER_BACKGROUND, 1300, uidMatched = false, nowMs = 22_000L + i * 10L)
        }
        val dl = detector.evaluate(23_000L)
        assertEquals(TrafficProfile.DOWNLOAD, dl.profile)
        assertNotNull(dl.observedGoodputMbps)

        // After Download window goes quiet -> returns to SAFE_BALANCED
        val idleAgain = detector.evaluate(35_000L)
        assertEquals(TrafficProfile.SAFE_BALANCED, idleAgain.profile)
        assertFalse(idleAgain.detectedFromPackets)
    }

    @Test
    fun stage5ControlPlaneClientParsesBootstrapAndAppliesConfigOverLocalHttp() {
        val capturedAppKey = AtomicReference<String?>("")
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/api/v1/session/bootstrap") { exchange ->
            capturedAppKey.set(exchange.requestHeaders.getFirst("X-Jiter-App-Key"))
            val body = """
                {
                  "ok": true,
                  "source": "supabase",
                  "ttlSeconds": 300,
                  "policy": {
                    "tunnelScope": "FULL_INTERNET_TUNNEL",
                    "routingMode": "PRIVACY_ALWAYS_TUNNEL",
                    "failurePolicy": "FAIL_OPEN",
                    "fecPolicy": "AUTO_ADAPTIVE",
                    "probeHost": "1.1.1.1",
                    "probePort": 443
                  },
                  "nodes": [
                    {
                      "id": "jkt-1",
                      "region": "JKT-1",
                      "host": "203.0.113.10",
                      "port": 51820,
                      "psk": "auto-distributed-psk-jkt",
                      "priority": 1
                    },
                    {
                      "id": "sg-1",
                      "region": "SG-1",
                      "host": "198.51.100.20",
                      "port": 51820,
                      "psk": "auto-distributed-psk-sg",
                      "priority": 2
                    }
                  ]
                }
            """.trimIndent().toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        server.start()

        try {
            val baseUrl = "http://127.0.0.1:${server.address.port}"
            val result = requireNotNull(
                ControlPlaneClient.bootstrap(
                    baseUrl = baseUrl,
                    appKey = "dev-secret-app-key",
                    preferredRegion = "JKT",
                    networkType = "Wi-Fi",
                    appVersion = "0.6.0-stage5-onetap",
                ),
            )
            assertEquals("dev-secret-app-key", capturedAppKey.get())
            assertEquals("supabase", result.source)
            assertEquals(2, result.nodes.size)
            assertEquals("JKT-1", result.nodes[0].region)
            assertEquals("203.0.113.10", result.nodes[0].host)
            assertEquals(TunnelScope.FULL_INTERNET_TUNNEL, result.policy.tunnelScope)

            val effective = ControlPlaneClient.applyToConfig(
                base = BackendConfig(controlPlaneUrl = baseUrl),
                node = result.nodes[0],
                policy = result.policy,
            )
            assertEquals("203.0.113.10", effective.relayHost)
            assertEquals(51820, effective.relayPort)
            assertEquals("auto-distributed-psk-jkt", effective.relayPsk)
            assertEquals(TunnelScope.FULL_INTERNET_TUNNEL, effective.tunnelScope)
            assertEquals(RoutingMode.PRIVACY_ALWAYS_TUNNEL, effective.routingMode)
        } finally {
            server.stop(0)
        }
    }
}
