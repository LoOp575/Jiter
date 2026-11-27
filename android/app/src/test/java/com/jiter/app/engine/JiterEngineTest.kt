package com.jiter.app.engine

import com.jiter.app.bridge.KotlinEngineAdapter
import com.jiter.app.bridge.NativeEngineBridge
import com.jiter.app.config.BackendConfig
import com.jiter.app.config.RoutingMode
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale
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
}
