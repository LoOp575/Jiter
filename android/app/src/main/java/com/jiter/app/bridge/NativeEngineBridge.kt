package com.jiter.app.bridge

import com.jiter.app.config.EngineRuntimePreference
import com.jiter.app.engine.ControlDecision
import com.jiter.app.engine.FecMode
import com.jiter.app.engine.QualityState
import com.jiter.app.engine.RouteChoice
import com.jiter.app.engine.RouteMetrics
import com.jiter.app.engine.TrafficProfile

/**
 * Narrow JNI bridge to `libjiter_native.so`:
 *   - C (`jiter_packet.c`): zero-copy IPv4/UDP/TCP packet parsing & 64-bit GF(2) XOR kernel
 *   - C++ (`jiter_scheduler.cpp` / `PacketPool`): zero-heap slab memory pool & 3-tier priority scheduler
 *   - Rust (`libjiter_math.a`): memory-safe Formulas #1, #2, #3 & AdaptiveController (via C-ABI FFI)
 */
object NativeEngineBridge {
    const val CAP_C_PACKET_ENGINE = 1 shl 0
    const val CAP_CPP_MEMORY_SCHEDULER = 1 shl 1
    const val CAP_RUST_MATH_ENGINE = 1 shl 2

    private val libraryLoaded: Boolean = try {
        System.loadLibrary("jiter_native")
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    } catch (_: SecurityException) {
        false
    }

    val capabilities: Int
        get() = if (libraryLoaded) {
            try {
                nativeCapabilities()
            } catch (_: UnsatisfiedLinkError) {
                0
            }
        } else {
            0
        }

    val hasCPacketEngine: Boolean
        get() = (capabilities and CAP_C_PACKET_ENGINE) != 0

    val hasCppScheduler: Boolean
        get() = (capabilities and CAP_CPP_MEMORY_SCHEDULER) != 0

    val hasRustMathEngine: Boolean
        get() = (capabilities and CAP_RUST_MATH_ENGINE) != 0

    fun createAdapter(preference: EngineRuntimePreference): EngineAdapter {
        if (preference == EngineRuntimePreference.KOTLIN_PURE) {
            return KotlinEngineAdapter()
        }
        if (libraryLoaded && hasRustMathEngine) {
            val handle = nativeCreateSession()
            if (handle != 0L) {
                return NativeRustCppAdapter(handle)
            }
        }
        if (libraryLoaded && hasCPacketEngine && hasCppScheduler) {
            val handle = nativeCreateSession()
            if (handle != 0L) {
                return HybridNativePacketKotlinMathAdapter(handle)
            }
        }
        return KotlinEngineAdapter()
    }

    fun classifyIpv4PacketTier(rawPacket: ByteArray): Int {
        if (!libraryLoaded || !hasCPacketEngine) return -1
        return nativeClassifyIpv4Tier(rawPacket)
    }

    external fun nativeCapabilities(): Int
    external fun nativeCreateSession(): Long
    external fun nativeDestroySession(handle: Long)
    external fun nativeResetSession(handle: Long)
    external fun nativeResetBaseline(handle: Long, newMinRttMs: Double)
    external fun nativeSubmitRtt(handle: Long, rttMs: Double, timestampMs: Long): Boolean
    external fun nativeStepMath(
        handle: Long,
        nowMs: Long,
        profileId: Int,
        lossPct: Double,
        bandwidthMbps: Double,
        hasAltRoute: Boolean,
        altSrttMs: Double,
        altJitterMs: Double,
        altLossPct: Double,
        altBloatMs: Double,
        outDoubles: DoubleArray,
        outInts: IntArray,
    ): Boolean

    external fun nativeConfigurePacer(handle: Long, bgPacerRatio: Double, estimatedLinkMbps: Double)
    external fun nativeClassifyIpv4Tier(rawPacket: ByteArray): Int
    external fun nativePoolStats(handle: Long, outStats: LongArray): Boolean
    external fun nativeEnqueuePacket(
        handle: Long,
        rawPacket: ByteArray,
        length: Int,
        nowMs: Long,
        tierOverride: Int,
    ): Boolean

    external fun nativeDequeuePacket(
        handle: Long,
        nowMs: Long,
        outBuf: ByteArray,
        outTierAndLen: IntArray,
    ): Boolean

    internal fun decodeReasonFlags(flags: Int): List<String> {
        if (flags == 0) return emptyList()
        val out = ArrayList<String>(4)
        if ((flags and (1 shl 0)) != 0) out.add("STALE_OR_MISSING_SAMPLES")
        if ((flags and (1 shl 1)) != 0) out.add("VETO_GAME_CRITICAL_LOSS")
        if ((flags and (1 shl 2)) != 0) out.add("VETO_GAME_BUFFERBLOAT")
        if ((flags and (1 shl 3)) != 0) out.add("VETO_GAME_BELOW_MIN_BW")
        if ((flags and (1 shl 4)) != 0) out.add("VETO_STREAMING_STARVED")
        if ((flags and (1 shl 5)) != 0) out.add("VETO_STREAMING_LOSS")
        if ((flags and (1 shl 6)) != 0) out.add("PACER_THROTTLE_BG")
        if ((flags and (1 shl 7)) != 0) out.add("PACER_RESERVE_HEADROOM")
        if ((flags and (1 shl 8)) != 0) out.add("PACER_FULL_THROUGHPUT")
        if ((flags and (1 shl 9)) != 0) out.add("FEC_ACTIVE_K4")
        if ((flags and (1 shl 10)) != 0) out.add("FEC_ELEVATED_K2")
        if ((flags and (1 shl 11)) != 0) out.add("FEC_STANDBY_CLEAN_LINK")
        if ((flags and (1 shl 12)) != 0) out.add("ROUTE_SWITCH_TO_RELAY")
        if ((flags and (1 shl 13)) != 0) out.add("ROUTE_SWITCH_TO_NATIVE")
        return out
    }
}

/** Full native stack: Rust Math FFI + C++ Slab Pool/Scheduler + C Packet Engine. */
private class NativeRustCppAdapter(
    private var handle: Long,
) : EngineAdapter {
    private val outDoubles = DoubleArray(7)
    private val outInts = IntArray(6)

    override val engineLabel: String = "Native (Rust + C++ + C)"

    @Synchronized
    override fun reset() {
        if (handle != 0L) NativeEngineBridge.nativeResetSession(handle)
    }

    @Synchronized
    override fun resetBaseline(newMinRttMs: Double?) {
        if (handle != 0L) {
            NativeEngineBridge.nativeResetBaseline(handle, newMinRttMs ?: -1.0)
        }
    }

    @Synchronized
    override fun submitRtt(rttMs: Double, timestampMs: Long): Boolean {
        if (handle == 0L) return false
        return NativeEngineBridge.nativeSubmitRtt(handle, rttMs, timestampMs)
    }

    @Synchronized
    override fun step(
        nowMs: Long,
        profile: TrafficProfile,
        lossPct: Double,
        bandwidthMbps: Double?,
        alternateRoute: RouteMetrics?,
    ): EngineStepOutput {
        if (handle == 0L) {
            return EngineStepOutput(
                decision = ControlDecision(
                    qualityScore = null,
                    qualityState = QualityState.UNKNOWN,
                    fecMode = FecMode.OFF,
                    bgPacerRatio = 1.0,
                    selectedRoute = RouteChoice.NATIVE,
                    confidence = 0.0,
                    reasonCodes = listOf("NATIVE_HANDLE_CLOSED"),
                ),
                srttMs = null,
                jitterMs = null,
                bufferbloatMs = null,
                rtoMs = null,
            )
        }

        val ok = NativeEngineBridge.nativeStepMath(
            handle = handle,
            nowMs = nowMs,
            profileId = profile.ordinal,
            lossPct = lossPct,
            bandwidthMbps = bandwidthMbps ?: -1.0,
            hasAltRoute = alternateRoute != null,
            altSrttMs = alternateRoute?.srttMs ?: 0.0,
            altJitterMs = alternateRoute?.jitterMs ?: 0.0,
            altLossPct = alternateRoute?.lossPct ?: 0.0,
            altBloatMs = alternateRoute?.bufferbloatMs ?: 0.0,
            outDoubles = outDoubles,
            outInts = outInts,
        )
        if (!ok) {
            return EngineStepOutput(
                decision = ControlDecision(
                    qualityScore = null,
                    qualityState = QualityState.UNKNOWN,
                    fecMode = FecMode.OFF,
                    bgPacerRatio = 1.0,
                    selectedRoute = RouteChoice.NATIVE,
                    confidence = 0.0,
                    reasonCodes = listOf("NATIVE_STEP_FAILED"),
                ),
                srttMs = null,
                jitterMs = null,
                bufferbloatMs = null,
                rtoMs = null,
            )
        }

        val hasScore = outInts[0] != 0
        val qualityState = when (outInts[1]) {
            1 -> QualityState.GREEN
            2 -> QualityState.YELLOW
            3 -> QualityState.RED
            else -> QualityState.UNKNOWN
        }
        val fecMode = when (outInts[2]) {
            1 -> FecMode.XOR_K4_INTERLEAVED
            2 -> FecMode.XOR_K2_INTERLEAVED
            3 -> FecMode.DUPLICATE
            else -> FecMode.OFF
        }
        val route = if (outInts[3] == 1) RouteChoice.RELAY else RouteChoice.NATIVE
        val reasons = NativeEngineBridge.decodeReasonFlags(outInts[4])

        return EngineStepOutput(
            decision = ControlDecision(
                qualityScore = if (hasScore) outDoubles[0] else null,
                qualityState = qualityState,
                fecMode = fecMode,
                bgPacerRatio = outDoubles[5],
                selectedRoute = route,
                confidence = outDoubles[6],
                reasonCodes = reasons,
            ),
            srttMs = if (outDoubles[1] >= 0.0) outDoubles[1] else null,
            jitterMs = if (outDoubles[2] >= 0.0) outDoubles[2] else null,
            bufferbloatMs = if (outDoubles[3] >= 0.0) outDoubles[3] else null,
            rtoMs = if (outDoubles[4] >= 0.0) outDoubles[4] else null,
        )
    }

    @Synchronized
    override fun enqueueTunPacket(
        rawPacket: ByteArray,
        length: Int,
        nowMs: Long,
        tierOverride: Int,
    ): Boolean {
        if (handle == 0L) return false
        return NativeEngineBridge.nativeEnqueuePacket(handle, rawPacket, length, nowMs, tierOverride)
    }

    @Synchronized
    override fun dequeueScheduledPacket(
        nowMs: Long,
        outBuf: ByteArray,
        outTierAndLen: IntArray,
    ): Boolean {
        if (handle == 0L) return false
        return NativeEngineBridge.nativeDequeuePacket(handle, nowMs, outBuf, outTierAndLen)
    }

    @Synchronized
    override fun configureSchedulerPacer(bgPacerRatio: Double, estimatedLinkMbps: Double) {
        if (handle != 0L) {
            NativeEngineBridge.nativeConfigurePacer(handle, bgPacerRatio, estimatedLinkMbps)
        }
    }

    @Synchronized
    override fun close() {
        if (handle != 0L) {
            NativeEngineBridge.nativeDestroySession(handle)
            handle = 0L
        }
    }
}

/** Hybrid stack when C/C++ native library is present without Rust staticlib prebuilt. */
private class HybridNativePacketKotlinMathAdapter(
    private var handle: Long,
) : EngineAdapter {
    private val kotlinMath = KotlinEngineAdapter()

    override val engineLabel: String = "Hybrid (Kotlin Math + C/C++ Net)"

    @Synchronized
    override fun reset() {
        kotlinMath.reset()
        if (handle != 0L) NativeEngineBridge.nativeResetSession(handle)
    }

    @Synchronized
    override fun resetBaseline(newMinRttMs: Double?) {
        kotlinMath.resetBaseline(newMinRttMs)
    }

    @Synchronized
    override fun submitRtt(rttMs: Double, timestampMs: Long): Boolean =
        kotlinMath.submitRtt(rttMs, timestampMs)

    @Synchronized
    override fun step(
        nowMs: Long,
        profile: TrafficProfile,
        lossPct: Double,
        bandwidthMbps: Double?,
        alternateRoute: RouteMetrics?,
    ): EngineStepOutput {
        val out = kotlinMath.step(nowMs, profile, lossPct, bandwidthMbps, alternateRoute)
        if (handle != 0L) {
            NativeEngineBridge.nativeConfigurePacer(
                handle,
                out.decision.bgPacerRatio,
                bandwidthMbps ?: 25.0,
            )
        }
        return out
    }

    @Synchronized
    override fun enqueueTunPacket(
        rawPacket: ByteArray,
        length: Int,
        nowMs: Long,
        tierOverride: Int,
    ): Boolean {
        if (handle == 0L) return false
        return NativeEngineBridge.nativeEnqueuePacket(handle, rawPacket, length, nowMs, tierOverride)
    }

    @Synchronized
    override fun dequeueScheduledPacket(
        nowMs: Long,
        outBuf: ByteArray,
        outTierAndLen: IntArray,
    ): Boolean {
        if (handle == 0L) return false
        return NativeEngineBridge.nativeDequeuePacket(handle, nowMs, outBuf, outTierAndLen)
    }

    @Synchronized
    override fun configureSchedulerPacer(bgPacerRatio: Double, estimatedLinkMbps: Double) {
        if (handle != 0L) {
            NativeEngineBridge.nativeConfigurePacer(handle, bgPacerRatio, estimatedLinkMbps)
        }
    }

    @Synchronized
    override fun close() {
        if (handle != 0L) {
            NativeEngineBridge.nativeDestroySession(handle)
            handle = 0L
        }
    }
}
