package com.jiter.app.bridge

import com.jiter.app.engine.AdaptiveController
import com.jiter.app.engine.BitwiseEwmaEstimator
import com.jiter.app.engine.ControlDecision
import com.jiter.app.engine.FecMode
import com.jiter.app.engine.RouteMetrics
import com.jiter.app.engine.TrafficProfile

data class EngineStepOutput(
    val decision: ControlDecision,
    val srttMs: Double?,
    val jitterMs: Double?,
    val bufferbloatMs: Double?,
    val rtoMs: Double?,
)

/**
 * Pluggable runtime engine contract so JITER can transparently run either:
 *   1. Native Rust Math + C++ Memory Pool/Scheduler + C Packet Engine (via JNI), or
 *   2. Pure Kotlin Engine fallback (zero native dependency).
 */
interface EngineAdapter {
    val engineLabel: String

    fun reset()
    fun resetBaseline(newMinRttMs: Double? = null)
    fun submitRtt(rttMs: Double, timestampMs: Long): Boolean
    fun step(
        nowMs: Long,
        profile: TrafficProfile,
        lossPct: Double,
        bandwidthMbps: Double?,
        alternateRoute: RouteMetrics? = null,
    ): EngineStepOutput

    /**
     * Enqueue a raw IPv4 packet read from TUN into the 3-tier priority scheduler
     * (`0 = GAME`, `1 = STREAMING`, `2 = BACKGROUND`).
     */
    fun enqueueTunPacket(
        rawPacket: ByteArray,
        length: Int,
        nowMs: Long,
        tierOverride: Int = -1,
    ): Boolean

    /**
     * Dequeue the next highest-priority paced packet into `outBuf`.
     * Writes `[tier, byteLength]` into `outTierAndLen` (size >= 2).
     */
    fun dequeueScheduledPacket(
        nowMs: Long,
        outBuf: ByteArray,
        outTierAndLen: IntArray,
    ): Boolean

    /**
     * Explicitly overrides the C++ TrafficScheduler background pacer ratio (used by Mode B
     * Local Shaper so outbound TCP ACKs are never stranded on a blocking TUN read while
     * LocalTrafficShaper handles smooth 50 ms TCP rwnd downlink pacing).
     */
    fun configureSchedulerPacer(bgPacerRatio: Double, estimatedLinkMbps: Double) {}

    fun close() {}
}

class KotlinEngineAdapter : EngineAdapter {
    private val ewma = BitwiseEwmaEstimator()
    private val controller = AdaptiveController()

    private val queueLock = Any()
    private val qGame = ArrayDeque<ByteArray>(32)
    private val qStream = ArrayDeque<ByteArray>(32)
    private val qBg = ArrayDeque<ByteArray>(32)

    override val engineLabel: String = "Kotlin Pure"

    override fun reset() {
        ewma.reset()
        controller.reset()
        synchronized(queueLock) {
            qGame.clear()
            qStream.clear()
            qBg.clear()
        }
    }

    override fun resetBaseline(newMinRttMs: Double?) {
        ewma.resetBaseline(newMinRttMs)
    }

    override fun submitRtt(rttMs: Double, timestampMs: Long): Boolean =
        ewma.update(rttMs, timestampMs)

    override fun step(
        nowMs: Long,
        profile: TrafficProfile,
        lossPct: Double,
        bandwidthMbps: Double?,
        alternateRoute: RouteMetrics?,
    ): EngineStepOutput {
        val decision = controller.step(
            nowMs = nowMs,
            profile = profile,
            ewma = ewma,
            lossPct = lossPct,
            bandwidthMbps = bandwidthMbps,
            alternateRouteMetrics = alternateRoute,
        )
        return EngineStepOutput(
            decision = decision,
            srttMs = ewma.srttMs,
            jitterMs = ewma.jitterMs,
            bufferbloatMs = ewma.bufferbloatMs,
            rtoMs = ewma.rtoMs,
        )
    }

    override fun enqueueTunPacket(
        rawPacket: ByteArray,
        length: Int,
        nowMs: Long,
        tierOverride: Int,
    ): Boolean {
        if (length < 20 || length > rawPacket.size) return false
        val version = (rawPacket[0].toInt() ushr 4) and 0x0F
        if (version != 4) return false

        val tier = if (tierOverride in 0..2) {
            tierOverride
        } else {
            val proto = rawPacket[9].toInt() and 0xFF
            when {
                proto == 1 -> 0 // ICMP -> GAME
                proto == 17 && length <= 320 -> 0 // Small UDP -> GAME
                proto == 17 -> 1 // Large UDP (QUIC/Stream) -> STREAMING
                proto == 6 && length <= 96 -> 0 // Small TCP ACK -> GAME
                else -> 2
            }
        }

        val copy = rawPacket.copyOf(length)
        synchronized(queueLock) {
            val target = when (tier) {
                0 -> qGame
                1 -> qStream
                else -> qBg
            }
            if (target.size >= 48) return false
            target.addLast(copy)
            return true
        }
    }

    override fun dequeueScheduledPacket(
        nowMs: Long,
        outBuf: ByteArray,
        outTierAndLen: IntArray,
    ): Boolean {
        if (outTierAndLen.size < 2) return false
        val pair: Pair<Int, ByteArray> = synchronized(queueLock) {
            when {
                qGame.isNotEmpty() -> 0 to qGame.removeFirst()
                qStream.isNotEmpty() -> 1 to qStream.removeFirst()
                qBg.isNotEmpty() -> 2 to qBg.removeFirst()
                else -> return false
            }
        }
        val bytes = pair.second
        val copyLen = minOf(bytes.size, outBuf.size)
        System.arraycopy(bytes, 0, outBuf, 0, copyLen)
        outTierAndLen[0] = pair.first
        outTierAndLen[1] = copyLen
        return true
    }

    fun applyFecOverride(decision: ControlDecision, fecOverride: FecMode?): ControlDecision =
        if (fecOverride != null) decision.copy(fecMode = fecOverride) else decision
}
