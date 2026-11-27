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

    fun close() {}
}

class KotlinEngineAdapter : EngineAdapter {
    private val ewma = BitwiseEwmaEstimator()
    private val controller = AdaptiveController()

    override val engineLabel: String = "Kotlin Pure"

    override fun reset() {
        ewma.reset()
        controller.reset()
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

    fun applyFecOverride(decision: ControlDecision, fecOverride: FecMode?): ControlDecision =
        if (fecOverride != null) decision.copy(fecMode = fecOverride) else decision
}
