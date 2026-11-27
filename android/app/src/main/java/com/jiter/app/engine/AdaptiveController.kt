package com.jiter.app.engine

import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToLong

/**
 * Closed-loop controller coordinating:
 *   - Formula #2 (BitwiseEwmaEstimator)
 *   - Formula #1 (LinearCostScorer + ColorStateMachine)
 *   - Formula #3 (Adaptive XOR FEC mode selection)
 *   - Anti-bufferbloat background pacer ratio
 *   - Smart route selection with hysteresis & cooldown
 */
class AdaptiveController(
    private val routeHysteresisPts: Double = 10.0,
    private val routeCooldownMs: Long = 5_000L,
) {
    private val colorEngine = ColorStateMachine()
    private var fecMode: FecMode = FecMode.OFF
    private var bgPacerRatio: Double = 1.0
    private var selectedRoute: RouteChoice = RouteChoice.NATIVE
    private var lastRouteSwitchMs: Long = -routeCooldownMs

    val currentRoute: RouteChoice
        get() = selectedRoute

    val currentFecMode: FecMode
        get() = fecMode

    val currentBgPacerRatio: Double
        get() = bgPacerRatio

    fun reset() {
        colorEngine.reset()
        fecMode = FecMode.OFF
        bgPacerRatio = 1.0
        selectedRoute = RouteChoice.NATIVE
        lastRouteSwitchMs = -routeCooldownMs
    }

    fun step(
        nowMs: Long,
        profile: TrafficProfile,
        ewma: BitwiseEwmaEstimator,
        lossPct: Double,
        bandwidthMbps: Double?,
        alternateRouteMetrics: RouteMetrics? = null,
    ): ControlDecision {
        val reasons = mutableListOf<String>()

        if (ewma.isStale(nowMs)) {
            val qState = colorEngine.update(null, nowMs, isStale = true)
            fecMode = FecMode.OFF
            bgPacerRatio = 1.0
            return ControlDecision(
                qualityScore = null,
                qualityState = qState,
                fecMode = fecMode,
                bgPacerRatio = bgPacerRatio,
                selectedRoute = selectedRoute,
                confidence = 0.0,
                reasonCodes = listOf("STALE_OR_MISSING_SAMPLES"),
            )
        }

        val srttMs = ewma.srttMs ?: 0.0
        val jitterMs = ewma.jitterMs ?: 0.0
        val bloatMs = ewma.bufferbloatMs ?: 0.0

        val score = LinearCostScorer.evaluate(
            srttMs = srttMs,
            jitterMs = jitterMs,
            lossPct = lossPct,
            bufferbloatMs = bloatMs,
            bandwidthMbps = bandwidthMbps,
            profile = profile,
            sampleCount = ewma.sampleCount,
        )
        reasons.addAll(score.vetoReasons)
        val qState = colorEngine.update(score.scoreQ, nowMs, isStale = false)

        // 1) Anti-Bufferbloat Background Pacer
        if (profile == TrafficProfile.GAME || profile == TrafficProfile.STREAMING) {
            if (bloatMs > 5.0 || score.scoreQ < 85.0) {
                bgPacerRatio = max(0.15, round3(bgPacerRatio * 0.65))
                reasons.add("PACER_THROTTLE_BG")
            } else {
                bgPacerRatio = min(0.55, round3(bgPacerRatio + 0.03))
                reasons.add("PACER_RESERVE_HEADROOM")
            }
        } else {
            bgPacerRatio = 1.0
            reasons.add("PACER_FULL_THROUGHPUT")
        }

        // 2) Adaptive Formula #3 (XOR FEC) — ONLY for latency-sensitive profiles
        if (profile == TrafficProfile.GAME) {
            when {
                lossPct >= 6.0 -> {
                    fecMode = FecMode.XOR_K2_INTERLEAVED
                    reasons.add("FEC_ELEVATED_K2")
                }
                lossPct >= 1.0 || jitterMs >= 8.0 -> {
                    fecMode = FecMode.XOR_K4_INTERLEAVED
                    reasons.add("FEC_ACTIVE_K4")
                }
                lossPct < 0.3 && jitterMs < 4.0 -> {
                    fecMode = FecMode.OFF
                    reasons.add("FEC_STANDBY_CLEAN_LINK")
                }
            }
        } else {
            fecMode = FecMode.OFF
        }

        // 3) Route Intelligence (Active vs Alternate Route with Hysteresis & Cooldown)
        if (alternateRouteMetrics != null && (nowMs - lastRouteSwitchMs) >= routeCooldownMs) {
            val altScore = LinearCostScorer.evaluate(
                srttMs = alternateRouteMetrics.srttMs,
                jitterMs = alternateRouteMetrics.jitterMs,
                lossPct = alternateRouteMetrics.lossPct,
                bufferbloatMs = alternateRouteMetrics.bufferbloatMs,
                bandwidthMbps = bandwidthMbps,
                profile = profile,
                sampleCount = ewma.sampleCount,
            )
            if (altScore.scoreQ >= score.scoreQ + routeHysteresisPts) {
                if (selectedRoute == RouteChoice.NATIVE) {
                    selectedRoute = RouteChoice.RELAY
                    reasons.add("ROUTE_SWITCH_TO_RELAY")
                } else {
                    selectedRoute = RouteChoice.NATIVE
                    reasons.add("ROUTE_SWITCH_TO_NATIVE")
                }
                lastRouteSwitchMs = nowMs
            }
        }

        return ControlDecision(
            qualityScore = score.scoreQ,
            qualityState = qState,
            fecMode = fecMode,
            bgPacerRatio = bgPacerRatio,
            selectedRoute = selectedRoute,
            confidence = score.confidence,
            reasonCodes = reasons,
        )
    }

    private fun round3(value: Double): Double = (value * 1000.0).roundToLong() / 1000.0
}
