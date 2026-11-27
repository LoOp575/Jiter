package com.jiter.app.engine

import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToLong

/**
 * Formula #1: Composite weighted linear routing/quality cost model (EIGRP / SD-WAN style),
 * paired with non-compensatory Hard Veto guardrails so fatal impairments cannot be masked.
 */
object LinearCostScorer {
    const val RTT_SCALE_MS = 200.0
    const val JITTER_SCALE_MS = 50.0
    const val LOSS_SCALE_PCT = 10.0
    const val BLOAT_SCALE_MS = 300.0

    fun evaluate(
        srttMs: Double,
        jitterMs: Double,
        lossPct: Double,
        bufferbloatMs: Double,
        bandwidthMbps: Double?,
        profile: TrafficProfile,
        sampleCount: Int = 20,
    ): ScoreResult {
        val w = profile.weights

        val rNorm = min(max(srttMs, 0.0) / RTT_SCALE_MS, 1.0)
        val jNorm = min(max(jitterMs, 0.0) / JITTER_SCALE_MS, 1.0)
        val pNorm = min(max(lossPct, 0.0) / LOSS_SCALE_PCT, 1.0)
        val bNorm = min(max(bufferbloatMs, 0.0) / BLOAT_SCALE_MS, 1.0)

        var confidence = min(1.0, max(0.0, sampleCount / 10.0))
        val wNorm = if (bandwidthMbps == null) {
            // Missing bandwidth is never treated as 0 Mbps; keep neutral penalty & reduce confidence
            confidence *= 0.8
            0.0
        } else {
            min(1.0, max(0.0, 1.0 - (max(bandwidthMbps, 0.0) / w.minBwMbps)))
        }

        val costC =
            w.wRtt * rNorm +
                w.wJitter * jNorm +
                w.wLoss * pNorm +
                w.wBloat * bNorm +
                w.wBw * wNorm

        var scoreQ = 100.0 * (1.0 - costC)
        val vetoes = mutableListOf<String>()

        when (profile) {
            TrafficProfile.GAME -> {
                if (lossPct >= 5.0) {
                    scoreQ = min(scoreQ, 45.0)
                    vetoes.add("VETO_GAME_CRITICAL_LOSS")
                }
                if (bufferbloatMs >= 50.0) {
                    scoreQ = min(scoreQ, 49.0)
                    vetoes.add("VETO_GAME_BUFFERBLOAT")
                }
                if (bandwidthMbps != null && bandwidthMbps < w.minBwMbps) {
                    scoreQ = min(scoreQ, 45.0)
                    vetoes.add("VETO_GAME_BELOW_MIN_BW")
                }
            }
            TrafficProfile.STREAMING -> {
                if (bandwidthMbps != null && bandwidthMbps < (w.minBwMbps * 0.4)) {
                    scoreQ = min(scoreQ, 45.0)
                    vetoes.add("VETO_STREAMING_STARVED")
                }
                if (lossPct >= 5.0) {
                    scoreQ = min(scoreQ, 49.0)
                    vetoes.add("VETO_STREAMING_LOSS")
                }
            }
            else -> Unit
        }

        return ScoreResult(
            scoreQ = roundTo(scoreQ, 2),
            costC = roundTo(costC, 4),
            confidence = roundTo(confidence, 2),
            vetoReasons = vetoes,
            componentR = roundTo(rNorm, 4),
            componentJ = roundTo(jNorm, 4),
            componentP = roundTo(pNorm, 4),
            componentB = roundTo(bNorm, 4),
            componentW = roundTo(wNorm, 4),
        )
    }

    private fun roundTo(value: Double, decimals: Int): Double {
        var factor = 1.0
        repeat(decimals) { factor *= 10.0 }
        return (value * factor).roundToLong() / factor
    }
}

/**
 * Anti-flicker status color state machine using EWMA score smoothing, asymmetric
 * hysteresis bands, minimum dwell time, and explicit UNKNOWN on stale input.
 */
class ColorStateMachine(
    private val minDwellMs: Long = 2_000L,
    private val ewmaAlpha: Double = 0.35,
) {
    private var smoothedQ: Double? = null
    private var currentState: QualityState = QualityState.UNKNOWN
    private var lastTransitionMs: Long = -minDwellMs

    val state: QualityState
        get() = currentState

    val smoothedScore: Double?
        get() = smoothedQ

    fun reset() {
        smoothedQ = null
        currentState = QualityState.UNKNOWN
        lastTransitionMs = -minDwellMs
    }

    fun update(scoreQ: Double?, nowMs: Long, isStale: Boolean = false): QualityState {
        if (isStale || scoreQ == null || !scoreQ.isFinite()) {
            currentState = QualityState.UNKNOWN
            smoothedQ = null
            lastTransitionMs = nowMs
            return currentState
        }

        val prevSmoothed = smoothedQ
        val q = if (prevSmoothed == null) {
            scoreQ
        } else {
            ewmaAlpha * scoreQ + (1.0 - ewmaAlpha) * prevSmoothed
        }
        smoothedQ = q

        val dwellElapsed = (nowMs - lastTransitionMs) >= minDwellMs

        if (currentState == QualityState.UNKNOWN) {
            currentState = when {
                q >= 80.0 -> QualityState.GREEN
                q >= 50.0 -> QualityState.YELLOW
                else -> QualityState.RED
            }
            lastTransitionMs = nowMs
            return currentState
        }

        val target = when (currentState) {
            QualityState.GREEN -> when {
                q < 48.0 -> QualityState.RED
                q < 75.0 -> QualityState.YELLOW
                else -> QualityState.GREEN
            }
            QualityState.YELLOW -> when {
                q >= 82.0 -> QualityState.GREEN
                q < 48.0 -> QualityState.RED
                else -> QualityState.YELLOW
            }
            QualityState.RED -> when {
                q >= 82.0 -> QualityState.GREEN
                q >= 55.0 -> QualityState.YELLOW
                else -> QualityState.RED
            }
            QualityState.UNKNOWN -> currentState
        }

        val severeDrop = (target == QualityState.RED && scoreQ < 45.0)
        if (target != currentState && (dwellElapsed || severeDrop)) {
            currentState = target
            lastTransitionMs = nowMs
        }

        return currentState
    }
}
