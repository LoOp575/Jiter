package com.jiter.app.engine

import kotlin.math.abs
import kotlin.math.max
import kotlin.math.roundToLong

/**
 * Formula #2: Integer-only fixed-point RTT & jitter estimator modeled after
 * Van Jacobson (1988) / RFC 6298 / Linux kernel `tcp_rtt_estimator`.
 *
 * Internal registers use microseconds scaled by powers of two BEFORE shifting:
 *   - srttScaled   = SRTT_us   << 3   (alpha = 1/8 = 2^-3)
 *   - rttvarScaled = RTTVAR_us << 2   (beta  = 1/4 = 2^-2)
 */
class BitwiseEwmaEstimator {
    private var initialized: Boolean = false
    private var srttScaled: Long = 0L
    private var rttvarScaled: Long = 0L
    private var minRttUs: Long? = null
    private var lastSampleTsMs: Long? = null
    private var samples: Int = 0

    val isInitialized: Boolean
        get() = initialized

    val sampleCount: Int
        get() = samples

    val lastSampleTimestampMs: Long?
        get() = lastSampleTsMs

    fun reset() {
        initialized = false
        srttScaled = 0L
        rttvarScaled = 0L
        minRttUs = null
        lastSampleTsMs = null
        samples = 0
    }

    fun resetBaseline(newMinRttMs: Double? = null) {
        minRttUs = if (newMinRttMs != null && newMinRttMs.isFinite() && newMinRttMs > 0.0) {
            max(1L, (newMinRttMs * 1000.0).roundToLong())
        } else {
            null
        }
    }

    /**
     * Ingest a new RTT measurement in milliseconds.
     * Returns true if accepted, false if rejected as invalid, non-finite, or out-of-order.
     */
    fun update(rttMs: Double, timestampMs: Long): Boolean {
        if (!rttMs.isFinite() || rttMs <= 0.0) return false
        val rttUs = (rttMs * 1000.0).roundToLong()
        if (rttUs <= 0L || rttUs > MAX_VALID_RTT_US) return false
        val prevTs = lastSampleTsMs
        if (prevTs != null && timestampMs < prevTs) return false

        val currentMin = minRttUs
        if (currentMin == null || rttUs < currentMin) {
            minRttUs = rttUs
        }

        if (!initialized) {
            // RFC 6298 initialization: SRTT <- R, RTTVAR <- R/2
            srttScaled = rttUs shl 3
            rttvarScaled = max(1L, rttUs ushr 1) shl 2
            initialized = true
        } else {
            // Scaled bitwise update (4 integer ops, zero floating-point drift)
            val err = rttUs - (srttScaled ushr 3)
            srttScaled = (srttScaled + err).coerceAtLeast(1L)
            val absErr = abs(err)
            rttvarScaled = (rttvarScaled + absErr - (rttvarScaled ushr 2)).coerceAtLeast(0L)
        }

        lastSampleTsMs = timestampMs
        samples += 1
        return true
    }

    fun isStale(nowMs: Long, maxAgeMs: Long = DEFAULT_MAX_AGE_MS): Boolean {
        val lastTs = lastSampleTsMs ?: return true
        return !initialized || (nowMs - lastTs) > maxAgeMs
    }

    val srttMs: Double?
        get() = if (!initialized) null else (srttScaled / 8.0) / 1000.0

    val jitterMs: Double?
        get() = if (!initialized) null else (rttvarScaled / 4.0) / 1000.0

    /** Retransmission Timeout = SRTT + 4 * RTTVAR (without 1s TCP floor). */
    val rtoMs: Double?
        get() = if (!initialized) null else ((srttScaled ushr 3) + rttvarScaled) / 1000.0

    val minRttMs: Double?
        get() = minRttUs?.let { it / 1000.0 }

    val bufferbloatMs: Double?
        get() {
            val baseUs = minRttUs ?: return null
            if (!initialized) return null
            val srttUs = srttScaled ushr 3
            val bloatUs = (srttUs - baseUs).coerceAtLeast(0L)
            return bloatUs / 1000.0
        }

    companion object {
        const val MAX_VALID_RTT_US: Long = 30_000_000L // 30 seconds sanity bound
        const val DEFAULT_MAX_AGE_MS: Long = 10_000L
    }
}
