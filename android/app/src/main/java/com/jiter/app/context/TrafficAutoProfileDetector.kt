package com.jiter.app.context

import com.jiter.app.engine.TrafficProfile
import com.jiter.app.relay.RelayProtocol

data class AutoProfileAssessment(
    val profile: TrafficProfile,
    val detectedFromPackets: Boolean,
    val concurrentStreaming: Boolean,
    val observedGoodputMbps: Double?,
)

/**
 * Stage 5 Zero-Permission Packet Activity Auto-Profile Detector.
 *
 * Observes live IPv4 packet tiers flowing through the TUN pump (classified by Android UID
 * + C IPv4/UDP/TCP heuristics) and automatically transitions JITER between:
 *   - `GAME` (sticky 15 s window so loading screens / lobbies never drop game priority)
 *   - `STREAMING` (sticky 10 s window when media streams without active gaming)
 *   - `DOWNLOAD` (sticky 8 s window on heavy bulk transfers without Game/Streaming)
 *   - `SAFE_BALANCED` (when idle)
 *
 * When Game and Streaming flow simultaneously, keeps `GAME` priority active while
 * flagging `concurrentStreaming = true` so tier-0 protects Game and tier-1 keeps video smooth.
 */
class TrafficAutoProfileDetector(
    private val gameStickyMs: Long = 15_000L,
    private val streamingStickyMs: Long = 10_000L,
    private val downloadStickyMs: Long = 8_000L,
    private val burstWindowMs: Long = 3_000L,
) {
    private val lock = Any()

    private var windowStartMs: Long = 0L
    private var windowGamePkts: Int = 0
    private var windowStreamPkts: Int = 0
    private var windowStreamBytes: Long = 0L
    private var windowBgBytes: Long = 0L
    private var windowTotalBytes: Long = 0L

    private var lastGameConfirmedMs: Long = Long.MIN_VALUE
    private var lastStreamConfirmedMs: Long = Long.MIN_VALUE
    private var lastDownloadConfirmedMs: Long = Long.MIN_VALUE

    private var lastGoodputMbps: Double? = null

    fun reset() = synchronized(lock) {
        windowStartMs = 0L
        windowGamePkts = 0
        windowStreamPkts = 0
        windowStreamBytes = 0L
        windowBgBytes = 0L
        windowTotalBytes = 0L
        lastGameConfirmedMs = Long.MIN_VALUE
        lastStreamConfirmedMs = Long.MIN_VALUE
        lastDownloadConfirmedMs = Long.MIN_VALUE
        lastGoodputMbps = null
    }

    /**
     * Records a packet observed on the TUN interface.
     * `uidMatched = true` indicates authoritative Android app UID confirmation.
     */
    fun recordPacket(
        tier: Int,
        byteLength: Int,
        uidMatched: Boolean,
        nowMs: Long,
    ) = synchronized(lock) {
        if (byteLength <= 0) return@synchronized
        rotateWindowIfNeeded(nowMs)

        windowTotalBytes += byteLength
        when (tier) {
            RelayProtocol.TIER_GAME -> {
                windowGamePkts += 1
                if (uidMatched || windowGamePkts >= HEURISTIC_GAME_MIN_PKTS) {
                    lastGameConfirmedMs = nowMs
                }
            }
            RelayProtocol.TIER_STREAMING -> {
                windowStreamPkts += 1
                windowStreamBytes += byteLength
                if (uidMatched ||
                    windowStreamPkts >= HEURISTIC_STREAM_MIN_PKTS ||
                    windowStreamBytes >= HEURISTIC_STREAM_MIN_BYTES
                ) {
                    lastStreamConfirmedMs = nowMs
                }
            }
            RelayProtocol.TIER_BACKGROUND -> {
                windowBgBytes += byteLength
                if (windowBgBytes >= BULK_DOWNLOAD_MIN_BYTES) {
                    lastDownloadConfirmedMs = nowMs
                }
            }
        }
    }

    fun evaluate(nowMs: Long): AutoProfileAssessment = synchronized(lock) {
        rotateWindowIfNeeded(nowMs)

        val gameActive = lastGameConfirmedMs != Long.MIN_VALUE &&
            (nowMs - lastGameConfirmedMs) in 0..gameStickyMs
        val streamActive = lastStreamConfirmedMs != Long.MIN_VALUE &&
            (nowMs - lastStreamConfirmedMs) in 0..streamingStickyMs
        val downloadActive = lastDownloadConfirmedMs != Long.MIN_VALUE &&
            (nowMs - lastDownloadConfirmedMs) in 0..downloadStickyMs

        val instantMbps = if (windowStartMs > 0L && nowMs > windowStartMs && windowTotalBytes > 0L) {
            val elapsedSec = ((nowMs - windowStartMs).coerceAtLeast(250L)) / 1000.0
            (windowTotalBytes * 8.0) / (elapsedSec * 1_000_000.0)
        } else {
            lastGoodputMbps
        }

        return@synchronized when {
            gameActive -> AutoProfileAssessment(
                profile = TrafficProfile.GAME,
                detectedFromPackets = true,
                concurrentStreaming = streamActive,
                observedGoodputMbps = instantMbps,
            )
            streamActive -> AutoProfileAssessment(
                profile = TrafficProfile.STREAMING,
                detectedFromPackets = true,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
            )
            downloadActive -> AutoProfileAssessment(
                profile = TrafficProfile.DOWNLOAD,
                detectedFromPackets = true,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
            )
            else -> AutoProfileAssessment(
                profile = TrafficProfile.SAFE_BALANCED,
                detectedFromPackets = false,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
            )
        }
    }

    private fun rotateWindowIfNeeded(nowMs: Long) {
        if (windowStartMs == 0L) {
            windowStartMs = nowMs
            return
        }
        val elapsed = nowMs - windowStartMs
        if (elapsed >= burstWindowMs) {
            if (windowTotalBytes > 0L) {
                lastGoodputMbps = (windowTotalBytes * 8.0) / ((elapsed / 1000.0) * 1_000_000.0)
            } else {
                lastGoodputMbps = null
            }
            windowStartMs = nowMs
            windowGamePkts = 0
            windowStreamPkts = 0
            windowStreamBytes = 0L
            windowBgBytes = 0L
            windowTotalBytes = 0L
        }
    }

    companion object {
        private const val HEURISTIC_GAME_MIN_PKTS = 4
        private const val HEURISTIC_STREAM_MIN_PKTS = 12
        private const val HEURISTIC_STREAM_MIN_BYTES = 16_384L
        private const val BULK_DOWNLOAD_MIN_BYTES = 65_536L
    }
}
