package com.jiter.app.context

import com.jiter.app.engine.TrafficProfile
import com.jiter.app.relay.RelayProtocol

data class AutoProfileAssessment(
    val profile: TrafficProfile,
    val detectedFromPackets: Boolean,
    val concurrentStreaming: Boolean,
    val observedGoodputMbps: Double?,
    val uidVerified: Boolean = false,
)

/**
 * Stage 6.2 Packet & Downlink Activity Auto-Profile Detector.
 *
 * Cleanly separates packet QoS queue priority from app-activity profile detection so
 * control frames (DNS port 53, TCP SYN/ACK <= 96 B, ICMP, and HTTPS/QUIC port 80/443)
 * NEVER false-trigger `GAME` mode while browsing, streaming, or downloading!
 *
 * Automatically transitions JITER between:
 *   - `GAME` (sticky 15 s): ONLY when confirmed by Android Game UID or sustained non-443/non-53 game UDP
 *   - `STREAMING` (sticky 10 s): confirmed by media UID or sustained high-rate streaming bytes
 *   - `BROWSER` / `SOCIAL` (sticky 8 s): confirmed by browser/social app UID
 *   - `DOWNLOAD` (sticky 8 s): heavy bulk uplink or downlink transfers without active Game/Streaming
 *   - `SAFE_BALANCED`: when idle
 */
class TrafficAutoProfileDetector(
    private val gameStickyMs: Long = 15_000L,
    private val streamingStickyMs: Long = 10_000L,
    private val downloadStickyMs: Long = 8_000L,
    private val interactiveStickyMs: Long = 8_000L,
    private val burstWindowMs: Long = 3_000L,
) {
    private val lock = Any()

    private var windowStartMs: Long = 0L
    private var windowGamePkts: Int = 0
    private var windowStreamPkts: Int = 0
    private var windowStreamBytes: Long = 0L
    private var windowBgBytes: Long = 0L
    private var windowTotalBytes: Long = 0L

    private var lastGameUidConfirmedMs: Long = Long.MIN_VALUE
    private var lastGameHeuristicConfirmedMs: Long = Long.MIN_VALUE
    private var lastStreamConfirmedMs: Long = Long.MIN_VALUE
    private var lastStreamUidConfirmedMs: Long = Long.MIN_VALUE
    private var lastBrowserUidConfirmedMs: Long = Long.MIN_VALUE
    private var lastSocialUidConfirmedMs: Long = Long.MIN_VALUE
    private var lastDownloadConfirmedMs: Long = Long.MIN_VALUE

    private var lastGoodputMbps: Double? = null

    fun reset() = synchronized(lock) {
        windowStartMs = 0L
        windowGamePkts = 0
        windowStreamPkts = 0
        windowStreamBytes = 0L
        windowBgBytes = 0L
        windowTotalBytes = 0L
        lastGameUidConfirmedMs = Long.MIN_VALUE
        lastGameHeuristicConfirmedMs = Long.MIN_VALUE
        lastStreamConfirmedMs = Long.MIN_VALUE
        lastStreamUidConfirmedMs = Long.MIN_VALUE
        lastBrowserUidConfirmedMs = Long.MIN_VALUE
        lastSocialUidConfirmedMs = Long.MIN_VALUE
        lastDownloadConfirmedMs = Long.MIN_VALUE
        lastGoodputMbps = null
    }

    /**
     * Records an outbound packet observed on the TUN interface.
     *
     * - `uidMatched = true` indicates authoritative Android app UID confirmation.
     * - `isControlPacket = true` (DNS 53/853, TCP ACK/SYN <= 96 B, ICMP) ensures network
     *   control traffic keeps QoS priority in the scheduler without falsely locking `GAME` mode.
     */
    fun recordPacket(
        tier: Int,
        byteLength: Int,
        uidMatched: Boolean,
        nowMs: Long,
        protocol: Int = 0,
        dstPort: Int = 0,
        uidProfile: TrafficProfile? = null,
        isControlPacket: Boolean = false,
    ) = synchronized(lock) {
        if (byteLength <= 0) return@synchronized
        rotateWindowIfNeeded(nowMs)

        windowTotalBytes += byteLength

        // 1. Authoritative UID app-profile signals (Browser / Social / Game / Streaming / Download)
        if (uidMatched && uidProfile != null) {
            when (uidProfile) {
                TrafficProfile.GAME -> {
                    lastGameUidConfirmedMs = nowMs
                    return@synchronized
                }
                TrafficProfile.STREAMING -> {
                    windowStreamPkts += 1
                    windowStreamBytes += byteLength
                    lastStreamConfirmedMs = nowMs
                    lastStreamUidConfirmedMs = nowMs
                    return@synchronized
                }
                TrafficProfile.BROWSER -> {
                    lastBrowserUidConfirmedMs = nowMs
                    return@synchronized
                }
                TrafficProfile.SOCIAL -> {
                    lastSocialUidConfirmedMs = nowMs
                    return@synchronized
                }
                TrafficProfile.DOWNLOAD -> {
                    windowBgBytes += byteLength
                    if (windowBgBytes >= BULK_DOWNLOAD_MIN_BYTES) {
                        lastDownloadConfirmedMs = nowMs
                    }
                    return@synchronized
                }
                TrafficProfile.SAFE_BALANCED -> Unit
            }
        }

        // 2. Legacy/generic UID match (when caller only passed tier + uidMatched=true)
        if (uidMatched && uidProfile == null) {
            when (tier) {
                RelayProtocol.TIER_GAME -> {
                    lastGameUidConfirmedMs = nowMs
                    return@synchronized
                }
                RelayProtocol.TIER_STREAMING -> {
                    windowStreamPkts += 1
                    windowStreamBytes += byteLength
                    lastStreamConfirmedMs = nowMs
                    lastStreamUidConfirmedMs = nowMs
                    return@synchronized
                }
                RelayProtocol.TIER_BACKGROUND -> {
                    windowBgBytes += byteLength
                    if (windowBgBytes >= BULK_DOWNLOAD_MIN_BYTES) {
                        lastDownloadConfirmedMs = nowMs
                    }
                    return@synchronized
                }
            }
        }

        // 3. Heuristic-only packet classification (never let DNS / TCP ACK / ICMP / port 80/443 fake GAME!)
        if (isControlPacket || isWebOrControlPacket(protocol, dstPort, byteLength)) {
            // Still count large port-443 UDP (QUIC video/HTTP3) as streaming heuristic if sustained
            if (protocol == PROTO_UDP && dstPort == 443 && byteLength > 320) {
                windowStreamPkts += 1
                windowStreamBytes += byteLength
                if (windowStreamPkts >= HEURISTIC_STREAM_MIN_PKTS &&
                    windowStreamBytes >= HEURISTIC_STREAM_MIN_BYTES
                ) {
                    lastStreamConfirmedMs = nowMs
                }
            }
            return@synchronized
        }

        when (tier) {
            RelayProtocol.TIER_GAME -> {
                // Only sustained non-web, non-DNS UDP bursts qualify as heuristic game traffic
                if (protocol == 0 || protocol == PROTO_UDP) {
                    windowGamePkts += 1
                    if (windowGamePkts >= HEURISTIC_GAME_MIN_PKTS) {
                        lastGameHeuristicConfirmedMs = nowMs
                    }
                }
            }
            RelayProtocol.TIER_STREAMING -> {
                windowStreamPkts += 1
                windowStreamBytes += byteLength
                if (windowStreamPkts >= HEURISTIC_STREAM_MIN_PKTS &&
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

    /**
     * Records downlink payload bytes delivered by `LocalTrafficShaper` (remote -> Android)
     * so `observedGoodputMbps` reflects actual download speed (e.g. 50–100+ Mbps) instead of
     * only measuring tiny 40-byte uplink TCP ACKs!
     */
    fun recordDownlinkBytes(
        tier: Int,
        byteLength: Int,
        isUdp: Boolean,
        nowMs: Long,
    ) = synchronized(lock) {
        if (byteLength <= 0) return@synchronized
        rotateWindowIfNeeded(nowMs)

        windowTotalBytes += byteLength
        when (tier) {
            RelayProtocol.TIER_BACKGROUND -> {
                windowBgBytes += byteLength
                if (windowBgBytes >= DOWNLINK_BULK_DOWNLOAD_MIN_BYTES) {
                    lastDownloadConfirmedMs = nowMs
                }
            }
            RelayProtocol.TIER_STREAMING -> {
                if (isUdp) {
                    windowStreamPkts += 1
                    windowStreamBytes += byteLength
                    if (windowStreamBytes >= DOWNLINK_STREAM_MIN_BYTES) {
                        lastStreamConfirmedMs = nowMs
                    }
                } else {
                    // Sustained high-rate TCP downlink on port 443 (e.g. file download inside browser)
                    windowBgBytes += byteLength
                    if (windowBgBytes >= DOWNLINK_HTTPS_BULK_MIN_BYTES) {
                        lastDownloadConfirmedMs = nowMs
                    }
                }
            }
        }
    }

    fun evaluate(nowMs: Long): AutoProfileAssessment = synchronized(lock) {
        rotateWindowIfNeeded(nowMs)

        val gameUidActive = isWithin(nowMs, lastGameUidConfirmedMs, gameStickyMs)
        val gameHeuristicActive = isWithin(nowMs, lastGameHeuristicConfirmedMs, gameStickyMs)
        val gameActive = gameUidActive || gameHeuristicActive
        val streamActive = isWithin(nowMs, lastStreamConfirmedMs, streamingStickyMs)
        val streamUidActive = isWithin(nowMs, lastStreamUidConfirmedMs, streamingStickyMs)
        val browserUidActive = isWithin(nowMs, lastBrowserUidConfirmedMs, interactiveStickyMs)
        val socialUidActive = isWithin(nowMs, lastSocialUidConfirmedMs, interactiveStickyMs)
        val downloadActive = isWithin(nowMs, lastDownloadConfirmedMs, downloadStickyMs)

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
                uidVerified = gameUidActive,
            )
            streamUidActive -> AutoProfileAssessment(
                profile = TrafficProfile.STREAMING,
                detectedFromPackets = true,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
                uidVerified = true,
            )
            downloadActive -> AutoProfileAssessment(
                profile = TrafficProfile.DOWNLOAD,
                detectedFromPackets = true,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
                uidVerified = false,
            )
            browserUidActive -> AutoProfileAssessment(
                profile = TrafficProfile.BROWSER,
                detectedFromPackets = true,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
                uidVerified = true,
            )
            socialUidActive -> AutoProfileAssessment(
                profile = TrafficProfile.SOCIAL,
                detectedFromPackets = true,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
                uidVerified = true,
            )
            streamActive -> AutoProfileAssessment(
                profile = TrafficProfile.STREAMING,
                detectedFromPackets = true,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
                uidVerified = false,
            )
            else -> AutoProfileAssessment(
                profile = TrafficProfile.SAFE_BALANCED,
                detectedFromPackets = false,
                concurrentStreaming = false,
                observedGoodputMbps = instantMbps,
                uidVerified = false,
            )
        }
    }

    private fun isWithin(nowMs: Long, lastMs: Long, windowMs: Long): Boolean =
        lastMs != Long.MIN_VALUE && (nowMs - lastMs) in 0..windowMs

    private fun isWebOrControlPacket(protocol: Int, dstPort: Int, byteLength: Int): Boolean {
        if (protocol == PROTO_ICMP) return true
        if (dstPort in NON_GAME_CONTROL_PORTS) return true
        if (protocol == PROTO_TCP && byteLength <= 96) return true
        if ((protocol == PROTO_UDP || protocol == PROTO_TCP) && (dstPort == 80 || dstPort == 443)) {
            return true
        }
        return false
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
        private const val PROTO_ICMP = 1
        private const val PROTO_TCP = 6
        private const val PROTO_UDP = 17

        // Non-game system/discovery/VoIP/STUN ports that must never falsely lock heuristic GAME mode
        private val NON_GAME_CONTROL_PORTS = setOf(
            53,    // DNS
            123,   // NTP clock sync
            500,   // IKEv2 / IPsec / VoWiFi
            853,   // DoT / DoQ
            1900,  // SSDP / UPnP discovery
            3478,  // STUN / TURN (WhatsApp/WebRTC)
            3479,  // STUN / TURN alt
            4500,  // IPsec NAT-T / VoWiFi
            5349,  // STUNS / TURNS
            5353,  // mDNS / Bonjour / Cast
            19302, // Google WebRTC STUN
        )

        private const val HEURISTIC_GAME_MIN_PKTS = 15
        private const val HEURISTIC_STREAM_MIN_PKTS = 16
        private const val HEURISTIC_STREAM_MIN_BYTES = 24_576L
        private const val BULK_DOWNLOAD_MIN_BYTES = 65_536L
        private const val DOWNLINK_BULK_DOWNLOAD_MIN_BYTES = 262_144L // 256 KB in 3 s for dedicated Tier-2 downloaders
        private const val DOWNLINK_HTTPS_BULK_MIN_BYTES = 1_500_000L // 1.5 MB in 3 s (~4 Mbps) for in-browser HTTPS downloads
        private const val DOWNLINK_STREAM_MIN_BYTES = 131_072L
    }
}
