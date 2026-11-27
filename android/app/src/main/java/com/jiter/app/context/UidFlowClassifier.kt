package com.jiter.app.context

import android.content.Context
import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import com.jiter.app.relay.RelayProtocol
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Stage 4 Android API 29+ App-UID Flow Classifier.
 *
 * Uses `ConnectivityManager.getConnectionOwnerUid` to resolve the exact owning Android
 * package for outgoing IPv4 TCP/UDP packets read from the TUN interface, overriding
 * packet-size heuristics whenever the app belongs to a known Game, Streaming, or
 * Background Downloader tier.
 *
 * Falls back cleanly to `-1` (C layer IPv4/port/DSCP classifier) on unknown apps or
 * OEM ROM restrictions.
 */
class UidFlowClassifier(context: Context) {
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val packageManager = context.packageManager

    private val uidTierCache = object : LinkedHashMap<Int, Int>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, Int>?): Boolean =
            size > 128
    }

    /**
     * Returns `0 (GAME)`, `1 (STREAMING)`, `2 (BACKGROUND)`, or `-1` (defer to C heuristic).
     */
    fun classifyIpv4Packet(rawPacket: ByteArray, length: Int): Int {
        if (length < 28 || length > rawPacket.size) return -1
        val version = (rawPacket[0].toInt() ushr 4) and 0x0F
        val ihl = (rawPacket[0].toInt() and 0x0F) * 4
        if (version != 4 || ihl < 20 || ihl + 8 > length) return -1

        val proto = rawPacket[9].toInt() and 0xFF
        val osProto = when (proto) {
            6 -> OsConstants.IPPROTO_TCP
            17 -> OsConstants.IPPROTO_UDP
            else -> return -1
        }
        if (proto == 6 && ihl + 20 > length) return -1

        return try {
            val srcIp = InetAddress.getByAddress(rawPacket.copyOfRange(12, 16))
            val dstIp = InetAddress.getByAddress(rawPacket.copyOfRange(16, 20))
            val srcPort = ((rawPacket[ihl].toInt() and 0xFF) shl 8) or
                (rawPacket[ihl + 1].toInt() and 0xFF)
            val dstPort = ((rawPacket[ihl + 2].toInt() and 0xFF) shl 8) or
                (rawPacket[ihl + 3].toInt() and 0xFF)

            val uid = connectivityManager.getConnectionOwnerUid(
                osProto,
                InetSocketAddress(srcIp, srcPort),
                InetSocketAddress(dstIp, dstPort),
            )
            if (uid == Process.INVALID_UID || uid <= 0) return -1
            resolveTierForUid(uid)
        } catch (_: Exception) {
            -1
        }
    }

    private fun resolveTierForUid(uid: Int): Int {
        synchronized(uidTierCache) {
            uidTierCache[uid]?.let { return it }
        }
        val pkgs = try {
            packageManager.getPackagesForUid(uid)
        } catch (_: Exception) {
            null
        }
        val tier = classifyPackages(pkgs)
        synchronized(uidTierCache) {
            uidTierCache[uid] = tier
        }
        return tier
    }

    companion object {
        private val GAME_HINTS = listOf(
            "mobile.legends",
            "tencent.ig",
            "pubg",
            "freefire",
            "mihoyo",
            "genshin",
            "riotgames",
            "wildrift",
            "codm",
            "callofduty",
            "roblox",
            "supercell",
            "garena",
            "activision",
            "epicgames",
            "valorant",
            "honkai",
            "minecraft",
        )

        private val STREAMING_HINTS = listOf(
            "youtube",
            "netflix",
            "twitch",
            "disney",
            "musically",
            "tiktok",
            "bilibili",
            "vidio",
            "viu",
            "spotify",
            "primevideo",
            "hbo",
        )

        private val BACKGROUND_HINTS = listOf(
            "android.vending",
            "providers.downloads",
            "adm.pro",
            "idm",
            "torrent",
            "google.android.gms",
        )

        internal fun classifyPackages(packages: Array<String>?): Int {
            if (packages == null || packages.isEmpty()) return -1
            for (raw in packages) {
                val pkg = raw.lowercase()
                if (GAME_HINTS.any { pkg.contains(it) }) return RelayProtocol.TIER_GAME
                if (STREAMING_HINTS.any { pkg.contains(it) }) return RelayProtocol.TIER_STREAMING
                if (BACKGROUND_HINTS.any { pkg.contains(it) }) return RelayProtocol.TIER_BACKGROUND
            }
            return -1
        }
    }
}
