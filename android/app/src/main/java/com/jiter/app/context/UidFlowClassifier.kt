package com.jiter.app.context

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import com.jiter.app.relay.RelayProtocol
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Stage 5 Android API 29+ Zero-Config App-UID Flow Classifier.
 *
 * Resolves the exact owning Android app for outgoing IPv4 TCP/UDP packets read from
 * the TUN interface (`ConnectivityManager.getConnectionOwnerUid`), then classifies by:
 *   1. Official Android OS `ApplicationInfo.category` (`CATEGORY_GAME`, `CATEGORY_VIDEO`,
 *      `CATEGORY_AUDIO`) and legacy `FLAG_IS_GAME` — automatically covers every new game
 *      and media app from Play Store without manual allowlist maintenance!
 *   2. Curated package-name fallback hints for sideloaded or uncategorized apps.
 *
 * Returns `-1` for unrecognized apps so the C layer IPv4/port/DSCP classifier takes over.
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

    @Suppress("DEPRECATION")
    private fun resolveTierForUid(uid: Int): Int {
        synchronized(uidTierCache) {
            uidTierCache[uid]?.let { return it }
        }
        val pkgs = try {
            packageManager.getPackagesForUid(uid)
        } catch (_: Exception) {
            null
        }

        var osCategory = ApplicationInfo.CATEGORY_UNDEFINED
        var legacyGameFlag = false
        if (pkgs != null && pkgs.isNotEmpty()) {
            for (pkg in pkgs) {
                try {
                    val info = packageManager.getApplicationInfo(pkg, 0)
                    if (info.category == ApplicationInfo.CATEGORY_GAME) {
                        osCategory = ApplicationInfo.CATEGORY_GAME
                        break
                    }
                    if ((info.flags and ApplicationInfo.FLAG_IS_GAME) != 0) {
                        legacyGameFlag = true
                        break
                    }
                    if (osCategory == ApplicationInfo.CATEGORY_UNDEFINED &&
                        (info.category == ApplicationInfo.CATEGORY_VIDEO ||
                            info.category == ApplicationInfo.CATEGORY_AUDIO)
                    ) {
                        osCategory = info.category
                    }
                } catch (_: Exception) {
                    // Package visibility may restrict some system apps; package hints still apply
                }
            }
        }

        val tier = classifyAppMetadata(
            category = osCategory,
            isLegacyGameFlag = legacyGameFlag,
            packages = pkgs,
        )
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
            "hoyoverse",
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
            "levelinfinite",
            "sgameglobal",
        )

        private val STREAMING_HINTS = listOf(
            "youtube",
            "netflix",
            "twitch",
            "disney",
            "musically",
            "tiktok",
            "ugc.trill",
            "bilibili",
            "bstar",
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
            "dv.adm",
            "idm",
            "torrent",
            "google.android.gms",
        )

        internal fun classifyAppMetadata(
            category: Int,
            isLegacyGameFlag: Boolean,
            packages: Array<String>?,
        ): Int {
            // Layer 1: Official Android OS ApplicationInfo category
            if (category == ApplicationInfo.CATEGORY_GAME || isLegacyGameFlag) {
                return RelayProtocol.TIER_GAME
            }
            if (category == ApplicationInfo.CATEGORY_VIDEO ||
                category == ApplicationInfo.CATEGORY_AUDIO
            ) {
                return RelayProtocol.TIER_STREAMING
            }
            // Layer 2: Curated fallback hints for sideloaded or uncategorized apps
            return classifyPackages(packages)
        }

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
