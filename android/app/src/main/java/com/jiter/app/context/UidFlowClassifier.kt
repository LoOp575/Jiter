package com.jiter.app.context

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.os.Process
import android.os.SystemClock
import android.system.OsConstants
import com.jiter.app.engine.TrafficProfile
import com.jiter.app.relay.RelayProtocol
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Combined QoS queue tier + app activity profile resolved from an Android UID.
 *
 * - `qosTier`: `0 (GAME)`, `1 (STREAMING)`, `2 (BACKGROUND)`, or `-1` (defer QoS tier to C layer).
 * - `appProfile`: Exact `TrafficProfile` inferred from the owning Android app's OS category or package.
 */
data class FlowClassification(
    val qosTier: Int,
    val appProfile: TrafficProfile?,
) {
    val uidMatched: Boolean
        get() = qosTier in 0..2 || appProfile != null

    companion object {
        val UNKNOWN = FlowClassification(qosTier = -1, appProfile = null)
    }
}

internal data class FlowTupleKey(
    val proto: Int,
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int,
)

/**
 * Lightweight synchronized LRU + TTL cache for 5-tuple network flows.
 * Eliminates 99%+ of per-packet Binder IPC calls to `ConnectivityManager.getConnectionOwnerUid`
 * during high-throughput downloads (where thousands of TCP ACKs/sec share the same 5-tuple).
 */
internal class FlowTupleCache<V>(
    private val maxEntries: Int = 512,
    private val ttlMs: Long = 30_000L,
) {
    private data class Entry<V>(val value: V, val cachedAtMs: Long)

    private val map = object : LinkedHashMap<FlowTupleKey, Entry<V>>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowTupleKey, Entry<V>>?): Boolean =
            size > maxEntries
    }

    @Synchronized
    fun get(key: FlowTupleKey, nowMs: Long): V? {
        val entry = map[key] ?: return null
        val age = nowMs - entry.cachedAtMs
        if (age < 0L || age > ttlMs) {
            map.remove(key)
            return null
        }
        return entry.value
    }

    @Synchronized
    fun put(key: FlowTupleKey, value: V, nowMs: Long) {
        map[key] = Entry(value, nowMs)
    }

    @Synchronized
    fun clear() {
        map.clear()
    }

    @Synchronized
    fun size(): Int = map.size
}

/**
 * Stage 6.2 High-Performance Android API 29+ App-UID Flow Classifier.
 *
 * Resolves the exact owning Android app for outgoing IPv4 TCP/UDP flows via
 * `ConnectivityManager.getConnectionOwnerUid`, protected by a 5-tuple LRU+TTL cache
 * (512 flows, 30 s TTL) so Binder IPC runs ONCE per new connection instead of per packet!
 *
 * Classifies apps using:
 *   1. Official Android OS `ApplicationInfo.category` (`CATEGORY_GAME`, `CATEGORY_VIDEO`,
 *      `CATEGORY_AUDIO`, `CATEGORY_SOCIAL`) and legacy `FLAG_IS_GAME`.
 *   2. Curated package-name hints covering games, streaming, browsers, social, and downloaders.
 */
class UidFlowClassifier(context: Context) {
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val packageManager = context.packageManager

    private val flowCache = FlowTupleCache<FlowClassification>(
        maxEntries = FLOW_CACHE_MAX_ENTRIES,
        ttlMs = FLOW_CACHE_TTL_MS,
    )

    private val uidClassificationCache = object : LinkedHashMap<Int, FlowClassification>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, FlowClassification>?): Boolean =
            size > 128
    }

    fun clearCache() {
        flowCache.clear()
        synchronized(uidClassificationCache) {
            uidClassificationCache.clear()
        }
    }

    /**
     * Backward-compatible QoS tier lookup: returns `0 (GAME)`, `1 (STREAMING)`, `2 (BACKGROUND)`, or `-1`.
     */
    fun classifyIpv4Packet(rawPacket: ByteArray, length: Int): Int =
        classifyFlow(rawPacket, length, SystemClock.elapsedRealtime()).qosTier

    /**
     * Fast 5-tuple cached lookup returning both QoS tier and owning app's `TrafficProfile`.
     */
    fun classifyFlow(rawPacket: ByteArray, length: Int, nowMs: Long): FlowClassification {
        if (length < 28 || length > rawPacket.size) return FlowClassification.UNKNOWN
        val version = (rawPacket[0].toInt() ushr 4) and 0x0F
        val ihl = (rawPacket[0].toInt() and 0x0F) * 4
        if (version != 4 || ihl < 20 || ihl + 8 > length) return FlowClassification.UNKNOWN

        val proto = rawPacket[9].toInt() and 0xFF
        val osProto = when (proto) {
            6 -> OsConstants.IPPROTO_TCP
            17 -> OsConstants.IPPROTO_UDP
            else -> return FlowClassification.UNKNOWN
        }
        if (proto == 6 && ihl + 20 > length) return FlowClassification.UNKNOWN

        val srcIpInt = readBe32(rawPacket, 12)
        val dstIpInt = readBe32(rawPacket, 16)
        val srcPort = ((rawPacket[ihl].toInt() and 0xFF) shl 8) or
            (rawPacket[ihl + 1].toInt() and 0xFF)
        val dstPort = ((rawPacket[ihl + 2].toInt() and 0xFF) shl 8) or
            (rawPacket[ihl + 3].toInt() and 0xFF)

        val tupleKey = FlowTupleKey(proto, srcIpInt, srcPort, dstIpInt, dstPort)
        flowCache.get(tupleKey, nowMs)?.let { return it }

        val resolved = try {
            val srcIp = InetAddress.getByAddress(rawPacket.copyOfRange(12, 16))
            val dstIp = InetAddress.getByAddress(rawPacket.copyOfRange(16, 20))
            val uid = connectivityManager.getConnectionOwnerUid(
                osProto,
                InetSocketAddress(srcIp, srcPort),
                InetSocketAddress(dstIp, dstPort),
            )
            if (uid == Process.INVALID_UID || uid <= 0) {
                FlowClassification.UNKNOWN
            } else {
                resolveClassificationForUid(uid)
            }
        } catch (_: Exception) {
            FlowClassification.UNKNOWN
        }

        flowCache.put(tupleKey, resolved, nowMs)
        return resolved
    }

    @Suppress("DEPRECATION")
    private fun resolveClassificationForUid(uid: Int): FlowClassification {
        synchronized(uidClassificationCache) {
            uidClassificationCache[uid]?.let { return it }
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
                            info.category == ApplicationInfo.CATEGORY_AUDIO ||
                            info.category == ApplicationInfo.CATEGORY_SOCIAL)
                    ) {
                        osCategory = info.category
                    }
                } catch (_: Exception) {
                    // Package visibility may restrict some system apps; package hints still apply
                }
            }
        }

        val classification = classifyAppFlow(
            category = osCategory,
            isLegacyGameFlag = legacyGameFlag,
            packages = pkgs,
        )
        synchronized(uidClassificationCache) {
            uidClassificationCache[uid] = classification
        }
        return classification
    }

    private fun readBe32(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 24) or
            ((buf[offset + 1].toInt() and 0xFF) shl 16) or
            ((buf[offset + 2].toInt() and 0xFF) shl 8) or
            (buf[offset + 3].toInt() and 0xFF)

    companion object {
        private const val FLOW_CACHE_MAX_ENTRIES = 512
        private const val FLOW_CACHE_TTL_MS = 30_000L

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
            "proximabeta",
            "fifamobile",
        )

        private val STREAMING_HINTS = listOf(
            "youtube",
            "netflix",
            "twitch",
            "disney",
            "musically",
            "tiktok",
            "ugc.trill",
            "ugc.aweme",
            "bilibili",
            "bstar",
            "vidio",
            "viu",
            "spotify",
            "primevideo",
            "hbo",
            "wetv",
            "iqiyi",
            "loklok",
        )

        private val BACKGROUND_HINTS = listOf(
            "android.vending",
            "providers.downloads",
            "adm.pro",
            "dv.adm",
            "idm",
            "torrent",
            "google.android.gms",
            "fdroid",
        )

        private val BROWSER_HINTS = listOf(
            "android.chrome",
            "chrome.beta",
            "chrome.dev",
            "mozilla.firefox",
            "brave.browser",
            "microsoft.emmx",
            "opera.browser",
            "opera.mini",
            "sec.android.app.sbrowser",
            "ucmobile",
            "kiwibrowser",
            "duckduckgo",
            "yandex.browser",
            "heytap.browser",
            "coloros.browser",
            "mi.globalbrowser",
            "vivo.browser",
            "via.browser",
        )

        private val SOCIAL_HINTS = listOf(
            "whatsapp",
            "instagram",
            "telegram",
            "facebook.katana",
            "facebook.orca",
            "twitter.android",
            "discord",
            "jp.naver.line",
            "threads",
        )

        internal fun classifyAppFlow(
            category: Int,
            isLegacyGameFlag: Boolean,
            packages: Array<String>?,
        ): FlowClassification {
            // Layer 1: Official Android OS ApplicationInfo category
            if (category == ApplicationInfo.CATEGORY_GAME || isLegacyGameFlag) {
                return FlowClassification(RelayProtocol.TIER_GAME, TrafficProfile.GAME)
            }
            if (category == ApplicationInfo.CATEGORY_VIDEO ||
                category == ApplicationInfo.CATEGORY_AUDIO
            ) {
                return FlowClassification(RelayProtocol.TIER_STREAMING, TrafficProfile.STREAMING)
            }
            // Check curated package hints before generic CATEGORY_SOCIAL (some streaming/game apps omit category)
            val hintMatch = classifyPackagesToFlow(packages)
            if (hintMatch != FlowClassification.UNKNOWN) {
                return hintMatch
            }
            if (category == ApplicationInfo.CATEGORY_SOCIAL) {
                return FlowClassification(-1, TrafficProfile.SOCIAL)
            }
            return FlowClassification.UNKNOWN
        }

        internal fun classifyPackagesToFlow(packages: Array<String>?): FlowClassification {
            if (packages == null || packages.isEmpty()) return FlowClassification.UNKNOWN
            for (raw in packages) {
                val pkg = raw.lowercase()
                if (GAME_HINTS.any { pkg.contains(it) }) {
                    return FlowClassification(RelayProtocol.TIER_GAME, TrafficProfile.GAME)
                }
                if (STREAMING_HINTS.any { pkg.contains(it) }) {
                    return FlowClassification(RelayProtocol.TIER_STREAMING, TrafficProfile.STREAMING)
                }
                if (BACKGROUND_HINTS.any { pkg.contains(it) }) {
                    return FlowClassification(RelayProtocol.TIER_BACKGROUND, TrafficProfile.DOWNLOAD)
                }
                if (BROWSER_HINTS.any { pkg.contains(it) }) {
                    return FlowClassification(-1, TrafficProfile.BROWSER)
                }
                if (SOCIAL_HINTS.any { pkg.contains(it) }) {
                    return FlowClassification(-1, TrafficProfile.SOCIAL)
                }
            }
            return FlowClassification.UNKNOWN
        }

        internal fun classifyAppMetadata(
            category: Int,
            isLegacyGameFlag: Boolean,
            packages: Array<String>?,
        ): Int = classifyAppFlow(category, isLegacyGameFlag, packages).qosTier

        internal fun classifyPackages(packages: Array<String>?): Int =
            classifyPackagesToFlow(packages).qosTier
    }
}
