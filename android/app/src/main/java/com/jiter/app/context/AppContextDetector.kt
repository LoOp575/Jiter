package com.jiter.app.context

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Process
import com.jiter.app.engine.TrafficProfile

data class DetectedContext(
    val foregroundPackage: String?,
    val profile: TrafficProfile,
    val hasUsagePermission: Boolean,
)

/**
 * Foreground application detector using Android Usage Access (`UsageStatsManager`).
 * Deliberately avoids AccessibilityService. Falls back safely to `SAFE_BALANCED`
 * whenever permission is absent or package is unknown.
 */
class AppContextDetector(private val context: Context) {

    fun hasUsageAccess(): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            ?: return false
        val mode = appOps.unsafeCheckOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS,
            Process.myUid(),
            context.packageName,
        )
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun detect(windowMs: Long = 15_000L): DetectedContext {
        if (!hasUsageAccess()) {
            return DetectedContext(
                foregroundPackage = null,
                profile = TrafficProfile.SAFE_BALANCED,
                hasUsagePermission = false,
            )
        }

        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return DetectedContext(null, TrafficProfile.SAFE_BALANCED, true)

        val endTime = System.currentTimeMillis()
        val startTime = endTime - windowMs
        val events = usm.queryEvents(startTime, endTime)
        val event = UsageEvents.Event()
        var latestPkg: String? = null

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            if (event.eventType == UsageEvents.Event.ACTIVITY_RESUMED && !event.packageName.isNullOrBlank()) {
                latestPkg = event.packageName
            }
        }

        // Ignore our own app UI so switching to JITER dashboard does not overwrite last profile prematurely
        if (latestPkg == context.packageName) {
            latestPkg = null
        }

        val profile = if (latestPkg != null) {
            classifyPackage(latestPkg)
        } else {
            TrafficProfile.SAFE_BALANCED
        }

        return DetectedContext(
            foregroundPackage = latestPkg,
            profile = profile,
            hasUsagePermission = true,
        )
    }

    fun classifyPackage(packageName: String): TrafficProfile {
        val pkg = packageName.lowercase()

        if (KNOWN_GAMES.any { pkg == it || pkg.startsWith("$it.") }) {
            return TrafficProfile.GAME
        }
        if (KNOWN_STREAMING.any { pkg == it || pkg.startsWith("$it.") }) {
            return TrafficProfile.STREAMING
        }
        if (KNOWN_DOWNLOADERS.any { pkg == it || pkg.startsWith("$it.") }) {
            return TrafficProfile.DOWNLOAD
        }
        if (KNOWN_BROWSERS.any { pkg == it || pkg.startsWith("$it.") }) {
            return TrafficProfile.BROWSER
        }
        if (KNOWN_SOCIAL.any { pkg == it || pkg.startsWith("$it.") }) {
            return TrafficProfile.SOCIAL
        }

        // Best-effort Android app category lookup (gracefully ignored if package visibility restricts it)
        return try {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            when (info.category) {
                ApplicationInfo.CATEGORY_GAME -> TrafficProfile.GAME
                ApplicationInfo.CATEGORY_VIDEO,
                ApplicationInfo.CATEGORY_AUDIO,
                -> TrafficProfile.STREAMING
                ApplicationInfo.CATEGORY_SOCIAL -> TrafficProfile.SOCIAL
                else -> TrafficProfile.SAFE_BALANCED
            }
        } catch (_: Exception) {
            TrafficProfile.SAFE_BALANCED
        }
    }

    companion object {
        private val KNOWN_GAMES = setOf(
            "com.mobile.legends",
            "com.tencent.ig",
            "com.pubg.imobile",
            "com.dts.freefireth",
            "com.dts.freefiremax",
            "com.mihoyo.genshinimpact",
            "com.hoyoverse.hkrpgoversea",
            "com.levelinfinite.sgameglobal", // Honor of Kings
            "com.garena.game.codm",
            "com.activision.callofduty.shooter",
            "com.riotgames.league.wildrift",
            "com.supercell.brawlstars",
            "com.supercell.clashroyale",
            "com.roblox.client",
            "com.ea.gp.fifamobile",
        )

        private val KNOWN_STREAMING = setOf(
            "com.google.android.youtube",
            "com.netflix.mediaclient",
            "com.zhiliaoapp.musically",
            "com.ss.android.ugc.trill", // TikTok SEA
            "tv.twitch.android.app",
            "com.bstar.intl", // Bstation
            "com.disney.disneyplus",
            "com.vidio.android",
            "com.spotify.music",
        )

        private val KNOWN_DOWNLOADERS = setOf(
            "com.dv.adm",
            "idm.internet.download.manager",
            "idm.internet.download.manager.plus",
            "com.android.vending", // Play Store downloads/updates
            "org.fdroid.fdroid",
        )

        private val KNOWN_BROWSERS = setOf(
            "com.android.chrome",
            "org.mozilla.firefox",
            "com.brave.browser",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.sec.android.app.sbrowser",
        )

        private val KNOWN_SOCIAL = setOf(
            "com.whatsapp",
            "com.instagram.android",
            "org.telegram.messenger",
            "com.facebook.katana",
            "com.twitter.android",
            "com.discord",
        )
    }
}
