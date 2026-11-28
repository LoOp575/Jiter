package com.jiter.app.context

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
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
 *
 * Stage 6.2 fixes:
 *  - Skips JITER itself (`context.packageName`) and `com.android.systemui` *inside* the
 *    UsageEvents loop so switching to the JITER dashboard preserves the active app context.
 *  - Remembers `lastForegroundPackage` across quiet periods (e.g., watching a 15-minute
 *    YouTube video or playing a match without switching apps) and clears it cleanly when
 *    the user returns to the device Home launcher.
 */
class AppContextDetector(private val context: Context) {

    @Volatile
    private var lastForegroundPackage: String? = null

    private val defaultLauncherPackage: String? by lazy {
        try {
            val homeIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
            val resolved = context.packageManager.resolveActivity(
                homeIntent,
                PackageManager.MATCH_DEFAULT_ONLY,
            )
            resolved?.activityInfo?.packageName
        } catch (_: Exception) {
            null
        }
    }

    fun reset() {
        lastForegroundPackage = null
    }

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

    fun detect(windowMs: Long = DEFAULT_QUERY_WINDOW_MS): DetectedContext {
        if (!hasUsageAccess()) {
            lastForegroundPackage = null
            return DetectedContext(
                foregroundPackage = null,
                profile = TrafficProfile.SAFE_BALANCED,
                hasUsagePermission = false,
            )
        }

        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return DetectedContext(null, TrafficProfile.SAFE_BALANCED, true)

        val endTime = System.currentTimeMillis()
        val effectiveWindowMs = if (lastForegroundPackage == null) {
            maxOf(windowMs, INITIAL_QUERY_WINDOW_MS)
        } else {
            windowMs
        }
        val startTime = endTime - effectiveWindowMs
        val events = usm.queryEvents(startTime, endTime)
        val event = UsageEvents.Event()
        val resumedPackages = ArrayList<String>(8)

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            if (event.eventType == UsageEvents.Event.ACTIVITY_RESUMED && !event.packageName.isNullOrBlank()) {
                resumedPackages.add(event.packageName)
            }
        }

        val resolvedPkg = resolveForegroundPackageFromEvents(
            resumedPackages = resumedPackages,
            previousForeground = lastForegroundPackage,
            selfPackage = context.packageName,
            launcherPackage = defaultLauncherPackage,
        )
        lastForegroundPackage = resolvedPkg

        val profile = if (resolvedPkg != null) {
            classifyPackage(resolvedPkg)
        } else {
            TrafficProfile.SAFE_BALANCED
        }

        return DetectedContext(
            foregroundPackage = resolvedPkg,
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

        // Best-effort Android app category lookup (enabled via <queries> on Android 11+)
        @Suppress("DEPRECATION")
        return try {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            if (info.category == ApplicationInfo.CATEGORY_GAME ||
                (info.flags and ApplicationInfo.FLAG_IS_GAME) != 0
            ) {
                TrafficProfile.GAME
            } else {
                when (info.category) {
                    ApplicationInfo.CATEGORY_VIDEO,
                    ApplicationInfo.CATEGORY_AUDIO,
                    -> TrafficProfile.STREAMING
                    ApplicationInfo.CATEGORY_SOCIAL -> TrafficProfile.SOCIAL
                    else -> TrafficProfile.SAFE_BALANCED
                }
            }
        } catch (_: Exception) {
            TrafficProfile.SAFE_BALANCED
        }
    }

    companion object {
        private const val DEFAULT_QUERY_WINDOW_MS = 60_000L
        private const val INITIAL_QUERY_WINDOW_MS = 300_000L

        private val IGNORED_SYSTEM_PACKAGES = setOf(
            "com.android.systemui",
            "com.android.permissioncontroller",
            "com.google.android.permissioncontroller",
            "com.google.android.inputmethod.latin",
        )

        private val LAUNCHER_HINTS = listOf(
            ".launcher",
            "nexuslauncher",
            "trebuchet",
            "miui.home",
            "sec.android.app.launcher",
            "bbk.launcher",
            "coloros.launcher",
            "oppo.launcher",
        )

        /**
         * Pure resolution logic: walks recent `ACTIVITY_RESUMED` events in order,
         * ignoring JITER's own dashboard and SystemUI overlays, clearing on Home launcher,
         * and remembering `previousForeground` when the user stays inside an app quietly.
         */
        internal fun resolveForegroundPackageFromEvents(
            resumedPackages: List<String>,
            previousForeground: String?,
            selfPackage: String,
            launcherPackage: String?,
        ): String? {
            var current = previousForeground
            for (pkg in resumedPackages) {
                if (pkg == selfPackage || pkg in IGNORED_SYSTEM_PACKAGES) {
                    continue
                }
                val lower = pkg.lowercase()
                val isLauncher = (launcherPackage != null && pkg == launcherPackage) ||
                    LAUNCHER_HINTS.any { lower.contains(it) }
                current = if (isLauncher) null else pkg
            }
            return current
        }

        private val KNOWN_GAMES = setOf(
            "com.mobile.legends",
            "com.tencent.ig",
            "com.pubg.imobile",
            "com.vng.pubgmobile",
            "com.dts.freefireth",
            "com.dts.freefiremax",
            "com.mihoyo.genshinimpact",
            "com.hoyoverse.hkrpgoversea",
            "com.levelinfinite.sgameglobal",
            "com.garena.game.codm",
            "com.garena.game.kgid",
            "com.activision.callofduty.shooter",
            "com.riotgames.league.wildrift",
            "com.supercell.brawlstars",
            "com.supercell.clashroyale",
            "com.supercell.clashofclans",
            "com.roblox.client",
            "com.ea.gp.fifamobile",
            "com.mojang.minecraftpe",
            "com.proximabeta.mf.uamo",
        )

        private val KNOWN_STREAMING = setOf(
            "com.google.android.youtube",
            "com.netflix.mediaclient",
            "com.zhiliaoapp.musically",
            "com.ss.android.ugc.trill",
            "com.ss.android.ugc.aweme",
            "tv.twitch.android.app",
            "com.bstar.intl",
            "com.disney.disneyplus",
            "com.vidio.android",
            "com.viu.phone",
            "com.spotify.music",
            "com.amazon.avod.thirdpartyclient",
            "com.tencent.qqlivei18n",
        )

        private val KNOWN_DOWNLOADERS = setOf(
            "com.dv.adm",
            "com.dv.adm.pay",
            "idm.internet.download.manager",
            "idm.internet.download.manager.plus",
            "com.android.vending",
            "com.android.providers.downloads.ui",
            "org.fdroid.fdroid",
        )

        private val KNOWN_BROWSERS = setOf(
            "com.android.chrome",
            "com.chrome.beta",
            "com.chrome.dev",
            "org.mozilla.firefox",
            "com.brave.browser",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.sec.android.app.sbrowser",
            "com.UCMobile.intl",
            "com.kiwibrowser.browser",
            "com.duckduckgo.mobile.android",
            "com.yandex.browser",
            "com.heytap.browser",
            "com.coloros.browser",
            "com.mi.globalbrowser",
            "com.vivo.browser",
            "mark.via.gp",
        )

        private val KNOWN_SOCIAL = setOf(
            "com.whatsapp",
            "com.whatsapp.w4b",
            "com.instagram.android",
            "com.instagram.barcelona",
            "org.telegram.messenger",
            "org.telegram.messenger.web",
            "com.facebook.katana",
            "com.facebook.orca",
            "com.twitter.android",
            "com.discord",
            "jp.naver.line.android",
        )
    }
}
