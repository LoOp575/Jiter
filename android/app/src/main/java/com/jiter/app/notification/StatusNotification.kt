package com.jiter.app.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.jiter.app.MainActivity
import com.jiter.app.R
import com.jiter.app.engine.QualityState
import com.jiter.app.engine.SessionSnapshot
import com.jiter.app.vpn.JiterVpnService
import java.util.Locale

/**
 * Persistent foreground notification & monochrome status-bar indicator.
 *
 * Android enforces monochrome tinting on status-bar smallIcon across Android 5–16,
 * so status-bar state is conveyed via distinct vertical-line vector shapes while
 * Green/Yellow/Red colors and detailed metrics appear in the expanded notification.
 */
class StatusNotification(private val context: Context) {

    private val notificationManager =
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private var lastPostedElapsedMs: Long = 0L

    fun ensureChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.notification_channel_desc)
            setShowBadge(false)
        }
        notificationManager.createNotificationChannel(channel)
    }

    fun build(snapshot: SessionSnapshot): Notification {
        val openAppIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openAppPending = PendingIntent.getActivity(
            context,
            REQ_OPEN_APP,
            openAppIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val stopIntent = Intent(context, JiterVpnService::class.java).apply {
            action = JiterVpnService.ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            context,
            REQ_STOP_SESSION,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val smallIconRes = when (snapshot.qualityState) {
            QualityState.GREEN -> R.drawable.ic_stat_jiter_good
            QualityState.YELLOW -> R.drawable.ic_stat_jiter_moderate
            QualityState.RED -> R.drawable.ic_stat_jiter_degraded
            QualityState.UNKNOWN -> R.drawable.ic_stat_jiter_unknown
        }

        val accentColorRes = when (snapshot.qualityState) {
            QualityState.GREEN -> R.color.jiter_green
            QualityState.YELLOW -> R.color.jiter_yellow
            QualityState.RED -> R.color.jiter_red
            QualityState.UNKNOWN -> R.color.jiter_unknown
        }

        val scoreText = snapshot.qualityScore?.let { String.format(Locale.US, "Q:%.0f", it) } ?: "Q:--"
        val title = "JITER · ${snapshot.sessionState.label} | ${snapshot.activeProfile.displayName} ($scoreText)"

        val rttStr = snapshot.srttMs?.let { String.format(Locale.US, "%.1f ms", it) } ?: "--"
        val jitStr = snapshot.jitterMs?.let { String.format(Locale.US, "%.1f ms", it) } ?: "--"
        val lossStr = snapshot.lossPct?.let { String.format(Locale.US, "%.1f%%", it) } ?: "--"
        val bloatStr = snapshot.bufferbloatMs?.let { String.format(Locale.US, "+%.1f ms", it) } ?: "--"
        val pacerPct = (snapshot.bgPacerRatio * 100.0).toInt()

        val summary = "Probe RTT: $rttStr · Jitter: $jitStr · Loss: $lossStr"
        val expanded = buildString {
            appendLine(summary)
            appendLine("Bufferbloat: $bloatStr · FEC: ${snapshot.fecMode.label} · BG Pacer: $pacerPct%")
            append("Net: ${snapshot.networkType} · Route: ${snapshot.selectedRoute.label}")
        }

        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(smallIconRes)
            .setColor(ContextCompat.getColor(context, accentColorRes))
            .setContentTitle(title)
            .setContentText(summary)
            .setStyle(NotificationCompat.BigTextStyle().bigText(expanded))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openAppPending)
            .addAction(0, context.getString(R.string.action_stop), stopPending)
            .build()
    }

    fun updateIfAllowed(snapshot: SessionSnapshot, force: Boolean = false) {
        val now = SystemClock.elapsedRealtime()
        if (!force && (now - lastPostedElapsedMs) < MIN_UPDATE_INTERVAL_MS) {
            return
        }
        lastPostedElapsedMs = now
        notificationManager.notify(NOTIFICATION_ID, build(snapshot))
    }

    fun cancel() {
        lastPostedElapsedMs = 0L
        notificationManager.cancel(NOTIFICATION_ID)
    }

    companion object {
        const val CHANNEL_ID = "jiter_session_channel"
        const val NOTIFICATION_ID = 7701
        private const val REQ_OPEN_APP = 100
        private const val REQ_STOP_SESSION = 101
        private const val MIN_UPDATE_INTERVAL_MS = 1_000L
    }
}
