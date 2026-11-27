package com.jiter.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.jiter.app.context.AppContextDetector
import com.jiter.app.engine.QualityState
import com.jiter.app.engine.SessionSnapshot
import com.jiter.app.engine.SessionState
import com.jiter.app.engine.TrafficProfile
import com.jiter.app.state.SessionStore
import com.jiter.app.vpn.JiterVpnService
import kotlinx.coroutines.launch
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var appContextDetector: AppContextDetector

    private lateinit var statusLineIndicator: View
    private lateinit var tvSessionState: TextView
    private lateinit var tvQualityScore: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var btnGoStop: MaterialButton

    private lateinit var tvMetricRtt: TextView
    private lateinit var tvMetricJitter: TextView
    private lateinit var tvMetricBloat: TextView
    private lateinit var tvMetricLoss: TextView
    private lateinit var tvMetricProfile: TextView
    private lateinit var tvMetricFec: TextView
    private lateinit var tvMetricPacer: TextView
    private lateinit var tvMetricNetwork: TextView
    private lateinit var tvReasons: TextView

    private lateinit var chipGroupProfile: ChipGroup
    private lateinit var chipAuto: Chip
    private lateinit var chipGame: Chip
    private lateinit var chipStreaming: Chip
    private lateinit var chipDownload: Chip

    private lateinit var tvUsageStatus: TextView
    private lateinit var btnUsageSettings: MaterialButton

    private var updatingChipsProgrammatically = false

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startJiterService()
        } else {
            SessionStore.update {
                it.copy(
                    sessionState = SessionState.STOPPED,
                    statusDetail = "VPN consent declined — session not started",
                )
            }
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        // Proceed with VPN consent regardless of notification permission result
        requestVpnConsentAndStart()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        appContextDetector = AppContextDetector(this)
        bindViews()
        setupListeners()

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                SessionStore.snapshot.collect { snapshot ->
                    renderSnapshot(snapshot)
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshUsageAccessStatus()
    }

    private fun bindViews() {
        statusLineIndicator = findViewById(R.id.statusLineIndicator)
        tvSessionState = findViewById(R.id.tvSessionState)
        tvQualityScore = findViewById(R.id.tvQualityScore)
        tvStatusDetail = findViewById(R.id.tvStatusDetail)
        btnGoStop = findViewById(R.id.btnGoStop)

        tvMetricRtt = findViewById(R.id.tvMetricRtt)
        tvMetricJitter = findViewById(R.id.tvMetricJitter)
        tvMetricBloat = findViewById(R.id.tvMetricBloat)
        tvMetricLoss = findViewById(R.id.tvMetricLoss)
        tvMetricProfile = findViewById(R.id.tvMetricProfile)
        tvMetricFec = findViewById(R.id.tvMetricFec)
        tvMetricPacer = findViewById(R.id.tvMetricPacer)
        tvMetricNetwork = findViewById(R.id.tvMetricNetwork)
        tvReasons = findViewById(R.id.tvReasons)

        chipGroupProfile = findViewById(R.id.chipGroupProfile)
        chipAuto = findViewById(R.id.chipAuto)
        chipGame = findViewById(R.id.chipGame)
        chipStreaming = findViewById(R.id.chipStreaming)
        chipDownload = findViewById(R.id.chipDownload)

        tvUsageStatus = findViewById(R.id.tvUsageStatus)
        btnUsageSettings = findViewById(R.id.btnUsageSettings)
    }

    private fun setupListeners() {
        btnGoStop.setOnClickListener {
            val state = SessionStore.snapshot.value.sessionState
            if (isSessionActive(state)) {
                stopJiterService()
            } else {
                beginStartFlow()
            }
        }

        chipGroupProfile.setOnCheckedStateChangeListener { _, checkedIds ->
            if (updatingChipsProgrammatically) return@setOnCheckedStateChangeListener
            val overrideProfile: TrafficProfile? = when (checkedIds.firstOrNull()) {
                R.id.chipGame -> TrafficProfile.GAME
                R.id.chipStreaming -> TrafficProfile.STREAMING
                R.id.chipDownload -> TrafficProfile.DOWNLOAD
                else -> null
            }
            sendProfileOverride(overrideProfile)
        }

        btnUsageSettings.setOnClickListener {
            val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
            try {
                startActivity(intent)
            } catch (_: Exception) {
                startActivity(Intent(Settings.ACTION_SETTINGS))
            }
        }
    }

    private fun beginStartFlow() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        requestVpnConsentAndStart()
    }

    private fun requestVpnConsentAndStart() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnConsentLauncher.launch(prepareIntent)
        } else {
            startJiterService()
        }
    }

    private fun startJiterService() {
        val preselected = SessionStore.snapshot.value.manualProfileOverride
        val intent = Intent(this, JiterVpnService::class.java).apply {
            action = JiterVpnService.ACTION_START
            if (preselected != null) {
                putExtra(JiterVpnService.EXTRA_PROFILE_NAME, preselected.name)
            }
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopJiterService() {
        val intent = Intent(this, JiterVpnService::class.java).apply {
            action = JiterVpnService.ACTION_STOP
        }
        startService(intent)
    }

    private fun sendProfileOverride(profile: TrafficProfile?) {
        val state = SessionStore.snapshot.value.sessionState
        if (isSessionActive(state)) {
            val intent = Intent(this, JiterVpnService::class.java).apply {
                action = JiterVpnService.ACTION_SET_PROFILE_OVERRIDE
                if (profile != null) {
                    putExtra(JiterVpnService.EXTRA_PROFILE_NAME, profile.name)
                }
            }
            startService(intent)
        } else {
            SessionStore.update {
                it.copy(
                    manualProfileOverride = profile,
                    activeProfile = profile ?: TrafficProfile.SAFE_BALANCED,
                )
            }
        }
    }

    private fun refreshUsageAccessStatus() {
        val granted = appContextDetector.hasUsageAccess()
        if (granted) {
            tvUsageStatus.text = getString(R.string.usage_access_granted)
            btnUsageSettings.text = getString(R.string.usage_access_manage)
        } else {
            tvUsageStatus.text = getString(R.string.usage_access_missing)
            btnUsageSettings.text = getString(R.string.usage_access_grant)
        }
    }

    private fun renderSnapshot(snapshot: SessionSnapshot) {
        val active = isSessionActive(snapshot.sessionState)

        tvSessionState.text = snapshot.sessionState.label
        tvStatusDetail.text = snapshot.statusDetail
        tvQualityScore.text = snapshot.qualityScore?.let {
            String.format(Locale.US, "Q %.0f", it)
        } ?: "Q --"

        val indicatorColorRes = when (snapshot.qualityState) {
            QualityState.GREEN -> R.color.jiter_green
            QualityState.YELLOW -> R.color.jiter_yellow
            QualityState.RED -> R.color.jiter_red
            QualityState.UNKNOWN -> R.color.jiter_unknown
        }
        val indicatorColor = ContextCompat.getColor(this, indicatorColorRes)
        (statusLineIndicator.background as? GradientDrawable)?.setColor(indicatorColor)
            ?: statusLineIndicator.setBackgroundColor(indicatorColor)

        if (active) {
            btnGoStop.text = getString(R.string.action_stop)
            btnGoStop.backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this, R.color.jiter_red),
            )
        } else {
            btnGoStop.text = getString(R.string.action_go)
            btnGoStop.backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this, R.color.jiter_green),
            )
        }

        tvMetricRtt.text = snapshot.srttMs?.let {
            String.format(Locale.US, "%.1f ms", it)
        } ?: "--"
        tvMetricJitter.text = snapshot.jitterMs?.let {
            String.format(Locale.US, "%.1f ms", it)
        } ?: "--"
        tvMetricBloat.text = snapshot.bufferbloatMs?.let {
            String.format(Locale.US, "+%.1f ms", it)
        } ?: "--"
        tvMetricLoss.text = snapshot.lossPct?.let {
            String.format(Locale.US, "%.1f%%", it)
        } ?: "--"

        tvMetricProfile.text = snapshot.activeProfile.displayName
        tvMetricFec.text = snapshot.fecMode.label
        tvMetricPacer.text = String.format(Locale.US, "%d%%", (snapshot.bgPacerRatio * 100.0).toInt())
        tvMetricNetwork.text = snapshot.networkType

        tvReasons.text = if (snapshot.reasonCodes.isEmpty()) {
            getString(R.string.reasons_idle)
        } else {
            snapshot.reasonCodes.joinToString(" · ")
        }

        updatingChipsProgrammatically = true
        when (snapshot.manualProfileOverride) {
            TrafficProfile.GAME -> chipGame.isChecked = true
            TrafficProfile.STREAMING -> chipStreaming.isChecked = true
            TrafficProfile.DOWNLOAD -> chipDownload.isChecked = true
            else -> chipAuto.isChecked = true
        }
        updatingChipsProgrammatically = false
    }

    private fun isSessionActive(state: SessionState): Boolean = when (state) {
        SessionState.STARTING,
        SessionState.CONNECTING,
        SessionState.ACTIVE,
        SessionState.DEGRADED,
        SessionState.RECOVERING,
        -> true
        SessionState.STOPPED,
        SessionState.STOPPING,
        SessionState.ERROR,
        -> false
    }
}
