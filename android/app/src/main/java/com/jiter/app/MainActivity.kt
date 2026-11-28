package com.jiter.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.jiter.app.config.AppLanguage
import com.jiter.app.config.BackendConfig
import com.jiter.app.config.BackendConfigStore
import com.jiter.app.config.EngineRuntimePreference
import com.jiter.app.config.FailurePolicy
import com.jiter.app.config.FecPolicy
import com.jiter.app.config.LanguageManager
import com.jiter.app.config.RoutingMode
import com.jiter.app.config.TunnelScope
import com.jiter.app.context.AppContextDetector
import com.jiter.app.engine.QualityState
import com.jiter.app.engine.SessionSnapshot
import com.jiter.app.engine.SessionState
import com.jiter.app.engine.TrafficProfile
import com.jiter.app.state.SessionStore
import com.jiter.app.ui.LatencyRingView
import com.jiter.app.ui.LatencySparklineView
import com.jiter.app.vpn.JiterVpnService
import kotlinx.coroutines.launch
import java.util.Locale
import kotlin.math.roundToInt

/**
 * Stage 5 Ultra-Minimalist One-Tap GO Interface.
 *
 * Regular users see only the signature vertical line indicator `|`, one big GO/STOP button,
 * and plain-language status while JITER handles server selection, AEAD encryption, and
 * Game/Streaming packet detection automatically.
 *
 * Developers can tap the "JITER" title 5 times to open the Hidden Developer Console with
 * full C/C++/Rust/AEAD telemetry and swappable Backend/Relay/Control Plane controls.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var appContextDetector: AppContextDetector

    private lateinit var llBrandHeader: LinearLayout
    private lateinit var btnLanguageSwitch: MaterialButton
    private lateinit var flRingContainer: FrameLayout
    private lateinit var latencyRingView: LatencyRingView
    private lateinit var tvLatencyValue: TextView
    private lateinit var tvLatencyUnit: TextView
    private lateinit var tvLatencyLabel: TextView
    private lateinit var viewStatusDot: View
    private lateinit var tvMainStatus: TextView
    private lateinit var tvMainSubtitle: TextView
    private lateinit var tvSparklineTrend: TextView
    private lateinit var latencySparklineView: LatencySparklineView
    private lateinit var tvModeAuto: TextView
    private lateinit var tvModeGame: TextView
    private lateinit var tvModeStream: TextView
    private lateinit var tvModeDownload: TextView
    private lateinit var tvModeCaption: TextView
    private lateinit var btnPrimaryAction: MaterialButton

    // Hidden 5-tap Developer Console state
    private var devTapCount = 0
    private var lastDevTapMs = 0L
    private var devConsoleDialog: AlertDialog? = null
    private var devTelemetryView: TextView? = null
    private var devUsageStatusView: TextView? = null
    private var devUsageButton: MaterialButton? = null

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startJiterService()
        } else {
            SessionStore.update {
                it.copy(
                    sessionState = SessionState.STOPPED,
                    statusDetail = getString(R.string.status_vpn_declined),
                )
            }
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        requestVpnConsentAndStart()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        appContextDetector = AppContextDetector(this)
        BackendConfigStore.ensureLoaded(this)
        bindViews()
        setupListeners()

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    SessionStore.snapshot.collect { snapshot ->
                        renderMainScreen(snapshot)
                        updateDeveloperConsoleIfOpen(snapshot, BackendConfigStore.config.value)
                    }
                }
                launch {
                    BackendConfigStore.config.collect { cfg ->
                        updateDeveloperConsoleIfOpen(SessionStore.snapshot.value, cfg)
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshLanguageToggleLabel()
        refreshDevUsageViews()
    }

    override fun onDestroy() {
        devConsoleDialog?.dismiss()
        devConsoleDialog = null
        devTelemetryView = null
        devUsageStatusView = null
        devUsageButton = null
        super.onDestroy()
    }

    private fun bindViews() {
        llBrandHeader = findViewById(R.id.llBrandHeader)
        btnLanguageSwitch = findViewById(R.id.btnLanguageSwitch)
        flRingContainer = findViewById(R.id.flRingContainer)
        latencyRingView = findViewById(R.id.latencyRingView)
        tvLatencyValue = findViewById(R.id.tvLatencyValue)
        tvLatencyUnit = findViewById(R.id.tvLatencyUnit)
        tvLatencyLabel = findViewById(R.id.tvLatencyLabel)
        viewStatusDot = findViewById(R.id.viewStatusDot)
        tvMainStatus = findViewById(R.id.tvMainStatus)
        tvMainSubtitle = findViewById(R.id.tvMainSubtitle)
        tvSparklineTrend = findViewById(R.id.tvSparklineTrend)
        latencySparklineView = findViewById(R.id.latencySparklineView)
        tvModeAuto = findViewById(R.id.tvModeAuto)
        tvModeGame = findViewById(R.id.tvModeGame)
        tvModeStream = findViewById(R.id.tvModeStream)
        tvModeDownload = findViewById(R.id.tvModeDownload)
        tvModeCaption = findViewById(R.id.tvModeCaption)
        btnPrimaryAction = findViewById(R.id.btnPrimaryAction)
    }

    private fun setupListeners() {
        btnLanguageSwitch.setOnClickListener {
            val next = LanguageManager.toggleIndonesianEnglish()
            LanguageManager.apply(next)
            notifyServiceConfigChanged()
        }

        val toggleSession = View.OnClickListener {
            val state = SessionStore.snapshot.value.sessionState
            if (isSessionActive(state)) {
                stopJiterService()
            } else {
                beginStartFlow()
            }
        }
        btnPrimaryAction.setOnClickListener(toggleSession)
        flRingContainer.setOnClickListener(toggleSession)

        tvModeAuto.setOnClickListener { sendProfileOverride(null) }
        tvModeGame.setOnClickListener { sendProfileOverride(TrafficProfile.GAME) }
        tvModeStream.setOnClickListener { sendProfileOverride(TrafficProfile.STREAMING) }
        tvModeDownload.setOnClickListener { sendProfileOverride(TrafficProfile.DOWNLOAD) }

        // Hidden 5-tap unlock for Developer Console & Swappable Backend Controls
        llBrandHeader.setOnClickListener {
            val now = SystemClock.elapsedRealtime()
            if (now - lastDevTapMs > DEV_TAP_WINDOW_MS) {
                devTapCount = 0
            }
            lastDevTapMs = now
            devTapCount += 1

            val remaining = DEV_UNLOCK_TAPS - devTapCount
            when {
                remaining <= 0 -> {
                    devTapCount = 0
                    showDeveloperConsoleDialog()
                }
                remaining <= 2 -> {
                    Toast.makeText(
                        this,
                        getString(R.string.dev_unlock_remaining_fmt, remaining),
                        Toast.LENGTH_SHORT,
                    ).show()
                }
            }
        }
    }

    private fun refreshLanguageToggleLabel() {
        val next = LanguageManager.toggleIndonesianEnglish()
        btnLanguageSwitch.text = if (next == AppLanguage.INDONESIAN) {
            getString(R.string.lang_switch_id)
        } else {
            getString(R.string.lang_switch_en)
        }
    }

    private fun renderMainScreen(snapshot: SessionSnapshot) {
        val active = isSessionActive(snapshot.sessionState)
        val connecting = snapshot.sessionState == SessionState.STARTING ||
            snapshot.sessionState == SessionState.CONNECTING

        val cyan = ContextCompat.getColor(this, R.color.jiter_cyan)
        val green = ContextCompat.getColor(this, R.color.jiter_green)
        val yellow = ContextCompat.getColor(this, R.color.jiter_yellow)
        val red = ContextCompat.getColor(this, R.color.jiter_red)
        val muted = ContextCompat.getColor(this, R.color.jiter_unknown)

        // 1. Center Circular Latency Ring + Big Ping Readout
        val displayPingMs = snapshot.relayRttMs ?: snapshot.srttMs
        val ringAccent = when {
            !active -> cyan
            connecting -> cyan
            snapshot.sessionState == SessionState.DEGRADED ||
                snapshot.qualityState == QualityState.RED -> red
            snapshot.qualityState == QualityState.YELLOW -> yellow
            else -> cyan
        }
        val ringProgress = when {
            !active -> 0.24f
            connecting -> 0.35f
            snapshot.qualityScore != null ->
                (0.25 + (snapshot.qualityScore.coerceIn(0.0, 100.0) / 100.0) * 0.65).toFloat()
            else -> 0.72f
        }
        latencyRingView.setRingState(
            progressFraction = ringProgress,
            accentColor = ringAccent,
            connecting = connecting,
        )

        if (active && !connecting && displayPingMs != null) {
            tvLatencyValue.text = displayPingMs.roundToInt().toString()
            tvLatencyUnit.visibility = View.VISIBLE
            tvLatencyLabel.text = getString(R.string.ring_label_latency)
        } else if (connecting) {
            tvLatencyValue.text = "--"
            tvLatencyUnit.visibility = View.VISIBLE
            tvLatencyLabel.text = getString(R.string.ring_label_connecting)
        } else {
            tvLatencyValue.text = "--"
            tvLatencyUnit.visibility = View.VISIBLE
            tvLatencyLabel.text = getString(R.string.ring_label_tap_go)
        }

        // 2. Inline Status Dot + Status Word + Short Protection Subtitle
        val dotColor = when {
            !active -> muted
            connecting -> cyan
            snapshot.sessionState == SessionState.DEGRADED ||
                snapshot.qualityState == QualityState.RED -> red
            snapshot.qualityState == QualityState.YELLOW -> yellow
            else -> green
        }
        (viewStatusDot.background as? GradientDrawable)?.setColor(dotColor)
            ?: viewStatusDot.setBackgroundColor(dotColor)

        tvMainStatus.text = when {
            snapshot.sessionState == SessionState.STARTING ||
                snapshot.sessionState == SessionState.CONNECTING ->
                getString(R.string.main_status_connecting)
            snapshot.sessionState == SessionState.ERROR ->
                getString(R.string.main_status_error)
            !active ->
                getString(R.string.main_status_ready)
            snapshot.sessionState == SessionState.DEGRADED ||
                snapshot.qualityState == QualityState.RED ->
                getString(R.string.main_status_degraded)
            snapshot.qualityState == QualityState.YELLOW ->
                getString(R.string.main_status_moderate)
            else ->
                getString(R.string.main_status_stable)
        }

        tvMainSubtitle.text = when {
            !active -> {
                if (snapshot.statusDetail == getString(R.string.status_vpn_declined)) {
                    snapshot.statusDetail
                } else {
                    getString(R.string.main_subtitle_short_idle)
                }
            }
            connecting -> getString(R.string.main_subtitle_short_connecting)
            snapshot.networkType == "Offline" -> getString(R.string.main_subtitle_short_offline)
            snapshot.sessionState == SessionState.DEGRADED ||
                snapshot.qualityState == QualityState.RED ->
                getString(R.string.main_subtitle_short_degraded)
            snapshot.qualityState == QualityState.YELLOW ->
                getString(R.string.main_subtitle_short_moderate)
            snapshot.relayConnected && snapshot.relayEncrypted ->
                getString(R.string.main_subtitle_short_encrypted_fmt, snapshot.relayRegion ?: "EDGE")
            snapshot.localShaperActive ->
                getString(R.string.main_subtitle_short_shaper)
            else ->
                getString(R.string.main_subtitle_short_local)
        }

        // 3. Live 60-Second Latency Sparkline + Trend Label
        val sparkColor = when {
            !active -> muted
            snapshot.sessionState == SessionState.DEGRADED ||
                snapshot.qualityState == QualityState.RED -> red
            snapshot.qualityState == QualityState.YELLOW -> yellow
            else -> cyan
        }
        latencySparklineView.setSeries(
            values = if (active) snapshot.rttHistoryMs else emptyList(),
            accentColor = sparkColor,
        )
        tvSparklineTrend.text = computeSparklineTrendLabel(active, snapshot)

        // 4. 4-Segment Mode Pill Bar (Auto | Game | Stream | Download) + Dynamic Caption
        renderModePillBar(snapshot)

        // 5. Primary Action Button (GO Cyan Pill <-> Dark Crimson Outlined STOP Pill)
        if (active) {
            val stopBg = ContextCompat.getColor(this, R.color.jiter_stop_bg)
            val stopStroke = ContextCompat.getColor(this, R.color.jiter_stop_stroke)
            val stopText = ContextCompat.getColor(this, R.color.jiter_stop_text)
            btnPrimaryAction.text = getString(R.string.action_stop)
            btnPrimaryAction.setTextColor(stopText)
            btnPrimaryAction.backgroundTintList = ColorStateList.valueOf(stopBg)
            btnPrimaryAction.strokeColor = ColorStateList.valueOf(stopStroke)
            btnPrimaryAction.setIconResource(R.drawable.ic_action_stop)
            btnPrimaryAction.iconTint = ColorStateList.valueOf(stopText)
        } else {
            val goText = ContextCompat.getColor(this, R.color.jiter_cyan_dark)
            btnPrimaryAction.text = getString(R.string.action_go)
            btnPrimaryAction.setTextColor(goText)
            btnPrimaryAction.backgroundTintList = ColorStateList.valueOf(cyan)
            btnPrimaryAction.strokeColor = ColorStateList.valueOf(cyan)
            btnPrimaryAction.setIconResource(R.drawable.ic_action_play)
            btnPrimaryAction.iconTint = ColorStateList.valueOf(goText)
        }
    }

    private fun computeSparklineTrendLabel(active: Boolean, snapshot: SessionSnapshot): String {
        if (!active || snapshot.rttHistoryMs.isEmpty()) {
            return getString(R.string.sparkline_trend_idle)
        }
        val jit = snapshot.jitterMs ?: 0.0
        val bloat = snapshot.bufferbloatMs ?: 0.0
        return when {
            snapshot.qualityState == QualityState.RED || jit >= 25.0 || bloat >= 60.0 ->
                getString(R.string.sparkline_trend_spike)
            snapshot.qualityState == QualityState.YELLOW || jit >= 10.0 || bloat >= 25.0 ->
                getString(R.string.sparkline_trend_variable)
            else ->
                getString(R.string.sparkline_trend_steady)
        }
    }

    private fun renderModePillBar(snapshot: SessionSnapshot) {
        val selectedOverride = snapshot.manualProfileOverride
        val tabs = listOf(
            tvModeAuto to null,
            tvModeGame to TrafficProfile.GAME,
            tvModeStream to TrafficProfile.STREAMING,
            tvModeDownload to TrafficProfile.DOWNLOAD,
        )
        val darkText = ContextCompat.getColor(this, R.color.jiter_cyan_dark)
        val secondaryText = ContextCompat.getColor(this, R.color.jiter_text_secondary)

        for ((tab, profile) in tabs) {
            val isSelected = selectedOverride == profile
            if (isSelected) {
                tab.setBackgroundResource(R.drawable.bg_mode_tab_selected)
                tab.setTextColor(darkText)
                tab.setTypeface(null, Typeface.BOLD)
            } else {
                tab.background = null
                tab.setTextColor(secondaryText)
                tab.setTypeface(null, Typeface.NORMAL)
            }
        }

        val active = isSessionActive(snapshot.sessionState)
        tvModeCaption.text = when (selectedOverride) {
            TrafficProfile.GAME -> getString(R.string.mode_caption_game)
            TrafficProfile.STREAMING -> getString(R.string.mode_caption_stream)
            TrafficProfile.DOWNLOAD -> getString(R.string.mode_caption_download)
            else -> {
                if (active && snapshot.activeProfile != TrafficProfile.SAFE_BALANCED) {
                    val detectedName = if (snapshot.activeProfile == TrafficProfile.GAME &&
                        snapshot.concurrentStreamingDetected
                    ) {
                        "Game + Stream"
                    } else {
                        snapshot.activeProfile.displayName
                    }
                    getString(R.string.mode_caption_auto_detected_fmt, detectedName)
                } else {
                    getString(R.string.mode_caption_auto)
                }
            }
        }
    }

    private fun showDeveloperConsoleDialog() {
        devConsoleDialog?.dismiss()
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_developer_console, null)
        val tvTelemetry = view.findViewById<TextView>(R.id.tvDevTelemetry)
        val chipGroup = view.findViewById<ChipGroup>(R.id.devChipGroupProfile)
        val chipAuto = view.findViewById<Chip>(R.id.devChipAuto)
        val chipGame = view.findViewById<Chip>(R.id.devChipGame)
        val chipStreaming = view.findViewById<Chip>(R.id.devChipStreaming)
        val chipDownload = view.findViewById<Chip>(R.id.devChipDownload)
        val tvUsage = view.findViewById<TextView>(R.id.tvDevUsageStatus)
        val btnBackend = view.findViewById<MaterialButton>(R.id.btnDevBackendSettings)
        val btnUsage = view.findViewById<MaterialButton>(R.id.btnDevUsageSettings)

        devTelemetryView = tvTelemetry
        devUsageStatusView = tvUsage
        devUsageButton = btnUsage

        val snapshot = SessionStore.snapshot.value
        when (snapshot.manualProfileOverride) {
            TrafficProfile.GAME -> chipGame.isChecked = true
            TrafficProfile.STREAMING -> chipStreaming.isChecked = true
            TrafficProfile.DOWNLOAD -> chipDownload.isChecked = true
            else -> chipAuto.isChecked = true
        }

        chipGroup.setOnCheckedStateChangeListener { _, checkedIds ->
            val overrideProfile: TrafficProfile? = when (checkedIds.firstOrNull()) {
                R.id.devChipGame -> TrafficProfile.GAME
                R.id.devChipStreaming -> TrafficProfile.STREAMING
                R.id.devChipDownload -> TrafficProfile.DOWNLOAD
                else -> null
            }
            sendProfileOverride(overrideProfile)
        }

        btnBackend.setOnClickListener {
            showBackendConfigDialog()
        }

        btnUsage.setOnClickListener {
            val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
            try {
                startActivity(intent)
            } catch (_: Exception) {
                startActivity(Intent(Settings.ACTION_SETTINGS))
            }
        }

        refreshDevUsageViews()
        updateDeveloperConsoleIfOpen(snapshot, BackendConfigStore.config.value)

        devConsoleDialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.dev_console_title)
            .setView(view)
            .setPositiveButton(R.string.action_close, null)
            .setOnDismissListener {
                devTelemetryView = null
                devUsageStatusView = null
                devUsageButton = null
                devConsoleDialog = null
            }
            .show()
    }

    private fun refreshDevUsageViews() {
        val tvUsage = devUsageStatusView ?: return
        val btnUsage = devUsageButton ?: return
        if (appContextDetector.hasUsageAccess()) {
            tvUsage.text = getString(R.string.usage_access_granted)
            btnUsage.text = getString(R.string.usage_access_manage)
        } else {
            tvUsage.text = getString(R.string.usage_access_missing)
            btnUsage.text = getString(R.string.usage_access_grant)
        }
    }

    private fun updateDeveloperConsoleIfOpen(snapshot: SessionSnapshot, cfg: BackendConfig) {
        val tv = devTelemetryView ?: return
        val rtt = snapshot.srttMs?.let { String.format(Locale.US, "%.1f ms", it) } ?: "--"
        val relayRtt = snapshot.relayRttMs?.let { String.format(Locale.US, "%.1f ms", it) } ?: "--"
        val jitter = snapshot.jitterMs?.let { String.format(Locale.US, "%.1f ms", it) } ?: "--"
        val bloat = snapshot.bufferbloatMs?.let { String.format(Locale.US, "+%.1f ms", it) } ?: "--"
        val loss = snapshot.lossPct?.let { String.format(Locale.US, "%.1f%%", it) } ?: "--"
        val qScore = snapshot.qualityScore?.let { String.format(Locale.US, "%.1f", it) } ?: "--"
        val pacerPct = (snapshot.bgPacerRatio * 100.0).toInt()
        val reasons = if (snapshot.reasonCodes.isEmpty()) "-" else snapshot.reasonCodes.joinToString(", ")

        tv.text = buildString {
            appendLine("Version : ${BuildConfig.VERSION_NAME} (v${BuildConfig.VERSION_CODE})")
            appendLine("Engine  : ${snapshot.engineRuntimeLabel}")
            appendLine("State   : ${snapshot.sessionState.label} | Q=$qScore (${snapshot.qualityState.name})")
            appendLine("Profile : ${snapshot.activeProfile.displayName} [${snapshot.detectionSource}]${if (snapshot.concurrentStreamingDetected) " +Stream" else ""}")
            appendLine("Latency : SRTT=$rtt | Relay=$relayRtt | Jitter=$jitter")
            appendLine("Link    : Bloat=$bloat | Loss=$loss | Net=${snapshot.networkType}")
            appendLine("Actuator: FEC=${snapshot.fecMode.label} | BG Pacer=$pacerPct% | Route=${snapshot.selectedRoute.label}")
            appendLine("Tunnel  : AEAD=${snapshot.relayEncrypted} | FullTUN=${snapshot.fullInternetTunnelActive} | LocalShaper=${snapshot.localShaperActive}")
            appendLine("Local   : ActiveFlows=${snapshot.localActiveFlows} | PacedBG=${snapshot.localPacedBytes / 1024} KB | IP=${snapshot.assignedTunnelIp ?: "-"}")
            appendLine("Relay   : Connected=${snapshot.relayConnected} (${snapshot.relayRegion ?: "-"}) | CP=${snapshot.controlPlaneActive}")
            appendLine("Counters: TX=${snapshot.tunTxPackets} | RX=${snapshot.tunRxPackets} | FEC Recov=${snapshot.fecRecoveredPackets}")
            appendLine("Config  : ${cfg.summaryLabel()}")
            append("Reasons : $reasons")
        }
    }

    private fun showBackendConfigDialog() {
        val current = BackendConfigStore.ensureLoaded(this)
        val currentLang = LanguageManager.currentSelection()
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_backend_config, null)

        val etControlUrl = view.findViewById<EditText>(R.id.etControlPlaneUrl)
        val etControlAppKey = view.findViewById<EditText>(R.id.etControlPlaneAppKey)
        val etRelayHost = view.findViewById<EditText>(R.id.etRelayHost)
        val etRelayPort = view.findViewById<EditText>(R.id.etRelayPort)
        val etRelayPsk = view.findViewById<EditText>(R.id.etRelayPsk)
        val spTunnelScope = view.findViewById<Spinner>(R.id.spinnerTunnelScope)
        val etProbeHost = view.findViewById<EditText>(R.id.etProbeHost)
        val etProbePort = view.findViewById<EditText>(R.id.etProbePort)
        val spRouting = view.findViewById<Spinner>(R.id.spinnerRoutingMode)
        val spFailure = view.findViewById<Spinner>(R.id.spinnerFailurePolicy)
        val spFec = view.findViewById<Spinner>(R.id.spinnerFecPolicy)
        val spEngine = view.findViewById<Spinner>(R.id.spinnerEngineBackend)
        val spLanguage = view.findViewById<Spinner>(R.id.spinnerLanguage)

        etControlUrl.setText(current.controlPlaneUrl)
        etControlAppKey.setText(current.controlPlaneAppKey)
        etRelayHost.setText(current.relayHost)
        etRelayPort.setText(current.relayPort.toString())
        etRelayPsk.setText(current.relayPsk)
        etProbeHost.setText(current.probeHost)
        etProbePort.setText(current.probePort.toString())

        val scopeItems = TunnelScope.entries
        spTunnelScope.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            scopeItems.map { it.label },
        )
        spTunnelScope.setSelection(scopeItems.indexOf(current.tunnelScope).coerceAtLeast(0))

        val routingItems = RoutingMode.entries
        spRouting.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            routingItems.map { it.label },
        )
        spRouting.setSelection(routingItems.indexOf(current.routingMode).coerceAtLeast(0))

        val failureItems = FailurePolicy.entries
        spFailure.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            failureItems.map { it.label },
        )
        spFailure.setSelection(failureItems.indexOf(current.failurePolicy).coerceAtLeast(0))

        val fecItems = FecPolicy.entries
        spFec.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            fecItems.map { it.label },
        )
        spFec.setSelection(fecItems.indexOf(current.fecPolicy).coerceAtLeast(0))

        val engineItems = EngineRuntimePreference.entries
        spEngine.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            engineItems.map { it.label },
        )
        spEngine.setSelection(engineItems.indexOf(current.enginePreference).coerceAtLeast(0))

        val languageItems = AppLanguage.entries
        val languageLabels = languageItems.map { lang ->
            when (lang) {
                AppLanguage.SYSTEM -> getString(R.string.lang_label_system)
                AppLanguage.INDONESIAN -> getString(R.string.lang_label_id)
                AppLanguage.ENGLISH -> getString(R.string.lang_label_en)
            }
        }
        spLanguage.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            languageLabels,
        )
        spLanguage.setSelection(languageItems.indexOf(currentLang).coerceAtLeast(0))

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.dialog_backend_title)
            .setView(view)
            .setPositiveButton(R.string.action_save) { _, _ ->
                val updated = BackendConfig(
                    controlPlaneUrl = etControlUrl.text.toString(),
                    controlPlaneAppKey = etControlAppKey.text.toString(),
                    relayHost = etRelayHost.text.toString(),
                    relayPort = etRelayPort.text.toString().toIntOrNull()
                        ?: BackendConfig.DEFAULT_RELAY_PORT,
                    relayPsk = etRelayPsk.text.toString(),
                    tunnelScope = scopeItems[spTunnelScope.selectedItemPosition],
                    probeHost = etProbeHost.text.toString(),
                    probePort = etProbePort.text.toString().toIntOrNull()
                        ?: BackendConfig.DEFAULT_PROBE_PORT,
                    routingMode = routingItems[spRouting.selectedItemPosition],
                    failurePolicy = failureItems[spFailure.selectedItemPosition],
                    fecPolicy = fecItems[spFec.selectedItemPosition],
                    enginePreference = engineItems[spEngine.selectedItemPosition],
                )
                BackendConfigStore.save(this, updated)
                val chosenLang = languageItems[spLanguage.selectedItemPosition]
                if (chosenLang != currentLang) {
                    LanguageManager.apply(chosenLang)
                }
                notifyServiceConfigChanged()
            }
            .setNeutralButton(R.string.action_reset) { _, _ ->
                BackendConfigStore.resetDefaults(this)
                LanguageManager.apply(AppLanguage.SYSTEM)
                notifyServiceConfigChanged()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun notifyServiceConfigChanged() {
        val state = SessionStore.snapshot.value.sessionState
        if (isSessionActive(state)) {
            val intent = Intent(this, JiterVpnService::class.java).apply {
                action = JiterVpnService.ACTION_RELOAD_CONFIG
            }
            startService(intent)
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
                    detectionSource = if (profile != null) "Manual" else "Standby",
                )
            }
        }
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

    companion object {
        private const val DEV_UNLOCK_TAPS = 5
        private const val DEV_TAP_WINDOW_MS = 2_500L
    }
}
