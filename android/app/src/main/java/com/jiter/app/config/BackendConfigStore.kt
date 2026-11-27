package com.jiter.app.config

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Minimal persistence for non-personal technical backend/relay configuration.
 * Keeps JITER decoupled from any single relay/control-plane provider so operators
 * and users can swap endpoints at runtime.
 */
object BackendConfigStore {
    private const val PREFS_NAME = "jiter_backend_config"
    private const val KEY_CONTROL_URL = "control_plane_url"
    private const val KEY_RELAY_HOST = "relay_host"
    private const val KEY_RELAY_PORT = "relay_port"
    private const val KEY_RELAY_PSK = "relay_psk"
    private const val KEY_TUNNEL_SCOPE = "tunnel_scope"
    private const val KEY_PROBE_HOST = "probe_host"
    private const val KEY_PROBE_PORT = "probe_port"
    private const val KEY_ROUTING_MODE = "routing_mode"
    private const val KEY_FAILURE_POLICY = "failure_policy"
    private const val KEY_FEC_POLICY = "fec_policy"
    private const val KEY_ENGINE_PREF = "engine_preference"

    @Volatile
    private var loaded = false

    private val _config = MutableStateFlow(BackendConfig())
    val config: StateFlow<BackendConfig> = _config.asStateFlow()

    fun ensureLoaded(context: Context): BackendConfig {
        if (loaded) return _config.value
        synchronized(this) {
            if (!loaded) {
                _config.value = readFromPrefs(context.applicationContext)
                loaded = true
            }
        }
        return _config.value
    }

    fun save(context: Context, updated: BackendConfig): BackendConfig {
        val clean = updated.sanitized()
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(KEY_CONTROL_URL, clean.controlPlaneUrl)
            .putString(KEY_RELAY_HOST, clean.relayHost)
            .putInt(KEY_RELAY_PORT, clean.relayPort)
            .putString(KEY_RELAY_PSK, clean.relayPsk)
            .putString(KEY_TUNNEL_SCOPE, clean.tunnelScope.name)
            .putString(KEY_PROBE_HOST, clean.probeHost)
            .putInt(KEY_PROBE_PORT, clean.probePort)
            .putString(KEY_ROUTING_MODE, clean.routingMode.name)
            .putString(KEY_FAILURE_POLICY, clean.failurePolicy.name)
            .putString(KEY_FEC_POLICY, clean.fecPolicy.name)
            .putString(KEY_ENGINE_PREF, clean.enginePreference.name)
            .apply()
        _config.value = clean
        loaded = true
        return clean
    }

    fun resetDefaults(context: Context): BackendConfig = save(context, BackendConfig())

    private fun readFromPrefs(context: Context): BackendConfig {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return BackendConfig(
            controlPlaneUrl = prefs.getString(KEY_CONTROL_URL, BackendConfig.DEFAULT_CONTROL_PLANE_URL)
                ?: BackendConfig.DEFAULT_CONTROL_PLANE_URL,
            relayHost = prefs.getString(KEY_RELAY_HOST, BackendConfig.DEFAULT_RELAY_HOST)
                ?: BackendConfig.DEFAULT_RELAY_HOST,
            relayPort = prefs.getInt(KEY_RELAY_PORT, BackendConfig.DEFAULT_RELAY_PORT),
            relayPsk = prefs.getString(KEY_RELAY_PSK, BackendConfig.DEFAULT_RELAY_PSK)
                ?: BackendConfig.DEFAULT_RELAY_PSK,
            tunnelScope = parseEnum(
                prefs.getString(KEY_TUNNEL_SCOPE, null),
                TunnelScope.DIAGNOSTIC_SUBNET,
            ),
            probeHost = prefs.getString(KEY_PROBE_HOST, BackendConfig.DEFAULT_PROBE_HOST)
                ?: BackendConfig.DEFAULT_PROBE_HOST,
            probePort = prefs.getInt(KEY_PROBE_PORT, BackendConfig.DEFAULT_PROBE_PORT),
            routingMode = parseEnum(prefs.getString(KEY_ROUTING_MODE, null), RoutingMode.HYBRID_ADAPTIVE),
            failurePolicy = parseEnum(prefs.getString(KEY_FAILURE_POLICY, null), FailurePolicy.FAIL_OPEN),
            fecPolicy = parseEnum(prefs.getString(KEY_FEC_POLICY, null), FecPolicy.AUTO_ADAPTIVE),
            enginePreference = parseEnum(
                prefs.getString(KEY_ENGINE_PREF, null),
                EngineRuntimePreference.AUTO_NATIVE_FIRST,
            ),
        ).sanitized()
    }

    private inline fun <reified T : Enum<T>> parseEnum(raw: String?, fallback: T): T {
        if (raw.isNullOrBlank()) return fallback
        return enumValues<T>().firstOrNull { it.name == raw } ?: fallback
    }
}
