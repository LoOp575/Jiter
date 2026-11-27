package com.jiter.app.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.os.PowerManager
import android.os.SystemClock
import java.net.InetSocketAddress
import java.net.Socket

data class ProbeSample(
    val timestampMs: Long,
    val rttMs: Double?,
    val lossPct: Double,
    val estimatedThroughputMbps: Double?,
    val networkType: String,
)

/**
 * Lightweight network sensor:
 *  - Tracks active transport (Wi-Fi / Mobile / Offline) via ConnectivityManager
 *  - Measures bounded TCP handshake RTT (using optional VpnService.protect hook)
 *  - Tracks rolling probe loss window without treating timeouts as 0 ms
 *  - Estimates passive throughput via TrafficStats deltas (zero active speedtest waste)
 *  - Exposes screen-interactive state for cellular radio battery backoff
 */
class NetworkMonitor(
    private val context: Context,
    initialProbeHost: String = DEFAULT_PROBE_HOST,
    initialProbePort: Int = DEFAULT_PROBE_PORT,
    private val probeTimeoutMs: Int = DEFAULT_PROBE_TIMEOUT_MS,
) {
    @Volatile
    private var probeHost: String = initialProbeHost

    @Volatile
    private var probePort: Int = initialProbePort

    fun updateProbeEndpoint(host: String, port: Int) {
        val cleanHost = host.trim().ifEmpty { DEFAULT_PROBE_HOST }
        val cleanPort = port.coerceIn(1, 65535)
        if (cleanHost != probeHost || cleanPort != probePort) {
            probeHost = cleanHost
            probePort = cleanPort
            synchronized(recentProbes) {
                recentProbes.clear()
            }
        }
    }
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val powerManager =
        context.getSystemService(Context.POWER_SERVICE) as PowerManager

    @Volatile
    private var currentNetworkType: String = queryActiveNetworkType()

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val recentProbes = ArrayDeque<Boolean>(LOSS_WINDOW_SIZE)

    private var lastTrafficBytes: Long = -1L
    private var lastTrafficElapsedMs: Long = -1L

    fun startObservingNetwork(onNetworkChanged: (newType: String) -> Unit) {
        stopObservingNetwork()
        currentNetworkType = queryActiveNetworkType()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val next = transportName(caps)
                if (next != currentNetworkType) {
                    currentNetworkType = next
                    onNetworkChanged(next)
                }
            }

            override fun onLost(network: Network) {
                val next = queryActiveNetworkType()
                if (next != currentNetworkType) {
                    currentNetworkType = next
                    onNetworkChanged(next)
                }
            }
        }
        networkCallback = cb
        try {
            connectivityManager.registerDefaultNetworkCallback(cb)
        } catch (_: Exception) {
            // Best-effort; falls back to direct capability query during probe
        }
    }

    fun stopObservingNetwork() {
        networkCallback?.let { cb ->
            try {
                connectivityManager.unregisterNetworkCallback(cb)
            } catch (_: Exception) {
                // Ignore if already unregistered
            }
        }
        networkCallback = null
        synchronized(recentProbes) {
            recentProbes.clear()
        }
        lastTrafficBytes = -1L
        lastTrafficElapsedMs = -1L
    }

    fun isScreenInteractive(): Boolean = powerManager.isInteractive

    fun getNetworkType(): String {
        val active = queryActiveNetworkType()
        currentNetworkType = active
        return active
    }

    /**
     * Runs a single bounded probe on a background dispatcher.
     * `socketProtector` should invoke `VpnService.protect(socket)` when measuring
     * baseline connectivity outside the TUN interface.
     */
    fun runProbe(socketProtector: ((Socket) -> Boolean)? = null): ProbeSample {
        val nowMs = SystemClock.elapsedRealtime()
        val netType = getNetworkType()
        val passiveMbps = samplePassiveThroughputMbps(nowMs)

        if (netType == "Offline") {
            val loss = recordProbeOutcome(success = false)
            return ProbeSample(
                timestampMs = nowMs,
                rttMs = null,
                lossPct = loss,
                estimatedThroughputMbps = null,
                networkType = netType,
            )
        }

        val rttMs = measureTcpConnectRttMs(socketProtector)
        val loss = recordProbeOutcome(success = rttMs != null)
        return ProbeSample(
            timestampMs = nowMs,
            rttMs = rttMs,
            lossPct = loss,
            estimatedThroughputMbps = passiveMbps,
            networkType = netType,
        )
    }

    private fun measureTcpConnectRttMs(socketProtector: ((Socket) -> Boolean)?): Double? {
        val socket = Socket()
        return try {
            socket.tcpNoDelay = true
            socketProtector?.invoke(socket)
            val startNs = System.nanoTime()
            socket.connect(InetSocketAddress(probeHost, probePort), probeTimeoutMs)
            val elapsedNs = System.nanoTime() - startNs
            val rttMs = elapsedNs / 1_000_000.0
            if (rttMs.isFinite() && rttMs > 0.0) rttMs else null
        } catch (_: Exception) {
            null
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
                // Ignore close error
            }
        }
    }

    private fun recordProbeOutcome(success: Boolean): Double = synchronized(recentProbes) {
        if (recentProbes.size >= LOSS_WINDOW_SIZE) {
            recentProbes.removeFirst()
        }
        recentProbes.addLast(success)
        if (recentProbes.isEmpty()) return 0.0
        val failed = recentProbes.count { !it }
        (failed * 100.0) / recentProbes.size
    }

    private fun samplePassiveThroughputMbps(nowElapsedMs: Long): Double? {
        val rx = TrafficStats.getTotalRxBytes()
        val tx = TrafficStats.getTotalTxBytes()
        if (rx == TrafficStats.UNSUPPORTED.toLong() || tx == TrafficStats.UNSUPPORTED.toLong()) {
            return null
        }
        val total = rx + tx
        val prevBytes = lastTrafficBytes
        val prevMs = lastTrafficElapsedMs
        lastTrafficBytes = total
        lastTrafficElapsedMs = nowElapsedMs

        if (prevBytes < 0L || prevMs < 0L || nowElapsedMs <= prevMs || total < prevBytes) {
            return null
        }
        val deltaBytes = total - prevBytes
        val deltaSec = (nowElapsedMs - prevMs) / 1000.0
        val mbps = (deltaBytes * 8.0) / deltaSec / 1_000_000.0
        // Ignore near-zero idle readings so bandwidth scorer does not mistake idle for congestion
        return if (mbps >= 0.05) mbps else null
    }

    private fun queryActiveNetworkType(): String {
        val active = connectivityManager.activeNetwork ?: return "Offline"
        val caps = connectivityManager.getNetworkCapabilities(active) ?: return "Offline"
        return transportName(caps)
    }

    private fun transportName(caps: NetworkCapabilities): String = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
        else -> "Other"
    }

    companion object {
        const val DEFAULT_PROBE_HOST = "1.1.1.1"
        const val DEFAULT_PROBE_PORT = 443
        const val DEFAULT_PROBE_TIMEOUT_MS = 1_500
        const val LOSS_WINDOW_SIZE = 20
    }
}
