package com.jiter.app.relay

import com.jiter.app.config.BackendConfig
import com.jiter.app.config.FailurePolicy
import com.jiter.app.config.FecPolicy
import com.jiter.app.config.RoutingMode
import com.jiter.app.config.TunnelScope
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

data class BootstrapRelayNode(
    val id: String,
    val region: String,
    val host: String,
    val port: Int,
    val psk: String,
    val priority: Int,
)

data class BootstrapPolicy(
    val tunnelScope: TunnelScope,
    val routingMode: RoutingMode,
    val failurePolicy: FailurePolicy,
    val fecPolicy: FecPolicy,
    val probeHost: String,
    val probePort: Int,
)

data class BootstrapResult(
    val nodes: List<BootstrapRelayNode>,
    val policy: BootstrapPolicy,
    val ttlSeconds: Int,
    val source: String,
)

/**
 * Stage 5 Zero-Config Developer Control Plane Client.
 *
 * Calls `POST <controlPlaneUrl>/api/v1/session/bootstrap` using built-in `HttpURLConnection`
 * + `org.json` (zero extra APK dependencies) so regular users never have to enter VPS IPs,
 * ports, or PSK credentials manually.
 */
object ControlPlaneClient {

    private const val CONNECT_TIMEOUT_MS = 2_500
    private const val READ_TIMEOUT_MS = 3_000

    fun bootstrap(
        baseUrl: String,
        appKey: String = "",
        preferredRegion: String = "",
        networkType: String = "Unknown",
        appVersion: String = "0.6.0",
    ): BootstrapResult? {
        val cleanBase = baseUrl.trim().trimEnd('/')
        if (cleanBase.isEmpty()) return null
        val endpoint = if (cleanBase.endsWith("/api/v1/session/bootstrap")) {
            cleanBase
        } else {
            "$cleanBase/api/v1/session/bootstrap"
        }

        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setRequestProperty("Accept", "application/json")
                if (appKey.isNotBlank()) {
                    setRequestProperty("X-Jiter-App-Key", appKey.trim())
                }
            }

            val reqJson = JSONObject().apply {
                put("appVersion", appVersion)
                put("preferredRegion", preferredRegion)
                put("networkType", networkType)
            }.toString()

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(reqJson)
                writer.flush()
            }

            if (conn.responseCode !in 200..299) {
                return null
            }

            val body = BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8)).use {
                it.readText()
            }
            parseBootstrapJson(body)
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    internal fun parseBootstrapJson(rawJson: String): BootstrapResult? {
        return try {
            val root = JSONObject(rawJson)
            if (!root.optBoolean("ok", false)) return null

            val policyObj = root.optJSONObject("policy") ?: JSONObject()
            val policy = BootstrapPolicy(
                tunnelScope = parseEnum(
                    policyObj.optString("tunnelScope", ""),
                    TunnelScope.FULL_INTERNET_TUNNEL,
                ),
                routingMode = parseEnum(
                    policyObj.optString("routingMode", ""),
                    RoutingMode.HYBRID_ADAPTIVE,
                ),
                failurePolicy = parseEnum(
                    policyObj.optString("failurePolicy", ""),
                    FailurePolicy.FAIL_OPEN,
                ),
                fecPolicy = parseEnum(
                    policyObj.optString("fecPolicy", ""),
                    FecPolicy.AUTO_ADAPTIVE,
                ),
                probeHost = policyObj.optString("probeHost", BackendConfig.DEFAULT_PROBE_HOST)
                    .trim()
                    .ifEmpty { BackendConfig.DEFAULT_PROBE_HOST },
                probePort = policyObj.optInt("probePort", BackendConfig.DEFAULT_PROBE_PORT)
                    .coerceIn(1, 65535),
            )

            val nodesArr = root.optJSONArray("nodes")
            val nodes = ArrayList<BootstrapRelayNode>()
            if (nodesArr != null) {
                for (i in 0 until nodesArr.length()) {
                    val obj = nodesArr.optJSONObject(i) ?: continue
                    val host = obj.optString("host", "").trim()
                    val port = obj.optInt("port", BackendConfig.DEFAULT_RELAY_PORT)
                    if (host.isEmpty() || port !in 1..65535) continue
                    nodes.add(
                        BootstrapRelayNode(
                            id = obj.optString("id", "edge-$i").trim().ifEmpty { "edge-$i" },
                            region = obj.optString("region", "EDGE").trim().ifEmpty { "EDGE" },
                            host = host,
                            port = port,
                            psk = obj.optString("psk", "").trim(),
                            priority = obj.optInt("priority", i + 1),
                        ),
                    )
                }
            }

            BootstrapResult(
                nodes = nodes,
                policy = policy,
                ttlSeconds = root.optInt("ttlSeconds", 300).coerceIn(30, 3600),
                source = root.optString("source", "remote"),
            )
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Picks the lowest-latency reachable node from a multi-node list (e.g. JKT-1 vs SG-1).
     * If only one node is returned, returns it immediately without probe overhead.
     */
    fun selectBestNode(
        nodes: List<BootstrapRelayNode>,
        probeTimeoutMs: Int = 350,
        socketProtector: ((Socket) -> Boolean)? = null,
    ): BootstrapRelayNode? {
        if (nodes.isEmpty()) return null
        if (nodes.size == 1) return nodes.first()

        var bestNode: BootstrapRelayNode? = null
        var bestRttNs = Long.MAX_VALUE

        for (node in nodes.take(4)) {
            val rttNs = measureTcpReachabilityNs(node.host, 443, probeTimeoutMs, socketProtector)
            if (rttNs != null && rttNs < bestRttNs) {
                bestRttNs = rttNs
                bestNode = node
            }
        }
        return bestNode ?: nodes.first()
    }

    private fun measureTcpReachabilityNs(
        host: String,
        port: Int,
        timeoutMs: Int,
        socketProtector: ((Socket) -> Boolean)?,
    ): Long? {
        val sock = Socket()
        return try {
            socketProtector?.invoke(sock)
            val t0 = System.nanoTime()
            sock.connect(InetSocketAddress(host, port), timeoutMs)
            System.nanoTime() - t0
        } catch (_: Exception) {
            null
        } finally {
            try {
                sock.close()
            } catch (_: Exception) {
                // Ignore close error
            }
        }
    }

    /**
     * Merges a bootstrapped node & developer policy into a RAM-only effective `BackendConfig`
     * for the active session without modifying stored user/developer overrides.
     */
    fun applyToConfig(
        base: BackendConfig,
        node: BootstrapRelayNode,
        policy: BootstrapPolicy,
    ): BackendConfig {
        val scope = if (node.psk.isNotBlank()) {
            policy.tunnelScope
        } else {
            TunnelScope.DIAGNOSTIC_SUBNET
        }
        return base.copy(
            relayHost = node.host,
            relayPort = node.port,
            relayPsk = node.psk,
            tunnelScope = scope,
            routingMode = policy.routingMode,
            failurePolicy = policy.failurePolicy,
            fecPolicy = policy.fecPolicy,
            probeHost = policy.probeHost,
            probePort = policy.probePort,
        ).sanitized()
    }

    private inline fun <reified T : Enum<T>> parseEnum(raw: String, fallback: T): T {
        if (raw.isBlank()) return fallback
        return enumValues<T>().firstOrNull { it.name == raw } ?: fallback
    }
}
