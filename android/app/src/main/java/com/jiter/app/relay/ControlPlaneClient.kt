package com.jiter.app.relay

import com.jiter.app.config.BackendConfig
import com.jiter.app.config.FailurePolicy
import com.jiter.app.config.FecPolicy
import com.jiter.app.config.RoutingMode
import com.jiter.app.config.TunnelScope
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
 * and a self-contained pure-Kotlin RFC 8259 JSON parser (zero external APK dependencies and
 * zero `android.jar` `org.json` stub conflicts during JVM unit tests).
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

            val reqJson = buildString {
                append('{')
                append("\"appVersion\":\"").append(escapeJson(appVersion)).append("\",")
                append("\"preferredRegion\":\"").append(escapeJson(preferredRegion)).append("\",")
                append("\"networkType\":\"").append(escapeJson(networkType)).append("\"")
                append('}')
            }

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
            val root = MiniJsonParser(rawJson).parseValue() as? Map<*, *> ?: return null
            if (root["ok"] != true) return null

            val policyMap = root["policy"] as? Map<*, *> ?: emptyMap<String, Any?>()
            val policy = BootstrapPolicy(
                tunnelScope = parseEnum(
                    asString(policyMap["tunnelScope"]),
                    TunnelScope.FULL_INTERNET_TUNNEL,
                ),
                routingMode = parseEnum(
                    asString(policyMap["routingMode"]),
                    RoutingMode.HYBRID_ADAPTIVE,
                ),
                failurePolicy = parseEnum(
                    asString(policyMap["failurePolicy"]),
                    FailurePolicy.FAIL_OPEN,
                ),
                fecPolicy = parseEnum(
                    asString(policyMap["fecPolicy"]),
                    FecPolicy.AUTO_ADAPTIVE,
                ),
                probeHost = asString(policyMap["probeHost"])
                    .trim()
                    .ifEmpty { BackendConfig.DEFAULT_PROBE_HOST },
                probePort = asInt(policyMap["probePort"], BackendConfig.DEFAULT_PROBE_PORT)
                    .coerceIn(1, 65535),
            )

            val rawNodes = root["nodes"] as? List<*> ?: emptyList<Any?>()
            val nodes = ArrayList<BootstrapRelayNode>()
            rawNodes.forEachIndexed { idx, item ->
                val obj = item as? Map<*, *> ?: return@forEachIndexed
                val host = asString(obj["host"]).trim()
                val port = asInt(obj["port"], BackendConfig.DEFAULT_RELAY_PORT)
                if (host.isEmpty() || port !in 1..65535) return@forEachIndexed
                nodes.add(
                    BootstrapRelayNode(
                        id = asString(obj["id"]).trim().ifEmpty { "edge-$idx" },
                        region = asString(obj["region"]).trim().ifEmpty { "EDGE" },
                        host = host,
                        port = port,
                        psk = asString(obj["psk"]).trim(),
                        priority = asInt(obj["priority"], idx + 1),
                    ),
                )
            }

            BootstrapResult(
                nodes = nodes,
                policy = policy,
                ttlSeconds = asInt(root["ttlSeconds"], 300).coerceIn(30, 3600),
                source = asString(root["source"]).ifEmpty { "remote" },
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

    private fun escapeJson(raw: String): String = buildString(raw.length) {
        for (ch in raw) {
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(ch)
            }
        }
    }

    private fun asString(value: Any?): String = (value as? String) ?: ""

    private fun asInt(value: Any?, fallback: Int): Int = when (value) {
        is Number -> value.toInt()
        is String -> value.trim().toIntOrNull() ?: fallback
        else -> fallback
    }

    private inline fun <reified T : Enum<T>> parseEnum(raw: String, fallback: T): T {
        if (raw.isBlank()) return fallback
        return enumValues<T>().firstOrNull { it.name == raw } ?: fallback
    }
}

/**
 * Minimal, dependency-free RFC 8259 JSON parser (objects, arrays, strings, numbers, booleans, null).
 */
private class MiniJsonParser(private val src: String) {
    private var pos = 0

    fun parseValue(): Any? {
        skipWs()
        if (pos >= src.length) error("Unexpected EOF")
        return when (src[pos]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't' -> expectLiteral("true", true)
            'f' -> expectLiteral("false", false)
            'n' -> expectLiteral("null", null)
            '-', in '0'..'9' -> parseNumber()
            else -> error("Unexpected char '${src[pos]}' at $pos")
        }
    }

    private fun parseObject(): Map<String, Any?> {
        pos++ // '{'
        val map = LinkedHashMap<String, Any?>()
        skipWs()
        if (pos < src.length && src[pos] == '}') {
            pos++
            return map
        }
        while (true) {
            skipWs()
            if (pos >= src.length || src[pos] != '"') error("Expected string key at $pos")
            val key = parseString()
            skipWs()
            if (pos >= src.length || src[pos] != ':') error("Expected ':' at $pos")
            pos++
            map[key] = parseValue()
            skipWs()
            if (pos >= src.length) error("Unterminated object")
            when (src[pos]) {
                ',' -> pos++
                '}' -> {
                    pos++
                    return map
                }
                else -> error("Expected ',' or '}' at $pos")
            }
        }
    }

    private fun parseArray(): List<Any?> {
        pos++ // '['
        val list = ArrayList<Any?>()
        skipWs()
        if (pos < src.length && src[pos] == ']') {
            pos++
            return list
        }
        while (true) {
            list.add(parseValue())
            skipWs()
            if (pos >= src.length) error("Unterminated array")
            when (src[pos]) {
                ',' -> pos++
                ']' -> {
                    pos++
                    return list
                }
                else -> error("Expected ',' or ']' at $pos")
            }
        }
    }

    private fun parseString(): String {
        pos++ // '"'
        val sb = StringBuilder()
        while (pos < src.length) {
            val ch = src[pos++]
            when (ch) {
                '"' -> return sb.toString()
                '\\' -> {
                    if (pos >= src.length) error("Unterminated escape")
                    when (val esc = src[pos++]) {
                        '"', '\\', '/' -> sb.append(esc)
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = src.substring(pos, pos + 4)
                            sb.append(hex.toInt(16).toChar())
                            pos += 4
                        }
                        else -> sb.append(esc)
                    }
                }
                else -> sb.append(ch)
            }
        }
        error("Unterminated string")
    }

    private fun parseNumber(): Number {
        val start = pos
        if (src[pos] == '-') pos++
        while (pos < src.length && src[pos] in '0'..'9') pos++
        var isFloat = false
        if (pos < src.length && src[pos] == '.') {
            isFloat = true
            pos++
            while (pos < src.length && src[pos] in '0'..'9') pos++
        }
        if (pos < src.length && (src[pos] == 'e' || src[pos] == 'E')) {
            isFloat = true
            pos++
            if (pos < src.length && (src[pos] == '+' || src[pos] == '-')) pos++
            while (pos < src.length && src[pos] in '0'..'9') pos++
        }
        val token = src.substring(start, pos)
        return if (isFloat) token.toDouble() else token.toLong()
    }

    private fun <T> expectLiteral(lit: String, value: T): T {
        if (!src.startsWith(lit, pos)) error("Expected $lit at $pos")
        pos += lit.length
        return value
    }

    private fun skipWs() {
        while (pos < src.length && src[pos] <= ' ') pos++
    }
}
