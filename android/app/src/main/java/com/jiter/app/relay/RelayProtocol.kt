package com.jiter.app.relay

import com.jiter.app.engine.FecMode
import kotlin.math.floor

/**
 * JITER Relay Wire Protocol v1 (`JT`) — 16-byte big-endian fixed header.
 *
 * Byte-for-byte identical to:
 *   - C11 Packet Engine (`engine-native/c/src/jiter_packet.c`)
 *   - Rust Relay Server (`relay/src/protocol.rs`)
 */
object RelayProtocol {
    const val WIRE_HEADER_BYTES = 16
    const val MAGIC_0: Byte = 0x4A // 'J'
    const val MAGIC_1: Byte = 0x54 // 'T'
    const val WIRE_VERSION = 1
    const val MAX_PAYLOAD_BYTES = 1440

    const val TIER_GAME = 0
    const val TIER_STREAMING = 1
    const val TIER_BACKGROUND = 2

    const val MSG_PROBE_REQ = 1
    const val MSG_PROBE_RESP = 2
    const val MSG_HELLO_REQ = 3
    const val MSG_HELLO_ACK = 4
    const val MSG_DATA_PLAIN = 5
    const val MSG_DATA_FEC = 6
    const val MSG_POLICY_SYNC = 7
    const val MSG_CONTROL = 8

    const val FLAG_GOODBYE = 0x01
    const val FLAG_FEC_PARITY = 0x02
    const val FLAG_ENCRYPTED = 0x04

    const val PROBE_REQ_BYTES = 12
    const val PROBE_RESP_BYTES = 24
    const val HELLO_REQ_BYTES = 8
    const val HELLO_ACK_BYTES = 12
    const val POLICY_SYNC_BYTES = 8

    fun pacerRatioToQ8(ratio: Double): Int {
        if (!ratio.isFinite() || ratio <= 0.0) return 0
        if (ratio >= 1.0) return 255
        val scaled = floor(ratio * 255.0 + 0.5).toInt()
        return scaled.coerceIn(0, 255)
    }

    fun q8ToPacerRatio(q8: Int): Double = (q8.coerceIn(0, 255)) / 255.0

    fun fecModeToWireByte(mode: FecMode): Int = when (mode) {
        FecMode.OFF -> 0
        FecMode.XOR_K4_INTERLEAVED -> 1
        FecMode.XOR_K2_INTERLEAVED -> 2
        FecMode.DUPLICATE -> 3
    }

    fun wireByteToFecMode(raw: Int): FecMode = when (raw) {
        1 -> FecMode.XOR_K4_INTERLEAVED
        2 -> FecMode.XOR_K2_INTERLEAVED
        3 -> FecMode.DUPLICATE
        else -> FecMode.OFF
    }

    internal fun putU16(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value ushr 8) and 0xFF).toByte()
        buf[off + 1] = (value and 0xFF).toByte()
    }

    internal fun putU32(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value ushr 24) and 0xFF).toByte()
        buf[off + 1] = ((value ushr 16) and 0xFF).toByte()
        buf[off + 2] = ((value ushr 8) and 0xFF).toByte()
        buf[off + 3] = (value and 0xFF).toByte()
    }

    internal fun putU64(buf: ByteArray, off: Int, value: Long) {
        buf[off] = ((value ushr 56) and 0xFFL).toByte()
        buf[off + 1] = ((value ushr 48) and 0xFFL).toByte()
        buf[off + 2] = ((value ushr 40) and 0xFFL).toByte()
        buf[off + 3] = ((value ushr 32) and 0xFFL).toByte()
        buf[off + 4] = ((value ushr 24) and 0xFFL).toByte()
        buf[off + 5] = ((value ushr 16) and 0xFFL).toByte()
        buf[off + 6] = ((value ushr 8) and 0xFFL).toByte()
        buf[off + 7] = (value and 0xFFL).toByte()
    }

    internal fun getU16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    internal fun getU32(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 24) or
            ((buf[off + 1].toInt() and 0xFF) shl 16) or
            ((buf[off + 2].toInt() and 0xFF) shl 8) or
            (buf[off + 3].toInt() and 0xFF)

    internal fun getU64(buf: ByteArray, off: Int): Long =
        ((buf[off].toLong() and 0xFFL) shl 56) or
            ((buf[off + 1].toLong() and 0xFFL) shl 48) or
            ((buf[off + 2].toLong() and 0xFFL) shl 40) or
            ((buf[off + 3].toLong() and 0xFFL) shl 32) or
            ((buf[off + 4].toLong() and 0xFFL) shl 24) or
            ((buf[off + 5].toLong() and 0xFFL) shl 16) or
            ((buf[off + 6].toLong() and 0xFFL) shl 8) or
            (buf[off + 7].toLong() and 0xFFL)
}

data class WireHeader(
    val version: Int = RelayProtocol.WIRE_VERSION,
    val msgType: Int,
    val trafficTier: Int = RelayProtocol.TIER_GAME,
    val flags: Int = 0,
    val sessionId: Int,
    val sequence: Int,
    val payloadLen: Int,
    val pacerQ8: Int = 255,
    val fecMode: Int = 0,
) {
    fun pack(): ByteArray {
        require(version == RelayProtocol.WIRE_VERSION) { "Unsupported wire version: $version" }
        require(msgType in RelayProtocol.MSG_PROBE_REQ..RelayProtocol.MSG_CONTROL) {
            "Invalid msgType: $msgType"
        }
        require(trafficTier in RelayProtocol.TIER_GAME..RelayProtocol.TIER_BACKGROUND) {
            "Invalid trafficTier: $trafficTier"
        }
        require(payloadLen in 0..RelayProtocol.MAX_PAYLOAD_BYTES) {
            "Invalid payloadLen: $payloadLen"
        }

        val out = ByteArray(RelayProtocol.WIRE_HEADER_BYTES)
        out[0] = RelayProtocol.MAGIC_0
        out[1] = RelayProtocol.MAGIC_1
        out[2] = (((version and 0x0F) shl 4) or (msgType and 0x0F)).toByte()
        out[3] = (((trafficTier and 0x03) shl 6) or (flags and 0x3F)).toByte()
        RelayProtocol.putU32(out, 4, sessionId)
        RelayProtocol.putU32(out, 8, sequence)
        RelayProtocol.putU16(out, 12, payloadLen)
        out[14] = (pacerQ8 and 0xFF).toByte()
        out[15] = (fecMode and 0xFF).toByte()
        return out
    }

    fun frameBytes(payload: ByteArray, payloadLength: Int = payload.size): ByteArray {
        require(payloadLength == payloadLen && payloadLength <= payload.size) {
            "Payload length mismatch: header=$payloadLen actual=$payloadLength"
        }
        val out = ByteArray(RelayProtocol.WIRE_HEADER_BYTES + payloadLength)
        val hdr = pack()
        System.arraycopy(hdr, 0, out, 0, RelayProtocol.WIRE_HEADER_BYTES)
        if (payloadLength > 0) {
            System.arraycopy(payload, 0, out, RelayProtocol.WIRE_HEADER_BYTES, payloadLength)
        }
        return out
    }

    companion object {
        fun unpack(buf: ByteArray, len: Int = buf.size): WireHeader? {
            if (len < RelayProtocol.WIRE_HEADER_BYTES || buf.size < RelayProtocol.WIRE_HEADER_BYTES) {
                return null
            }
            if (buf[0] != RelayProtocol.MAGIC_0 || buf[1] != RelayProtocol.MAGIC_1) {
                return null
            }
            val b2 = buf[2].toInt() and 0xFF
            val b3 = buf[3].toInt() and 0xFF
            val version = b2 ushr 4
            val msgType = b2 and 0x0F
            val tier = b3 ushr 6
            val flags = b3 and 0x3F
            val payloadLen = RelayProtocol.getU16(buf, 12)

            if (version != RelayProtocol.WIRE_VERSION ||
                msgType !in RelayProtocol.MSG_PROBE_REQ..RelayProtocol.MSG_CONTROL ||
                tier !in RelayProtocol.TIER_GAME..RelayProtocol.TIER_BACKGROUND ||
                payloadLen > RelayProtocol.MAX_PAYLOAD_BYTES
            ) {
                return null
            }

            return WireHeader(
                version = version,
                msgType = msgType,
                trafficTier = tier,
                flags = flags,
                sessionId = RelayProtocol.getU32(buf, 4),
                sequence = RelayProtocol.getU32(buf, 8),
                payloadLen = payloadLen,
                pacerQ8 = buf[14].toInt() and 0xFF,
                fecMode = buf[15].toInt() and 0xFF,
            )
        }
    }
}

data class ProbeReqPayload(
    val clientTxUs: Long,
    val profileId: Int,
) {
    fun pack(): ByteArray {
        val out = ByteArray(RelayProtocol.PROBE_REQ_BYTES)
        RelayProtocol.putU64(out, 0, clientTxUs)
        RelayProtocol.putU16(out, 8, profileId)
        RelayProtocol.putU16(out, 10, 0)
        return out
    }
}

data class ProbeRespPayload(
    val echoTxUs: Long,
    val relayRxLossBps: Long,
    val relayQueueUs: Long,
    val relayFecRecovered: Long,
    val relayPacerQ8: Int,
    val relayFecMode: Int,
) {
    val relayRxLossPct: Double get() = relayRxLossBps / 100.0
    val relayQueueMs: Double get() = relayQueueUs / 1000.0

    companion object {
        fun unpack(buf: ByteArray, offset: Int, len: Int): ProbeRespPayload? {
            if (len < RelayProtocol.PROBE_RESP_BYTES || offset + RelayProtocol.PROBE_RESP_BYTES > buf.size) {
                return null
            }
            return ProbeRespPayload(
                echoTxUs = RelayProtocol.getU64(buf, offset),
                relayRxLossBps = RelayProtocol.getU32(buf, offset + 8).toLong() and 0xFFFF_FFFFL,
                relayQueueUs = RelayProtocol.getU32(buf, offset + 12).toLong() and 0xFFFF_FFFFL,
                relayFecRecovered = RelayProtocol.getU32(buf, offset + 16).toLong() and 0xFFFF_FFFFL,
                relayPacerQ8 = RelayProtocol.getU16(buf, offset + 20),
                relayFecMode = RelayProtocol.getU16(buf, offset + 22),
            )
        }
    }
}

data class HelloReqPayload(
    val profileId: Int,
    val routingMode: Int,
    val fecPolicy: Int,
    val mtu: Int,
    val linkHintMbpsX10: Int,
) {
    fun pack(): ByteArray {
        val out = ByteArray(RelayProtocol.HELLO_REQ_BYTES)
        out[0] = (profileId and 0xFF).toByte()
        out[1] = (routingMode and 0xFF).toByte()
        out[2] = (fecPolicy and 0xFF).toByte()
        out[3] = 0
        RelayProtocol.putU16(out, 4, mtu)
        RelayProtocol.putU16(out, 6, linkHintMbpsX10)
        return out
    }
}

data class HelloAckPayload(
    val acceptedMtu: Int,
    val relayCaps: Int,
    val regionTag: String,
) {
    companion object {
        fun unpack(buf: ByteArray, offset: Int, len: Int): HelloAckPayload? {
            if (len < RelayProtocol.HELLO_ACK_BYTES || offset + RelayProtocol.HELLO_ACK_BYTES > buf.size) {
                return null
            }
            val mtu = RelayProtocol.getU16(buf, offset)
            val caps = RelayProtocol.getU16(buf, offset + 2)
            var end = 8
            for (i in 0 until 8) {
                if (buf[offset + 4 + i].toInt() == 0) {
                    end = i
                    break
                }
            }
            val region = String(buf, offset + 4, end, Charsets.UTF_8).ifEmpty { "EDGE" }
            return HelloAckPayload(acceptedMtu = mtu, relayCaps = caps, regionTag = region)
        }
    }
}

data class PolicySyncPayload(
    val profileId: Int,
    val fecMode: Int,
    val pacerQ8: Int,
    val linkMbpsX10: Int,
) {
    fun pack(): ByteArray {
        val out = ByteArray(RelayProtocol.POLICY_SYNC_BYTES)
        out[0] = (profileId and 0xFF).toByte()
        out[1] = (fecMode and 0xFF).toByte()
        out[2] = (pacerQ8 and 0xFF).toByte()
        out[3] = 0
        RelayProtocol.putU16(out, 4, linkMbpsX10)
        RelayProtocol.putU16(out, 6, 0)
        return out
    }
}
