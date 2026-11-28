package com.jiter.app.local

import java.net.InetAddress

data class ParsedIpv4Udp(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
)

/**
 * Pure-Kotlin IPv4 / UDP / TCP header parser and IPv4+UDP downlink builder with
 * RFC 1071 one's-complement checksums for Stage 6 Local Traffic Shaper.
 */
object Ipv4PacketCodec {
    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun getProtocol(raw: ByteArray, length: Int): Int {
        if (length < 20 || length > raw.size) return -1
        val version = (raw[0].toInt() ushr 4) and 0x0F
        if (version != 4) return -1
        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > length) return -1
        return raw[9].toInt() and 0xFF
    }

    fun getDstPort(raw: ByteArray, length: Int): Int {
        if (length < 24 || length > raw.size) return -1
        val version = (raw[0].toInt() ushr 4) and 0x0F
        if (version != 4) return -1
        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl + 4 > length) return -1
        val proto = raw[9].toInt() and 0xFF
        if (proto != PROTO_TCP && proto != PROTO_UDP) return -1
        return ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
    }

    fun parseIpv4Udp(raw: ByteArray, length: Int): ParsedIpv4Udp? {
        if (length < 28 || length > raw.size) return null
        val version = (raw[0].toInt() ushr 4) and 0x0F
        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (version != 4 || ihl < 20 || ihl + 8 > length) return null
        if ((raw[9].toInt() and 0xFF) != PROTO_UDP) return null

        val ipTotalLen = ((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)
        val effectiveLen = minOf(length, ipTotalLen)
        if (effectiveLen < ihl + 8) return null

        val udpLen = ((raw[ihl + 4].toInt() and 0xFF) shl 8) or (raw[ihl + 5].toInt() and 0xFF)
        if (udpLen < 8 || ihl + udpLen > effectiveLen) return null

        val srcPort = ((raw[ihl].toInt() and 0xFF) shl 8) or (raw[ihl + 1].toInt() and 0xFF)
        val dstPort = ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
        return ParsedIpv4Udp(
            srcIp = raw.copyOfRange(12, 16),
            dstIp = raw.copyOfRange(16, 20),
            srcPort = srcPort,
            dstPort = dstPort,
            payloadOffset = ihl + 8,
            payloadLength = udpLen - 8,
        )
    }

    /**
     * Builds a complete IPv4 + UDP downlink packet (20B IPv4 + 8B UDP + payload)
     * with valid RFC 1071 IPv4 header checksum and UDP pseudo-header checksum.
     */
    fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size,
        identification: Int = 0,
    ): ByteArray {
        val udpLen = 8 + payloadLength
        val totalLen = 20 + udpLen
        val out = ByteArray(totalLen)

        // IPv4 Header (20 bytes)
        out[0] = 0x45.toByte() // Version 4, IHL 5
        out[1] = 0x00.toByte()
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = ((identification ushr 8) and 0xFF).toByte()
        out[5] = (identification and 0xFF).toByte()
        out[6] = 0x40.toByte() // Don't Fragment
        out[7] = 0x00.toByte()
        out[8] = 64.toByte() // TTL
        out[9] = PROTO_UDP.toByte()
        out[10] = 0x00.toByte()
        out[11] = 0x00.toByte()
        srcIp.copyInto(out, destinationOffset = 12, startIndex = 0, endIndex = 4)
        dstIp.copyInto(out, destinationOffset = 16, startIndex = 0, endIndex = 4)

        val ipChecksum = onesComplementChecksum(out, 0, 20)
        out[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        out[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header (8 bytes)
        out[20] = ((srcPort ushr 8) and 0xFF).toByte()
        out[21] = (srcPort and 0xFF).toByte()
        out[22] = ((dstPort ushr 8) and 0xFF).toByte()
        out[23] = (dstPort and 0xFF).toByte()
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0x00.toByte()
        out[27] = 0x00.toByte()

        if (payloadLength > 0) {
            payload.copyInto(
                out,
                destinationOffset = 28,
                startIndex = payloadOffset,
                endIndex = payloadOffset + payloadLength,
            )
        }

        val udpChecksum = computeUdpChecksum(srcIp, dstIp, out, 20, udpLen)
        out[26] = ((udpChecksum ushr 8) and 0xFF).toByte()
        out[27] = (udpChecksum and 0xFF).toByte()
        return out
    }

    fun ipv4BeIntToAddress(ipv4Be: Int): InetAddress {
        val bytes = byteArrayOf(
            ((ipv4Be ushr 24) and 0xFF).toByte(),
            ((ipv4Be ushr 16) and 0xFF).toByte(),
            ((ipv4Be ushr 8) and 0xFF).toByte(),
            (ipv4Be and 0xFF).toByte(),
        )
        return InetAddress.getByAddress(bytes)
    }

    fun isMulticastOrBroadcast(ip: ByteArray): Boolean {
        if (ip.size < 4) return true
        val b0 = ip[0].toInt() and 0xFF
        val b3 = ip[3].toInt() and 0xFF
        if (b0 == 0 || b0 >= 224) return true
        if (b0 == 255 && (ip[1].toInt() and 0xFF) == 255 &&
            (ip[2].toInt() and 0xFF) == 255 && b3 == 255
        ) {
            return true
        }
        return false
    }

    fun onesComplementChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return sum.toInt().inv() and 0xFFFF
    }

    private fun computeUdpChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        packet: ByteArray,
        udpOffset: Int,
        udpLen: Int,
    ): Int {
        var sum = 0L
        // IPv4 pseudo-header
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += PROTO_UDP.toLong()
        sum += udpLen.toLong()

        var i = udpOffset
        val end = udpOffset + udpLen
        while (i + 1 < end) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        val folded = sum.toInt().inv() and 0xFFFF
        // Per RFC 768, a computed checksum of 0 is transmitted as 0xFFFF
        return if (folded == 0) 0xFFFF else folded
    }
}
