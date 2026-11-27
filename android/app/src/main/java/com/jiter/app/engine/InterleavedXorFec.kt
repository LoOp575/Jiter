package com.jiter.app.engine

import kotlin.experimental.xor

/**
 * Lightweight wire frame for JITER Formula #3 Adaptive XOR Parity FEC (8-byte header + payload).
 *
 * Wire layout (big-endian):
 *   bytes 0..3 : groupId (u32)
 *   bytes 4..5 : payloadLen (u16)
 *   byte  6    : slotIndex (u8; 0..blockK-1 = data, blockK = parity)
 *   byte  7    : flagsAndK (bit 7: 1=parity/0=data, bits 0..3: blockK 1..15)
 *   bytes 8..N : payload
 */
data class FecFrame(
    val groupId: Int,
    val slotIndex: Int,
    val blockK: Int,
    val isParity: Boolean,
    val payload: ByteArray,
) {
    fun toWireBytes(): ByteArray {
        require(payload.size <= 0xFFFF) { "Payload exceeds 65535 bytes" }
        val out = ByteArray(HEADER_SIZE + payload.size)
        out[0] = ((groupId ushr 24) and 0xFF).toByte()
        out[1] = ((groupId ushr 16) and 0xFF).toByte()
        out[2] = ((groupId ushr 8) and 0xFF).toByte()
        out[3] = (groupId and 0xFF).toByte()
        out[4] = ((payload.size ushr 8) and 0xFF).toByte()
        out[5] = (payload.size and 0xFF).toByte()
        out[6] = (slotIndex and 0xFF).toByte()
        val flags = (if (isParity) 0x80 else 0x00) or (blockK and 0x0F)
        out[7] = flags.toByte()
        payload.copyInto(out, destinationOffset = HEADER_SIZE)
        return out
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FecFrame) return false
        return groupId == other.groupId &&
            slotIndex == other.slotIndex &&
            blockK == other.blockK &&
            isParity == other.isParity &&
            payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = groupId
        result = 31 * result + slotIndex
        result = 31 * result + blockK
        result = 31 * result + isParity.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    companion object {
        const val HEADER_SIZE = 8

        fun fromWireBytes(wire: ByteArray): FecFrame {
            require(wire.size >= HEADER_SIZE) { "Wire frame shorter than $HEADER_SIZE bytes" }
            val groupId =
                ((wire[0].toInt() and 0xFF) shl 24) or
                    ((wire[1].toInt() and 0xFF) shl 16) or
                    ((wire[2].toInt() and 0xFF) shl 8) or
                    (wire[3].toInt() and 0xFF)
            val payloadLen =
                ((wire[4].toInt() and 0xFF) shl 8) or
                    (wire[5].toInt() and 0xFF)
            require(wire.size >= HEADER_SIZE + payloadLen) {
                "Truncated FEC wire frame: expected ${HEADER_SIZE + payloadLen} bytes, got ${wire.size}"
            }
            val slotIndex = wire[6].toInt() and 0xFF
            val flagsAndK = wire[7].toInt() and 0xFF
            val isParity = (flagsAndK and 0x80) != 0
            val blockK = flagsAndK and 0x0F
            require(blockK in 1..15) { "Invalid blockK: $blockK" }
            val payload = wire.copyOfRange(HEADER_SIZE, HEADER_SIZE + payloadLen)
            return FecFrame(
                groupId = groupId,
                slotIndex = slotIndex,
                blockK = blockK,
                isParity = isParity,
                payload = payload,
            )
        }
    }
}

data class RecoveredPacket(
    val groupId: Int,
    val slotIndex: Int,
    val payload: ByteArray,
    val wasRecoveredByParity: Boolean,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RecoveredPacket) return false
        return groupId == other.groupId &&
            slotIndex == other.slotIndex &&
            wasRecoveredByParity == other.wasRecoveredByParity &&
            payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = groupId
        result = 31 * result + slotIndex
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + wasRecoveredByParity.hashCode()
        return result
    }
}

internal object XorFecCodecMath {
    fun xorBuffers(buffers: Collection<ByteArray>): ByteArray {
        if (buffers.isEmpty()) return ByteArray(0)
        var maxLen = 0
        for (buf in buffers) {
            if (buf.size > maxLen) maxLen = buf.size
        }
        val acc = ByteArray(maxLen)
        for (buf in buffers) {
            for (i in buf.indices) {
                acc[i] = acc[i] xor buf[i]
            }
        }
        return acc
    }

    fun packLenPrefixed(payload: ByteArray): ByteArray {
        require(payload.size <= 0xFFFF) { "Payload exceeds 65535 bytes" }
        val out = ByteArray(2 + payload.size)
        out[0] = ((payload.size ushr 8) and 0xFF).toByte()
        out[1] = (payload.size and 0xFF).toByte()
        payload.copyInto(out, destinationOffset = 2)
        return out
    }

    fun unpackLenPrefixed(framed: ByteArray): ByteArray {
        require(framed.size >= 2) { "Corrupted FEC recovered buffer: shorter than 2 bytes" }
        val origLen = ((framed[0].toInt() and 0xFF) shl 8) or (framed[1].toInt() and 0xFF)
        require(origLen <= framed.size - 2) {
            "Corrupted FEC recovered length $origLen > ${framed.size - 2}"
        }
        return framed.copyOfRange(2, 2 + origLen)
    }
}

/**
 * Formula #3: Stateful GF(2) Bitwise XOR Parity Encoder with Interleaved Stride.
 * Emits data packets immediately (zero sender queueing delay) and emits one parity
 * frame each time a stride lane reaches `blockK` packets.
 */
class InterleavedXorFecEncoder(
    val blockK: Int = 4,
    val stride: Int = 4,
) {
    private var nextGroupId: Int = 0
    private val activeGroupIds: IntArray
    private val groupSlots: Array<MutableList<ByteArray>>
    private var cursor: Int = 0

    init {
        require(blockK in 1..15) { "blockK must be in 1..15" }
        require(stride in 1..16) { "stride must be in 1..16" }
        activeGroupIds = IntArray(stride) { allocGroupId() }
        groupSlots = Array(stride) { ArrayList(blockK) }
    }

    private fun allocGroupId(): Int {
        val id = nextGroupId
        nextGroupId += 1
        return id
    }

    fun encodePacket(payload: ByteArray): List<FecFrame> {
        val lane = cursor
        cursor = (cursor + 1) % stride

        val gid = activeGroupIds[lane]
        val slots = groupSlots[lane]
        val slotIdx = slots.size

        val dataFrame = FecFrame(
            groupId = gid,
            slotIndex = slotIdx,
            blockK = blockK,
            isParity = false,
            payload = payload.copyOf(),
        )
        slots.add(XorFecCodecMath.packLenPrefixed(payload))

        if (slots.size < blockK) {
            return listOf(dataFrame)
        }

        val parityPayload = XorFecCodecMath.xorBuffers(slots)
        val parityFrame = FecFrame(
            groupId = gid,
            slotIndex = blockK,
            blockK = blockK,
            isParity = true,
            payload = parityPayload,
        )
        slots.clear()
        activeGroupIds[lane] = allocGroupId()
        return listOf(dataFrame, parityFrame)
    }
}

/**
 * Formula #3: GF(2) Bitwise XOR Parity Decoder with bounded group tracking.
 * Reconstructs any single missing data packet per parity group instantly bit-for-bit.
 */
class InterleavedXorFecDecoder(
    private val maxTrackedGroups: Int = 64,
) {
    private class GroupState(val blockK: Int) {
        val dataSlots: MutableMap<Int, ByteArray> = HashMap(blockK)
        var parityPayload: ByteArray? = null
        var done: Boolean = false
    }

    private val groups = LinkedHashMap<Int, GroupState>()

    var recoveredCount: Int = 0
        private set

    var unrecoverableGroups: Int = 0
        private set

    fun reset() {
        groups.clear()
        recoveredCount = 0
        unrecoverableGroups = 0
    }

    private fun evictOldestIfNeeded() {
        val iter = groups.entries.iterator()
        while (groups.size > maxTrackedGroups && iter.hasNext()) {
            val evicted = iter.next().value
            iter.remove()
            if (evicted.dataSlots.size < evicted.blockK) {
                unrecoverableGroups += 1
            }
        }
    }

    fun receive(frame: FecFrame): List<RecoveredPacket> {
        val gid = frame.groupId
        var grp = groups[gid]
        if (grp == null) {
            grp = GroupState(frame.blockK)
            groups[gid] = grp
            evictOldestIfNeeded()
        }
        if (grp.done) return emptyList()

        val delivered = ArrayList<RecoveredPacket>(2)

        if (!frame.isParity) {
            if (frame.slotIndex in 0 until grp.blockK && !grp.dataSlots.containsKey(frame.slotIndex)) {
                grp.dataSlots[frame.slotIndex] = XorFecCodecMath.packLenPrefixed(frame.payload)
                delivered.add(
                    RecoveredPacket(
                        groupId = gid,
                        slotIndex = frame.slotIndex,
                        payload = frame.payload,
                        wasRecoveredByParity = false,
                    ),
                )
            }
        } else {
            grp.parityPayload = frame.payload
        }

        if (grp.dataSlots.size == grp.blockK) {
            grp.done = true
            return delivered
        }

        val parity = grp.parityPayload
        if (parity != null && grp.dataSlots.size == grp.blockK - 1) {
            var missingIdx = -1
            for (idx in 0 until grp.blockK) {
                if (!grp.dataSlots.containsKey(idx)) {
                    missingIdx = idx
                    break
                }
            }
            if (missingIdx >= 0) {
                val inputs = ArrayList<ByteArray>(grp.blockK)
                inputs.addAll(grp.dataSlots.values)
                inputs.add(parity)
                val recoveredFramed = XorFecCodecMath.xorBuffers(inputs)
                val recoveredPayload = XorFecCodecMath.unpackLenPrefixed(recoveredFramed)
                grp.dataSlots[missingIdx] = recoveredFramed
                grp.done = true
                recoveredCount += 1
                delivered.add(
                    RecoveredPacket(
                        groupId = gid,
                        slotIndex = missingIdx,
                        payload = recoveredPayload,
                        wasRecoveredByParity = true,
                    ),
                )
            }
        }

        return delivered
    }
}
