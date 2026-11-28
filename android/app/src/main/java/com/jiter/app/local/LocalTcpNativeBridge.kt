package com.jiter.app.local

import com.jiter.app.bridge.NativeEngineBridge

/**
 * Abstraction over the Rust `smoltcp` user-space TCP stack so `LocalTrafficShaper`
 * can run natively on Android and remain cleanly testable on JVM unit tests.
 */
interface LocalTcpBackend : AutoCloseable {
    fun ingestIpv4(pkt: ByteArray, length: Int, tier: Int, nowMs: Long, outMeta: LongArray): Int
    fun poll(nowMs: Long)
    fun popTxPacket(outBuf: ByteArray): Int
    fun recvFromApp(flowId: Long, outBuf: ByteArray, maxLen: Int, nowMs: Long): Int
    fun sendToApp(flowId: Long, data: ByteArray, offset: Int, length: Int, nowMs: Long): Int
    fun canSendToApp(flowId: Long): Int
    fun closeFlow(flowId: Long, abort: Boolean)
    fun getStats(outStats: LongArray)
}

/**
 * JNI bridge into `libjiter_native.so`'s Rust `smoltcp` transparent TCP stack.
 */
object LocalTcpNativeBridge {

    fun isSupported(): Boolean {
        if (!NativeEngineBridge.hasRustMathEngine) return false
        return try {
            nativeIsSupported()
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    fun openStack(mtu: Int, seed: Long): LocalTcpBackend? {
        if (!isSupported()) return null
        val handle = try {
            nativeCreate(mtu, seed)
        } catch (_: UnsatisfiedLinkError) {
            0L
        }
        if (handle == 0L) return null
        return NativeLocalTcpSession(handle)
    }

    private class NativeLocalTcpSession(private var handle: Long) : LocalTcpBackend {
        override fun ingestIpv4(
            pkt: ByteArray,
            length: Int,
            tier: Int,
            nowMs: Long,
            outMeta: LongArray,
        ): Int = if (handle != 0L) nativeIngestIpv4(handle, pkt, length, tier, nowMs, outMeta) else -1

        override fun poll(nowMs: Long) {
            if (handle != 0L) nativePoll(handle, nowMs)
        }

        override fun popTxPacket(outBuf: ByteArray): Int =
            if (handle != 0L) nativePopTxPacket(handle, outBuf) else 0

        override fun recvFromApp(flowId: Long, outBuf: ByteArray, maxLen: Int, nowMs: Long): Int =
            if (handle != 0L) nativeRecvFromApp(handle, flowId, outBuf, maxLen, nowMs) else -2

        override fun sendToApp(
            flowId: Long,
            data: ByteArray,
            offset: Int,
            length: Int,
            nowMs: Long,
        ): Int = if (handle != 0L) nativeSendToApp(handle, flowId, data, offset, length, nowMs) else -1

        override fun canSendToApp(flowId: Long): Int =
            if (handle != 0L) nativeCanSendToApp(handle, flowId) else -1

        override fun closeFlow(flowId: Long, abort: Boolean) {
            if (handle != 0L) nativeCloseFlow(handle, flowId, abort)
        }

        override fun getStats(outStats: LongArray) {
            if (handle != 0L) nativeGetStats(handle, outStats)
        }

        override fun close() {
            val h = handle
            handle = 0L
            if (h != 0L) {
                nativeDestroy(h)
            }
        }
    }

    @JvmStatic
    private external fun nativeIsSupported(): Boolean

    @JvmStatic
    private external fun nativeCreate(mtu: Int, seed: Long): Long

    @JvmStatic
    private external fun nativeDestroy(handle: Long)

    @JvmStatic
    private external fun nativeIngestIpv4(
        handle: Long,
        pkt: ByteArray,
        length: Int,
        tier: Int,
        nowMs: Long,
        outMeta: LongArray,
    ): Int

    @JvmStatic
    private external fun nativePoll(handle: Long, nowMs: Long)

    @JvmStatic
    private external fun nativePopTxPacket(handle: Long, outBuf: ByteArray): Int

    @JvmStatic
    private external fun nativeRecvFromApp(
        handle: Long,
        flowId: Long,
        outBuf: ByteArray,
        maxLen: Int,
        nowMs: Long,
    ): Int

    @JvmStatic
    private external fun nativeSendToApp(
        handle: Long,
        flowId: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
        nowMs: Long,
    ): Int

    @JvmStatic
    private external fun nativeCanSendToApp(handle: Long, flowId: Long): Int

    @JvmStatic
    private external fun nativeCloseFlow(handle: Long, flowId: Long, abort: Boolean)

    @JvmStatic
    private external fun nativeGetStats(handle: Long, outStats: LongArray)
}
