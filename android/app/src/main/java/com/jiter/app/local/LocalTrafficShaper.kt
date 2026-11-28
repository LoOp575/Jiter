package com.jiter.app.local

import com.jiter.app.relay.RelayProtocol
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

data class LocalShaperStats(
    val activeUdpFlows: Int = 0,
    val activeTcpFlows: Int = 0,
    val txPackets: Long = 0L,
    val rxPackets: Long = 0L,
    val pacedBackgroundBytes: Long = 0L,
    val txBytes: Long = 0L,
    val rxBytes: Long = 0L,
) {
    val activeFlows: Int get() = activeUdpFlows + activeTcpFlows
}

/**
 * Stage 6.2 High-Throughput Local Traffic Shaper (No-VPS Hybrid Mode).
 *
 * Runs a single lightweight NIO `Selector` I/O loop owning:
 *   1. Non-blocking UDP Local NAT (`DatagramChannel`, max 256 flows) with DNS port-53 Tier-0 Fast-Path.
 *   2. Transparent user-space TCP proxy backed by Rust `smoltcp` (`LocalTcpBackend`, max 256 flows,
 *      256 KB TX / 128 KB RX windows, 64 KB NIO multi-read draining, zero-wait active bursts, and
 *      coalesced `selector.wakeup()`).
 *   3. Rolling 50 ms Token-Bucket Background Pacer on Tier-2 TCP flows driven live by the
 *      Rust Adaptive Controller's `bgPacerRatio` — smoothly pausing `OP_READ` on background
 *      download sockets when active Game/Streaming experiences bufferbloat so `rwnd` slows
 *      remote CDNs cleanly without dropping packets or breaking HTTPS / Play Store / m-banking.
 *      When `bgPacerRatio >= 0.99` (Download / Browser / Social / Standby), pacing is 100% bypassed.
 *
 * Every outbound socket is protected via `VpnService.protect()` before connecting so traffic
 * never loops back into Android's TUN interface.
 */
class LocalTrafficShaper(
    private val protectDatagram: (DatagramSocket) -> Boolean,
    private val protectStream: (Socket) -> Boolean,
    private val onDownlinkPacket: (ByteArray, Int) -> Unit,
    private val tcpBackendFactory: (Int, Long) -> LocalTcpBackend? = { mtu, seed ->
        LocalTcpNativeBridge.openStack(mtu, seed)
    },
    private val clockMs: () -> Long = { System.nanoTime() / 1_000_000L },
    private val onDownlinkActivity: ((tier: Int, bytes: Int, isUdp: Boolean) -> Unit)? = null,
) {
    private data class QueuedOutbound(
        val rawIpv4: ByteArray,
        val tier: Int,
    )

    private data class UdpFlowKey(
        val srcIpInt: Int,
        val srcPort: Int,
        val dstIpInt: Int,
        val dstPort: Int,
    )

    private class UdpFlow(
        val key: UdpFlowKey,
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val channel: DatagramChannel,
        var tier: Int,
        var lastActiveMs: Long,
    )

    private class TcpFlow(
        val flowId: Long,
        val channel: SocketChannel,
        val tier: Int,
        var connected: Boolean = false,
        var appEof: Boolean = false,
        var remoteEof: Boolean = false,
        var pendingWrite: ByteBuffer? = null,
        var lastActiveMs: Long,
    )

    private val outboundQueue = ConcurrentLinkedQueue<QueuedOutbound>()
    private val running = AtomicBoolean(false)
    private val selectorSleeping = AtomicBoolean(false)

    private val txPacketsCounter = AtomicLong(0L)
    private val rxPacketsCounter = AtomicLong(0L)
    private val txBytesCounter = AtomicLong(0L)
    private val rxBytesCounter = AtomicLong(0L)
    private val pacedBgBytesCounter = AtomicLong(0L)
    private val activeUdpCounter = AtomicInteger(0)
    private val activeTcpCounter = AtomicInteger(0)

    @Volatile
    private var bgPacerRatio: Double = 1.0

    @Volatile
    private var estimatedLinkMbps: Double = DEFAULT_LINK_MBPS

    @Volatile
    private var selector: Selector? = null

    @Volatile
    private var ioThread: Thread? = null

    private var ipIdCounter = 1

    fun start(mtu: Int = 1500): Boolean {
        if (running.getAndSet(true)) return true
        val sel = try {
            Selector.open()
        } catch (_: Exception) {
            running.set(false)
            return false
        }
        selector = sel
        selectorSleeping.set(false)
        val tcpBackend = tcpBackendFactory(mtu, System.nanoTime())

        val thread = Thread({
            elevateIoThreadPriority()
            runIoLoop(sel, tcpBackend)
        }, "jiter-local-shaper").apply {
            isDaemon = true
            priority = (Thread.MAX_PRIORITY - 1).coerceIn(Thread.NORM_PRIORITY, Thread.MAX_PRIORITY)
            start()
        }
        ioThread = thread
        return true
    }

    private fun elevateIoThreadPriority() {
        try {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_DISPLAY)
        } catch (_: Throwable) {
            // Plain JVM unit tests do not mock android.os.Process
        }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        selectorSleeping.set(false)
        try {
            selector?.wakeup()
        } catch (_: Exception) {
            // Ignore wakeup error
        }
        try {
            ioThread?.join(1_500L)
        } catch (_: InterruptedException) {
            // Ignore interrupt
        }
        ioThread = null
        selector = null
        outboundQueue.clear()
        activeUdpCounter.set(0)
        activeTcpCounter.set(0)
    }

    fun updatePacer(ratio: Double, linkMbps: Double?) {
        bgPacerRatio = ratio.coerceIn(0.15, 1.0)
        if (linkMbps != null && linkMbps.isFinite() && linkMbps > 0.5) {
            estimatedLinkMbps = linkMbps.coerceIn(1.0, 500.0)
        }
    }

    fun submitScheduledPacket(rawIpv4: ByteArray, length: Int, tier: Int) {
        if (!running.get() || length < 20 || length > rawIpv4.size) return
        if (outboundQueue.size >= MAX_OUTBOUND_QUEUE) return

        // DNS Fast-Path: elevate UDP port 53 to Tier 0 (instant priority)
        val proto = Ipv4PacketCodec.getProtocol(rawIpv4, length)
        val effectiveTier = if (proto == Ipv4PacketCodec.PROTO_UDP &&
            Ipv4PacketCodec.getDstPort(rawIpv4, length) == 53
        ) {
            RelayProtocol.TIER_GAME
        } else {
            tier
        }

        outboundQueue.offer(QueuedOutbound(rawIpv4.copyOf(length), effectiveTier))
        if (selectorSleeping.compareAndSet(true, false)) {
            try {
                selector?.wakeup()
            } catch (_: Exception) {
                // Ignore wakeup race
            }
        }
    }

    fun stats(): LocalShaperStats = LocalShaperStats(
        activeUdpFlows = activeUdpCounter.get(),
        activeTcpFlows = activeTcpCounter.get(),
        txPackets = txPacketsCounter.get(),
        rxPackets = rxPacketsCounter.get(),
        pacedBackgroundBytes = pacedBgBytesCounter.get(),
        txBytes = txBytesCounter.get(),
        rxBytes = rxBytesCounter.get(),
    )

    private fun runIoLoop(sel: Selector, tcpBackend: LocalTcpBackend?) {
        val udpFlows = LinkedHashMap<UdpFlowKey, UdpFlow>(64, 0.75f, true)
        val tcpFlows = HashMap<Long, TcpFlow>(64)

        val udpRxBuf = ByteBuffer.allocate(2048)
        val tcpTmpBuf = ByteArray(64 * 1024)
        val tcpDownBuf = ByteBuffer.allocate(64 * 1024)
        val tunTxBuf = ByteArray(2048)
        val metaOut = LongArray(3)

        var lastGcMs = clockMs()
        var lastPacerWindowMs = lastGcMs
        var bgWindowBytesUsed = 0L

        try {
            while (running.get()) {
                val nowMs = clockMs()
                var didWork = false

                // Reset 50 ms rolling Token-Bucket for Tier-2 Background TCP pacing
                if (nowMs - lastPacerWindowMs >= PACER_WINDOW_MS) {
                    lastPacerWindowMs = nowMs
                    bgWindowBytesUsed = 0L
                }
                val bgBudgetBytes = computeBgWindowBudgetBytes()

                // 1. Drain newly scheduled outbound IPv4 packets from TUN pump
                var drained = 0
                while (drained < MAX_OUTBOUND_DRAIN_PER_TICK) {
                    val pkt = outboundQueue.poll() ?: break
                    drained += 1
                    didWork = true
                    val proto = Ipv4PacketCodec.getProtocol(pkt.rawIpv4, pkt.rawIpv4.size)
                    when (proto) {
                        Ipv4PacketCodec.PROTO_UDP -> handleOutboundUdp(
                            sel = sel,
                            raw = pkt.rawIpv4,
                            tier = pkt.tier,
                            nowMs = nowMs,
                            udpFlows = udpFlows,
                        )
                        Ipv4PacketCodec.PROTO_TCP -> if (tcpBackend != null) {
                            handleOutboundTcp(
                                sel = sel,
                                tcpBackend = tcpBackend,
                                raw = pkt.rawIpv4,
                                tier = pkt.tier,
                                nowMs = nowMs,
                                metaOut = metaOut,
                                tcpFlows = tcpFlows,
                            )
                        }
                    }
                }

                // 2. Drive smoltcp timers & flush downlink TCP IPv4 packets back to TUN
                if (tcpBackend != null) {
                    tcpBackend.poll(nowMs)
                    if (drainTcpDownlinkToTun(tcpBackend, tunTxBuf) > 0) {
                        didWork = true
                    }
                    if (pumpAppBytesToRemoteTcp(
                            tcpBackend = tcpBackend,
                            tcpFlows = tcpFlows,
                            tmpBuf = tcpTmpBuf,
                            nowMs = nowMs,
                        )
                    ) {
                        didWork = true
                    }
                    updateTcpInterestOps(
                        tcpBackend = tcpBackend,
                        tcpFlows = tcpFlows,
                        bgBudgetBytes = bgBudgetBytes,
                        bgWindowBytesUsed = bgWindowBytesUsed,
                    )
                }

                // 3. Zero-wait poll during active traffic bursts; 4 ms sleep only when idle
                if (didWork || !outboundQueue.isEmpty()) {
                    sel.selectNow()
                } else {
                    selectorSleeping.set(true)
                    if (!outboundQueue.isEmpty()) {
                        selectorSleeping.set(false)
                        sel.selectNow()
                    } else {
                        sel.select(4L)
                        selectorSleeping.set(false)
                    }
                }

                val postSelectNow = clockMs()
                if (postSelectNow - lastPacerWindowMs >= PACER_WINDOW_MS) {
                    lastPacerWindowMs = postSelectNow
                    bgWindowBytesUsed = 0L
                }
                val activeBgBudget = computeBgWindowBudgetBytes()

                val iter = sel.selectedKeys().iterator()
                while (iter.hasNext()) {
                    val key = iter.next()
                    iter.remove()
                    if (!key.isValid) continue

                    when (val att = key.attachment()) {
                        is UdpFlow -> handleReadableUdp(att, udpRxBuf, postSelectNow)
                        is TcpFlow -> if (tcpBackend != null) {
                            bgWindowBytesUsed = handleTcpSelectionKey(
                                key = key,
                                flow = att,
                                tcpBackend = tcpBackend,
                                tcpFlows = tcpFlows,
                                downBuf = tcpDownBuf,
                                nowMs = postSelectNow,
                                bgBudgetBytes = activeBgBudget,
                                bgWindowBytesUsed = bgWindowBytesUsed,
                            )
                        }
                    }
                }

                // 4. Flush any TCP packets produced after remote reads/writes
                if (tcpBackend != null) {
                    tcpBackend.poll(postSelectNow)
                    drainTcpDownlinkToTun(tcpBackend, tunTxBuf)
                }

                // 5. Periodic GC (every 5 seconds)
                if (postSelectNow - lastGcMs >= 5_000L) {
                    lastGcMs = postSelectNow
                    gcUdpFlows(udpFlows, postSelectNow)
                    if (tcpBackend != null) {
                        gcTcpFlows(tcpBackend, tcpFlows, postSelectNow)
                    }
                    activeUdpCounter.set(udpFlows.size)
                    activeTcpCounter.set(tcpFlows.size)
                }
            }
        } catch (_: Exception) {
            // Safe teardown on stop
        } finally {
            selectorSleeping.set(false)
            for (u in udpFlows.values) {
                closeQuietly(u.channel)
            }
            udpFlows.clear()
            for (tf in tcpFlows.values) {
                closeQuietly(tf.channel)
            }
            tcpFlows.clear()
            try {
                tcpBackend?.close()
            } catch (_: Exception) {
                // Ignore
            }
            try {
                sel.close()
            } catch (_: Exception) {
                // Ignore
            }
        }
    }

    private fun computeBgWindowBudgetBytes(): Long {
        val ratio = bgPacerRatio
        if (ratio >= 0.99) return Long.MAX_VALUE
        val targetBytesPerSec = maxOf(
            BG_PACER_FLOOR_BYTES_PER_SEC,
            (estimatedLinkMbps * 1_000_000.0 / 8.0) * ratio,
        )
        return ((targetBytesPerSec * PACER_WINDOW_MS) / 1000.0).toLong().coerceAtLeast(2048L)
    }

    private fun handleOutboundUdp(
        sel: Selector,
        raw: ByteArray,
        tier: Int,
        nowMs: Long,
        udpFlows: LinkedHashMap<UdpFlowKey, UdpFlow>,
    ) {
        val parsed = Ipv4PacketCodec.parseIpv4Udp(raw, raw.size) ?: return
        if (Ipv4PacketCodec.isMulticastOrBroadcast(parsed.dstIp)) return
        if (parsed.dstPort <= 0 || parsed.srcPort <= 0) return

        val key = UdpFlowKey(
            srcIpInt = bytesToInt(parsed.srcIp),
            srcPort = parsed.srcPort,
            dstIpInt = bytesToInt(parsed.dstIp),
            dstPort = parsed.dstPort,
        )

        var flow = udpFlows[key]
        if (flow == null) {
            if (udpFlows.size >= MAX_UDP_FLOWS) {
                evictOldestUdp(udpFlows)
            }
            val ch = try {
                DatagramChannel.open().apply {
                    configureBlocking(false)
                    protectDatagram(socket())
                    connect(InetSocketAddress(InetAddress.getByAddress(parsed.dstIp), parsed.dstPort))
                }
            } catch (_: Exception) {
                return
            }
            flow = UdpFlow(
                key = key,
                srcIp = parsed.srcIp,
                dstIp = parsed.dstIp,
                channel = ch,
                tier = tier,
                lastActiveMs = nowMs,
            )
            try {
                ch.register(sel, SelectionKey.OP_READ, flow)
            } catch (_: Exception) {
                closeQuietly(ch)
                return
            }
            udpFlows[key] = flow
            activeUdpCounter.set(udpFlows.size)
        }

        flow.tier = tier
        flow.lastActiveMs = nowMs
        try {
            val payloadBuf = ByteBuffer.wrap(raw, parsed.payloadOffset, parsed.payloadLength)
            val sent = flow.channel.write(payloadBuf)
            if (sent >= 0) {
                txPacketsCounter.incrementAndGet()
                txBytesCounter.addAndGet(sent.toLong())
            }
        } catch (_: Exception) {
            udpFlows.remove(key)
            closeQuietly(flow.channel)
            activeUdpCounter.set(udpFlows.size)
        }
    }

    private fun handleReadableUdp(flow: UdpFlow, rxBuf: ByteBuffer, nowMs: Long) {
        try {
            var count = 0
            while (count < 32) {
                rxBuf.clear()
                val n = flow.channel.read(rxBuf)
                if (n <= 0) break
                count += 1
                flow.lastActiveMs = nowMs
                val downlink = Ipv4PacketCodec.buildIpv4UdpPacket(
                    srcIp = flow.dstIp,
                    srcPort = flow.key.dstPort,
                    dstIp = flow.srcIp,
                    dstPort = flow.key.srcPort,
                    payload = rxBuf.array(),
                    payloadOffset = 0,
                    payloadLength = n,
                    identification = nextIpId(),
                )
                rxPacketsCounter.incrementAndGet()
                rxBytesCounter.addAndGet(n.toLong())
                onDownlinkActivity?.invoke(flow.tier, n, true)
                onDownlinkPacket(downlink, downlink.size)
            }
        } catch (_: Exception) {
            // Ignore transient ICMP unreachable / socket read error
        }
    }

    private fun handleOutboundTcp(
        sel: Selector,
        tcpBackend: LocalTcpBackend,
        raw: ByteArray,
        tier: Int,
        nowMs: Long,
        metaOut: LongArray,
        tcpFlows: HashMap<Long, TcpFlow>,
    ) {
        txPacketsCounter.incrementAndGet()
        txBytesCounter.addAndGet(raw.size.toLong())
        val res = tcpBackend.ingestIpv4(raw, raw.size, tier, nowMs, metaOut)
        if (res != 1) return

        val flowId = metaOut[0]
        val dstIpv4Be = metaOut[1].toInt()
        val dstPort = metaOut[2].toInt() and 0xFFFF

        if (tcpFlows.size >= MAX_TCP_FLOWS) {
            tcpBackend.closeFlow(flowId, abort = true)
            return
        }

        val ch = try {
            SocketChannel.open().apply {
                configureBlocking(false)
                val sock = socket()
                sock.tcpNoDelay = true
                try {
                    sock.receiveBufferSize = REMOTE_TCP_RCVBUF_BYTES
                    sock.sendBufferSize = REMOTE_TCP_SNDBUF_BYTES
                } catch (_: Exception) {
                    // Best-effort OS socket buffer hint
                }
                protectStream(sock)
            }
        } catch (_: Exception) {
            tcpBackend.closeFlow(flowId, abort = true)
            return
        }

        val remoteAddr = InetSocketAddress(Ipv4PacketCodec.ipv4BeIntToAddress(dstIpv4Be), dstPort)
        val connectedImmediately = try {
            ch.connect(remoteAddr)
        } catch (_: Exception) {
            closeQuietly(ch)
            tcpBackend.closeFlow(flowId, abort = true)
            return
        }

        val flow = TcpFlow(
            flowId = flowId,
            channel = ch,
            tier = tier,
            connected = connectedImmediately,
            lastActiveMs = nowMs,
        )
        try {
            val ops = if (connectedImmediately) SelectionKey.OP_READ else SelectionKey.OP_CONNECT
            ch.register(sel, ops, flow)
            tcpFlows[flowId] = flow
            activeTcpCounter.set(tcpFlows.size)
        } catch (_: Exception) {
            closeQuietly(ch)
            tcpBackend.closeFlow(flowId, abort = true)
        }
    }

    private fun pumpAppBytesToRemoteTcp(
        tcpBackend: LocalTcpBackend,
        tcpFlows: HashMap<Long, TcpFlow>,
        tmpBuf: ByteArray,
        nowMs: Long,
    ): Boolean {
        var transferredAny = false
        val toDrop = ArrayList<Long>()
        for (flow in tcpFlows.values) {
            if (!flow.connected || flow.appEof) continue
            if (flow.pendingWrite != null) continue

            val n = tcpBackend.recvFromApp(flow.flowId, tmpBuf, tmpBuf.size, nowMs)
            when {
                n > 0 -> {
                    transferredAny = true
                    flow.lastActiveMs = nowMs
                    val bb = ByteBuffer.wrap(tmpBuf.copyOf(n))
                    try {
                        flow.channel.write(bb)
                        if (bb.hasRemaining()) {
                            flow.pendingWrite = bb
                        }
                    } catch (_: Exception) {
                        tcpBackend.closeFlow(flow.flowId, abort = true)
                        toDrop.add(flow.flowId)
                    }
                }
                n == -1 -> {
                    flow.appEof = true
                    try {
                        flow.channel.shutdownOutput()
                    } catch (_: Exception) {
                        // Ignore
                    }
                    if (flow.remoteEof) {
                        toDrop.add(flow.flowId)
                    }
                }
                n == -2 -> {
                    toDrop.add(flow.flowId)
                }
            }
        }
        for (id in toDrop) {
            removeTcpFlow(tcpFlows, id)
        }
        return transferredAny
    }

    private fun updateTcpInterestOps(
        tcpBackend: LocalTcpBackend,
        tcpFlows: HashMap<Long, TcpFlow>,
        bgBudgetBytes: Long,
        bgWindowBytesUsed: Long,
    ) {
        val sel = selector ?: return
        val bgBudgetExhausted = bgBudgetBytes < Long.MAX_VALUE && bgWindowBytesUsed >= bgBudgetBytes
        for (flow in tcpFlows.values) {
            val key = flow.channel.keyFor(sel) ?: continue
            if (!key.isValid) continue
            if (!flow.connected) {
                key.interestOps(SelectionKey.OP_CONNECT)
                continue
            }
            var ops = 0
            if (flow.pendingWrite != null) {
                ops = ops or SelectionKey.OP_WRITE
            }
            if (!flow.remoteEof) {
                val txSpace = tcpBackend.canSendToApp(flow.flowId)
                val isPacedTier2 = flow.tier == RelayProtocol.TIER_BACKGROUND && bgBudgetExhausted
                if (txSpace >= 1024 && !isPacedTier2) {
                    ops = ops or SelectionKey.OP_READ
                }
            }
            if (key.interestOps() != ops) {
                key.interestOps(ops)
            }
        }
    }

    private fun handleTcpSelectionKey(
        key: SelectionKey,
        flow: TcpFlow,
        tcpBackend: LocalTcpBackend,
        tcpFlows: HashMap<Long, TcpFlow>,
        downBuf: ByteBuffer,
        nowMs: Long,
        bgBudgetBytes: Long,
        bgWindowBytesUsed: Long,
    ): Long {
        var usedBg = bgWindowBytesUsed

        if (key.isConnectable) {
            try {
                if (flow.channel.finishConnect()) {
                    flow.connected = true
                    flow.lastActiveMs = nowMs
                    key.interestOps(SelectionKey.OP_READ)
                }
            } catch (_: Exception) {
                tcpBackend.closeFlow(flow.flowId, abort = true)
                removeTcpFlow(tcpFlows, flow.flowId)
                return usedBg
            }
        }

        if (key.isValid && key.isWritable) {
            val pending = flow.pendingWrite
            if (pending != null) {
                try {
                    flow.channel.write(pending)
                    flow.lastActiveMs = nowMs
                    if (!pending.hasRemaining()) {
                        flow.pendingWrite = null
                    }
                } catch (_: Exception) {
                    tcpBackend.closeFlow(flow.flowId, abort = true)
                    removeTcpFlow(tcpFlows, flow.flowId)
                    return usedBg
                }
            }
        }

        if (key.isValid && key.isReadable && flow.connected && !flow.remoteEof) {
            var reads = 0
            while (reads < MAX_TCP_READS_PER_KEY && !flow.remoteEof) {
                val freeSpace = tcpBackend.canSendToApp(flow.flowId)
                if (freeSpace < 0) {
                    removeTcpFlow(tcpFlows, flow.flowId)
                    return usedBg
                }
                if (freeSpace == 0) break

                var maxRead = minOf(freeSpace, downBuf.capacity())
                val pacingActive = flow.tier == RelayProtocol.TIER_BACKGROUND && bgBudgetBytes < Long.MAX_VALUE
                if (pacingActive) {
                    val remaining = (bgBudgetBytes - usedBg).coerceAtLeast(0L)
                    if (remaining == 0L) break
                    maxRead = minOf(maxRead, remaining.toInt())
                }

                downBuf.clear()
                downBuf.limit(maxRead)
                val readN = try {
                    flow.channel.read(downBuf)
                } catch (_: Exception) {
                    tcpBackend.closeFlow(flow.flowId, abort = true)
                    removeTcpFlow(tcpFlows, flow.flowId)
                    return usedBg
                }

                if (readN < 0) {
                    flow.remoteEof = true
                    tcpBackend.closeFlow(flow.flowId, abort = false)
                    if (flow.appEof) {
                        removeTcpFlow(tcpFlows, flow.flowId)
                    }
                    break
                } else if (readN == 0) {
                    break
                } else {
                    reads += 1
                    flow.lastActiveMs = nowMs
                    val written = tcpBackend.sendToApp(flow.flowId, downBuf.array(), 0, readN, nowMs)
                    if (written < 0) {
                        removeTcpFlow(tcpFlows, flow.flowId)
                        return usedBg
                    }
                    rxBytesCounter.addAndGet(readN.toLong())
                    onDownlinkActivity?.invoke(flow.tier, readN, false)
                    if (pacingActive) {
                        usedBg += readN.toLong()
                        pacedBgBytesCounter.addAndGet(readN.toLong())
                    }
                    if (readN < maxRead) break
                }
            }
        }

        return usedBg
    }

    private fun drainTcpDownlinkToTun(tcpBackend: LocalTcpBackend, tunTxBuf: ByteArray): Int {
        var count = 0
        while (count < MAX_TUN_DRAIN_PER_TICK) {
            val n = tcpBackend.popTxPacket(tunTxBuf)
            if (n <= 0) break
            count += 1
            rxPacketsCounter.incrementAndGet()
            onDownlinkPacket(tunTxBuf, n)
        }
        return count
    }

    private fun gcUdpFlows(udpFlows: LinkedHashMap<UdpFlowKey, UdpFlow>, nowMs: Long) {
        val it = udpFlows.entries.iterator()
        while (it.hasNext()) {
            val flow = it.next().value
            if (nowMs - flow.lastActiveMs > UDP_IDLE_TIMEOUT_MS) {
                closeQuietly(flow.channel)
                it.remove()
            }
        }
    }

    private fun gcTcpFlows(
        tcpBackend: LocalTcpBackend,
        tcpFlows: HashMap<Long, TcpFlow>,
        nowMs: Long,
    ) {
        val toRemove = ArrayList<Long>()
        for (flow in tcpFlows.values) {
            val idle = nowMs - flow.lastActiveMs
            val deadInStack = tcpBackend.canSendToApp(flow.flowId) < 0 && flow.appEof
            if (deadInStack || idle > TCP_IDLE_TIMEOUT_MS || (flow.remoteEof && flow.appEof)) {
                toRemove.add(flow.flowId)
            }
        }
        for (id in toRemove) {
            tcpBackend.closeFlow(id, abort = false)
            removeTcpFlow(tcpFlows, id)
        }
    }

    private fun evictOldestUdp(udpFlows: LinkedHashMap<UdpFlowKey, UdpFlow>) {
        val it = udpFlows.entries.iterator()
        if (it.hasNext()) {
            val oldest = it.next().value
            closeQuietly(oldest.channel)
            it.remove()
        }
    }

    private fun removeTcpFlow(tcpFlows: HashMap<Long, TcpFlow>, flowId: Long) {
        val flow = tcpFlows.remove(flowId)
        if (flow != null) {
            closeQuietly(flow.channel)
            activeTcpCounter.set(tcpFlows.size)
        }
    }

    private fun nextIpId(): Int {
        ipIdCounter = (ipIdCounter + 1) and 0xFFFF
        return ipIdCounter
    }

    private fun bytesToInt(b: ByteArray): Int =
        ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)

    private fun closeQuietly(ch: java.io.Closeable) {
        try {
            ch.close()
        } catch (_: Exception) {
            // Ignore close error
        }
    }

    companion object {
        private const val MAX_UDP_FLOWS = 256
        private const val MAX_TCP_FLOWS = 256
        private const val MAX_OUTBOUND_QUEUE = 2048
        private const val MAX_OUTBOUND_DRAIN_PER_TICK = 256
        private const val MAX_TUN_DRAIN_PER_TICK = 512
        private const val MAX_TCP_READS_PER_KEY = 4
        private const val REMOTE_TCP_RCVBUF_BYTES = 256 * 1024
        private const val REMOTE_TCP_SNDBUF_BYTES = 128 * 1024
        private const val UDP_IDLE_TIMEOUT_MS = 60_000L
        private const val TCP_IDLE_TIMEOUT_MS = 120_000L
        private const val PACER_WINDOW_MS = 50L
        private const val DEFAULT_LINK_MBPS = 25.0
        private const val BG_PACER_FLOOR_BYTES_PER_SEC = 50_000.0 // 400 Kbps floor so downloads never timeout
    }
}
