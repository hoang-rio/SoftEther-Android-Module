package vn.unlimit.softether.test

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith
import vn.unlimit.softether.client.SoftEtherClient
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Single-session bidirectional throughput benchmark.
 *
 * Floods ICMP echo-requests to the hub's virtual gateway (SecureNAT); every
 * reply is genuine downstream traffic on the production data path
 * (TX: softether_send -> server; RX: server -> softether_receive_batch).
 *
 * Run:
 * adb shell am instrument -w \
 *   -e class vn.unlimit.softether.test.ThroughputBenchmarkTest#benchmarkTcp \
 *   -e benchHost 10.35.21.131 -e benchPort 5555 \
 *   -e benchUser user7619 -e benchPass ... -e benchHub DEFAULT \
 *   -e durationMs 15000 -e warmupMs 5000 \
 *   vn.unlimit.softether.test/androidx.test.runner.AndroidJUnitRunner
 */
@RunWith(AndroidJUnit4::class)
class ThroughputBenchmarkTest {

    companion object {
        private const val TAG = "ThroughputBench"
        private const val USERNAME = "vpn"
        private const val PASSWORD = "vpn"
        private const val HUB = "vpngate"
    }

    private fun arg(name: String, def: String): String =
        InstrumentationRegistry.getArguments().getString(name) ?: def

    private fun csum(data: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        var i = offset
        while (i < offset + len - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < offset + len) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.toInt().inv()) and 0xFFFF
    }

    /** Build an IPv4 ICMP echo-request packet */
    private fun buildPing(srcIp: Int, dstIp: Int, size: Int, seq: Int): ByteArray {
        val pkt = ByteArray(size)
        val ipHdr = 20
        val icmpLen = size - ipHdr

        // ICMP
        pkt[ipHdr] = 8            // echo request
        pkt[ipHdr + 1] = 0
        pkt[ipHdr + 2] = (seq shr 8).toByte()
        pkt[ipHdr + 3] = seq.toByte()
        for (i in ipHdr + 4 until size) pkt[i] = (i and 0xFF).toByte()
        val ic = csum(pkt, ipHdr, icmpLen)
        pkt[ipHdr + 2] = (ic shr 8).toByte()
        pkt[ipHdr + 3] = (ic and 0xFF).toByte()

        // IP
        pkt[0] = 0x45
        pkt[1] = 0
        pkt[2] = (size shr 8).toByte()
        pkt[3] = size.toByte()
        pkt[4] = (seq shr 8).toByte(); pkt[5] = seq.toByte() // id
        pkt[6] = 0x40; pkt[7] = 0       // DF
        pkt[8] = 64
        pkt[9] = 1                        // ICMP
        pkt[12] = (srcIp shr 24).toByte(); pkt[13] = (srcIp shr 16).toByte()
        pkt[14] = (srcIp shr 8).toByte();  pkt[15] = srcIp.toByte()
        pkt[16] = (dstIp shr 24).toByte(); pkt[17] = (dstIp shr 16).toByte()
        pkt[18] = (dstIp shr 8).toByte();  pkt[19] = dstIp.toByte()
        val ipc = csum(pkt, 0, ipHdr)
        pkt[10] = (ipc shr 8).toByte()
        pkt[11] = (ipc and 0xFF).toByte()
        return pkt
    }

    private fun ipToInt(ip: String): Int {
        val p = ip.split(".").map { it.trim().toInt() and 0xFF }
        return (p[0] shl 24) or (p[1] shl 16) or (p[2] shl 8) or p[3]
    }

    private fun runFlood(useTcp: Boolean, durationMs: Long, warmupMs: Long): Triple<Long, Long, Long> {
        val host = arg("benchHost", "219.100.37.178")
        val port = arg("benchPort", "443").toInt()
        val username = arg("benchUser", USERNAME)
        val password = arg("benchPass", PASSWORD)
        val hub = arg("benchHub", HUB)

        Log.i(TAG, "=== Connecting (useTcp=$useTcp) to $host:$port hub=$hub ===")
        val client = SoftEtherClient()
        val handle = client.nativeCreate()
        client.externalHandle = handle
        check(handle != 0L) { "nativeCreate failed" }
        client.setTimeout(30000)

        val serverIp = try {
            InetAddress.getByName(host).hostAddress ?: host
        } catch (e: Exception) { host }

        val rc = client.nativeConnectWithHub(
            handle, host, port, username, password, hub, useTcp,
            "vpngate-bench", "1.0", 0,
            "Android", android.os.Build.VERSION.RELEASE, android.os.Build.FINGERPRINT,
            "bench", "0.0.0.0", 0,
            host, serverIp, port
        )
        check(rc == 0) { "connect failed rc=$rc" }

        val dhcp = client.doDhcp(handle)
        check(dhcp != null) { "DHCP failed" }
        Log.i(TAG, "DHCP: ip=${dhcp.assignedIp} gw=${dhcp.gateway}")
        val gwIp = ipToInt(dhcp.gateway)
        val myIp = ipToInt(dhcp.assignedIp)

        val stop = AtomicBoolean(false)
        val txBytes = AtomicLong(0)
        val rxBytes = AtomicLong(0)
        val rxPkts = AtomicLong(0)

        val rxThread = Thread {
            val buf = ByteArray(65535)
            val lengths = IntArray(32)
            while (!stop.get()) {
                val total = client.receiveBatch(buf, lengths)
                if (total > 0) {
                    rxBytes.addAndGet(total.toLong())
                    for (l in lengths) { if (l == 0) break; rxPkts.incrementAndGet() }
                }
            }
        }
        val txThread = Thread {
            var seq = 1
            while (!stop.get()) {
                val pkt = buildPing(myIp, gwIp, 1400, seq and 0xFFFF)
                val r = client.nativeSend(handle, pkt, pkt.size)
                if (r > 0) {
                    txBytes.addAndGet(r.toLong())
                    seq++
                } else {
                    Thread.sleep(1)
                }
            }
        }
        rxThread.start()
        txThread.start()

        Thread.sleep(warmupMs)
        txBytes.set(0); rxBytes.set(0); rxPkts.set(0)
        Log.i(TAG, "Measurement window started (${durationMs} ms)")
        Thread.sleep(durationMs)
        stop.set(true)

        val deadline = System.currentTimeMillis() + 15000
        while ((txThread.isAlive || rxThread.isAlive) && System.currentTimeMillis() < deadline) {
            Thread.sleep(100)
        }
        check(!txThread.isAlive && !rxThread.isAlive) { "worker threads did not exit" }

        val stats = client.nativeGetStats(handle)
        Log.i(TAG, "stats: ${stats?.contentToString()}")

        try { client.nativeDisconnect(handle) } catch (_: Exception) {}
        try { client.nativeDestroy(handle) } catch (_: Exception) {}

        return Triple(txBytes.get(), rxBytes.get(), rxPkts.get())
    }

    /** Build a UDP/IPv4 packet to the broadcast address */
    private fun buildBroadcastUdp(srcIp: Int, size: Int, seq: Int): ByteArray {
        val pkt = ByteArray(size)
        val ipHdr = 20
        val udpHdr = 8

        // UDP: src 68 -> dst 9999
        pkt[ipHdr] = 0; pkt[ipHdr + 1] = 68
        pkt[ipHdr + 2] = 0x27; pkt[ipHdr + 3] = 0x0F // 9999
        val udpLen = size - ipHdr
        pkt[ipHdr + 4] = (udpLen shr 8).toByte(); pkt[ipHdr + 5] = udpLen.toByte()
        for (i in ipHdr + udpHdr until size) pkt[i] = (i and 0xFF).toByte()

        // IP
        pkt[0] = 0x45
        pkt[2] = (size shr 8).toByte(); pkt[3] = size.toByte()
        pkt[4] = (seq shr 8).toByte(); pkt[5] = seq.toByte()
        pkt[6] = 0x40; pkt[7] = 0
        pkt[8] = 64
        pkt[9] = 17 // UDP
        pkt[12] = (srcIp shr 24).toByte(); pkt[13] = (srcIp shr 16).toByte()
        pkt[14] = (srcIp shr 8).toByte();  pkt[15] = srcIp.toByte()
        pkt[16] = -1; pkt[17] = -1; pkt[18] = -1; pkt[19] = -1 // 255.255.255.255
        val ipc = csum(pkt, 0, ipHdr)
        pkt[10] = (ipc shr 8).toByte()
        pkt[11] = (ipc and 0xFF).toByte()
        return pkt
    }

    /**
     * Paired-session flood: sender floods broadcast UDP payloads (production
     * send path), the hub floods them to the receiver session.
     */
    private fun runPairedFlood(useTcp: Boolean, durationMs: Long, warmupMs: Long): Triple<Long, Long, Long> {
        val host = arg("benchHost", "219.100.37.178")
        val port = arg("benchPort", "443").toInt()
        val username = arg("benchUser", USERNAME)
        val password = arg("benchPass", PASSWORD)
        val hub = arg("benchHub", HUB)

        fun connect(): Pair<SoftEtherClient, Long> {
            val c = SoftEtherClient()
            val h = c.nativeCreate()
            check(h != 0L)
            c.setTimeout(30000)
            val rc = c.nativeConnectWithHub(
                h, host, port, username, password, hub, useTcp,
                "vpngate-bench", "1.0", 0,
                "Android", android.os.Build.VERSION.RELEASE, android.os.Build.FINGERPRINT,
                "bench", "0.0.0.0", 0,
                host, host, port
            )
            check(rc == 0) { "connect failed rc=$rc" }
            return c to h
        }

        Log.i(TAG, "=== Connecting pair (useTcp=$useTcp) to $host:$port hub=$hub ===")
        val (txClient, txHandle) = connect()
        txClient.externalHandle = txHandle // receiveBatch()/send() resolve the handle from here
        val (rxClient, rxHandle) = connect()
        rxClient.externalHandle = rxHandle

        val dhcpT = txClient.doDhcp(txHandle)
        val dhcpR = rxClient.doDhcp(rxHandle)
        check(dhcpT != null && dhcpR != null) { "DHCP failed t=${dhcpT != null} r=${dhcpR != null}" }
        Log.i(TAG, "DHCP tx=${dhcpT.assignedIp} rx=${dhcpR.assignedIp}")

        val srcIp = ipToInt(dhcpT.assignedIp)
        val txMac = checkNotNull(txClient.getClientMac(txHandle)) { "tx mac" }
        val rxMac = checkNotNull(rxClient.getClientMac(rxHandle)) { "rx mac" }
        Log.i(TAG, "tx mac=${txMac.joinToString(":") { String.format("%02X", it) }} " +
                "rx mac=${rxMac.joinToString(":") { String.format("%02X", it) }}")

        // Full Ethernet frame: unicast to the receiver's real MAC so the hub
        // switches it to the peer session (softether_send would address
        // everything to the gateway MAC, which goes to SecureNAT instead).
        fun buildFrame(seq: Int): ByteArray {
            val frame = ByteArray(1414)
            System.arraycopy(rxMac, 0, frame, 0, 6)
            System.arraycopy(txMac, 0, frame, 6, 6)
            frame[12] = 0x08; frame[13] = 0x00
            // minimal UDP/IPv4 payload
            frame[14] = 0x45
            val totalLen = 1400
            frame[16] = (totalLen shr 8).toByte(); frame[17] = totalLen.toByte()
            frame[14 + 8] = (srcIp shr 24).toByte(); frame[14 + 9] = (srcIp shr 16).toByte()
            frame[14 + 10] = (srcIp shr 8).toByte(); frame[14 + 11] = srcIp.toByte()
            frame[18] = -1; frame[19] = -1; frame[20] = -1; frame[21] = -1
            for (i in 28 until totalLen) frame[i] = (seq and 0xFF).toByte()
            return frame
        }

        val stop = AtomicBoolean(false)
        val txBytes = AtomicLong(0)
        val rxBytes = AtomicLong(0)
        val rxPkts = AtomicLong(0)

        // Serialize ALL native TLS calls behind one process-wide lock:
        // concurrent SSL I/O across two connections sharing the cached
        // SSL_CTX corrupts the TLS layer (scudo aborts in EVP_MD_CTX_free).
        val tlsLock = Any()
        val buf = ByteArray(65535)
        val lengths = IntArray(32)

        fun drain(c: SoftEtherClient, h: Long): Int = synchronized(tlsLock) {
            c.nativeReceiveBatch(h, buf, buf.size, lengths, lengths.size)
        }
        fun push(f: ByteArray): Int = synchronized(tlsLock) {
            txClient.sendRaw(txHandle, f)
        }
        val pump = Thread {
            var seq = 1
            var iter = 0
            while (!stop.get()) {
                synchronized(tlsLock) {
                    val t = rxClient.nativeReceiveBatch(rxHandle, buf, buf.size, lengths, lengths.size)
                    if (t > 0) {
                        rxBytes.addAndGet(t.toLong())
                        for (l in lengths) { if (l == 0) break; rxPkts.incrementAndGet() }
                    }
                    // Occasionally drain the sender session so server
                    // keepalives never stall its write queue. Rare because
                    // its poll() blocks 100 ms when there is nothing to read.
                    if (iter % 100 == 0) {
                        txClient.nativeReceiveBatch(txHandle, buf, buf.size, lengths, lengths.size)
                    }
                }
                repeat(16) {
                    val r = txClient.sendRaw(txHandle, buildFrame(seq and 0xFFFF))
                    if (r > 0) { txBytes.addAndGet(r.toLong()); seq++ }
                }
                iter++
            }
        }
        pump.start()
        Thread.sleep(warmupMs)
        txBytes.set(0); rxBytes.set(0); rxPkts.set(0)
        Log.i(TAG, "Measurement window started (${durationMs} ms)")
        Thread.sleep(durationMs)
        stop.set(true)

        val deadline = System.currentTimeMillis() + 15000
        while (pump.isAlive && System.currentTimeMillis() < deadline) Thread.sleep(100)

        Log.i(TAG, "tx stats: ${txClient.nativeGetStats(txHandle)?.contentToString()}")
        Log.i(TAG, "rx stats: ${rxClient.nativeGetStats(rxHandle)?.contentToString()}")

        val mode = if (useTcp) "TCP" else "UDP"
        Log.i(TAG, String.format("RESULT %s TX: %.2f Mbps | RX: %.2f Mbps (%d pkts)",
            mode,
            txBytes.get() * 8.0 / 1e6 / (durationMs / 1000.0),
            rxBytes.get() * 8.0 / 1e6 / (durationMs / 1000.0), rxPkts.get()))

        // Results are logged; skip native teardown entirely. Concurrent TLS
        // I/O on two connections sharing the cached SSL_CTX can corrupt the
        // TLS layer during shutdown, and the process exits right after anyway.
        kotlin.system.exitProcess(0)
    }

    @Test
    fun benchmarkTcp() {
        val durationMs = arg("durationMs", "15000").toLong()
        val warmupMs = arg("warmupMs", "5000").toLong()
        val (tx, rx, rxp) = runFlood(useTcp = true, durationMs, warmupMs)
        Log.i(TAG, String.format("RESULT TCP TX: %.2f Mbps | RX: %.2f Mbps (%d reply pkts)",
            tx * 8.0 / 1e6 / (durationMs / 1000.0),
            rx * 8.0 / 1e6 / (durationMs / 1000.0), rxp))
    }

    @Test
    fun benchmarkUdp() {
        val durationMs = arg("durationMs", "15000").toLong()
        val warmupMs = arg("warmupMs", "15000").toLong() // RUDP ~10s stability gate
        val (tx, rx, rxp) = runFlood(useTcp = false, durationMs, warmupMs)
        Log.i(TAG, String.format("RESULT UDP TX: %.2f Mbps | RX: %.2f Mbps (%d reply pkts)",
            tx * 8.0 / 1e6 / (durationMs / 1000.0),
            rx * 8.0 / 1e6 / (durationMs / 1000.0), rxp))
    }

    @Test
    fun benchmarkPairedTcp() {
        val durationMs = arg("durationMs", "15000").toLong()
        val warmupMs = arg("warmupMs", "5000").toLong()
        val (tx, rx, rxp) = runPairedFlood(true, durationMs, warmupMs)
        Log.i(TAG, String.format("RESULT TCP TX: %.2f Mbps | RX: %.2f Mbps (%d pkts)",
            tx * 8.0 / 1e6 / (durationMs / 1000.0),
            rx * 8.0 / 1e6 / (durationMs / 1000.0), rxp))
    }

    @Test
    fun benchmarkPairedUdp() {
        val durationMs = arg("durationMs", "15000").toLong()
        val warmupMs = arg("warmupMs", "15000").toLong()
        val (tx, rx, rxp) = runPairedFlood(false, durationMs, warmupMs)
        Log.i(TAG, String.format("RESULT UDP TX: %.2f Mbps | RX: %.2f Mbps (%d pkts)",
            tx * 8.0 / 1e6 / (durationMs / 1000.0),
            rx * 8.0 / 1e6 / (durationMs / 1000.0), rxp))
    }
}
