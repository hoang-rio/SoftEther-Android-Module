package vn.unlimit.softether.client

import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SoftEtherClient - JNI bridge wrapper to native SoftEther implementation
 * Provides high-level API for connection management
 */
class SoftEtherClient {

    private val tag = "SoftEtherClient"
    private var nativeHandle: Long = 0
    private val isConnected = AtomicBoolean(false)
    
    // External handle set by ConnectionController when it manages the native connection directly
    @Volatile
    var externalHandle: Long = 0

    init {
        System.loadLibrary("softether")
    }

    /**
     * Set half/full-duplex mode (Phase 17).
     * @param halfConnection true = half-duplex (directional C2S/S2C split),
     *   false = full-duplex (all connections BOTH). Must be called before connect.
     */
    fun setHalfConnection(halfConnection: Boolean) {
        if (nativeHandle == 0L) return
        nativeSetHalfConnection(nativeHandle, halfConnection)
    }

    /**
     * Get all active TCP socket FDs (primary + additional) for VpnService.protect()
     * @return Array of socket FDs, or null if none
     */
    fun getAllSocketFds(): IntArray? {
        if (nativeHandle == 0L) return null
        return nativeGetAllSocketFds(nativeHandle)
    }

    /**
     * Disconnect from VPN server
     */
    fun disconnect() {
        if (!isConnected.getAndSet(false) || nativeHandle == 0L) {
            return
        }

        Log.d(tag, "Disconnecting...")
        nativeDisconnect(nativeHandle)
        nativeDestroy(nativeHandle)
        nativeHandle = 0
        Log.d(tag, "Disconnected")
    }

    /**
     * Send data through the VPN tunnel
     *
     * @param data Data to send
     * @return Number of bytes sent, or -1 on error
     */
    fun send(data: ByteArray): Int {
        val handle = externalHandle.takeIf { it != 0L } ?: nativeHandle
        if (handle == 0L) return -1
        return nativeSend(handle, data, data.size)
    }

    /**
     * Send a slice of [buffer] through the VPN tunnel without copying
     * (Phase 13E: lets the TUN read loop pass its scratch buffer directly).
     *
     * @return Number of bytes sent, or -1 on error
     */
    fun send(buffer: ByteArray, offset: Int, length: Int): Int {
        val handle = externalHandle.takeIf { it != 0L } ?: nativeHandle
        if (handle == 0L) return -1
        return nativeSendSlice(handle, buffer, offset, length)
    }

    /**
     * Receive data from the VPN tunnel
     *
     * @param buffer Buffer to store received data
     * @return Number of bytes received, 0 for keepalive, or -1 on error
     */
    fun receive(buffer: ByteArray): Int {
        val handle = externalHandle.takeIf { it != 0L } ?: nativeHandle
        if (handle == 0L) return -1
        return nativeReceive(handle, buffer, buffer.size)
    }

    /**
     * Receive multiple packets in one call (Phase 13D).
     *
     * @param buffer Buffer to store received frames contiguously
     * @param lengths Output array; lengths[0..n-1] receive per-frame sizes,
     *                remaining entries are zeroed. Size caps the batch.
     * @return Total bytes written into buffer (0 = nothing available), or -1 on error
     */
    fun receiveBatch(buffer: ByteArray, lengths: IntArray): Int {
        val handle = externalHandle.takeIf { it != 0L } ?: nativeHandle
        if (handle == 0L) return -1
        return nativeReceiveBatch(handle, buffer, buffer.size, lengths, lengths.size)
    }

    /**
     * Permanent traffic/health counters (Phase 13G).
     *
     * @return Snapshot of native counters, or null when disconnected
     */
    fun getStats(): NativeStats? {
        val handle = externalHandle.takeIf { it != 0L } ?: nativeHandle
        if (handle == 0L) return null
        val arr = nativeGetStats(handle) ?: return null
        if (arr.size < 9) return null
        return NativeStats(
            txPackets = arr[0],
            txBytes = arr[1],
            rxPackets = arr[2],
            rxBytes = arr[3],
            rxSkippedBlocks = arr[4],
            rudpOverflowCount = arr[5],
            rudpRxPackets = arr[6],
            rudpTickGaps = arr[7],
            rudpDataSuspended = arr[8] != 0L
        )
    }

    /**
     * Check if currently connected
     */
    fun isConnected(): Boolean = isConnected.get()

    /**
     * Set connection timeout
     *
     * @param timeoutMs Timeout in milliseconds
     */
    fun setTimeout(timeoutMs: Int) {
        if (nativeHandle != 0L) {
            nativeSetOption(nativeHandle, OPTION_TIMEOUT, timeoutMs.toLong())
        }
    }

    // Native methods
    external fun nativeCreate(): Long
    external fun nativeDestroy(handle: Long)
    external fun nativeConnect(
        handle: Long,
        host: String,
        port: Int,
        username: String,
        password: String
    ): Int
    external fun nativeConnectWithHub(
        handle: Long,
        host: String,
        port: Int,
        username: String,
        password: String,
        hubName: String,
        useTcp: Boolean,
        clientProductName: String,
        clientVersion: String,
        clientBuild: Int,
        clientOsName: String,
        clientOsVersion: String,
        clientOsProductId: String,
        clientHostName: String,
        clientIpAddress: String,
        clientPort: Int,
        serverHostName: String,
        serverIpAddress: String,
        serverPort: Int
    ): Int
    external fun nativeDisconnect(handle: Long)
    external fun nativeGetState(handle: Long): Int
    external fun nativeSend(handle: Long, data: ByteArray, length: Int): Int
    external fun nativeSendSlice(handle: Long, data: ByteArray, offset: Int, length: Int): Int
    external fun nativeGetStats(handle: Long): LongArray?
    external fun nativeReceive(handle: Long, buffer: ByteArray, maxLength: Int): Int
    external fun nativeReceiveBatch(handle: Long, buffer: ByteArray, maxLength: Int, lengths: IntArray, maxPackets: Int): Int
    external fun nativeSetOption(handle: Long, option: Int, value: Long)
    external fun nativeGetSocketFd(handle: Long): Int
    external fun nativeGetRudpSocketFd(handle: Long): Int
    external fun nativeGetNatTUdpSocketFd(handle: Long): Int
    external fun nativeDoDhcp(handle: Long): IntArray?
    external fun nativeSetAuthType(handle: Long, authType: Int)
    external fun nativeSetMaxConnection(handle: Long, maxConnections: Int)
    external fun nativeSetHalfConnection(handle: Long, halfConnection: Boolean)
    external fun nativeGetNumConnections(handle: Long): Int
    external fun nativeGetAllSocketFds(handle: Long): IntArray?
    external fun nativeForceCloseSocket(handle: Long)
    external fun nativeGetClientMac(handle: Long): ByteArray?
    external fun nativeSetClientMac(handle: Long, mac: ByteArray)
    external fun nativeSendRaw(handle: Long, data: ByteArray, length: Int): Int

    /**
     * This session's virtual MAC address (6 bytes), or null if the handle is invalid.
     */
    fun getClientMac(handle: Long = nativeHandle): ByteArray? = nativeGetClientMac(handle)

    /**
     * Set a stable client MAC (local-bridge ARP stability across reconnects).
     */
    fun setClientMac(handle: Long = nativeHandle, mac: ByteArray) = nativeSetClientMac(handle, mac)

    /**
     * Send a raw L2 Ethernet frame (no automatic Ethernet-header wrapping).
     * Benchmark/diagnostics use only.
     */
    fun sendRaw(handle: Long = nativeHandle, frame: ByteArray): Int =
        nativeSendRaw(handle, frame, frame.size)

    /**
     * Perform DHCP over SoftEther tunnel to get IP configuration
     * @param handle Native connection handle (from ConnectionController)
     * @return DhcpResult or null on failure
     */
    fun doDhcp(handle: Long = nativeHandle): DhcpResult? {
        if (handle == 0L) return null
        val arr = nativeDoDhcp(handle) ?: return null
        if (arr.size < 7 || arr[0] == 0) return null
        return DhcpResult(
            assignedIp = intToIpString(arr[1]),
            subnetMask = intToIpString(arr[2]),
            gateway = intToIpString(arr[3]),
            dnsServer = intToIpString(arr[4]),
            dnsServer2 = intToIpString(arr[5]),
            leaseTime = arr[6],
            prefixLength = subnetMaskToPrefix(arr[2])
        )
    }

    companion object {
        // Option types for nativeSetOption
        const val OPTION_TIMEOUT = 1
        const val OPTION_UDP_PORT = 4
        const val OPTION_UDP_ONLY = 5

        private fun intToIpString(ip: Int): String {
            return "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"
        }

        private fun subnetMaskToPrefix(mask: Int): Int {
            var m = mask
            var prefix = 0
            for (i in 31 downTo 0) {
                if ((m and (1 shl i)) != 0) prefix++ else break
            }
            return prefix
        }
    }
}

/**
 * DHCP result from SoftEther tunnel
 */
data class DhcpResult(
    val assignedIp: String,
    val subnetMask: String,
    val gateway: String,
    val dnsServer: String,
    val dnsServer2: String,
    val leaseTime: Int,
    val prefixLength: Int
)

/**
 * Permanent native traffic/health counters (Phase 13G).
 *
 * @param rudpDataSuspended true = data currently routed via TCP while RUDP re-probes
 */
data class NativeStats(
    val txPackets: Long,
    val txBytes: Long,
    val rxPackets: Long,
    val rxBytes: Long,
    val rxSkippedBlocks: Long,
    val rudpOverflowCount: Long,
    val rudpRxPackets: Long,
    val rudpTickGaps: Long,
    val rudpDataSuspended: Boolean
)
