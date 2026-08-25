package vn.unlimit.softether.client

import android.util.Log
import vn.unlimit.softether.model.ConnectionException
import vn.unlimit.softether.model.SoftEtherError
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
     * Connect to SoftEther VPN server
     *
     * @param host Server hostname or IP address
     * @param port Server port (typically 443, 992, or 5555)
     * @param username Authentication username
     * @param password Authentication password
     * @throws ConnectionException if connection fails
     */
    @Throws(ConnectionException::class)
    fun connect(host: String, port: Int, username: String, password: String) {
        connect(host, port, username, password, DEFAULT_HUB_NAME)
    }

    /**
     * Connect to SoftEther VPN server with hub name
     *
     * @param host Server hostname or IP address
     * @param port Server port (typically 443, 992, or 5555)
     * @param username Authentication username
     * @param password Authentication password
     * @param hubName Virtual hub name (default: "VPN" for VPNGate)
     * @throws ConnectionException if connection fails
     */
    @Throws(ConnectionException::class)
    fun connect(host: String, port: Int, username: String, password: String, hubName: String) {
        connect(host, port, username, password, hubName, vn.unlimit.softether.model.AuthMethod.AUTO)
    }

    /**
     * Connect to SoftEther VPN server with hub name and explicit auth method
     *
     * @param host Server hostname or IP address
     * @param port Server port (typically 443, 992, or 5555)
     * @param username Authentication username
     * @param password Authentication password
     * @param hubName Virtual hub name (default: "VPN" for VPNGate)
     * @param authMethod Authentication method to use
     * @throws ConnectionException if connection fails
     */
    @Throws(ConnectionException::class)
    fun connect(host: String, port: Int, username: String, password: String, hubName: String, authMethod: vn.unlimit.softether.model.AuthMethod = vn.unlimit.softether.model.AuthMethod.AUTO) {
        Log.d(tag, "Connecting to $host:$port as $username (hub: $hubName, auth: $authMethod)")

        // Create native connection
        nativeHandle = nativeCreate()
        if (nativeHandle == 0L) {
            throw ConnectionException("Failed to create native connection")
        }

        // Set default timeout
        nativeSetOption(nativeHandle, OPTION_TIMEOUT, 30000L)

        // Set auth type if not AUTO
        if (authMethod != vn.unlimit.softether.model.AuthMethod.AUTO) {
            val authTypeInt = when (authMethod) {
                vn.unlimit.softether.model.AuthMethod.ANONYMOUS -> 0
                vn.unlimit.softether.model.AuthMethod.PASSWORD -> 1
                vn.unlimit.softether.model.AuthMethod.PLAIN_PASSWORD -> 2
                vn.unlimit.softether.model.AuthMethod.AUTO -> 0
            }
            nativeSetAuthType(nativeHandle, authTypeInt)
        }

        // Build client info for server session list
        val clientInfo = vn.unlimit.softether.model.ClientInfoFactory.build(
            productName = "SoftEther VPN Client for Android",
            productVersion = "2.3.2",
            productBuild = 132,
            config = vn.unlimit.softether.model.ConnectionConfig(
                serverHost = host,
                serverPort = port,
                username = username,
                password = password,
                virtualHub = hubName
            )
        )

        // Connect to server with hub name
        val result = nativeConnectWithHub(nativeHandle, host, port, username, password, hubName,
            false,
            clientInfo.productName, clientInfo.productVersion, clientInfo.productBuild,
            clientInfo.osName, clientInfo.osVersion, clientInfo.osProductId,
            clientInfo.hostName, clientInfo.clientIpAddress, clientInfo.clientPort,
            clientInfo.serverHostName, clientInfo.serverIpAddress, clientInfo.serverPort)

        if (result != SoftEtherError.ERR_NONE) {
            nativeDestroy(nativeHandle)
            nativeHandle = 0
            throw ConnectionException("Connection failed: ${SoftEtherError.getErrorString(result)}")
        }

        isConnected.set(true)
        Log.d(tag, "Connected successfully")
    }

    /**
     * Set authentication type explicitly before connecting.
     * @param authMethod The authentication method to use
     */
    fun setAuthType(authMethod: vn.unlimit.softether.model.AuthMethod) {
        if (nativeHandle == 0L) return
        val authTypeInt = when (authMethod) {
            vn.unlimit.softether.model.AuthMethod.ANONYMOUS -> 0
            vn.unlimit.softether.model.AuthMethod.PASSWORD -> 1
            vn.unlimit.softether.model.AuthMethod.PLAIN_PASSWORD -> 2
            vn.unlimit.softether.model.AuthMethod.AUTO -> 0
        }
        nativeSetAuthType(nativeHandle, authTypeInt)
    }

    /**
     * Set the maximum number of TCP connections for multi-connection support
     * @param maxConnections Target number of connections (1-8, default 4)
     */
    fun setMaxConnection(maxConnections: Int) {
        if (nativeHandle == 0L) return
        nativeSetMaxConnection(nativeHandle, maxConnections.coerceIn(1, 8))
    }

    /**
     * Get the current number of active TCP connections (primary + additional)
     * @return Number of active connections
     */
    fun getNumConnections(): Int {
        if (nativeHandle == 0L) return 0
        return nativeGetNumConnections(nativeHandle)
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

    /**
     * Set keepalive interval
     *
     * @param intervalMs Keepalive interval in milliseconds
     */
    fun setKeepAliveInterval(intervalMs: Int) {
        if (nativeHandle != 0L) {
            nativeSetOption(nativeHandle, OPTION_KEEPALIVE_INTERVAL, intervalMs.toLong())
        }
    }

    /**
     * Set MTU for the connection
     *
     * @param mtu Maximum Transmission Unit
     */
    fun setMtu(mtu: Int) {
        if (nativeHandle != 0L) {
            nativeSetOption(nativeHandle, OPTION_MTU, mtu.toLong())
        }
    }

    /**
     * Cleanup resources
     */
    fun cleanup() {
        disconnect()
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
        const val OPTION_KEEPALIVE_INTERVAL = 2
        const val OPTION_MTU = 3
        const val OPTION_UDP_PORT = 4
        const val OPTION_UDP_ONLY = 5
        
        // Default hub name for VPNGate servers
        const val DEFAULT_HUB_NAME = "VPN"

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

/**
 * Custom exception for connection errors
 */
class ConnectionException(message: String) : Exception(message)

/**
 * SoftEther error codes matching native implementation
 */
object SoftEtherError {
    const val ERR_NONE = 0
    const val ERR_TCP_CONNECT = 1
    const val ERR_TLS_HANDSHAKE = 2
    const val ERR_PROTOCOL_VERSION = 3
    const val ERR_AUTHENTICATION = 4
    const val ERR_SESSION = 5
    const val ERR_DATA_TRANSMISSION = 6
    const val ERR_TIMEOUT = 7
    const val ERR_UNKNOWN = 99

    fun getErrorString(code: Int): String {
        return when (code) {
            ERR_NONE -> "No error"
            ERR_TCP_CONNECT -> "TCP connection failed"
            ERR_TLS_HANDSHAKE -> "TLS handshake failed"
            ERR_PROTOCOL_VERSION -> "Protocol version mismatch"
            ERR_AUTHENTICATION -> "Authentication failed"
            ERR_SESSION -> "Session setup failed"
            ERR_DATA_TRANSMISSION -> "Data transmission failed"
            ERR_TIMEOUT -> "Operation timed out"
            ERR_UNKNOWN -> "Unknown error"
            else -> "Undefined error ($code)"
        }
    }
}
