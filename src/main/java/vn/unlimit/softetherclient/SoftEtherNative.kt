package vn.unlimit.softetherclient

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Native SoftEther VPN client using the reimplemented protocol.
 * This class provides a Kotlin interface to the native SoftEther VPN protocol implementation.
 */
class SoftEtherNative {

    companion object {
        private const val TAG = "SoftEtherNative"

        // Connection states
        const val STATE_DISCONNECTED = 0
        const val STATE_CONNECTING = 1
        const val STATE_CONNECTED = 2
        const val STATE_DISCONNECTING = 3
        const val STATE_ERROR = 4

        // Error codes
        const val ERR_NO_ERROR = 0
        const val ERR_CONNECT_FAILED = 1
        const val ERR_AUTH_FAILED = 2
        const val ERR_SERVER_CERT_INVALID = 3
        const val ERR_DHCP_FAILED = 4
        const val ERR_TUN_CREATE_FAILED = 5

        // Track if native library is available
        @JvmStatic
        var isNativeLibraryAvailable = false
            private set

        init {
            try {
                System.loadLibrary("softether-native")
                isNativeLibraryAvailable = true
                Log.i(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Native library not available: ${e.message}")
                isNativeLibraryAvailable = false
            }
        }
    }

    /**
     * Interface for connection state callbacks
     */
    interface ConnectionListener {
        fun onStateChanged(state: Int)
        fun onError(errorCode: Int, errorMessage: String?)
        fun onConnectionEstablished(virtualIp: String?, subnetMask: String?, dnsServer: String?)
        fun onPacketReceived(packet: ByteArray?)
        fun onBytesTransferred(sent: Long, received: Long)
    }

    /**
     * Connection parameters for SoftEther VPN
     */
    data class ConnectionParams(
        var serverHost: String? = null,
        var serverPort: Int = 443,
        var hubName: String = "VPN",
        var username: String? = null,
        var password: String? = null,
        var useEncrypt: Boolean = true,
        var useCompress: Boolean = false,
        var reconnectRetries: Int = 3,
        var checkServerCert: Boolean = false,
        var proxyHost: String? = null,
        var proxyPort: Int = 0,
        var proxyType: Int = 0, // 0: None, 1: HTTP, 2: SOCKS
        var mtu: Int = 1400
    )

    private var nativeHandle: Long = 0
    private var state: Int = STATE_DISCONNECTED
    private var vpnService: VpnService? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var connectionListener: ConnectionListener? = null

    // Native methods
    private external fun nativeInit(): Long
    private external fun nativeCleanup(handle: Long)
    private external fun nativeConnect(
        handle: Long,
        serverHost: String,
        serverPort: Int,
        hubName: String,
        username: String,
        password: String,
        useEncrypt: Boolean,
        useCompress: Boolean,
        checkServerCert: Boolean,
        tunFd: Int
    ): Boolean

    private external fun nativeDisconnect(handle: Long)
    private external fun nativeGetStatus(handle: Long): Int
    private external fun nativeGetStatistics(handle: Long): LongArray
    private external fun nativeGetLastError(handle: Long): Int
    private external fun nativeGetErrorString(handle: Long): String
    private external fun nativeGetProtocolVersion(): Int
    private external fun nativeIsLibraryLoaded(): Boolean

    // Test native methods
    private external fun nativeTestConnect(
        serverHost: String,
        serverPort: Int,
        hubName: String,
        username: String,
        password: String
    ): Int

    private external fun nativeTestEcho(message: String): String

    /**
     * Initialize the native client
     */
    fun initialize(): Boolean {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot initialize: native library not available")
            return false
        }

        return try {
            nativeHandle = nativeInit()
            nativeHandle != 0L
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeInit failed: ${e.message}")
            false
        }
    }

    /**
     * Cleanup native resources
     */
    fun cleanup() {
        if (nativeHandle != 0L) {
            try {
                nativeCleanup(nativeHandle)
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "nativeCleanup failed: ${e.message}")
            }
            nativeHandle = 0L
        }
    }

    /**
     * Connect to SoftEther VPN server
     */
    fun connect(service: VpnService, params: ConnectionParams): Boolean {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot connect: native library not available")
            setState(STATE_ERROR)
            onError(ERR_CONNECT_FAILED, "SoftEther native library not available")
            return false
        }

        if (nativeHandle == 0L) {
            if (!initialize()) {
                setState(STATE_ERROR)
                onError(ERR_CONNECT_FAILED, "Failed to initialize native client")
                return false
            }
        }

        if (state != STATE_DISCONNECTED && state != STATE_ERROR) {
            Log.w(TAG, "Already connected or connecting")
            return false
        }

        if (params.serverHost == null || params.username == null || params.password == null) {
            Log.e(TAG, "Missing required connection parameters")
            setState(STATE_ERROR)
            onError(ERR_CONNECT_FAILED, "Missing server host, username or password")
            return false
        }

        this.vpnService = service
        setState(STATE_CONNECTING)

        return try {
            // Create TUN interface
            val builder = service.Builder()
            builder.setMtu(params.mtu)
            builder.addAddress("10.0.0.2", 24)
            builder.addRoute("0.0.0.0", 0)
            builder.addDnsServer("8.8.8.8")
            builder.setSession("SoftEther VPN")

            tunInterface = builder.establish()
            if (tunInterface == null) {
                setState(STATE_ERROR)
                onError(ERR_TUN_CREATE_FAILED, "Failed to create TUN interface")
                return false
            }

            // Start native connection
            val tunFd = tunInterface!!.fd
            val result = nativeConnect(
                nativeHandle,
                params.serverHost!!,
                params.serverPort,
                params.hubName,
                params.username!!,
                params.password!!,
                params.useEncrypt,
                params.useCompress,
                params.checkServerCert,
                tunFd
            )

            if (!result) {
                val errorCode = nativeGetLastError(nativeHandle)
                val errorString = nativeGetErrorString(nativeHandle)
                setState(STATE_ERROR)
                onError(errorCode, errorString)
                closeTunInterface()
                return false
            }

            true
        } catch (e: Exception) {
            Log.e(TAG, "Error connecting", e)
            setState(STATE_ERROR)
            onError(ERR_CONNECT_FAILED, e.message)
            closeTunInterface()
            false
        }
    }

    /**
     * Disconnect from VPN server
     */
    fun disconnect() {
        if (state == STATE_DISCONNECTED || state == STATE_DISCONNECTING) {
            return
        }

        setState(STATE_DISCONNECTING)

        if (nativeHandle != 0L) {
            try {
                nativeDisconnect(nativeHandle)
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "nativeDisconnect failed: ${e.message}")
            }
        }

        closeTunInterface()
        setState(STATE_DISCONNECTED)
    }

    /**
     * Get current connection state
     */
    fun getState(): Int {
        if (nativeHandle != 0L) {
            try {
                return nativeGetStatus(nativeHandle)
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "nativeGetStatus failed: ${e.message}")
            }
        }
        return state
    }

    /**
     * Get connection statistics
     */
    fun getStatistics(): Pair<Long, Long> {
        if (nativeHandle != 0L) {
            try {
                val stats = nativeGetStatistics(nativeHandle)
                if (stats.size >= 2) {
                    return Pair(stats[0], stats[1])
                }
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "nativeGetStatistics failed: ${e.message}")
            }
        }
        return Pair(0L, 0L)
    }

    /**
     * Get the last error code
     */
    fun getLastError(): Int {
        if (nativeHandle != 0L) {
            try {
                return nativeGetLastError(nativeHandle)
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "nativeGetLastError failed: ${e.message}")
            }
        }
        return ERR_CONNECT_FAILED
    }

    /**
     * Get the last error string
     */
    fun getLastErrorString(): String {
        if (nativeHandle != 0L) {
            try {
                return nativeGetErrorString(nativeHandle)
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "nativeGetErrorString failed: ${e.message}")
            }
        }
        return "Unknown error"
    }

    /**
     * Get native protocol version
     */
    fun getProtocolVersion(): Int {
        return try {
            nativeGetProtocolVersion()
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeGetProtocolVersion failed: ${e.message}")
            0
        }
    }

    /**
     * Set the connection listener
     */
    fun setConnectionListener(listener: ConnectionListener?) {
        this.connectionListener = listener
    }

    private fun setState(newState: Int) {
        this.state = newState
        connectionListener?.onStateChanged(newState)
    }

    private fun closeTunInterface() {
        tunInterface?.let {
            try {
                it.close()
            } catch (e: Exception) {
                Log.e(TAG, "Error closing TUN interface", e)
            }
            tunInterface = null
        }
    }

    /**
     * Called from native code when connection is established
     */
    @Suppress("unused")
    private fun onConnectionEstablished(virtualIp: String, subnetMask: String, dnsServer: String) {
        setState(STATE_CONNECTED)
        connectionListener?.onConnectionEstablished(virtualIp, subnetMask, dnsServer)
    }

    /**
     * Called from native code when error occurs
     */
    @Suppress("unused")
    private fun onError(errorCode: Int, errorMessage: String?) {
        connectionListener?.onError(errorCode, errorMessage)
    }

    /**
     * Called from native code to report statistics
     */
    @Suppress("unused")
    private fun onBytesTransferred(sent: Long, received: Long) {
        connectionListener?.onBytesTransferred(sent, received)
    }

    /**
     * Called from native code when packet is received
     */
    @Suppress("unused")
    private fun onPacketReceived(packet: ByteArray) {
        connectionListener?.onPacketReceived(packet)
    }

    /**
     * Check if native library is loaded
     */
    fun isLibraryLoaded(): Boolean {
        return try {
            nativeIsLibraryLoaded()
        } catch (e: UnsatisfiedLinkError) {
            false
        }
    }

    // ============================================================================
    // Test Functions - For testing without VPN service
    // ============================================================================

    /**
     * Test native connection without VPN service
     * This function tests the connection logic without requiring TUN interface
     *
     * @param params Connection parameters
     * @return Error code: 0 = success, >0 = error
     */
    fun testConnect(params: ConnectionParams): Int {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot test connect: native library not available")
            return ERR_CONNECT_FAILED
        }

        if (params.serverHost == null || params.username == null || params.password == null) {
            Log.e(TAG, "Missing required connection parameters")
            return ERR_CONNECT_FAILED
        }

        return try {
            nativeTestConnect(
                params.serverHost!!,
                params.serverPort,
                params.hubName,
                params.username!!,
                params.password!!
            )
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeTestConnect failed: ${e.message}")
            ERR_CONNECT_FAILED
        }
    }

    /**
     * Test function to verify native method calling works
     *
     * @param message Message to echo
     * @return Echo response from native code
     */
    fun testEcho(message: String): String {
        return try {
            nativeTestEcho(message)
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeTestEcho failed: ${e.message}")
            "Error: ${e.message}"
        }
    }
}
