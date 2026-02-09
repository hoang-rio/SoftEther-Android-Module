package vn.unlimit.softetherclient

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Native SoftEther VPN client for Android.
 * This class provides a Kotlin interface to the native SoftEther VPN protocol implementation.
 */
class SoftEtherClient {

    companion object {
        private const val TAG = "SoftEtherClient"

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
                System.loadLibrary("softether-jni")
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
        var proxyType: Int = 0 // 0: None, 1: HTTP, 2: SOCKS
    )

    private var nativeHandle: Long = 0
    private var state: Int = STATE_DISCONNECTED
    private var vpnService: VpnService? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var connectionListener: ConnectionListener? = null

    /**
     * Initialize the SoftEther client
     * @return true if successful
     */
    external fun nativeInit(): Boolean

    /**
     * Cleanup the SoftEther client
     */
    external fun nativeCleanup()

    /**
     * Connect to SoftEther VPN server
     * @param params Connection parameters
     * @param tunFd File descriptor of the TUN interface
     * @return true if connection started successfully
     */
    private external fun nativeConnect(params: ConnectionParams, tunFd: Int): Boolean

    /**
     * Disconnect from VPN server
     */
    external fun nativeDisconnect()

    /**
     * Get current connection status
     * @return status code
     */
    external fun nativeGetStatus(): Int

    /**
     * Get connection statistics
     * @return array [sent_bytes, received_bytes]
     */
    external fun nativeGetStatistics(): LongArray

    /**
     * Write packet to VPN (called from native code)
     * @param packet IP packet data
     * @return true if successful
     */
    private external fun nativeWritePacket(packet: ByteArray?): Boolean

    /**
     * Read packet from VPN (called from native code)
     * @param buffer buffer to store packet data
     * @return number of bytes read, or -1 if no packet available
     */
    private external fun nativeReadPacket(buffer: ByteArray?): Int

    /**
     * Set the connection listener
     */
    fun setConnectionListener(listener: ConnectionListener?) {
        this.connectionListener = listener
    }

    /**
     * Get current connection state
     */
    fun getState(): Int = state

    /**
     * Safely initialize the client with library availability check
     */
    fun doNativeInit(): Boolean {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot initialize: native library not available")
            return false
        }
        return try {
            nativeInit()
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeInit failed: ${e.message}")
            false
        }
    }

    /**
     * Safely cleanup with library availability check
     */
    fun doNativeCleanup() {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot cleanup: native library not available")
            return
        }
        try {
            nativeCleanup()
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeCleanup failed: ${e.message}")
        }
    }

    /**
     * Safely connect with library availability check
     */
    private fun doNativeConnect(params: ConnectionParams, tunFd: Int): Boolean {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot connect: native library not available")
            return false
        }
        return try {
            nativeConnect(params, tunFd)
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeConnect failed: ${e.message}")
            false
        }
    }

    /**
     * Safely disconnect with library availability check
     */
    fun doNativeDisconnect() {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot disconnect: native library not available")
            return
        }
        try {
            nativeDisconnect()
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeDisconnect failed: ${e.message}")
        }
    }

    /**
     * Connect to VPN with the given parameters
     */
    fun connect(service: VpnService, params: ConnectionParams): Boolean {
        if (!isNativeLibraryAvailable) {
            Log.e(TAG, "Cannot connect: native library not available")
            setState(STATE_ERROR)
            onError(ERR_CONNECT_FAILED, "SoftEther native library not available")
            return false
        }

        if (state != STATE_DISCONNECTED && state != STATE_ERROR) {
            Log.w(TAG, "Already connected or connecting")
            return false
        }

        this.vpnService = service
        setState(STATE_CONNECTING)

        return try {
            // Initialize native client first
            if (!doNativeInit()) {
                setState(STATE_ERROR)
                onError(ERR_CONNECT_FAILED, "Failed to initialize native client")
                return false
            }

            // Create TUN interface
            val builder = service.Builder()
            builder.setMtu(1400)
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
            val result = doNativeConnect(params, tunFd)

            if (!result) {
                setState(STATE_ERROR)
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
     * Disconnect from VPN
     */
    fun disconnect() {
        if (state == STATE_DISCONNECTED || state == STATE_DISCONNECTING) {
            return
        }

        setState(STATE_DISCONNECTING)
        doNativeDisconnect()
        closeTunInterface()
        setState(STATE_DISCONNECTED)
    }

    /**
     * Cleanup resources
     */
    fun cleanup() {
        disconnect()
        doNativeCleanup()
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

    private fun setState(newState: Int) {
        this.state = newState
        connectionListener?.onStateChanged(newState)
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
}