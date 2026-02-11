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
        Log.d(tag, "Connecting to $host:$port as $username")

        // Create native connection
        nativeHandle = nativeCreate()
        if (nativeHandle == 0L) {
            throw ConnectionException("Failed to create native connection")
        }

        // Set default timeout
        nativeSetOption(nativeHandle, OPTION_TIMEOUT, 30000L)

        // Connect to server
        val result = nativeConnect(nativeHandle, host, port, username, password)

        if (result != SoftEtherError.ERR_NONE) {
            nativeDestroy(nativeHandle)
            nativeHandle = 0
            throw ConnectionException("Connection failed: ${SoftEtherError.getErrorString(result)}")
        }

        isConnected.set(true)
        Log.d(tag, "Connected successfully")
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
        if (!isConnected.get() || nativeHandle == 0L) {
            return -1
        }
        return nativeSend(nativeHandle, data, data.size)
    }

    /**
     * Receive data from the VPN tunnel
     *
     * @param buffer Buffer to store received data
     * @return Number of bytes received, 0 for keepalive, or -1 on error
     */
    fun receive(buffer: ByteArray): Int {
        if (!isConnected.get() || nativeHandle == 0L) {
            return -1
        }
        return nativeReceive(nativeHandle, buffer, buffer.size)
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
    external fun nativeDisconnect(handle: Long)
    external fun nativeSend(handle: Long, data: ByteArray, length: Int): Int
    external fun nativeReceive(handle: Long, buffer: ByteArray, maxLength: Int): Int
    external fun nativeSetOption(handle: Long, option: Int, value: Long)

    companion object {
        // Option types for nativeSetOption
        const val OPTION_TIMEOUT = 1
        const val OPTION_KEEPALIVE_INTERVAL = 2
        const val OPTION_MTU = 3
    }
}

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
