package vn.unlimit.softether.controller

import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import vn.unlimit.softether.SoftEtherVpnService
import vn.unlimit.softether.client.SoftEtherClient
import vn.unlimit.softether.client.protocol.KeepAliveManager
import vn.unlimit.softether.client.protocol.PacketHandler
import vn.unlimit.softether.model.ConnectionConfig
import vn.unlimit.softether.model.ConnectionState
import vn.unlimit.softether.terminal.TunTerminal
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * ConnectionController - Manages the SoftEther VPN connection lifecycle
 * Implements complete data forwarding between TUN interface and SoftEther connection
 */
class ConnectionController(
    private val service: SoftEtherVpnService,
    private val config: ConnectionConfig,
    private val onStateChange: (ConnectionState) -> Unit,
    private val onError: (String) -> Unit
) {
    companion object {
        private const val TAG = "ConnectionController"
        private const val MAX_RECONNECT_ATTEMPTS = 3
        private const val RECONNECT_DELAY_MS = 3000L
        private const val DATA_LOOP_DELAY_MS = 1L
        private const val STATS_INTERVAL_MS = 10000L
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val client = SoftEtherClient()
    private val isCancelled = AtomicBoolean(false)
    private val isReconnecting = AtomicBoolean(false)
    private val reconnectAttempts = AtomicInteger(0)
    private val connectionMutex = Mutex()

    // Statistics
    private val bytesSent = AtomicLong(0)
    private val bytesReceived = AtomicLong(0)
    private val packetsSent = AtomicLong(0)
    private val packetsReceived = AtomicLong(0)

    private var currentState: ConnectionState = ConnectionState.DISCONNECTED
        set(value) {
            field = value
            onStateChange(value)
        }

    private var nativeHandle: Long = 0
    private var vpnInterface: ParcelFileDescriptor? = null

    /**
     * Initiates VPN connection with automatic retry logic
     */
    suspend fun connect() {
        connectionMutex.withLock {
            if (isCancelled.get()) {
                Log.w(TAG, "Connection cancelled, not starting")
                return
            }
            
            if (currentState != ConnectionState.DISCONNECTED) {
                Log.w(TAG, "Connection already in progress or established")
                return
            }

            try {
                performConnect()
            } catch (e: Exception) {
                if (isCancelled.get()) {
                    Log.d(TAG, "Connection cancelled, not retrying")
                    return
                }
                
                if (reconnectAttempts.incrementAndGet() < MAX_RECONNECT_ATTEMPTS) {
                    Log.w(TAG, "Connection failed, attempting retry ${reconnectAttempts.get()}/$MAX_RECONNECT_ATTEMPTS")
                    delay(RECONNECT_DELAY_MS)
                    connect()
                } else {
                    Log.e(TAG, "Connection failed after ${reconnectAttempts.get()} attempts", e)
                    currentState = ConnectionState.DISCONNECTED
                    onError(e.message ?: "Unknown error")
                    throw e
                }
            }
        }
    }

    /**
     * Perform actual connection
     */
    private suspend fun performConnect() {
        Log.d(TAG, "Starting connection to ${config.serverHost}:${config.serverPort}")
        currentState = ConnectionState.CONNECTING
        isCancelled.set(false)

        // Create native connection
        nativeHandle = client.nativeCreate()
        if (nativeHandle == 0L) {
            throw Exception("Failed to create native connection")
        }

        // Check if already cancelled before proceeding
        if (isCancelled.get()) {
            Log.d(TAG, "Connection cancelled before starting")
            val handle = nativeHandle
            nativeHandle = 0  // Clear handle first
            client.nativeDestroy(handle)
            throw CancellationException("Connection cancelled by user")
        }

        // Set timeout
        client.setTimeout(config.connectTimeoutMs)

        currentState = ConnectionState.TLS_HANDSHAKE

        // Connect to server (includes TLS handshake, protocol handshake, auth, session setup)
        val result = client.nativeConnect(
            nativeHandle,
            config.serverHost,
            config.serverPort,
            config.username,
            config.password
        )

        // Check if cancelled during connection
        if (isCancelled.get()) {
            Log.d(TAG, "Connection was cancelled during connect")
            val handle = nativeHandle
            nativeHandle = 0  // Clear handle first
            client.nativeDisconnect(handle)
            client.nativeDestroy(handle)
            throw CancellationException("Connection cancelled by user")
        }

        if (result != 0) {
            val handle = nativeHandle
            nativeHandle = 0  // Clear handle first
            client.nativeDestroy(handle)
            throw Exception("Connection failed with error code: $result")
        }

        currentState = ConnectionState.CONNECTED
        reconnectAttempts.set(0) // Reset on successful connection
        Log.d(TAG, "VPN connection established successfully")

        // Check if cancelled before establishing VPN interface
        if (isCancelled.get()) {
            Log.d(TAG, "Connection cancelled after successful connect, tearing down")
            val handle = nativeHandle
            nativeHandle = 0  // Clear handle first
            client.nativeDisconnect(handle)
            client.nativeDestroy(handle)
            throw CancellationException("Connection cancelled by user")
        }

        // Establish VPN interface
        vpnInterface = service.establishVpnInterface(config)
            ?: throw Exception("Failed to establish VPN interface")

        // Start data forwarding loops
        startDataForwarding()

        // Start statistics logging
        startStatisticsLogging()
    }

    /**
     * Attempt to reconnect using stored credentials
     */
    suspend fun reconnect(): Boolean {
        if (isReconnecting.getAndSet(true)) {
            Log.w(TAG, "Reconnection already in progress")
            return false
        }

        return try {
            Log.d(TAG, "Attempting to reconnect...")
            disconnect()
            delay(RECONNECT_DELAY_MS)
            connect()
            true
        } catch (e: Exception) {
            Log.e(TAG, "Reconnection failed", e)
            false
        } finally {
            isReconnecting.set(false)
        }
    }

    /**
     * Disconnect VPN gracefully
     */
    fun disconnect() {
        Log.d(TAG, "Disconnecting VPN")
        isCancelled.set(true)

        // Use mutex to prevent race with connect()
        connectionMutex.tryLock()
        try {
            // Update state
            if (currentState == ConnectionState.CONNECTED || currentState == ConnectionState.CONNECTING) {
                currentState = ConnectionState.DISCONNECTING
            }

            // Disconnect native connection (this will interrupt any blocking operations)
            if (nativeHandle != 0L) {
                val handle = nativeHandle
                nativeHandle = 0  // Clear the handle first to prevent double-free
                
                try {
                    Log.d(TAG, "Calling nativeDisconnect on handle $handle")
                    client.nativeDisconnect(handle)
                    Log.d(TAG, "nativeDisconnect completed, calling nativeDestroy")
                    client.nativeDestroy(handle)
                    Log.d(TAG, "nativeDestroy completed")
                } catch (e: Exception) {
                    Log.e(TAG, "Error during native disconnect", e)
                }
            }
        } finally {
            if (connectionMutex.isLocked) {
                connectionMutex.unlock()
            }
        }

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        // Cancel all coroutines
        scope.cancel()

        currentState = ConnectionState.DISCONNECTED
        Log.d(TAG, "VPN disconnected. Stats: sent=${bytesSent.get()} bytes (${packetsSent.get()} pkts), " +
                "received=${bytesReceived.get()} bytes (${packetsReceived.get()} pkts)")
    }

    /**
     * Get current connection state
     */
    fun getState(): ConnectionState = currentState

    /**
     * Check if currently connected
     */
    fun isConnected(): Boolean = currentState == ConnectionState.CONNECTED

    /**
     * Get connection statistics
     */
    fun getStatistics(): ConnectionStatistics {
        return ConnectionStatistics(
            bytesSent = bytesSent.get(),
            bytesReceived = bytesReceived.get(),
            packetsSent = packetsSent.get(),
            packetsReceived = packetsReceived.get(),
            reconnectAttempts = reconnectAttempts.get()
        )
    }

    /**
     * Start data forwarding between TUN interface and SoftEther connection
     * This is the core data tunnel implementation
     */
    private fun startDataForwarding() {
        val tunInterface = vpnInterface
            ?: throw IllegalStateException("VPN interface not established")

        val tunTerminal = TunTerminal(tunInterface, scope)
        val packetHandler = PacketHandler(client)
        val keepAliveManager = KeepAliveManager(client)

        // Start TUN interface reading
        tunTerminal.start(
            onPacket = { packet ->
                // Packet from TUN (local system) -> send to VPN
                packetHandler.queuePacket(packet)
            },
            onError = { error ->
                Log.e(TAG, "TUN interface error", error)
                if (!isCancelled.get()) {
                    onError("TUN error: ${error.message}")
                    scope.launch { attemptReconnect() }
                }
            }
        )

        // Send loop: TUN -> VPN
        scope.launch {
            val sendBuffer = ByteArray(65535)
            while (isConnected() && !isCancelled.get()) {
                try {
                    val packet = packetHandler.pollSendQueue()
                    if (packet != null) {
                        val result = client.send(packet)
                        if (result > 0) {
                            bytesSent.addAndGet(result.toLong())
                            packetsSent.incrementAndGet()
                        } else if (result < 0) {
                            Log.w(TAG, "Send failed: $result")
                            if (isConnected()) {
                                scope.launch { attemptReconnect() }
                                break
                            }
                        }
                    } else {
                        // No packets to send, brief delay
                        delay(DATA_LOOP_DELAY_MS)
                    }
                } catch (e: CancellationException) {
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Send loop error", e)
                    if (isConnected()) {
                        scope.launch { attemptReconnect() }
                    }
                    break
                }
            }
        }

        // Receive loop: VPN -> TUN
        scope.launch {
            val receiveBuffer = ByteArray(65535)
            while (isConnected() && !isCancelled.get()) {
                try {
                    val result = client.receive(receiveBuffer)
                    when {
                        result > 0 -> {
                            // Valid data received
                            val packet = receiveBuffer.copyOf(result)
                            val writeResult = tunTerminal.write(packet)
                            if (writeResult > 0) {
                                bytesReceived.addAndGet(result.toLong())
                                packetsReceived.incrementAndGet()
                            }
                        }
                        result == 0 -> {
                            // Keepalive or no data, brief delay
                            keepAliveManager.recordReceived()
                            delay(DATA_LOOP_DELAY_MS)
                        }
                        result < 0 -> {
                            // Error receiving
                            Log.e(TAG, "Receive error: $result")
                            if (isConnected() && !isCancelled.get()) {
                                scope.launch { attemptReconnect() }
                            }
                            break
                        }
                    }
                } catch (e: CancellationException) {
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Receive loop error", e)
                    if (isConnected() && !isCancelled.get()) {
                        scope.launch { attemptReconnect() }
                    }
                    break
                }
            }
        }

        // Start keepalive
        startKeepalive(keepAliveManager)

        // Cleanup on disconnect
        scope.launch {
            while (isConnected() && !isCancelled.get()) {
                delay(100)
            }
            tunTerminal.stop()
            packetHandler.clearQueues()
        }
    }

    /**
     * Attempt automatic reconnection if enabled and under max attempts
     */
    private suspend fun attemptReconnect() {
        if (isCancelled.get() || isReconnecting.get()) {
            return
        }

        if (reconnectAttempts.incrementAndGet() >= MAX_RECONNECT_ATTEMPTS) {
            Log.e(TAG, "Max reconnection attempts reached")
            onError("Connection lost - max reconnection attempts reached")
            disconnect()
            return
        }

        Log.w(TAG, "Attempting automatic reconnection (${reconnectAttempts.get()}/$MAX_RECONNECT_ATTEMPTS)")

        try {
            // Disconnect current connection
            if (nativeHandle != 0L) {
                val handle = nativeHandle
                nativeHandle = 0  // Clear handle first
                client.nativeDisconnect(handle)
                client.nativeDestroy(handle)
            }

            currentState = ConnectionState.CONNECTING

            // Wait before reconnecting
            delay(RECONNECT_DELAY_MS)

            if (isCancelled.get()) {
                return
            }

            // Create new connection
            nativeHandle = client.nativeCreate()
            if (nativeHandle == 0L) {
                throw Exception("Failed to create native connection for reconnect")
            }

            client.setTimeout(config.connectTimeoutMs)

            val result = client.nativeConnect(
                nativeHandle,
                config.serverHost,
                config.serverPort,
                config.username,
                config.password
            )

            if (result != 0) {
                throw Exception("Reconnection failed with error code: $result")
            }

            currentState = ConnectionState.CONNECTED
            reconnectAttempts.set(0) // Reset on successful reconnection
            Log.d(TAG, "Reconnection successful")

        } catch (e: Exception) {
            Log.e(TAG, "Reconnection attempt failed", e)
            // Will retry on next failure if under max attempts
        }
    }

    /**
     * Start keepalive monitoring
     */
    private fun startKeepalive(keepAliveManager: KeepAliveManager) {
        keepAliveManager.setInterval(config.keepAliveIntervalMs.toLong())
        keepAliveManager.setTimeout(30000L) // 30 second timeout
        keepAliveManager.start()

        scope.launch {
            while (isConnected() && !isCancelled.get()) {
                try {
                    delay(1000) // Check every second

                    if (keepAliveManager.shouldSendKeepAlive()) {
                        // Keepalive is handled in native layer
                        keepAliveManager.recordSent()
                    }

                    if (keepAliveManager.isConnectionDead()) {
                        Log.e(TAG, "Connection appears dead (keepalive timeout)")
                        scope.launch { attemptReconnect() }
                        break
                    }
                } catch (e: CancellationException) {
                    break
                }
            }
            keepAliveManager.stop()
        }
    }

    /**
     * Start periodic statistics logging
     */
    private fun startStatisticsLogging() {
        scope.launch {
            while (isConnected() && !isCancelled.get()) {
                try {
                    delay(STATS_INTERVAL_MS)
                    if (isConnected()) {
                        Log.d(TAG, "Stats: sent=${bytesSent.get()} bytes (${packetsSent.get()} pkts), " +
                                "received=${bytesReceived.get()} bytes (${packetsReceived.get()} pkts)")
                    }
                } catch (e: CancellationException) {
                    break
                }
            }
        }
    }
}

/**
 * Connection statistics data class
 */
data class ConnectionStatistics(
    val bytesSent: Long,
    val bytesReceived: Long,
    val packetsSent: Long,
    val packetsReceived: Long,
    val reconnectAttempts: Int
) {
    fun getTotalBytes(): Long = bytesSent + bytesReceived
    fun getTotalPackets(): Long = packetsSent + packetsReceived
}
