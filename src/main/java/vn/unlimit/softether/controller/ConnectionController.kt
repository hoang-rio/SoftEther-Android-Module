package vn.unlimit.softether.controller

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import vn.unlimit.softether.SoftEtherVpnService
import vn.unlimit.softether.client.SoftEtherClient
import vn.unlimit.softether.model.ConnectionConfig
import vn.unlimit.softether.model.ConnectionState
import java.util.concurrent.atomic.AtomicBoolean

/**
 * ConnectionController - Manages the SoftEther VPN connection lifecycle
 */
class ConnectionController(
    private val service: SoftEtherVpnService,
    private val config: ConnectionConfig,
    private val onStateChange: (ConnectionState) -> Unit,
    private val onError: (String) -> Unit
) {
    companion object {
        private const val TAG = "ConnectionController"
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val client = SoftEtherClient()
    private val isCancelled = AtomicBoolean(false)

    private var currentState: ConnectionState = ConnectionState.DISCONNECTED
        set(value) {
            field = value
            onStateChange(value)
        }

    /**
     * Initiates VPN connection
     */
    suspend fun connect() {
        try {
            Log.d(TAG, "Starting connection to ${config.serverHost}:${config.serverPort}")
            currentState = ConnectionState.CONNECTING

            // Create native connection
            val handle = client.nativeCreate()
            if (handle == 0L) {
                throw Exception("Failed to create native connection")
            }

            currentState = ConnectionState.TLS_HANDSHAKE

            // Connect to server
            val result = client.nativeConnect(
                handle,
                config.serverHost,
                config.serverPort,
                config.username,
                config.password
            )

            if (result != 0) {
                throw Exception("Connection failed with error code: $result")
            }

            currentState = ConnectionState.AUTHENTICATING

            // Authentication is handled in native layer during connect
            currentState = ConnectionState.SESSION_SETUP

            // Establish VPN interface
            val vpnInterface = service.establishVpnInterface(config)
                ?: throw Exception("Failed to establish VPN interface")

            currentState = ConnectionState.CONNECTED
            Log.d(TAG, "VPN connection established successfully")

            // Start data forwarding loops
            startDataForwarding(handle, vpnInterface)

            // Start keepalive
            startKeepalive(handle)

        } catch (e: Exception) {
            Log.e(TAG, "Connection failed", e)
            currentState = ConnectionState.DISCONNECTED
            onError(e.message ?: "Unknown error")
            throw e
        }
    }

    /**
     * Disconnect VPN
     */
    fun disconnect() {
        Log.d(TAG, "Disconnecting VPN")
        currentState = ConnectionState.DISCONNECTING
        isCancelled.set(true)

        scope.cancel()

        // Cleanup will be handled by native layer
        currentState = ConnectionState.DISCONNECTED
        Log.d(TAG, "VPN disconnected")
    }

    /**
     * Get current connection state
     */
    fun getState(): ConnectionState = currentState

    /**
     * Check if currently connected
     */
    fun isConnected(): Boolean = currentState == ConnectionState.CONNECTED

    private suspend fun startDataForwarding(handle: Long, vpnInterface: android.os.ParcelFileDescriptor) {
        val tunTerminal = vn.unlimit.softether.terminal.TunTerminal(vpnInterface, scope)
        val packetHandler = vn.unlimit.softether.client.protocol.PacketHandler(client)

        // Start TUN interface reading
        tunTerminal.start(
            onPacket = { packet ->
                // Queue packet for sending through VPN
                packetHandler.queuePacket(packet)
            },
            onError = { error ->
                Log.e(TAG, "TUN interface error", error)
                onError("TUN error: ${error.message}")
            }
        )

        // Send loop - process queued packets
        scope.launch {
            val sendBuffer = ByteArray(65535)
            while (isConnected() && !isCancelled.get()) {
                try {
                    // Process send queue
                    packetHandler.processSendQueue()

                    // Small delay to prevent busy-waiting
                    delay(10)
                } catch (e: Exception) {
                    Log.e(TAG, "Send loop error", e)
                    if (isConnected()) {
                        onError("Send error: ${e.message}")
                    }
                    break
                }
            }
        }

        // Receive loop - receive packets from VPN and write to TUN
        scope.launch {
            val receiveBuffer = ByteArray(65535)
            while (isConnected() && !isCancelled.get()) {
                try {
                    val result = packetHandler.receivePacket(receiveBuffer)
                    when {
                        result > 0 -> {
                            // Write received packet to TUN interface
                            val packet = packetHandler.pollReceivedPacket()
                            if (packet != null) {
                                tunTerminal.write(packet)
                            }
                        }
                        result == 0 -> {
                            // Keepalive received, no action needed
                        }
                        result < 0 -> {
                            // Error receiving
                            Log.e(TAG, "Receive error: $result")
                            if (isConnected()) {
                                onError("Receive error")
                            }
                            break
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Receive loop error", e)
                    if (isConnected()) {
                        onError("Receive error: ${e.message}")
                    }
                    break
                }
            }
        }

        // Wait for disconnect
        while (isConnected() && !isCancelled.get()) {
            delay(100)
        }

        // Cleanup
        tunTerminal.stop()
        packetHandler.clearQueues()
    }

    private suspend fun startKeepalive(handle: Long) {
        val keepAliveManager = vn.unlimit.softether.client.protocol.KeepAliveManager(client)
        keepAliveManager.setInterval(config.keepAliveIntervalMs.toLong())
        keepAliveManager.start()

        scope.launch {
            while (isConnected() && !isCancelled.get()) {
                delay(1000) // Check every second

                if (keepAliveManager.shouldSendKeepAlive()) {
                    // Keepalive is handled in native layer
                    keepAliveManager.recordSent()
                }

                if (keepAliveManager.isConnectionDead()) {
                    Log.e(TAG, "Connection appears dead (keepalive timeout)")
                    onError("Connection timeout")
                    disconnect()
                    break
                }
            }
            keepAliveManager.stop()
        }
    }
}
