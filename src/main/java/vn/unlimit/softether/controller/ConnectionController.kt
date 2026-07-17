package vn.unlimit.softether.controller

import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import vn.unlimit.softether.SoftEtherVpnService
import vn.unlimit.softether.SoftEtherTrafficSnapshot
import vn.unlimit.softether.client.SoftEtherClient
import vn.unlimit.softether.client.protocol.KeepAliveManager
import vn.unlimit.softether.client.protocol.PacketHandler
import vn.unlimit.softether.model.ClientInfo
import vn.unlimit.softether.model.ConnectionConfig
import vn.unlimit.softether.model.ConnectionState
import vn.unlimit.softether.terminal.TunTerminal
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
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
    private val onError: (String) -> Unit,
    private val onTrafficUpdate: (SoftEtherTrafficSnapshot) -> Unit
) {
    companion object {
        private const val TAG = "ConnectionController"
        private const val MAX_RECONNECT_ATTEMPTS = 3
        private const val RECONNECT_DELAY_MS = 3000L
        private const val DATA_LOOP_DELAY_MS = 1L
        private const val STATS_INTERVAL_MS = 1000L
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val client = SoftEtherClient()
    private val isCancelled = AtomicBoolean(false)
    private val isReconnecting = AtomicBoolean(false)
    private val reconnectAttempts = AtomicInteger(0)
    private val connectionMutex = Mutex()
    private var stateMonitorJob: Job? = null

    // Statistics
    private val bytesSent = AtomicLong(0)
    private val bytesReceived = AtomicLong(0)
    private val packetsSent = AtomicLong(0)
    private val packetsReceived = AtomicLong(0)
    private var lastPublishedSentBytes = 0L
    private var lastPublishedReceivedBytes = 0L
    private var lastPublishedAtMs = 0L

    private var isNetworkAvailable = true
    
    private var currentState: ConnectionState = ConnectionState.DISCONNECTED
        set(value) {
            field = value
            onStateChange(value)
        }

    private var nativeHandle: Long = 0
    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunTerminal: TunTerminal? = null

    /**
     * Handle network connectivity changes
     */
    fun onNetworkChanged(isConnected: Boolean) {
        Log.d(TAG, "Network state changed: connected=$isConnected")
        isNetworkAvailable = isConnected
        
        if (isConnected) {
            // If we were in a "waiting" state (which we are removing), we would resume here.
            // But since we are failing immediately on network loss, there is nothing to resume.
            // The user must manually reconnect.
        } else {
            // Network lost - Fail immediately in all states
            if (currentState != ConnectionState.DISCONNECTED && currentState != ConnectionState.ERROR) {
                Log.w(TAG, "Network lost, forcing disconnect")
                onError("Network connection lost")
                disconnect()
            }
        }
    }

    private fun interruptNativeConnection() {
        val handle = nativeHandle
        if (handle != 0L) {
            try {
                client.nativeDisconnect(handle)
            } catch (e: Exception) {
                Log.e(TAG, "Error interrupting native connection", e)
            }
        }
    }

    /** DHCP-assigned local IP address (available after successful connect) */
    var assignedLocalIp: String? = null
        private set

    /**
     * Initiates VPN connection with automatic retry logic
     */
    suspend fun connect() {
        // Check if connection is already active before acquiring lock to avoid waiting
        if (currentState != ConnectionState.DISCONNECTED && currentState != ConnectionState.ERROR) {
            Log.w(TAG, "Connection already in progress or established")
            return
        }

        connectionMutex.withLock {
            if (isCancelled.get()) {
                Log.w(TAG, "Connection cancelled, not starting")
                return
            }
            
            // Check network availability
            if (!isNetworkAvailable) {
                Log.e(TAG, "Network unavailable, cannot connect")
                onError("Network unavailable")
                return
            }
            
            if (currentState != ConnectionState.DISCONNECTED && currentState != ConnectionState.ERROR) {
                Log.w(TAG, "Connection already in progress or established")
                return
            }

            reconnectAttempts.set(0)
            
            // Iterative connection loop
            while (reconnectAttempts.get() < MAX_RECONNECT_ATTEMPTS) {
                try {
                    performConnect()
                    // If performConnect returns, it means success (currentState == CONNECTED)
                    return
                } catch (e: Exception) {
                    if (isCancelled.get()) {
                        Log.d(TAG, "Connection cancelled, not retrying")
                        return
                    }
                    
                    // If network is lost during attempt, fail immediately
                    if (!isNetworkAvailable) {
                        Log.e(TAG, "Connection aborted due to network loss")
                        currentState = ConnectionState.DISCONNECTED
                        onError("Network connection lost")
                        return
                    }
                    
                    if (reconnectAttempts.incrementAndGet() < MAX_RECONNECT_ATTEMPTS) {
                        Log.w(TAG, "Connection failed, attempting retry ${reconnectAttempts.get()}/$MAX_RECONNECT_ATTEMPTS")
                        delay(RECONNECT_DELAY_MS)
                        // Loop continues to next attempt
                    } else {
                        Log.e(TAG, "Connection failed after ${reconnectAttempts.get()} attempts", e)
                        currentState = ConnectionState.DISCONNECTED
                        onError(e.message ?: "Unknown error")
                        // Stop loop
                        return
                    }
                }
            }
        }
    }

    /**
     * Build client info for reporting to server
     */
    private fun buildClientInfo(rudpPort: Int): ClientInfo {
        // Get local non-loopback IP
        var clientIp = "0.0.0.0"
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            if (interfaces != null) {
                while (interfaces.hasMoreElements()) {
                    val iface = interfaces.nextElement()
                    val addresses = iface.inetAddresses
                    while (addresses.hasMoreElements()) {
                        val addr = addresses.nextElement()
                        if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                            clientIp = addr.hostAddress
                            break
                        }
                    }
                    if (clientIp != "0.0.0.0") break
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to get local IP", e)
        }
        
        // Get hostname
        var hostName = ""
        try {
            hostName = java.net.InetAddress.getLocalHost().hostName
        } catch (e: Exception) {
            Log.w(TAG, "Failed to get hostname", e)
        }
        
        // Resolve server IP
        var serverIp = "0.0.0.0"
        try {
            serverIp = java.net.InetAddress.getByName(config.serverHost).hostAddress ?: "0.0.0.0"
        } catch (e: Exception) {
            Log.w(TAG, "Failed to resolve server IP for ${config.serverHost}", e)
        }
        
        Log.d(TAG, "Client IP: $clientIp, Server IP: $serverIp, Port: ${config.serverPort}")
        
        return ClientInfo(
            productName = config.clientProductName,
            productVersion = config.clientVersion,
            productBuild = config.clientBuild,
            osName = "Android",
            osVersion = Build.VERSION.RELEASE,
            osProductId = Build.FINGERPRINT,
            hostName = hostName,
            clientIpAddress = clientIp,
            clientPort = rudpPort,
            serverHostName = config.serverHost,
            serverIpAddress = serverIp,
            serverPort = config.serverPort
        )
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

        // Connect to server with hub name (includes TLS handshake, protocol handshake, auth, session setup)
        // Use virtualHub from config, default to "VPN" if not set
        val hubName = config.virtualHub.ifEmpty { "VPN" }
        Log.d(TAG, "Connecting with hub: $hubName")
        if (config.authMethod != vn.unlimit.softether.model.AuthMethod.AUTO) {
            val authTypeInt = when (config.authMethod) {
                vn.unlimit.softether.model.AuthMethod.ANONYMOUS -> 0
                vn.unlimit.softether.model.AuthMethod.PASSWORD -> 1
                vn.unlimit.softether.model.AuthMethod.PLAIN_PASSWORD -> 2
                else -> 0
            }
            client.nativeSetAuthType(nativeHandle, authTypeInt)
        }
        startNativeStateMonitor()
        // Build client info (rudpPort will be filled in by native code during RUDP init)
        val clientInfo = buildClientInfo(0)
        val result = try {
            client.nativeConnectWithHub(
                nativeHandle,
                config.serverHost,
                config.serverPort,
                config.username,
                config.password,
                hubName,
                config.useTcp,
                clientInfo.productName,
                clientInfo.productVersion,
                clientInfo.productBuild,
                clientInfo.osName,
                clientInfo.osVersion,
                clientInfo.osProductId,
                clientInfo.hostName,
                clientInfo.clientIpAddress,
                clientInfo.clientPort,
                clientInfo.serverHostName,
                clientInfo.serverIpAddress,
                clientInfo.serverPort
            )
        } finally {
            stopNativeStateMonitor()
        }

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
            currentState = ConnectionState.ERROR
            throw Exception("Connection failed with error code: $result")
        }

        // Connection established at protocol level — run DHCP before announcing CONNECTED
        // Keep internal state as SESSION_SETUP (DHCP phase) until we have an IP
        if (currentState != ConnectionState.CONNECTED) {
            currentState = ConnectionState.SESSION_SETUP
        }
        reconnectAttempts.set(0) // Reset on successful connection
        // Set external handle so send/receive work through ConnectionController
        client.externalHandle = nativeHandle
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

        // Protect VPN socket from routing through TUN (prevents routing loop)
        val socketFd = client.nativeGetSocketFd(nativeHandle)
        if (socketFd >= 0) {
            if (!service.protect(socketFd)) {
                Log.e(TAG, "Failed to protect VPN socket fd=$socketFd")
            } else {
                Log.d(TAG, "VPN socket fd=$socketFd protected from TUN routing")
            }
        } else {
            Log.e(TAG, "Invalid socket fd, cannot protect")
        }

        // Also protect RUDP UDP socket from routing through TUN (prevents RUDP routing loop)
        val rudpFd = client.nativeGetRudpSocketFd(nativeHandle)
        if (rudpFd >= 0) {
            if (!service.protect(rudpFd)) {
                Log.e(TAG, "Failed to protect RUDP socket fd=$rudpFd")
            } else {
                Log.d(TAG, "RUDP socket fd=$rudpFd protected from TUN routing")
            }
        }

        // Perform DHCP over the SoftEther tunnel to get IP configuration
        Log.d(TAG, "Starting DHCP over SoftEther tunnel...")
        val dhcpResult = client.doDhcp(nativeHandle)
        if (dhcpResult != null) {
            Log.d(TAG, "DHCP success: IP=${dhcpResult.assignedIp}/${dhcpResult.prefixLength} " +
                    "GW=${dhcpResult.gateway} DNS=${dhcpResult.dnsServer} DNS2=${dhcpResult.dnsServer2}")
            assignedLocalIp = dhcpResult.assignedIp
            // Update config with DHCP-assigned values
            val dhcpConfig = config.copy(
                localAddress = dhcpResult.assignedIp,
                prefixLength = dhcpResult.prefixLength,
                dnsServer = if (dhcpResult.dnsServer != "0.0.0.0") dhcpResult.dnsServer else config.dnsServer,
                secondaryDnsServer = if (dhcpResult.dnsServer2 != "0.0.0.0") dhcpResult.dnsServer2 else config.secondaryDnsServer
            )
            vpnInterface = service.establishVpnInterface(dhcpConfig)
                ?: throw Exception("Failed to establish VPN interface")
        } else {
            Log.w(TAG, "DHCP failed, falling back to hardcoded IP config")
            assignedLocalIp = config.localAddress
            vpnInterface = service.establishVpnInterface(config)
                ?: throw Exception("Failed to establish VPN interface")
        }

        // Now that we have an IP and VPN interface, transition to CONNECTED
        currentState = ConnectionState.CONNECTED
        resetTrafficPublishing(publishSnapshot = true)

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
        client.externalHandle = 0

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

        // Stop TunTerminal first to avoid reading from closed interface
        try {
            tunTerminal?.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping TunTerminal", e)
        }
        tunTerminal = null
        
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

        // Store reference to tunTerminal so we can stop it cleanly
        this.tunTerminal = TunTerminal(tunInterface, scope)
        val terminal = this.tunTerminal!!
        
        val packetHandler = PacketHandler(client)
        val keepAliveManager = KeepAliveManager(client)

        // Start TUN interface reading
        terminal.start(
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
                            maybePublishTrafficSnapshot()
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
                            val writeResult = terminal.write(packet)
                            if (writeResult > 0) {
                                bytesReceived.addAndGet(result.toLong())
                                packetsReceived.incrementAndGet()
                                maybePublishTrafficSnapshot()
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

            // Use hub name for reconnection
            val hubName = config.virtualHub.ifEmpty { "VPN" }
            if (config.authMethod != vn.unlimit.softether.model.AuthMethod.AUTO) {
                val authTypeInt = when (config.authMethod) {
                    vn.unlimit.softether.model.AuthMethod.ANONYMOUS -> 0
                    vn.unlimit.softether.model.AuthMethod.PASSWORD -> 1
                    vn.unlimit.softether.model.AuthMethod.PLAIN_PASSWORD -> 2
                    else -> 0
                }
                client.nativeSetAuthType(nativeHandle, authTypeInt)
            }
            val result = client.nativeConnectWithHub(
                nativeHandle,
                config.serverHost,
                config.serverPort,
                config.username,
                config.password,
                hubName,
                config.useTcp,
                "", "", 0, // client info placeholders for reconnection
                "", "", "",
                "", "",
                0, "", "", 0
            )

            if (result != 0) {
                throw Exception("Reconnection failed with error code: $result")
            }

            // Protect socket during reconnect too
            val socketFd = client.nativeGetSocketFd(nativeHandle)
            if (socketFd >= 0) {
                service.protect(socketFd)
            }
            client.externalHandle = nativeHandle

            if (currentState != ConnectionState.CONNECTED) {
                currentState = ConnectionState.CONNECTED
            }
            resetTrafficPublishing(publishSnapshot = true)
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
            while (!isCancelled.get() &&
                currentState != ConnectionState.DISCONNECTED &&
                currentState != ConnectionState.ERROR
            ) {
                try {
                    delay(STATS_INTERVAL_MS)
                    if (isConnected()) {
                        publishTrafficSnapshot()
                        Log.d(TAG, "Stats: sent=${bytesSent.get()} bytes (${packetsSent.get()} pkts), " +
                                "received=${bytesReceived.get()} bytes (${packetsReceived.get()} pkts)")
                    }
                } catch (e: CancellationException) {
                    break
                }
            }
        }
    }

    private fun resetTrafficPublishing(publishSnapshot: Boolean) {
        lastPublishedSentBytes = bytesSent.get()
        lastPublishedReceivedBytes = bytesReceived.get()
        lastPublishedAtMs = System.currentTimeMillis()
        if (publishSnapshot) {
            onTrafficUpdate(
                SoftEtherTrafficSnapshot(
                    inBytes = lastPublishedReceivedBytes,
                    outBytes = lastPublishedSentBytes,
                    diffInBytes = 0L,
                    diffOutBytes = 0L,
                    packetsIn = packetsReceived.get(),
                    packetsOut = packetsSent.get(),
                    intervalMs = STATS_INTERVAL_MS,
                    timestampMs = lastPublishedAtMs
                )
            )
        }
    }

    private fun publishTrafficSnapshot() {
        val now = System.currentTimeMillis()
        val currentSentBytes = bytesSent.get()
        val currentReceivedBytes = bytesReceived.get()
        val interval = (now - lastPublishedAtMs).coerceAtLeast(1L)
        val snapshot = SoftEtherTrafficSnapshot(
            inBytes = currentReceivedBytes,
            outBytes = currentSentBytes,
            diffInBytes = (currentReceivedBytes - lastPublishedReceivedBytes).coerceAtLeast(0L),
            diffOutBytes = (currentSentBytes - lastPublishedSentBytes).coerceAtLeast(0L),
            packetsIn = packetsReceived.get(),
            packetsOut = packetsSent.get(),
            intervalMs = interval,
            timestampMs = now
        )
        lastPublishedSentBytes = currentSentBytes
        lastPublishedReceivedBytes = currentReceivedBytes
        lastPublishedAtMs = now
        onTrafficUpdate(snapshot)
    }

    private fun maybePublishTrafficSnapshot() {
        val now = System.currentTimeMillis()
        if (now - lastPublishedAtMs >= STATS_INTERVAL_MS) {
            publishTrafficSnapshot()
        }
    }

    private fun startNativeStateMonitor() {
        stateMonitorJob?.cancel()
        stateMonitorJob = scope.launch {
            var lastBroadcastTime = 0L
            while (!isCancelled.get() && nativeHandle != 0L) {
                try {
                    val mapped = mapNativeState(client.nativeGetState(nativeHandle))
                    if (mapped != null &&
                        mapped != ConnectionState.DISCONNECTED &&
                        mapped != currentState
                    ) {
                        val now = System.currentTimeMillis()
                        // Ensure minimum 100ms between state updates
                        if (now - lastBroadcastTime >= 100) {
                            currentState = mapped
                            lastBroadcastTime = now
                        }
                    }

                    if (currentState == ConnectionState.CONNECTED ||
                        currentState == ConnectionState.DISCONNECTING ||
                        currentState == ConnectionState.DISCONNECTED
                    ) {
                        break
                    }
                    delay(50) // Reduced delay for better responsiveness
                } catch (_: Exception) {
                    break
                }
            }
        }
    }

    private suspend fun stopNativeStateMonitor() {
        stateMonitorJob?.cancel()
        stateMonitorJob = null
    }

    private fun mapNativeState(nativeState: Int): ConnectionState? {
        return when (nativeState) {
            0 -> ConnectionState.DISCONNECTED
            1 -> ConnectionState.CONNECTING
            2 -> ConnectionState.TLS_HANDSHAKE
            3 -> ConnectionState.PROTOCOL_HANDSHAKE
            4 -> ConnectionState.AUTHENTICATING
            5 -> ConnectionState.SESSION_SETUP
            6 -> ConnectionState.CONNECTED
            7 -> ConnectionState.DISCONNECTING
            else -> null
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
