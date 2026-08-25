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
        private const val STATS_INTERVAL_MS = 1000L
        private const val RX_BATCH_MAX_PACKETS = 32  // Phase 13D: frames per receiveBatch call
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
     * Handle network connectivity changes.
     * On network loss, do NOT destroy the connection — the data forwarding loops will
     * detect send/receive errors and trigger attemptReconnect() automatically.
     * Calling disconnect() or onError() here kills the scope permanently and makes
     * reconnect impossible.
     */
    fun onNetworkChanged(isConnected: Boolean) {
        Log.d(TAG, "Network state changed: connected=$isConnected")
        isNetworkAvailable = isConnected
        
        if (!isConnected) {
            Log.w(TAG, "Network lost — data loops will detect and attempt reconnect")
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
                        if (!addr.isLoopbackAddress &&
                            !addr.isLinkLocalAddress &&
                            (addr is java.net.Inet4Address || addr is java.net.Inet6Address)
                        ) {
                            clientIp = addr.hostAddress ?: "0.0.0.0"
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

        // Single-owner teardown: while this connect flow is alive, ONLY this
        // function destroys the native handle. disconnect()/destroyResources()
        // defer to it (see isConnectInFlight) so a user cancel during the
        // blocking nativeConnectWithHub can never free the connection out
        // from under the connect thread (zombie connect + stuck connect_mutex).
        try {
            performConnectInner()
        } catch (e: Throwable) {
            Log.d(TAG, "Connect flow ended (${e.javaClass.simpleName}), tearing down native handle")
            teardownNativeConnection()
            throw e
        }
    }

    private fun isConnectInFlight(): Boolean =
        currentState == ConnectionState.CONNECTING ||
            currentState == ConnectionState.TLS_HANDSHAKE ||
            currentState == ConnectionState.SESSION_SETUP

    /**
     * Gracefully disconnect and free the native handle (idempotent).
     * Only called from the connect flow itself or when no connect is in flight.
     */
    private fun teardownNativeConnection() {
        client.externalHandle = 0
        val handle = nativeHandle
        nativeHandle = 0
        if (handle == 0L) return

        try {
            Log.d(TAG, "Tearing down native handle $handle")
            client.nativeDisconnect(handle)
            client.nativeDestroy(handle)
            Log.d(TAG, "Native handle $handle torn down")
        } catch (e: Exception) {
            Log.e(TAG, "Error tearing down native handle", e)
        }
    }

    private suspend fun performConnectInner() {
        // Check if already cancelled before proceeding
        if (isCancelled.get()) {
            Log.d(TAG, "Connection cancelled before starting")
            throw CancellationException("Connection cancelled by user")
        }

        // Set timeout
        client.setTimeout(config.connectTimeoutMs)

        // Enable the direct R-UDP stage (UDP-only servers reachable without relay)
        if (config.udpPort > 0) {
            client.nativeSetOption(nativeHandle, SoftEtherClient.OPTION_UDP_PORT, config.udpPort.toLong())
            Log.d(TAG, "Direct R-UDP stage enabled (udpPort=${config.udpPort})")
        }

        // UDP-only servers have no TCP port — skip the doomed direct-TCP attempt
        if (config.udpOnly) {
            client.nativeSetOption(nativeHandle, SoftEtherClient.OPTION_UDP_ONLY, 1L)
            Log.d(TAG, "UDP-only server: skipping direct TCP attempt")
        }

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
                vn.unlimit.softether.model.AuthMethod.AUTO -> 0
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
            throw CancellationException("Connection cancelled by user")
        }

        if (result != 0) {
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

        // Protect NAT-T RUDP transport UDP socket (used when the primary
        // connection runs over the NAT-T fallback; -1 otherwise)
        val natTUdpFd = client.nativeGetNatTUdpSocketFd(nativeHandle)
        if (natTUdpFd >= 0) {
            if (!service.protect(natTUdpFd)) {
                Log.e(TAG, "Failed to protect NAT-T UDP socket fd=$natTUdpFd")
            } else {
                Log.d(TAG, "NAT-T UDP socket fd=$natTUdpFd protected from TUN routing")
            }
        }

        // Perform DHCP over the SoftEther tunnel to get IP configuration
        Log.d(TAG, "Starting DHCP over SoftEther tunnel...")
        val dhcpResult = client.doDhcp(nativeHandle)

        // Re-check after DHCP: if the user cancelled while doDhcp() was
        // blocking, stop here — never establish the system VPN interface
        // for a cancelled session (that is what left the VPN key icon up).
        if (isCancelled.get()) {
            Log.d(TAG, "Connection cancelled during DHCP, tearing down")
            throw CancellationException("Connection cancelled by user")
        }

        val dhcpConfig: ConnectionConfig?
        if (dhcpResult != null) {
            Log.d(TAG, "DHCP success: IP=${dhcpResult.assignedIp}/${dhcpResult.prefixLength} " +
                    "GW=${dhcpResult.gateway} DNS=${dhcpResult.dnsServer} DNS2=${dhcpResult.dnsServer2}")
            assignedLocalIp = dhcpResult.assignedIp
            // Update config with DHCP-assigned values
            dhcpConfig = config.copy(
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
     * Attempt to reconnect using stored credentials.
     * Fully disconnects, waits, then performs a fresh connect() with full lifecycle.
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
            // Reset isCancelled so connect() doesn't bail out immediately
            isCancelled.set(false)
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

            // Disconnect native connection (this will interrupt any blocking operations).
            // If a connect flow is in flight, DEFER native teardown to it: the
            // connect coroutine is blocked inside nativeConnectWithHub and owns
            // the handle. Freeing here would either deadlock on connect_mutex or
            // free the connection out from under the connect thread (zombie
            // session + poisoned state for every later connect attempt).
            if (isConnectInFlight()) {
                Log.w(TAG, "Connect in flight - deferring native teardown to connect flow")
            } else if (nativeHandle != 0L) {
                teardownNativeConnection()
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

        // Don't call scope.cancel() — it permanently kills the scope, making reconnect impossible.
        // The isCancelled flag (set above) causes all data forwarding loops, keepalive,
        // and statistics logging to exit naturally via their while-loop conditions.

        currentState = ConnectionState.DISCONNECTED
        Log.d(TAG, "VPN disconnected. Stats: sent=${bytesSent.get()} bytes (${packetsSent.get()} pkts), " +
                "received=${bytesReceived.get()} bytes (${packetsReceived.get()} pkts)")
    }

    /**
     * Quickly destroy native resources without graceful disconnect (non-blocking).
     * Sets isCancelled, stops TunTerminal, closes fd, and frees the native handle.
     * Does NOT send state change callbacks — caller is responsible for state updates.
     */
    fun destroyResources() {
        Log.d(TAG, "Destroying resources (fast cleanup)")
        isCancelled.set(true)
        client.externalHandle = 0

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

        // Force-close sockets to interrupt any blocking nativeConnectWithHub
        // that may be holding connect_mutex.  This makes softether_connect_with_hub
        // return with an error so softether_destroy can proceed without deadlock.
        // If a connect flow is in flight, DEFER native teardown entirely: a
        // force-close + 200ms sleep is not enough (the connect retries on new
        // sockets / NAT-T), and destroying here frees the connection under the
        // connect thread. The connect flow tears the handle down itself as soon
        // as nativeConnectWithHub returns.
        if (isConnectInFlight()) {
            Log.w(TAG, "Connect in flight - deferring native destroy to connect flow")
            return
        }

        val handle = nativeHandle
        nativeHandle = 0
        if (handle != 0L) {
            try {
                client.nativeForceCloseSocket(handle)
            } catch (e: Exception) {
                Log.e(TAG, "Error force-closing socket", e)
            }
            // Brief yield so the blocking connect can notice the socket closure
            // and release connect_mutex before we call nativeDestroy.
            try {
                Thread.sleep(200)
            } catch (_: InterruptedException) {}

            try {
                client.nativeDestroy(handle)
            } catch (e: Exception) {
                Log.e(TAG, "Error destroying native handle", e)
            }
        }
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

        val keepAliveManager = KeepAliveManager(client)

        // Start TUN interface reading.
        // Phase 13E: packets are sent directly from the TUN read loop as
        // (buffer, offset, length) slices — no per-packet copy, no queue,
        // no dedicated send coroutine. A slow VPN link now applies natural
        // backpressure to the TUN read instead of growing a queue. Native
        // softether_send serializes concurrent writers via its write mutex,
        // so sending here alongside keepalives is safe.
        terminal.start(
            onPacket = { buffer, offset, length ->
                // Packet from TUN (local system) -> send to VPN
                try {
                    val result = client.send(buffer, offset, length)
                    if (result > 0) {
                        bytesSent.addAndGet(result.toLong())
                        packetsSent.incrementAndGet()
                        maybePublishTrafficSnapshot()
                    } else if (result < 0 && isConnected() && !isCancelled.get()) {
                        Log.w(TAG, "Send failed: $result")
                        scope.launch { attemptReconnect() }
                    }
                } catch (e: Exception) {
                    if (!isCancelled.get()) {
                        Log.e(TAG, "Send error", e)
                        if (isConnected()) {
                            scope.launch { attemptReconnect() }
                        }
                    }
                }
            },
            onError = { error ->
                Log.e(TAG, "TUN interface error", error)
                if (!isCancelled.get()) {
                    // Don't call onError() here — it triggers stopVpn() in VpnService
                    // which destroys everything. Instead, let attemptReconnect handle
                    // the full lifecycle (tear down + reconnect + new TUN).
                    scope.launch { attemptReconnect() }
                }
            }
        )

        // Receive loop: VPN -> TUN
        scope.launch {
            val receiveBuffer = ByteArray(65535)
            val batchLengths = IntArray(RX_BATCH_MAX_PACKETS)
            var receiveCount = 0
            while (isConnected() && !isCancelled.get()) {
                try {
                    // Phase 13D: drain multiple frames per JNI crossing
                    val total = client.receiveBatch(receiveBuffer, batchLengths)
                    when {
                        total > 0 -> {
                            // Valid data received — write frames back-to-back
                            var offset = 0
                            var written = 0
                            for (len in batchLengths) {
                                if (len == 0) break
                                val writeResult = terminal.write(receiveBuffer, offset, len)
                                if (writeResult > 0) written++
                                offset += len
                            }
                            if (written > 0) {
                                bytesReceived.addAndGet(total.toLong())
                                packetsReceived.addAndGet(written.toLong())
                                maybePublishTrafficSnapshot()
                            }
                            // Periodically protect additional sockets (multi-connection)
                            receiveCount++
                            if (receiveCount % 50 == 0) {
                                protectAdditionalSockets()
                            }
                        }
                        total == 0 -> {
                            // Keepalive or no data. Phase 13E: no Kotlin-side
                            // delay — native receive blocks up to 100ms in
                            // poll() when idle, so this loop only wakes ~10x/s
                            // at idle and instantly when data arrives.
                            keepAliveManager.recordReceived()
                        }
                        else -> {
                            // Error receiving
                            Log.e(TAG, "Receive error: $total")
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
     * Attempt automatic reconnection with full lifecycle:
     * tear down old TUN/native → reconnect → DHCP → establish VPN interface → restart data forwarding
     */
    private suspend fun attemptReconnect() {
        if (isReconnecting.getAndSet(true)) {
            Log.w(TAG, "Reconnection already in progress")
            return
        }

        try {
            if (reconnectAttempts.incrementAndGet() >= MAX_RECONNECT_ATTEMPTS) {
                Log.e(TAG, "Max reconnection attempts reached")
                onError("Connection lost - max reconnection attempts reached")
                disconnect()
                return
            }

            Log.w(TAG, "Attempting automatic reconnection (${reconnectAttempts.get()}/$MAX_RECONNECT_ATTEMPTS)")

            // Reset isCancelled so loops and subsequent operations can proceed
            isCancelled.set(false)

            // Tear down old data forwarding (stop TunTerminal to avoid reading from stale fd)
            try {
                tunTerminal?.stop()
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping TunTerminal during reconnect", e)
            }
            tunTerminal = null

            // Close old VPN interface
            try {
                vpnInterface?.close()
            } catch (e: Exception) {
                Log.e(TAG, "Error closing VPN interface during reconnect", e)
            }
            vpnInterface = null

            // Disconnect old native handle
            if (nativeHandle != 0L) {
                val handle = nativeHandle
                nativeHandle = 0
                try {
                    client.nativeDisconnect(handle)
                    client.nativeDestroy(handle)
                } catch (e: Exception) {
                    Log.e(TAG, "Error disconnecting old native handle", e)
                }
            }

            currentState = ConnectionState.CONNECTING

            // Wait before reconnecting
            delay(RECONNECT_DELAY_MS)

            if (isCancelled.get()) {
                return
            }

            // Create new native connection
            nativeHandle = client.nativeCreate()
            if (nativeHandle == 0L) {
                throw Exception("Failed to create native connection for reconnect")
            }

            client.setTimeout(config.connectTimeoutMs)

            // Set auth type
            val hubName = config.virtualHub.ifEmpty { "VPN" }
            if (config.authMethod != vn.unlimit.softether.model.AuthMethod.AUTO) {
                val authTypeInt = when (config.authMethod) {
                    vn.unlimit.softether.model.AuthMethod.ANONYMOUS -> 0
                    vn.unlimit.softether.model.AuthMethod.PASSWORD -> 1
                    vn.unlimit.softether.model.AuthMethod.PLAIN_PASSWORD -> 2
                    vn.unlimit.softether.model.AuthMethod.AUTO -> 0
                }
                client.nativeSetAuthType(nativeHandle, authTypeInt)
            }

            // Connect to server (TLS + protocol + auth + session)
            startNativeStateMonitor()
            val reconnectClientInfo = buildClientInfo(0)
            val result = try {
                client.nativeConnectWithHub(
                    nativeHandle,
                    config.serverHost,
                    config.serverPort,
                    config.username,
                    config.password,
                    hubName,
                    config.useTcp,
                    reconnectClientInfo.productName, reconnectClientInfo.productVersion, reconnectClientInfo.productBuild,
                    reconnectClientInfo.osName, reconnectClientInfo.osVersion, reconnectClientInfo.osProductId,
                    reconnectClientInfo.hostName, reconnectClientInfo.clientIpAddress, reconnectClientInfo.clientPort,
                    reconnectClientInfo.serverHostName, reconnectClientInfo.serverIpAddress, reconnectClientInfo.serverPort
                )
            } finally {
                stopNativeStateMonitor()
            }

            if (result != 0) {
                throw Exception("Reconnection failed with error code: $result")
            }

            if (isCancelled.get()) {
                val handle = nativeHandle
                nativeHandle = 0
                client.nativeDisconnect(handle)
                client.nativeDestroy(handle)
                return
            }

            // Protect VPN socket from routing through TUN
            val socketFd = client.nativeGetSocketFd(nativeHandle)
            if (socketFd >= 0) {
                if (!service.protect(socketFd)) {
                    Log.e(TAG, "Failed to protect VPN socket fd=$socketFd during reconnect")
                } else {
                    Log.d(TAG, "VPN socket fd=$socketFd protected during reconnect")
                }
            }

            // Protect RUDP UDP socket
            val rudpFd = client.nativeGetRudpSocketFd(nativeHandle)
            if (rudpFd >= 0) {
                if (!service.protect(rudpFd)) {
                    Log.e(TAG, "Failed to protect RUDP socket fd=$rudpFd during reconnect")
                } else {
                    Log.d(TAG, "RUDP socket fd=$rudpFd protected during reconnect")
                }
            }

            // Protect NAT-T RUDP transport UDP socket during reconnect
            val natTUdpFd = client.nativeGetNatTUdpSocketFd(nativeHandle)
            if (natTUdpFd >= 0) {
                if (!service.protect(natTUdpFd)) {
                    Log.e(TAG, "Failed to protect NAT-T UDP socket fd=$natTUdpFd during reconnect")
                } else {
                    Log.d(TAG, "NAT-T UDP socket fd=$natTUdpFd protected during reconnect")
                }
            }

            client.externalHandle = nativeHandle

            // Perform DHCP over the new tunnel
            Log.d(TAG, "Starting DHCP over reconnected tunnel...")
            val dhcpResult = client.doDhcp(nativeHandle)
            if (dhcpResult != null) {
                Log.d(TAG, "DHCP success on reconnect: IP=${dhcpResult.assignedIp}/${dhcpResult.prefixLength}")
                assignedLocalIp = dhcpResult.assignedIp
                val dhcpConfig = config.copy(
                    localAddress = dhcpResult.assignedIp,
                    prefixLength = dhcpResult.prefixLength,
                    dnsServer = if (dhcpResult.dnsServer != "0.0.0.0") dhcpResult.dnsServer else config.dnsServer,
                    secondaryDnsServer = if (dhcpResult.dnsServer2 != "0.0.0.0") dhcpResult.dnsServer2 else config.secondaryDnsServer
                )
                vpnInterface = service.establishVpnInterface(dhcpConfig)
                    ?: throw Exception("Failed to establish VPN interface during reconnect")
            } else {
                Log.w(TAG, "DHCP failed on reconnect, falling back to hardcoded config")
                assignedLocalIp = config.localAddress
                vpnInterface = service.establishVpnInterface(config)
                    ?: throw Exception("Failed to establish VPN interface during reconnect")
            }

            // Transition to CONNECTED and restart data forwarding
            currentState = ConnectionState.CONNECTED
            resetTrafficPublishing(publishSnapshot = true)
            startDataForwarding()
            startStatisticsLogging()

            reconnectAttempts.set(0)
            Log.d(TAG, "Reconnection successful — data forwarding restarted")

        } catch (e: Exception) {
            Log.e(TAG, "Reconnection attempt failed", e)
            // Clean up partial native state left by failed reconnect
            if (nativeHandle != 0L) {
                val handle = nativeHandle
                nativeHandle = 0
                try {
                    client.nativeDisconnect(handle)
                    client.nativeDestroy(handle)
                } catch (ex: Exception) {
                    Log.e(TAG, "Error cleaning up failed reconnect handle", ex)
                }
            }
            // Transition to DISCONNECTED so the activity learns the connection is gone
            currentState = ConnectionState.DISCONNECTED
            onStateChange(ConnectionState.DISCONNECTED)
        } finally {
            isReconnecting.set(false)
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
            // Phase 13G: surface native health counters alongside the
            // traffic snapshot (same 1 s throttle, debug-level only)
            client.getStats()?.let { st ->
                Log.d(TAG,
                    "stats: tx=${st.txPackets}p/${st.txBytes}B rx=${st.rxPackets}p/${st.rxBytes}B " +
                    "skipped=${st.rxSkippedBlocks} rudp(rx=${st.rudpRxPackets} ovf=${st.rudpOverflowCount} " +
                    "gaps=${st.rudpTickGaps} susp=${st.rudpDataSuspended})")
            }
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
                        mapped != ConnectionState.CONNECTED &&
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

    // Track FDs we've already protected to avoid redundant protect() calls
    private val protectedFds = mutableSetOf<Int>()

    /**
     * Protect any new additional TCP sockets from routing through TUN.
     * Called periodically from the receive loop after additional connections are established.
     */
    private fun protectAdditionalSockets() {
        val allFds = client.getAllSocketFds() ?: return
        val natTUdpFd = client.nativeGetNatTUdpSocketFd(nativeHandle)
        for (fd in allFds) {
            if (fd >= 0 && fd !in protectedFds) {
                if (service.protect(fd)) {
                    protectedFds.add(fd)
                    Log.d(TAG, "Additional socket fd=$fd protected from TUN routing")
                } else {
                    Log.e(TAG, "Failed to protect additional socket fd=$fd")
                }
            }
        }
        if (natTUdpFd >= 0 && natTUdpFd !in protectedFds) {
            if (service.protect(natTUdpFd)) {
                protectedFds.add(natTUdpFd)
                Log.d(TAG, "NAT-T UDP socket fd=$natTUdpFd protected from TUN routing")
            } else {
                Log.e(TAG, "Failed to protect NAT-T UDP socket fd=$natTUdpFd")
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
