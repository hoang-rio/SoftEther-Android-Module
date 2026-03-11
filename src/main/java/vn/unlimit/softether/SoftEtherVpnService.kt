package vn.unlimit.softether

import android.media.AudioAttributes
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.VibrationEffect
import android.os.Vibrator
import android.media.RingtoneManager
import android.media.Ringtone
import android.net.Uri
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import vn.unlimit.softether.controller.ConnectionController
import vn.unlimit.softether.model.ConnectionConfig
import vn.unlimit.softether.model.ConnectionState

/**
 * SoftEther VPN Service - Main VPN service implementation for Android
 */
class SoftEtherVpnService : VpnService() {

    /** Listener interface — same pattern as OpenVPN's VpnStatus.StateListener */
    interface StateListener {
        fun onSoftEtherStateChanged(state: String, assignedIp: String)
    }

    companion object {
        private const val TAG = "SoftEtherVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "SoftEtherVPN"
        private const val NOTIFICATION_CHANNEL_ERROR_ID = "SoftEtherVPN_Error"
        private const val NOTIFICATION_ID = 1001

        // Actions (kept for service start/stop intents)
        const val ACTION_CONNECT = "vn.unlimit.softether.CONNECT"
        const val ACTION_DISCONNECT = "vn.unlimit.softether.DISCONNECT"

        // State string constants
        const val STATE_CONNECTED = "CONNECTED"
        const val STATE_DISCONNECTED = "DISCONNECTED"
        const val STATE_ERROR = "ERROR"
        const val STATE_CONNECTING = "CONNECTING"
        const val STATE_TLS_HANDSHAKE = "TLS_HANDSHAKE"
        const val STATE_PROTOCOL_HANDSHAKE = "PROTOCOL_HANDSHAKE"
        const val STATE_AUTHENTICATING = "AUTHENTICATING"
        const val STATE_SESSION_SETUP = "SESSION_SETUP"
        const val STATE_DISCONNECTING = "DISCONNECTING"

        // Extras
        const val EXTRA_CONFIG = "config"

        // Static state — survives Activity recreation, updated on every state change
        var currentState: String = STATE_DISCONNECTED
            private set
        var currentAssignedIp: String = ""
            private set

        private val stateListeners = mutableListOf<StateListener>()
        private val mainHandler = Handler(Looper.getMainLooper())

        fun addStateListener(listener: StateListener) {
            if (!stateListeners.contains(listener)) {
                stateListeners.add(listener)
                // Immediately deliver current state (same as OpenVPN's mLaststate replay)
                listener.onSoftEtherStateChanged(currentState, currentAssignedIp)
            }
        }

        fun removeStateListener(listener: StateListener) {
            stateListeners.remove(listener)
        }

        var notificationTargetActivity: Class<*>? = null

        private fun notifyListeners(state: String, assignedIp: String) {
            currentState = state
            currentAssignedIp = assignedIp
            mainHandler.post {
                stateListeners.forEach { it.onSoftEtherStateChanged(state, assignedIp) }
            }
        }
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var controller: ConnectionController? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var mWasConnected = false
    private var mIsUserDisconnect = false
    private var lastStateUpdateTime = 0L
    private var pendingStateUpdate: (() -> Unit)? = null
    private var currentSessionName: String? = null

    private val networkReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                ConnectivityManager.CONNECTIVITY_ACTION -> {
                    // Handle network changes
                    Log.d(TAG, "Network connectivity changed")
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Service created")
        createNotificationChannel()
        registerNetworkReceiver()
    }

    private fun triggerDisconnectNotification() {
        val channelId = NOTIFICATION_CHANNEL_ERROR_ID
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                getString(R.string.channel_name_error),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.channel_description_error)
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 250, 250, 250)
                
                // Set sound
                val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
                setSound(soundUri, AudioAttributes.Builder()
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                    .build())
            }
            notificationManager.createNotificationChannel(channel)
        }

        val builder = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.softether_notification_title_notconnect))
            .setContentText(getString(R.string.notification_disconnected_error))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setDefaults(Notification.DEFAULT_ALL)
            .setAutoCancel(true)

        notificationManager.notify(NOTIFICATION_CHANNEL_ERROR_ID.hashCode(), builder.build())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")

        when (intent?.action) {
            ACTION_CONNECT -> {
                mIsUserDisconnect = false
                val config = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(EXTRA_CONFIG, ConnectionConfig::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(EXTRA_CONFIG)
                }

                if (config != null) {
                    startVpn(config)
                } else {
                    Log.e(TAG, "No configuration provided")
                    stopSelf()
                }
            }
            ACTION_DISCONNECT -> {
                mIsUserDisconnect = true
                stopVpn()
            }
            else -> {
                Log.w(TAG, "Unknown action: ${intent?.action}")
            }
        }

        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "Service destroyed")
        
        // Cancel any ongoing connection attempt
        connectionJob?.cancel()
        connectionJob = null
        
        // Clean up resources
        try {
            controller?.disconnect()
            controller = null
        } catch (e: Exception) {
            Log.e(TAG, "Error disconnecting on destroy", e)
        }
        
        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface on destroy", e)
        }
        
        unregisterNetworkReceiver()
        serviceScope.cancel()
    }

    @Volatile
    private var connectionJob: kotlinx.coroutines.Job? = null

    private fun startVpn(config: ConnectionConfig) {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }

        Log.d(TAG, "Starting VPN with config: ${config.serverHost}:${config.serverPort}")

        // Store session name for use in notifications
        currentSessionName = config.sessionName
        
        // Start as foreground service
        startForeground(NOTIFICATION_ID, createNotification(getString(R.string.softether_connecting)))

        connectionJob = serviceScope.launch {
            try {
                // Initialize connection controller
                controller = ConnectionController(
                    service = this@SoftEtherVpnService,
                    config = config,
                    onStateChange = { state ->
                        handleConnectionState(state, config.serverHost)
                    },
                    onError = { error ->
                        Log.e(TAG, "VPN Error: $error")
                        updateNotification(getString(R.string.softether_disconnected_by_error))
                        mIsUserDisconnect = false
                        stopVpn()
                    }
                )

                // Establish connection (fires onStateChange -> STATE_CONNECTED with IP after DHCP)
                controller?.connect()
                isRunning = true
                Log.d(TAG, "VPN connection established")

            } catch (e: kotlinx.coroutines.CancellationException) {
                // Connection was cancelled (user pressed cancel)
                Log.d(TAG, "Connection cancelled by user")
                mIsUserDisconnect = true
                sendConnectionStateBroadcast(STATE_DISCONNECTED)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
                updateNotification("Connection failed: ${e.message}")
                mIsUserDisconnect = false
                stopVpn()
            }
        }
    }

    private fun stopVpn() {
        Log.d(TAG, "Stopping VPN")
        isRunning = false

        // Send disconnect broadcast
        sendConnectionStateBroadcast(STATE_DISCONNECTED)

        // Disconnect controller - this will interrupt any ongoing connection attempt
        try {
            controller?.disconnect()
        } catch (e: Exception) {
            Log.e(TAG, "Error disconnecting controller", e)
        }
        controller = null

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        // Show disconnected notification (dismissable, no disconnect button)
        showDisconnectedNotification()

        // Stop foreground service
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        stopSelf()
    }

    /**
     * Show disconnected notification (dismissable, no action buttons)
     */
    private fun showDisconnectedNotification() {
        // Intent to open DetailActivity when notification is tapped
        val contentIntent = Intent().apply {
            if (notificationTargetActivity != null) {
                setClass(this@SoftEtherVpnService, notificationTargetActivity!!)
                // Dynamically fetch TYPE_START and TYPE_FROM_NOTIFY from target activity
                // Similar to OpenVPNService.getContentIntent()
                try {
                    val startKey = notificationTargetActivity!!.getField("TYPE_START").get(null).toString()
                    val startValue = notificationTargetActivity!!.getField("TYPE_FROM_NOTIFY").get(null).toString().toInt()
                    putExtra(startKey, startValue)
                } catch (e: Exception) {
                    // Silent this exception
                }
            } else {
                setClassName(this@SoftEtherVpnService, "vn.unlimit.vpngate.activities.DetailActivity")
                putExtra("vn.unlimit.vpngate.TYPE_START", 1001)
            }
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            this, 0, contentIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.softether_vpn_service))
            .setContentText(getString(R.string.softether_disconnected))
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(contentPendingIntent)
            .setOngoing(false)  // Dismissable
            .setAutoCancel(true)  // Auto-dismiss when tapped
            .build()

        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    /**
     * Notify listeners of state change and update notification.
     * Uses in-process listener pattern (no broadcasts) — works on all Android versions.
     */
    private fun sendConnectionStateBroadcast(state: String, hostname: String = "") {
        val ip = if (hostname.isNotEmpty()) hostname else currentAssignedIp
        notifyListeners(state, if (state == STATE_DISCONNECTED || state == STATE_ERROR) "" else ip)
        Log.d(TAG, if (ip.isNotEmpty()) "State changed: $state ip=$ip" else "State changed: $state")
    }

    /**
     * Establish the VPN tunnel interface
     */
    fun establishVpnInterface(config: ConnectionConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(config.sessionName)
            .setMtu(config.mtu)
            .addAddress(config.localAddress, config.prefixLength)
            .addDnsServer(config.dnsServer)

        // Add secondary DNS if it differs from primary and is valid
        if (config.secondaryDnsServer.isNotEmpty() && config.secondaryDnsServer != config.dnsServer) {
            builder.addDnsServer(config.secondaryDnsServer)
        }

        // Add routes
        config.routes.forEach { route ->
            builder.addRoute(route.address, route.prefixLength)
        }

        // Exclude apps from VPN tunnel (they will use normal network instead)
        config.excludedApps.forEach { packageName ->
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.w(TAG, "Excluded app not found, skipping: $packageName")
            }
        }

        // Configure as metered/unmetered
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(config.isMetered)
        }

        // Set underlying networks
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            builder.setUnderlyingNetworks(null)
        }

        vpnInterface = builder.establish()
        return vpnInterface
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "SoftEther VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "SoftEther VPN connection status"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(content: String): Notification {
        // Intent to open DetailActivity when notification is tapped
        val contentIntent = Intent().apply {
            if (notificationTargetActivity != null) {
                setClass(this@SoftEtherVpnService, notificationTargetActivity!!)
                // Dynamically fetch TYPE_START and TYPE_FROM_NOTIFY from target activity
                // to support different activities without hardcoding keys here
                // Similar to OpenVPNService.getContentIntent()
                try {
                    val startKey = notificationTargetActivity!!.getField("TYPE_START").get(null).toString()
                    val startValue = notificationTargetActivity!!.getField("TYPE_FROM_NOTIFY").get(null).toString().toInt()
                    putExtra(startKey, startValue)
                } catch (e: Exception) {
                    // Silent this exception
                }
            } else {
                setClassName(this@SoftEtherVpnService, "vn.unlimit.vpngate.activities.DetailActivity")
                // Fallback hardcoded for DetailActivity if not set
                putExtra("vn.unlimit.vpngate.TYPE_START", 1001)
            }
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            this, 0, contentIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Intent for disconnect action button
        val disconnectIntent = Intent(this, SoftEtherVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Create notification title with server information from instance variable
        val notificationTitle = if (!currentSessionName.isNullOrEmpty()) {
            getString(R.string.softether_notification_title, currentSessionName)
        } else {
            getString(R.string.softether_notification_title_notconnect)
        }

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(notificationTitle)
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(contentPendingIntent)
            .setOngoing(true)
            .setAutoCancel(false)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.softether_disconnect), disconnectPendingIntent)
            .build()
    }

    private fun updateNotification(content: String) {
        val notification = createNotification(content)
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun handleConnectionState(state: ConnectionState, hostname: String) {
        val message = when (state) {
            ConnectionState.CONNECTING -> getString(R.string.softether_connecting)
            ConnectionState.TLS_HANDSHAKE -> getString(R.string.softether_tls_handshake)
            ConnectionState.PROTOCOL_HANDSHAKE -> getString(R.string.softether_protocol_handshake)
            ConnectionState.AUTHENTICATING -> getString(R.string.softether_authenticating)
            ConnectionState.SESSION_SETUP -> getString(R.string.softether_session_setup)
            ConnectionState.CONNECTED -> {
                val displayIp = controller?.assignedLocalIp ?: hostname
                getString(R.string.softether_connected, displayIp)
            }
            ConnectionState.DISCONNECTING -> getString(R.string.softether_disconnecting)
            ConnectionState.DISCONNECTED -> getString(R.string.softether_disconnected)
            ConnectionState.ERROR -> getString(R.string.softether_disconnected_by_error)
        }

        if (state == ConnectionState.CONNECTED) {
            mWasConnected = true
            mIsUserDisconnect = false
        } else if ((state == ConnectionState.DISCONNECTED || state == ConnectionState.ERROR) && mWasConnected && !mIsUserDisconnect) {
            triggerDisconnectNotification()
            mWasConnected = false
        }

        // Terminal states (CONNECTED, DISCONNECTED, ERROR) always pass through immediately
        val isTerminalState = state == ConnectionState.CONNECTED ||
                state == ConnectionState.DISCONNECTED ||
                state == ConnectionState.ERROR
        
        // Add minimum delay between state updates to ensure UI can process them
        val now = System.currentTimeMillis()
        if (!isTerminalState && now - lastStateUpdateTime < 200) {
            // Queue state update if too soon
            pendingStateUpdate = { 
                updateNotification(message)
                val stateValue = when (state) {
                    ConnectionState.CONNECTING -> STATE_CONNECTING
                    ConnectionState.TLS_HANDSHAKE -> STATE_TLS_HANDSHAKE
                    ConnectionState.PROTOCOL_HANDSHAKE -> STATE_PROTOCOL_HANDSHAKE
                    ConnectionState.AUTHENTICATING -> STATE_AUTHENTICATING
                    ConnectionState.SESSION_SETUP -> STATE_SESSION_SETUP
                    ConnectionState.CONNECTED -> STATE_CONNECTED
                    ConnectionState.DISCONNECTING -> STATE_DISCONNECTING
                    ConnectionState.DISCONNECTED -> STATE_DISCONNECTED
                    ConnectionState.ERROR -> STATE_ERROR
                }
                sendConnectionStateBroadcast(
                    stateValue,
                    if (state == ConnectionState.CONNECTED) (controller?.assignedLocalIp ?: hostname) else ""
                )
            }
            return
        }
        
        lastStateUpdateTime = now
        
        // Terminal states clear any pending update to prevent stale state overwriting
        if (isTerminalState) {
            pendingStateUpdate = null
        }
        
        updateNotification(message)

        val stateValue = when (state) {
            ConnectionState.CONNECTING -> STATE_CONNECTING
            ConnectionState.TLS_HANDSHAKE -> STATE_TLS_HANDSHAKE
            ConnectionState.PROTOCOL_HANDSHAKE -> STATE_PROTOCOL_HANDSHAKE
            ConnectionState.AUTHENTICATING -> STATE_AUTHENTICATING
            ConnectionState.SESSION_SETUP -> STATE_SESSION_SETUP
            ConnectionState.CONNECTED -> STATE_CONNECTED
            ConnectionState.DISCONNECTING -> STATE_DISCONNECTING
            ConnectionState.DISCONNECTED -> STATE_DISCONNECTED
            ConnectionState.ERROR -> STATE_ERROR
        }
        sendConnectionStateBroadcast(
            stateValue,
            if (state == ConnectionState.CONNECTED) (controller?.assignedLocalIp ?: hostname) else ""
        )
        
        // Process any pending state update
        pendingStateUpdate?.let {
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(it, 200)
            pendingStateUpdate = null
        }
    }

    private fun registerNetworkReceiver() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
            registerReceiver(networkReceiver, filter)
        }
    }

    private fun unregisterNetworkReceiver() {
        try {
            unregisterReceiver(networkReceiver)
        } catch (e: IllegalArgumentException) {
            // Receiver was not registered
        }
    }
}
