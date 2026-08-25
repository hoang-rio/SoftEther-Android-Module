package vn.unlimit.softether

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

    interface TrafficListener {
        fun onSoftEtherTrafficUpdated(snapshot: SoftEtherTrafficSnapshot)
    }

    companion object {
        private const val TAG = "SoftEtherVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "SoftEtherVPN"
        private const val NOTIFICATION_CHANNEL_ERROR_ID = "SoftEtherVPN_Error"
        private const val NOTIFICATION_ID = 1001
        private const val TRAFFIC_PREFS_SUFFIX = "_preferences"
        private const val DOWNLOADED_DATA_KEY = "downloaded_data"
        private const val UPLOADED_DATA_KEY = "uploaded_data"
        private const val KEY_ULA_V6 = "ula_v6"

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
        var currentTrafficSnapshot: SoftEtherTrafficSnapshot = SoftEtherTrafficSnapshot.EMPTY
            private set
        var lastTrafficSnapshot: SoftEtherTrafficSnapshot = SoftEtherTrafficSnapshot.EMPTY
            private set
        var mDisplaySpeed: Boolean = true

        private val stateListeners = mutableListOf<StateListener>()
        private val trafficListeners = mutableListOf<TrafficListener>()
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

        fun addTrafficListener(listener: TrafficListener) {
            if (!trafficListeners.contains(listener)) {
                trafficListeners.add(listener)
                listener.onSoftEtherTrafficUpdated(currentTrafficSnapshot)
            }
        }

        fun removeTrafficListener(listener: TrafficListener) {
            trafficListeners.remove(listener)
        }

        var notificationTargetActivity: Class<*>? = null

        private fun notifyListeners(state: String, assignedIp: String) {
            currentState = state
            currentAssignedIp = assignedIp
            mainHandler.post {
                stateListeners.forEach { it.onSoftEtherStateChanged(state, assignedIp) }
            }
        }

        private fun notifyTrafficListeners(snapshot: SoftEtherTrafficSnapshot) {
            currentTrafficSnapshot = snapshot
            if (snapshot.inBytes > 0L || snapshot.outBytes > 0L || snapshot.diffInBytes > 0L || snapshot.diffOutBytes > 0L) {
                lastTrafficSnapshot = snapshot
            }
            mainHandler.post {
                trafficListeners.forEach { it.onSoftEtherTrafficUpdated(snapshot) }
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

    @Suppress("DEPRECATION")
    private val networkReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ConnectivityManager.CONNECTIVITY_ACTION) {
                val cm = context?.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val activeNetwork = cm?.activeNetworkInfo
                val isConnected = activeNetwork?.isConnectedOrConnecting == true

                Log.d(TAG, "Network connectivity changed: isConnected=$isConnected")
                controller?.onNetworkChanged(isConnected)
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
        // Cancel the persistent status notification first
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.cancel(NOTIFICATION_ID)

        val channelId = NOTIFICATION_CHANNEL_ERROR_ID

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Delete old channel to ensure new settings (sound/vibration) take effect
            // notificationManager.deleteNotificationChannel(channelId) // Use with caution, might be annoying if called often

            val channel = NotificationChannel(
                channelId,
                getString(R.string.softether_channel_name_error),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.softether_channel_description_error)
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 250, 250, 250)
                
                // Set sound
                val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
                setSound(soundUri, AudioAttributes.Builder()
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                    .build())
                
                // Force show lights as well for visibility
                enableLights(true)
                lightColor = android.graphics.Color.RED
            }
            // Create (or update) the channel
            notificationManager.createNotificationChannel(channel)
        }

        // Intent to open DetailActivity when notification is tapped
        val contentIntent = Intent().apply {
            if (notificationTargetActivity != null) {
                setClass(this@SoftEtherVpnService, notificationTargetActivity!!)
                // Dynamically fetch TYPE_START and TYPE_FROM_NOTIFY from target activity
                // to support different activities without hardcoding keys here
                try {
                    val startKey = notificationTargetActivity?.getField("TYPE_START")?.get(null)?.toString()
                    val startValue = notificationTargetActivity?.getField("TYPE_FROM_NOTIFY")?.get(null)?.toString()?.toInt()
                    if (startKey != null && startValue != null) {
                        putExtra(startKey, startValue)
                    }
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

        val builder = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.softether_channel_name_error))
            .setContentText(getString(R.string.softether_notification_disconnected_error))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setDefaults(Notification.DEFAULT_ALL)
            .setVibrate(longArrayOf(0, 250, 250, 250)) // Explicitly set on builder too for pre-O
            .setAutoCancel(true)
            .setContentIntent(contentPendingIntent)

        notificationManager.notify(NOTIFICATION_CHANNEL_ERROR_ID.hashCode(), builder.build())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")

        // Android requires startForeground() within ~5s of startForegroundService().
        // Use the correct text and omit the disconnect action when disconnecting.
        val isDisconnectAction = intent?.action == ACTION_DISCONNECT
        startForeground(
            NOTIFICATION_ID,
            createNotification(
                if (isDisconnectAction) getString(R.string.softether_disconnecting) else getString(R.string.softether_connecting),
                !isDisconnectAction
            )
        )

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
                stopSelf()
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
        
        // Clean up resources OFF the main thread: disconnect/destroy make
        // blocking native calls (nativeDisconnect waits on connect_mutex and
        // can block for the whole connect timeout when a connect is in
        // flight — running that on main caused an ANR in softether_disconnect).
        val currentController = controller
        controller = null
        
        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface on destroy", e)
        }
        
        unregisterNetworkReceiver()
        notifyTrafficListeners(SoftEtherTrafficSnapshot.EMPTY)
        // NonCancellable: serviceScope is cancelled right below, but this
        // cleanup must still run to free the native connection.
        serviceScope.launch(NonCancellable + Dispatchers.IO) {
            try {
                currentController?.destroyResources()
            } catch (e: Exception) {
                Log.e(TAG, "Error destroying controller on destroy", e)
            }
        }
        serviceScope.cancel()
    }

    @Volatile
    private var connectionJob: kotlinx.coroutines.Job? = null
    @Volatile
    private var isStopping = false

    private fun startVpn(config: ConnectionConfig) {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }

        Log.d(TAG, "Starting VPN with config: ${config.serverHost}:${config.serverPort}")
        lastTrafficSnapshot = SoftEtherTrafficSnapshot.EMPTY
        notifyTrafficListeners(SoftEtherTrafficSnapshot.EMPTY)

        // Store session name for use in notifications
        currentSessionName = config.sessionName

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
                        // updateNotification(getString(R.string.softether_disconnected_by_error))
                        mIsUserDisconnect = false
                        stopVpn()
                    },
                    onTrafficUpdate = { snapshot ->
                        handleTrafficUpdate(snapshot)
                    }
                )

                // Establish connection (fires onStateChange -> STATE_CONNECTED with IP after DHCP)
                controller?.connect()
                isRunning = true
                Log.d(TAG, "VPN connection established")

            } catch (e: kotlinx.coroutines.CancellationException) {
                // Connection was canceled (user pressed cancel)
                Log.d(TAG, "Connection cancelled by user")
                mIsUserDisconnect = true
                // Clean up whatever the connect flow created (TUN interface,
                // terminal, deferred native handle). Idempotent — safe even if
                // the controller already tore itself down.
                try {
                    controller?.destroyResources()
                } catch (ce: Exception) {
                    Log.e(TAG, "Error destroying resources on cancel", ce)
                }
                controller = null
                sendConnectionStateBroadcast(STATE_DISCONNECTED)
                // stopForeground was already done by stopVpn(); make sure the
                // service itself also stops, or the process lingers with the
                // VPN route alive.
                stopSelf()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
                // updateNotification("Connection failed: ${e.message}")
                mIsUserDisconnect = false
                stopVpn()
            }
        }
    }

    private fun stopVpn() {
        if (isStopping) {
            Log.d(TAG, "Already stopping, skipping re-entrant call")
            return
        }
        isStopping = true

        Log.d(TAG, "Stopping VPN")
        isRunning = false

        // Send disconnect broadcast immediately so the UI reacts right away
        sendConnectionStateBroadcast(STATE_DISCONNECTED)
        notifyTrafficListeners(SoftEtherTrafficSnapshot.EMPTY)

        // Cancel the connection coroutine so it won't interfere
        connectionJob?.cancel()
        connectionJob = null

        // Move UI-facing cleanup (notification, foreground) to happen
        // immediately on the main thread so the user sees "disconnected"
        // right away.
        showDisconnectedNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        // Snapshot references and clear them immediately so onDestroy()
        // won't try to free the same resources concurrently.
        val currentController = controller
        val currentInterface = vpnInterface
        controller = null
        vpnInterface = null

        // Clean up resources on a background thread WITHOUT calling the
        // blocking graceful disconnect (nativeDisconnect waits for server
        // ACK which can hang).  destroyResources() just frees native memory
        // and closes fds — fast and non-blocking.
        serviceScope.launch(NonCancellable) {
            withContext(Dispatchers.IO) {
                try {
                    currentController?.destroyResources()
                } catch (e: Exception) {
                    Log.e(TAG, "Error destroying controller resources", e)
                }
            }
            stopSelf()
        }
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
                    val startKey = notificationTargetActivity?.getField("TYPE_START")?.get(null)?.toString()
                    val startValue = notificationTargetActivity?.getField("TYPE_FROM_NOTIFY")?.get(null)?.toString()?.toInt()
                    if (startKey != null && startValue != null) {
                        putExtra(startKey, startValue)
                    }
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
        val ip = hostname.ifEmpty { currentAssignedIp }
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

        // IPv6 tunnel: unique per-install ULA address, full default route, public DNS
        // Multiple clients must not share the same ULA — derive a stable unique one.
        // Never let IPv6 address setup take down the whole tunnel on a bad value.
        val localV6 = try {
            if (config.localAddressV6.isBlank() || config.localAddressV6 == "fd00::2") {
                deriveUniqueLocalAddressV6()
            } else {
                config.localAddressV6
            }
        } catch (e: Exception) {
            Log.w(TAG, "IPv6 ULA derivation failed, skipping IPv6 address", e)
            ""
        }
        if (localV6.isNotEmpty()) {
            try {
                builder.addAddress(localV6, config.prefixLengthV6)
            } catch (e: Exception) {
                Log.w(TAG, "Invalid IPv6 ULA, skipping: $localV6", e)
            }
        }
        if (config.dnsServerV6.isNotEmpty()) {
            builder.addDnsServer(config.dnsServerV6)
        }
        config.routesV6.forEach { route ->
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

    /**
     * Stable unique ULA (fd00::/8) per install so concurrent clients never
     * share an address. Derived from ANDROID_ID when available, else a random
     * value persisted across sessions.
     */
    private fun deriveUniqueLocalAddressV6(): String {
        val androidId = try {
            Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        } catch (e: Exception) {
            null
        }
        if (!androidId.isNullOrBlank()) {
            val hex = androidId.filter { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }.lowercase()
            if (hex.length >= 4) {
                return buildUla(hex)
            }
        }
        val prefs = getSharedPreferences("softether_vpn", Context.MODE_PRIVATE)
        prefs.getString(KEY_ULA_V6, null)?.let { return it }
        val generated = buildUla(java.util.UUID.randomUUID().toString().replace("-", "").take(16))
        prefs.edit().putString(KEY_ULA_V6, generated).apply()
        return generated
    }

    private fun buildUla(hex: String): String {
        val groups = hex.chunked(4).joinToString(":")
        return "fd00::$groups"
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

    private fun createNotification(content: String, showDisconnectAction: Boolean = true): Notification {
        // Intent to open DetailActivity when notification is tapped
        val contentIntent = Intent().apply {
            if (notificationTargetActivity != null) {
                setClass(this@SoftEtherVpnService, notificationTargetActivity!!)
                // Dynamically fetch TYPE_START and TYPE_FROM_NOTIFY from target activity
                // to support different activities without hardcoding keys here
                // Similar to OpenVPNService.getContentIntent()
                try {
                    val startKey = notificationTargetActivity?.getField("TYPE_START")?.get(null)?.toString()
                    val startValue = notificationTargetActivity?.getField("TYPE_FROM_NOTIFY")?.get(null)?.toString()?.toInt()
                    if (startKey != null && startValue != null) {
                        putExtra(startKey, startValue)
                    }
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

        val notificationTitle = if (!currentSessionName.isNullOrEmpty()) {
            getString(R.string.softether_notification_title, currentSessionName)
        } else {
            getString(R.string.softether_notification_title_notconnect)
        }

        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(notificationTitle)
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(contentPendingIntent)
            .setOngoing(true)
            .setAutoCancel(false)

        if (showDisconnectAction) {
            val disconnectIntent = Intent(this, SoftEtherVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            val disconnectPendingIntent = PendingIntent.getService(
                this, 1, disconnectIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.softether_disconnect),
                disconnectPendingIntent
            )
        }

        return builder.build()
    }

    private fun updateNotification(content: String, showDisconnectAction: Boolean = true) {
        val notification = createNotification(content, showDisconnectAction)
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun handleTrafficUpdate(snapshot: SoftEtherTrafficSnapshot) {
        accumulatePersistedTraffic(snapshot.diffInBytes, snapshot.diffOutBytes)
        notifyTrafficListeners(snapshot)
        if (currentState == STATE_CONNECTED && mDisplaySpeed) {
            updateNotification(formatTrafficSnapshot(snapshot))
        }
    }

    private fun accumulatePersistedTraffic(downloadedDelta: Long, uploadedDelta: Long) {
        if (downloadedDelta <= 0L && uploadedDelta <= 0L) return
        val prefs = getTrafficPrefs()
        prefs.edit()
            .putLong(DOWNLOADED_DATA_KEY, prefs.getLong(DOWNLOADED_DATA_KEY, 0L) + downloadedDelta)
            .putLong(UPLOADED_DATA_KEY, prefs.getLong(UPLOADED_DATA_KEY, 0L) + uploadedDelta)
            .apply()
    }

    private fun getTrafficPrefs(): SharedPreferences {
        return applicationContext.getSharedPreferences(
            applicationContext.packageName + TRAFFIC_PREFS_SUFFIX,
            Context.MODE_PRIVATE
        )
    }

    private fun formatTrafficSnapshot(snapshot: SoftEtherTrafficSnapshot): String {
        return getString(
            R.string.softether_statusline_bytecount,
            humanReadableByteCount(snapshot.inBytesPerSecond(), true),
            humanReadableByteCount(snapshot.inBytes, false),
            humanReadableByteCount(snapshot.outBytesPerSecond(), true),
            humanReadableByteCount(snapshot.outBytes, false)
        )
    }

    private fun humanReadableByteCount(bytes: Long, speed: Boolean): String {
        val value = if (speed) bytes * 8.0 else bytes.toDouble()
        val unit = if (speed) 1000.0 else 1024.0
        val units = if (speed) {
            arrayOf("bit/s", "kbit/s", "Mbit/s", "Gbit/s")
        } else {
            arrayOf("B", "KB", "MB", "GB")
        }
        if (value <= 0.0) {
            return if (speed) "0 bit/s" else "0 B"
        }
        val exp = kotlin.math.min((kotlin.math.ln(value) / kotlin.math.ln(unit)).toInt(), units.lastIndex)
        val scaled = value / Math.pow(unit, exp.toDouble())
        return String.format(java.util.Locale.getDefault(), "%.1f %s", scaled, units[exp])
    }

    private var pendingStateRunnable: Runnable? = null
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

    private fun handleConnectionState(state: ConnectionState, hostname: String) {
        // During user-initiated stopVpn() we already sent STATE_DISCONNECTED to listeners,
        // removed the foreground notification, and launched IO cleanup.
        // Do NOT touch the notification here — the controller's disconnect() fires
        // onStateChange from the IO thread and would re-show a notification with a
        // disconnect action button.
        if (isStopping) {
            return
        }

        // Cancel any previously pending delayed state update to prevent stale state
        // from overwriting a newer state (e.g., old AUTH firing after CONNECTED)
        pendingStateRunnable?.let { mainHandler.removeCallbacks(it) }
        pendingStateRunnable = null

        // If we are in ERROR state or DISCONNECTED (and not user disconnect),
        // show error notification but ALWAYS broadcast to activity so it doesn't get stuck
        if ((state == ConnectionState.ERROR || state == ConnectionState.DISCONNECTED) && !mIsUserDisconnect) {
            if (mWasConnected) {
                triggerDisconnectNotification()
                mWasConnected = false
            }
            // Still broadcast so the activity learns the connection is gone
            val stateValue = when (state) {
                ConnectionState.ERROR -> STATE_ERROR
                else -> STATE_DISCONNECTED
            }
            sendConnectionStateBroadcast(stateValue, "")
            return
        }

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

        // Don't show the disconnect action button when we're already disconnecting
        val showDisconnectAction = state != ConnectionState.DISCONNECTING

        if (state == ConnectionState.CONNECTED) {
            mWasConnected = true
            mIsUserDisconnect = false
        }

        // Terminal states always pass through immediately
        val isTerminalState = state == ConnectionState.CONNECTED ||
                state == ConnectionState.DISCONNECTED ||
                state == ConnectionState.ERROR

        // Rate-limit non-terminal states to avoid flooding the UI
        val now = System.currentTimeMillis()
        if (!isTerminalState && now - lastStateUpdateTime < 200) {
            // Cancel any previously queued pending update first
            pendingStateRunnable?.let { mainHandler.removeCallbacks(it) }
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
            pendingStateRunnable = Runnable {
                pendingStateRunnable = null
                updateNotification(message, showDisconnectAction)
                sendConnectionStateBroadcast(stateValue, "")
            }
            mainHandler.postDelayed(pendingStateRunnable!!, 200)
            return
        }

        lastStateUpdateTime = now

        // Terminal states clear any pending update
        if (isTerminalState) {
            pendingStateRunnable?.let { mainHandler.removeCallbacks(it) }
            pendingStateRunnable = null
        }

        updateNotification(message, showDisconnectAction)

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

    @Suppress("DEPRECATION")
    private fun registerNetworkReceiver() {
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkReceiver, filter)
    }

    private fun unregisterNetworkReceiver() {
        try {
            unregisterReceiver(networkReceiver)
        } catch (e: IllegalArgumentException) {
            // Receiver was not registered
        }
    }
}
