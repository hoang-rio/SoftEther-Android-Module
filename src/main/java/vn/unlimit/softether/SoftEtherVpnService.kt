package vn.unlimit.softether

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import vn.unlimit.softether.controller.ConnectionController
import vn.unlimit.softether.model.ConnectionConfig

/**
 * SoftEther VPN Service - Main VPN service implementation for Android
 */
class SoftEtherVpnService : VpnService() {

    companion object {
        private const val TAG = "SoftEtherVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "SoftEtherVPN"
        private const val NOTIFICATION_ID = 1001

        // Actions
        const val ACTION_CONNECT = "vn.unlimit.softether.CONNECT"
        const val ACTION_DISCONNECT = "vn.unlimit.softether.DISCONNECT"

        // Extras
        const val EXTRA_CONFIG = "config"
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var controller: ConnectionController? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")

        when (intent?.action) {
            ACTION_CONNECT -> {
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
        stopVpn()
        unregisterNetworkReceiver()
        serviceScope.cancel()
    }

    private fun startVpn(config: ConnectionConfig) {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }

        Log.d(TAG, "Starting VPN with config: ${config.serverHost}:${config.serverPort}")

        // Start as foreground service
        startForeground(NOTIFICATION_ID, createNotification("Connecting..."))

        serviceScope.launch {
            try {
                // Initialize connection controller
                controller = ConnectionController(
                    service = this@SoftEtherVpnService,
                    config = config,
                    onStateChange = { state ->
                        updateNotification("State: $state")
                    },
                    onError = { error ->
                        Log.e(TAG, "VPN Error: $error")
                        updateNotification("Error: $error")
                        stopVpn()
                    }
                )

                // Establish connection
                controller?.connect()
                isRunning = true

                Log.d(TAG, "VPN connection established")
                updateNotification("Connected to ${config.serverHost}")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
                updateNotification("Connection failed: ${e.message}")
                stopVpn()
            }
        }
    }

    private fun stopVpn() {
        Log.d(TAG, "Stopping VPN")
        isRunning = false

        // Disconnect controller
        controller?.disconnect()
        controller = null

        // Close VPN interface
        vpnInterface?.close()
        vpnInterface = null

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
     * Establish the VPN tunnel interface
     */
    fun establishVpnInterface(config: ConnectionConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(config.sessionName)
            .setMtu(config.mtu)
            .addAddress(config.localAddress, config.prefixLength)
            .addDnsServer(config.dnsServer)

        // Add routes
        config.routes.forEach { route ->
            builder.addRoute(route.address, route.prefixLength)
        }

        // Allow bypass for certain apps if configured
        config.allowedApps.forEach { packageName ->
            builder.addAllowedApplication(packageName)
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
        val disconnectIntent = Intent(this, SoftEtherVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this, 0, disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("SoftEther VPN")
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_menu_close_clear_cancel) // Replace with your icon
            .setOngoing(true)
            .setAutoCancel(false)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPendingIntent)
            .build()
    }

    private fun updateNotification(content: String) {
        val notification = createNotification(content)
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)
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
