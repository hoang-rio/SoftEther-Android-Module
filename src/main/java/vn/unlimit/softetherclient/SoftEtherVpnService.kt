package vn.unlimit.softetherclient

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * Android VPN Service implementation for SoftEther VPN protocol.
 *
 * This service manages the VPN tunnel lifecycle and provides foreground service
 * notification for persistent VPN connectivity.
 */
class SoftEtherVpnService : VpnService() {

    companion object {
        private const val TAG = "SoftEtherVpnService"

        // Notification constants
        private const val CHANNEL_ID = "softether_vpn_channel"
        private const val NOTIFICATION_ID = 2001

        // Actions
        const val ACTION_CONNECT = "vn.unlimit.softetherclient.CONNECT"
        const val ACTION_DISCONNECT = "vn.unlimit.softetherclient.DISCONNECT"

        // Preference keys
        private const val PREFS_NAME = "softether_vpn_prefs"

        // State constants for broadcasts
        const val STATE_DISCONNECTED = 0
        const val STATE_CONNECTING = 1
        const val STATE_CONNECTED = 2
        const val STATE_ERROR = 4

        @Volatile
        private var instance: SoftEtherVpnService? = null

        @JvmStatic
        fun getInstance(): SoftEtherVpnService? = instance
    }

    private var vpnClient: SoftEtherClient? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var wakeLock: PowerManager.WakeLock? = null
    @Volatile
    var isConnecting = false
        private set
    @Volatile
    var isConnected = false
        private set

    private var connectionParams: SoftEtherClient.ConnectionParams? = null
    private var currentVirtualIp: String = ""

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Service created")
        instance = this
        vpnClient = SoftEtherClient()
    }

    override fun onDestroy() {
        Log.d(TAG, "Service destroyed")
        disconnect()
        vpnClient?.cleanup()
        instance = null
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            Log.w(TAG, "Null intent received")
            return START_NOT_STICKY
        }

        val action = intent.action
        Log.d(TAG, "onStartCommand: $action")

        when (action) {
            ACTION_CONNECT -> {
                val params = extractParamsFromIntent(intent)
                if (params != null) {
                    connect(params)
                }
            }
            ACTION_DISCONNECT -> {
                disconnect()
                stopSelf()
            }
            else -> Log.w(TAG, "Unknown action: $action")
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /**
     * Extract connection parameters from intent extras
     */
    private fun extractParamsFromIntent(intent: Intent): SoftEtherClient.ConnectionParams? {
        val params = SoftEtherClient.ConnectionParams(
            serverHost = intent.getStringExtra("server_host"),
            serverPort = intent.getIntExtra("server_port", 443),
            hubName = intent.getStringExtra("hub_name") ?: "VPN",
            username = intent.getStringExtra("username"),
            password = intent.getStringExtra("password"),
            useEncrypt = intent.getBooleanExtra("use_encrypt", true),
            checkServerCert = intent.getBooleanExtra("check_server_cert", false)
        )

        return if (params.serverHost == null || params.username == null || params.password == null) {
            Log.e(TAG, "Missing required connection parameters")
            null
        } else {
            params
        }
    }

    /**
     * Start VPN connection with the given parameters
     */
    fun connect(params: SoftEtherClient.ConnectionParams) {
        if (isConnecting || isConnected) {
            Log.w(TAG, "Already connected or connecting")
            return
        }

        this.connectionParams = params
        isConnecting = true

        // Acquire wake lock to keep CPU running during connection
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SoftEtherVPN::WakeLock")
        wakeLock?.acquire(10 * 60 * 1000L) // 10 minutes max

        // Start as foreground service
        startForeground(NOTIFICATION_ID, createNotification("Connecting...", true))

        // Initialize the client
        vpnClient?.setConnectionListener(object : SoftEtherClient.ConnectionListener {
            override fun onStateChanged(state: Int) {
                handleStateChange(state)
            }

            override fun onError(errorCode: Int, errorMessage: String?) {
                handleError(errorCode, errorMessage)
            }

            override fun onConnectionEstablished(virtualIp: String?, subnetMask: String?, dnsServer: String?) {
                handleConnectionEstablished(virtualIp, subnetMask, dnsServer)
            }

            override fun onPacketReceived(packet: ByteArray?) {
                // Packets are handled internally
            }

            override fun onBytesTransferred(sent: Long, received: Long) {
                updateNotificationStats(sent, received)
            }
        })

        // Initialize native client
        val initSuccess = vpnClient?.nativeInit() ?: false
        if (!initSuccess) {
            handleError(SoftEtherClient.ERR_CONNECT_FAILED, "Failed to initialize native client")
            return
        }

        // Start connection on a background thread
        Thread {
            val success = vpnClient?.connect(this, params) ?: false
            if (!success) {
                mainHandler.post {
                    isConnecting = false
                    stopForeground(true)
                    stopSelf()
                }
            }
        }.start()
    }

    /**
     * Disconnect VPN and cleanup resources
     */
    fun disconnect() {
        Log.d(TAG, "Disconnecting...")

        isConnected = false
        isConnecting = false

        vpnClient?.disconnect()

        vpnInterface?.let {
            try {
                it.close()
            } catch (e: Exception) {
                Log.e(TAG, "Error closing VPN interface", e)
            }
            vpnInterface = null
        }

        wakeLock?.let {
            if (it.isHeld) {
                it.release()
            }
            wakeLock = null
        }

        // Notify UI of disconnection
        broadcastStateChange(STATE_DISCONNECTED)
    }

    private fun handleStateChange(state: Int) {
        mainHandler.post {
            Log.d(TAG, "State changed: $state")

            when (state) {
                SoftEtherClient.STATE_CONNECTING -> updateNotification("Connecting to VPN...", true)
                SoftEtherClient.STATE_CONNECTED -> {
                    isConnected = true
                    isConnecting = false
                    updateNotification("Connected: $currentVirtualIp", false)
                }
                SoftEtherClient.STATE_DISCONNECTED -> {
                    isConnected = false
                    isConnecting = false
                    stopForeground(true)
                }
                SoftEtherClient.STATE_ERROR -> {
                    isConnected = false
                    isConnecting = false
                    stopForeground(true)
                    stopSelf()
                }
            }

            broadcastStateChange(state)
        }
    }

    private fun handleError(errorCode: Int, errorMessage: String?) {
        Log.e(TAG, "VPN Error $errorCode: $errorMessage")

        mainHandler.post {
            // Update notification with error
            updateNotification("Error: $errorMessage", false)

            // Broadcast error to UI
            val intent = Intent("vn.unlimit.softetherclient.ERROR").apply {
                putExtra("error_code", errorCode)
                putExtra("error_message", errorMessage)
            }
            sendBroadcast(intent)
        }
    }

    private fun handleConnectionEstablished(virtualIp: String?, subnetMask: String?, dnsServer: String?) {
        this.currentVirtualIp = virtualIp ?: ""
        Log.i(TAG, "VPN Connected - IP: $virtualIp, Subnet: $subnetMask, DNS: $dnsServer")

        // Save connection info to preferences
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().apply {
            putString("last_virtual_ip", virtualIp)
            putString("last_dns", dnsServer)
            apply()
        }

        // Broadcast connection info
        val intent = Intent("vn.unlimit.softetherclient.CONNECTED").apply {
            putExtra("virtual_ip", virtualIp)
            putExtra("subnet_mask", subnetMask)
            putExtra("dns_server", dnsServer)
        }
        sendBroadcast(intent)
    }

    private fun broadcastStateChange(state: Int) {
        val intent = Intent("vn.unlimit.softetherclient.STATE_CHANGE").apply {
            putExtra("state", state)
        }
        sendBroadcast(intent)
    }

    private fun updateNotificationStats(sent: Long, received: Long) {
        // Only update every few seconds to avoid notification spam
        mainHandler.removeCallbacksAndMessages(null)
        mainHandler.postDelayed({
            val stats = "Connected - Sent: ${formatBytes(sent)}, Received: ${formatBytes(received)}"
            updateNotification(stats, false)
        }, 2000)
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            else -> {
                val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
                val unit = "KMGTPE"[exp - 1]
                String.format("%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), unit)
            }
        }
    }

    /**
     * Create notification for foreground service
     */
    private fun createNotification(contentText: String, onGoing: Boolean): Notification {
        createNotificationChannel()

        // Create pending intent for notification tap
        val intent = Intent(this, SoftEtherVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pendingIntent = PendingIntent.getService(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentTitle("SoftEther VPN")
            .setContentText(contentText)
            .setOngoing(onGoing)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .addAction(android.R.drawable.ic_delete, "Disconnect", pendingIntent)
            .build()
    }

    private fun updateNotification(contentText: String, onGoing: Boolean) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, createNotification(contentText, onGoing))
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SoftEther VPN",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "SoftEther VPN connection status"
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    fun getCurrentVirtualIp(): String = currentVirtualIp
}
