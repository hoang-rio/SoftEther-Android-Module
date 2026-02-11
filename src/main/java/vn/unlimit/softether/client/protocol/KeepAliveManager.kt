package vn.unlimit.softether.client.protocol

import android.util.Log
import vn.unlimit.softether.client.SoftEtherClient

/**
 * Manages keepalive packets to maintain VPN connection
 */
class KeepAliveManager(private val client: SoftEtherClient) {

    companion object {
        private const val TAG = "KeepAliveManager"
        private const val DEFAULT_INTERVAL_MS = 60000L // 60 seconds
        private const val DEFAULT_TIMEOUT_MS = 30000L // 30 seconds
        private const val MISSED_THRESHOLD = 3 // Number of missed keepalives before considering connection dead
    }

    private var intervalMs = DEFAULT_INTERVAL_MS
    private var timeoutMs = DEFAULT_TIMEOUT_MS
    private var lastSentTime = 0L
    private var lastReceivedTime = 0L
    private var missedCount = 0
    private var isRunning = false

    /**
     * Set keepalive interval
     * @param intervalMs Interval in milliseconds
     */
    fun setInterval(intervalMs: Long) {
        this.intervalMs = intervalMs
        Log.d(TAG, "Keepalive interval set to ${intervalMs}ms")
    }

    /**
     * Set keepalive timeout
     * @param timeoutMs Timeout in milliseconds
     */
    fun setTimeout(timeoutMs: Long) {
        this.timeoutMs = timeoutMs
        Log.d(TAG, "Keepalive timeout set to ${timeoutMs}ms")
    }

    /**
     * Start keepalive manager
     */
    fun start() {
        if (isRunning) return
        isRunning = true
        lastSentTime = System.currentTimeMillis()
        lastReceivedTime = System.currentTimeMillis()
        missedCount = 0
        Log.d(TAG, "Keepalive manager started")
    }

    /**
     * Stop keepalive manager
     */
    fun stop() {
        isRunning = false
        Log.d(TAG, "Keepalive manager stopped")
    }

    /**
     * Check if it's time to send a keepalive
     * @return true if keepalive should be sent
     */
    fun shouldSendKeepAlive(): Boolean {
        if (!isRunning) return false
        return System.currentTimeMillis() - lastSentTime >= intervalMs
    }

    /**
     * Record that a keepalive was sent
     */
    fun recordSent() {
        lastSentTime = System.currentTimeMillis()
        Log.v(TAG, "Keepalive sent recorded")
    }

    /**
     * Record that a keepalive was received
     */
    fun recordReceived() {
        lastReceivedTime = System.currentTimeMillis()
        missedCount = 0 // Reset missed counter on successful receipt
        Log.v(TAG, "Keepalive received recorded")
    }

    /**
     * Check if the connection appears to be dead
     * @return true if connection should be considered dead
     */
    fun isConnectionDead(): Boolean {
        if (!isRunning) return false

        val timeSinceLastReceive = System.currentTimeMillis() - lastReceivedTime
        if (timeSinceLastReceive > timeoutMs) {
            missedCount++
            Log.w(TAG, "Keepalive missed ($missedCount/$MISSED_THRESHOLD)")
        }

        return missedCount >= MISSED_THRESHOLD
    }

    /**
     * Get statistics
     */
    fun getStats(): KeepAliveStats {
        return KeepAliveStats(
            intervalMs = intervalMs,
            timeoutMs = timeoutMs,
            lastSentTime = lastSentTime,
            lastReceivedTime = lastReceivedTime,
            missedCount = missedCount,
            isRunning = isRunning
        )
    }

    /**
     * Reset statistics
     */
    fun reset() {
        lastSentTime = 0
        lastReceivedTime = 0
        missedCount = 0
    }
}

/**
 * Keepalive statistics
 */
data class KeepAliveStats(
    val intervalMs: Long,
    val timeoutMs: Long,
    val lastSentTime: Long,
    val lastReceivedTime: Long,
    val missedCount: Int,
    val isRunning: Boolean
) {
    /**
     * Get time since last received keepalive
     */
    fun timeSinceLastReceive(): Long {
        return if (lastReceivedTime > 0) {
            System.currentTimeMillis() - lastReceivedTime
        } else {
            0
        }
    }

    /**
     * Get time since last sent keepalive
     */
    fun timeSinceLastSend(): Long {
        return if (lastSentTime > 0) {
            System.currentTimeMillis() - lastSentTime
        } else {
            0
        }
    }
}
