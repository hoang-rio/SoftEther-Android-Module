package vn.unlimit.softether.client.protocol

import android.util.Log
import vn.unlimit.softether.client.SoftEtherClient
import vn.unlimit.softether.model.ConnectionState

/**
 * Manages the SoftEther protocol handshake process
 */
class HandshakeManager(private val client: SoftEtherClient) {

    companion object {
        private const val TAG = "HandshakeManager"
        private const val HANDSHAKE_TIMEOUT_MS = 30000L
        private const val MAX_RETRY_ATTEMPTS = 3
    }

    private var retryCount = 0
    private var currentState: ConnectionState = ConnectionState.DISCONNECTED

    /**
     * Perform complete handshake sequence
     * @return true if handshake successful, false otherwise
     */
    suspend fun performHandshake(): Boolean {
        Log.d(TAG, "Starting handshake sequence")
        currentState = ConnectionState.PROTOCOL_HANDSHAKE

        return try {
            // Step 1: Protocol version negotiation
            if (!negotiateVersion()) {
                Log.e(TAG, "Version negotiation failed")
                return false
            }

            // Step 2: Authentication (handled in native layer during connect)
            currentState = ConnectionState.AUTHENTICATING
            Log.d(TAG, "Authentication completed")

            // Step 3: Session setup (handled in native layer during connect)
            currentState = ConnectionState.SESSION_SETUP
            Log.d(TAG, "Session setup completed")

            currentState = ConnectionState.CONNECTED
            Log.d(TAG, "Handshake completed successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Handshake failed", e)
            false
        }
    }

    /**
     * Negotiate protocol version with server
     */
    private fun negotiateVersion(): Boolean {
        // Version negotiation is handled in native layer
        // This method serves as a placeholder for any additional
        // version-specific logic needed in the Kotlin layer
        return true
    }

    /**
     * Retry handshake with exponential backoff
     */
    suspend fun retryHandshake(): Boolean {
        if (retryCount >= MAX_RETRY_ATTEMPTS) {
            Log.e(TAG, "Max retry attempts reached")
            return false
        }

        retryCount++
        val delayMs = (1000 * retryCount).toLong()
        Log.d(TAG, "Retrying handshake in ${delayMs}ms (attempt $retryCount/$MAX_RETRY_ATTEMPTS)")

        kotlinx.coroutines.delay(delayMs)
        return performHandshake()
    }

    /**
     * Reset retry counter
     */
    fun resetRetryCount() {
        retryCount = 0
    }

    /**
     * Get current handshake state
     */
    fun getCurrentState(): ConnectionState = currentState

    /**
     * Check if handshake is in progress
     */
    fun isHandshakeInProgress(): Boolean {
        return currentState == ConnectionState.PROTOCOL_HANDSHAKE ||
                currentState == ConnectionState.AUTHENTICATING ||
                currentState == ConnectionState.SESSION_SETUP
    }
}
