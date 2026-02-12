package vn.unlimit.softether.test

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import vn.unlimit.softether.model.ServerInfo
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Utility class to check server availability before running tests
 * Helps skip tests against unavailable servers
 */
class ServerAvailabilityChecker {

    companion object {
        private const val TAG = "ServerAvailability"
        private const val TCP_TIMEOUT_MS = 5000
        private const val TLS_TIMEOUT_MS = 8000

        /**
         * Check if a server is available via TCP connection
         */
        suspend fun checkTcpAvailability(server: ServerInfo): Boolean = withContext(Dispatchers.IO) {
            try {
                withTimeout(TCP_TIMEOUT_MS.toLong()) {
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress(server.ip, server.port), TCP_TIMEOUT_MS)
                        true
                    }
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "TCP check timeout for ${server.ip}:${server.port}")
                false
            } catch (e: Exception) {
                Log.w(TAG, "TCP check failed for ${server.ip}:${server.port}: ${e.message}")
                false
            }
        }

        /**
         * Check if a server supports TLS
         */
        suspend fun checkTlsAvailability(server: ServerInfo): Boolean = withContext(Dispatchers.IO) {
            try {
                withTimeout(TLS_TIMEOUT_MS.toLong()) {
                    val sslContext = SSLContext.getInstance("TLS")
                    sslContext.init(null, null, null)
                    val factory: SSLSocketFactory = sslContext.socketFactory

                    factory.createSocket(server.ip, server.port).use { socket ->
                        (socket as SSLSocket).apply {
                            startHandshake()
                        }
                        true
                    }
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "TLS check timeout for ${server.ip}:${server.port}")
                false
            } catch (e: Exception) {
                Log.w(TAG, "TLS check failed for ${server.ip}:${server.port}: ${e.message}")
                false
            }
        }

        /**
         * Filter available servers from a list
         */
        suspend fun filterAvailableServers(
            servers: List<ServerInfo>,
            checkTls: Boolean = false
        ): List<ServerInfo> = withContext(Dispatchers.IO) {
            val availableServers = mutableListOf<ServerInfo>()

            for (server in servers) {
                val tcpAvailable = checkTcpAvailability(server)
                if (tcpAvailable) {
                    if (checkTls) {
                        if (checkTlsAvailability(server)) {
                            availableServers.add(server)
                            Log.d(TAG, "Server ${server.ip}:${server.port} is available (TCP+TLS)")
                        } else {
                            Log.w(TAG, "Server ${server.ip}:${server.port} TCP ok but TLS failed")
                        }
                    } else {
                        availableServers.add(server)
                        Log.d(TAG, "Server ${server.ip}:${server.port} is available (TCP)")
                    }
                } else {
                    Log.w(TAG, "Server ${server.ip}:${server.port} is not available")
                }
            }

            Log.d(TAG, "Found ${availableServers.size}/${servers.size} available servers")
            availableServers
        }

        /**
         * Get the first available server from a list
         */
        suspend fun getFirstAvailableServer(
            servers: List<ServerInfo>,
            checkTls: Boolean = false
        ): ServerInfo? = withContext(Dispatchers.IO) {
            for (server in servers) {
                val tcpAvailable = checkTcpAvailability(server)
                if (tcpAvailable) {
                    if (checkTls) {
                        if (checkTlsAvailability(server)) {
                            Log.d(TAG, "Found available server: ${server.ip}:${server.port}")
                            return@withContext server
                        }
                    } else {
                        Log.d(TAG, "Found available server: ${server.ip}:${server.port}")
                        return@withContext server
                    }
                }
            }
            Log.w(TAG, "No available servers found")
            null
        }

        /**
         * Batch check multiple servers concurrently
         */
        suspend fun batchCheckAvailability(
            servers: List<ServerInfo>,
            maxConcurrent: Int = 5,
            checkTls: Boolean = false
        ): Map<ServerInfo, Boolean> = withContext(Dispatchers.IO) {
            val results = mutableMapOf<ServerInfo, Boolean>()

            // Process in batches to avoid overwhelming the system
            val batches = servers.chunked(maxConcurrent)

            for (batch in batches) {
                val batchResults = batch.map { server ->
                    server to if (checkTls) {
                        checkTlsAvailability(server)
                    } else {
                        checkTcpAvailability(server)
                    }
                }
                results.putAll(batchResults)
            }

            results
        }
    }
}

/**
 * Data class representing server availability status
 */
data class ServerAvailabilityStatus(
    val server: ServerInfo,
    val tcpAvailable: Boolean,
    val tlsAvailable: Boolean,
    val checkTimeMs: Long
) {
    val isFullyAvailable: Boolean
        get() = tcpAvailable && tlsAvailable

    fun toSummaryString(): String {
        return buildString {
            append(server.ip)
            append(":")
            append(server.port)
            append(" [TCP:")
            append(if (tcpAvailable) "OK" else "FAIL")
            append(", TLS:")
            append(if (tlsAvailable) "OK" else "FAIL")
            append("] (")
            append(checkTimeMs)
            append("ms)")
        }
    }
}
