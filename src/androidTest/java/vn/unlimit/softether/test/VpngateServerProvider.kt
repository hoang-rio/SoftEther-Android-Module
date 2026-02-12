package vn.unlimit.softether.test

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import vn.unlimit.softether.model.ServerInfo
import java.net.HttpURLConnection
import java.net.URL

/**
 * Provider for VPNGate server list
 */
class VpngateServerProvider(private val context: Context) {

    companion object {
        private const val TAG = "VpngateServerProvider"
        private const val VPNGATE_API_URL = "https://www.vpngate.net/api/iphone/"
        private const val CACHE_DURATION_MS = 5 * 60 * 1000 // 5 minutes
    }

    private var cachedServers: List<ServerInfo>? = null
    private var cacheTime: Long = 0

    /**
     * Get all available servers
     */
    fun getServers(): List<ServerInfo> {
        return fetchServers()
    }

    /**
     * Get SoftEther-compatible servers
     */
    fun getSoftEtherServers(): List<ServerInfo> {
        return fetchServers().filter { it.supportsSoftEther }
    }

    /**
     * Get SoftEther servers with authentication info
     */
    fun getSoftEtherServersWithAuth(): List<ServerInfo> {
        return fetchServers().filter { it.supportsSoftEther }
    }

    /**
     * Get servers filtered by criteria
     */
    fun getFilteredServers(
        minScore: Int = TestConfig.MIN_SCORE,
        maxPing: Int = TestConfig.MAX_PING,
        minSpeed: Long = TestConfig.MIN_SPEED
    ): List<ServerInfo> {
        return fetchServers().filter {
            it.supportsSoftEther &&
            it.score >= minScore &&
            it.ping <= maxPing &&
            it.speed >= minSpeed
        }
    }

    private fun fetchServers(): List<ServerInfo> {
        // Check cache
        val now = System.currentTimeMillis()
        if (cachedServers != null && (now - cacheTime) < CACHE_DURATION_MS) {
            Log.d(TAG, "Returning cached servers: ${cachedServers?.size}")
            return cachedServers!!
        }

        val servers = mutableListOf<ServerInfo>()

        try {
            Log.d(TAG, "Fetching servers from VPNGate API")
            val url = URL(VPNGATE_API_URL)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 10000
            connection.readTimeout = 15000

            val response = connection.inputStream.bufferedReader().use { it.readText() }
            connection.disconnect()

            // Parse VPNGate API response (CSV format)
            // Format: *host,ip,score,ping,speed,country,countryLong,numVpnSessions,uptime,totalUsers,totalTraffic,logType,operator,message,configData
            val lines = response.lines()

            // Skip header lines
            var lineCount = 0
            for (line in lines) {
                lineCount++
                if (lineCount <= 2 || line.isBlank() || line.startsWith("*")) {
                    continue
                }

                val fields = line.split(",")
                if (fields.size >= 15) {
                    try {
                        val server = parseServer(fields)
                        if (server != null) {
                            servers.add(server)
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Error parsing server: ${e.message}")
                    }
                }
            }

            // Sort by score (higher is better)
            val sortedServers = servers.sortedByDescending { it.score }
            cachedServers = sortedServers
            cacheTime = now

            Log.d(TAG, "Fetched ${sortedServers.size} servers from VPNGate")
            return sortedServers

        } catch (e: Exception) {
            Log.e(TAG, "Error fetching servers: ${e.message}")
            return cachedServers ?: emptyList()
        }
    }

    private fun parseServer(fields: List<String>): ServerInfo? {
        val hostname = fields.getOrNull(0)?.trim()?.removePrefix("*") ?: return null
        val ip = fields.getOrNull(1)?.trim() ?: return null
        val score = fields.getOrNull(2)?.toIntOrNull() ?: 0
        val ping = fields.getOrNull(3)?.toIntOrNull() ?: 9999
        val speed = fields.getOrNull(4)?.toLongOrNull() ?: 0
        val countryLong = fields.getOrNull(6)?.trim() ?: ""
        val sessionCount = fields.getOrNull(7)?.toIntOrNull() ?: 0
        val uptime = fields.getOrNull(8)?.toLongOrNull() ?: 0
        val totalUsers = fields.getOrNull(9)?.toLongOrNull() ?: 0
        val totalTraffic = fields.getOrNull(10)?.toLongOrNull() ?: 0
        val logType = fields.getOrNull(11)?.trim() ?: ""
        val operator = fields.getOrNull(12)?.trim() ?: ""
        val message = fields.getOrNull(13)?.trim() ?: ""

        // Check if SoftEther is supported (usually port 443 or 992)
        val supportsSoftEther = true // VPNGate servers typically support SoftEther

        // Determine port (usually 443 for SoftEther SSL-VPN)
        val port = 443

        return ServerInfo(
            ip = ip,
            port = port,
            hostname = hostname,
            country = countryLong,
            score = score,
            ping = ping,
            speed = speed,
            sessionCount = sessionCount,
            uptime = uptime,
            operator = operator,
            message = message,
            supportsSoftEther = supportsSoftEther
        )
    }

    /**
     * Clear cached server list
     */
    fun clearCache() {
        cachedServers = null
        cacheTime = 0
    }
}
