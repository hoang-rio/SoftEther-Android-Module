package vn.unlimit.softether.controller

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import vn.unlimit.softether.model.ConnectionConfig

/**
 * Phase 17: device-tier selector that decides half vs full-duplex at connect time.
 *
 * Full-duplex (half_connection=0) makes every SoftEther connection BOTH, giving
 * up to 4 independent receive windows and letting each direction borrow any link.
 * It costs extra CPU/SSL/RX overhead per concurrent TLS session, which low-tier
 * devices (few cores, little RAM, weak/volatile link) waste because all TX is
 * serialized behind a single write_mutex anyway. So low-tier devices keep the
 * cheaper half-duplex directional C2S/S2C split (or fewer connections).
 */
object DuplexModeSelector {
    private const val TAG = "DuplexModeSelector"

    /**
     * Thresholds (tunable). Flagship tier -> full-duplex.
     */
    private const val MIN_CORES_FULL = 4
    private const val MIN_RAM_GB_FULL = 4

    /**
     * Resolve the duplex mode.
     *
     * Precedence:
     *  1. Explicit manual override in [ConnectionConfig.fullDuplex] (testing/debug).
     *  2. Network link strength gate: a volatile cellular/poor link goes half-duplex
     *     regardless of device power (multi-socket concurrency only adds stalls there).
     *  3. Device capability tier: cores + RAM thresholds.
     *
     * @return true = full-duplex (all BOTH), false = half-duplex (directional split).
     */
    fun resolve(context: Context, config: ConnectionConfig): Boolean {
        config.fullDuplex?.let { override ->
            Log.d(TAG, "Duplex override=$override (manual)")
            return override
        }

        val cores = Runtime.getRuntime().availableProcessors()
        val totalMemGB = totalMemGb(context)
        val network = classifyNetwork(context)

        val capabilityFull = cores >= MIN_CORES_FULL && totalMemGB >= MIN_RAM_GB_FULL
        val linkStrong = network in listOf(NetworkKind.WIFI, NetworkKind.CELLULAR_STRONG)
        val fullDuplex = capabilityFull && linkStrong

        Log.d(
            TAG,
            "Duplex auto: cores=$cores totalMemGB=$totalMemGB network=$network " +
                "=> fullDuplex=$fullDuplex (capability=$capabilityFull linkStrong=$linkStrong)"
        )
        return fullDuplex
    }

    private fun totalMemGb(context: Context): Int {
        return runCatching {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val memInfo = ActivityManager.MemoryInfo()
            am.getMemoryInfo(memInfo)
            (memInfo.totalMem / (1024L * 1024L * 1024L)).toInt()
        }.getOrDefault(0)
    }

    private fun classifyNetwork(context: Context): NetworkKind {
        return runCatching {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return NetworkKind.UNKNOWN
            val isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            val isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
            val strongCellular = isCellular &&
                caps.linkUpstreamBandwidthKbps >= 10_000 // ~10 Mbps uplink as "strong" proxy
            when {
                isWifi -> NetworkKind.WIFI
                strongCellular -> NetworkKind.CELLULAR_STRONG
                isCellular -> NetworkKind.CELLULAR_WEAK
                else -> NetworkKind.UNKNOWN
            }
        }.getOrDefault(NetworkKind.UNKNOWN)
    }

    private enum class NetworkKind {
        WIFI,
        CELLULAR_STRONG,
        CELLULAR_WEAK,
        UNKNOWN
    }
}
