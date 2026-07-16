package vn.unlimit.softether.model

import android.os.Build
import android.os.Parcel
import android.os.Parcelable

/**
 * Client information reported to SoftEther server during login PACK.
 * These fields appear in the server's session list for client identification.
 */
data class ClientInfo(
    // Product identification
    val productName: String,          // "VPN Gate Connector" / "VPN Gate Connector Pro"
    val productVersion: String,       // BuildConfig.VERSION_NAME (e.g., "2.3.2")
    val productBuild: Int,            // BuildConfig.VERSION_CODE (e.g., 132)

    // OS identification
    val osName: String,               // Build.MANUFACTURER + " " + Build.MODEL
    val osVersion: String,            // Build.VERSION.RELEASE (Android version)
    val osProductId: String,          // Build.FINGERPRINT

    // Host/Network info
    val hostName: String,             // Local hostname
    val clientIpAddress: String,      // Local non-loopback IP address
    val clientPort: Int,              // Local RUDP UDP port or 0

    // Server info (for cross-reference)
    val serverHostName: String,       // ConnectionConfig.serverHost
    val serverIpAddress: String,      // Resolved server IP
    val serverPort: Int               // ConnectionConfig.serverPort
) : Parcelable {

    constructor(parcel: Parcel) : this(
        productName = parcel.readString() ?: "",
        productVersion = parcel.readString() ?: "",
        productBuild = parcel.readInt(),
        osName = parcel.readString() ?: "",
        osVersion = parcel.readString() ?: "",
        osProductId = parcel.readString() ?: "",
        hostName = parcel.readString() ?: "",
        clientIpAddress = parcel.readString() ?: "",
        clientPort = parcel.readInt(),
        serverHostName = parcel.readString() ?: "",
        serverIpAddress = parcel.readString() ?: "",
        serverPort = parcel.readInt()
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(productName)
        parcel.writeString(productVersion)
        parcel.writeInt(productBuild)
        parcel.writeString(osName)
        parcel.writeString(osVersion)
        parcel.writeString(osProductId)
        parcel.writeString(hostName)
        parcel.writeString(clientIpAddress)
        parcel.writeInt(clientPort)
        parcel.writeString(serverHostName)
        parcel.writeString(serverIpAddress)
        parcel.writeInt(serverPort)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<ClientInfo> {
        override fun createFromParcel(parcel: Parcel): ClientInfo {
            return ClientInfo(parcel)
        }

        override fun newArray(size: Int): Array<ClientInfo?> {
            return arrayOfNulls(size)
        }
    }

    /**
     * Build ClientInfo from Android Build constants and connection config.
     * Must be called from a context where BuildConfig is available.
     */
    companion object {
        fun build(
            productName: String,
            productVersion: String,
            productBuild: Int,
            config: ConnectionConfig,
            rudpPort: Int = 0,
            hostName: String = getLocalHostName(),
            clientIpAddress: String = getLocalIpAddress()
        ): ClientInfo {
            return ClientInfo(
                productName = productName,
                productVersion = productVersion,
                productBuild = productBuild,
                osName = "${Build.MANUFACTURER} ${Build.MODEL}",
                osVersion = Build.VERSION.RELEASE,
                osProductId = Build.FINGERPRINT,
                hostName = hostName,
                clientIpAddress = clientIpAddress,
                clientPort = rudpPort,
                serverHostName = config.serverHost,
                serverIpAddress = resolveHostName(config.serverHost),
                serverPort = config.serverPort
            )
        }

        private fun getLocalHostName(): String {
            return try {
                java.net.InetAddress.getLocalHost().hostName
            } catch (e: Exception) {
                "android-device"
            }
        }

        private fun getLocalIpAddress(): String {
            return try {
                val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
                while (interfaces.hasMoreElements()) {
                    val iface = interfaces.nextElement()
                    val addresses = iface.inetAddresses
                    while (addresses.hasMoreElements()) {
                        val addr = addresses.nextElement()
                        if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                            return addr.hostAddress
                        }
                    }
                }
                "0.0.0.0"
            } catch (e: Exception) {
                "0.0.0.0"
            }
        }

        private fun resolveHostName(hostName: String): String {
            return try {
                java.net.InetAddress.getByName(hostName).hostAddress
            } catch (e: Exception) {
                "0.0.0.0"
            }
        }
    }
}