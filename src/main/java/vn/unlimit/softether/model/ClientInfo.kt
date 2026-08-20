package vn.unlimit.softether.model

import android.os.Build
import android.os.Parcel
import android.os.Parcelable

data class ClientInfo(
    val productName: String,
    val productVersion: String,
    val productBuild: Int,
    val osName: String,
    val osVersion: String,
    val osProductId: String,
    val hostName: String,
    val clientIpAddress: String,
    val isIPv6: Boolean = clientIpAddress.contains(":"),
    val clientPort: Int,
    val serverHostName: String,
    val serverIpAddress: String,
    val serverPort: Int
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
        isIPv6 = parcel.readByte() != 0.toByte(),
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
        parcel.writeByte(if (isIPv6) 1 else 0)
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
}

object ClientInfoFactory {
    fun build(
        productName: String,
        productVersion: String,
        productBuild: Int,
        config: ConnectionConfig,
        rudpPort: Int = 0,
        hostName: String = getLocalHostName(),
        clientIpAddress: String = getLocalIpAddress().takeIf { it.isNotEmpty() && it != "0.0.0.0" }
            ?: getLocalIPv6Address(),
        isIPv6: Boolean = clientIpAddress.contains(":")
    ): ClientInfo {
        return ClientInfo(
            productName = productName,
            productVersion = productVersion,
            productBuild = productBuild,
            osName = "Android",
            osVersion = Build.VERSION.RELEASE,
            osProductId = Build.FINGERPRINT,
            hostName = hostName,
            clientIpAddress = clientIpAddress,
            isIPv6 = isIPv6,
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
                        return addr.hostAddress ?: "0.0.0.0"
                    }
                }
            }
            return "0.0.0.0"
        } catch (e: Exception) {
            return "0.0.0.0"
        }
    }

    private fun getLocalIPv6Address(): String {
        return try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                val addresses = iface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val addr = addresses.nextElement()
                    if (!addr.isLoopbackAddress &&
                        !addr.isLinkLocalAddress &&
                        addr is java.net.Inet6Address
                    ) {
                        return addr.hostAddress ?: "::"
                    }
                }
            }
            return "::"
        } catch (e: Exception) {
            return "::"
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
