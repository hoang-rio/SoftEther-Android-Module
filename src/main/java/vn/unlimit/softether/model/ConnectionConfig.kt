package vn.unlimit.softether.model

import android.os.Parcel
import android.os.Parcelable

/**
 * Configuration for SoftEther VPN connection
 */
data class ConnectionConfig(
    val serverHost: String,
    val serverPort: Int = 443,
    val username: String,
    val password: String,
    val virtualHub: String = "VPN",
    val sessionName: String = "SoftEther VPN",
    val localAddress: String = "10.0.0.2",
    val prefixLength: Int = 24,
    val dnsServer: String = "8.8.8.8",
    val mtu: Int = 1500,
    val routes: List<Route> = listOf(Route("0.0.0.0", 0)), // Default route all traffic
    val allowedApps: List<String> = emptyList(), // Apps allowed to bypass VPN
    val isMetered: Boolean = false,
    val useTcp: Boolean = true,
    val useUdp: Boolean = false,
    val connectTimeoutMs: Int = 30000,
    val keepAliveIntervalMs: Int = 60000
) : Parcelable {

    constructor(parcel: Parcel) : this(
        serverHost = parcel.readString() ?: "",
        serverPort = parcel.readInt(),
        username = parcel.readString() ?: "",
        password = parcel.readString() ?: "",
        virtualHub = parcel.readString() ?: "VPN",
        sessionName = parcel.readString() ?: "SoftEther VPN",
        localAddress = parcel.readString() ?: "10.0.0.2",
        prefixLength = parcel.readInt(),
        dnsServer = parcel.readString() ?: "8.8.8.8",
        mtu = parcel.readInt(),
        routes = parcel.createTypedArrayList(Route.CREATOR) ?: listOf(Route("0.0.0.0", 0)),
        allowedApps = parcel.createStringArrayList() ?: emptyList(),
        isMetered = parcel.readByte() != 0.toByte(),
        useTcp = parcel.readByte() != 0.toByte(),
        useUdp = parcel.readByte() != 0.toByte(),
        connectTimeoutMs = parcel.readInt(),
        keepAliveIntervalMs = parcel.readInt()
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(serverHost)
        parcel.writeInt(serverPort)
        parcel.writeString(username)
        parcel.writeString(password)
        parcel.writeString(virtualHub)
        parcel.writeString(sessionName)
        parcel.writeString(localAddress)
        parcel.writeInt(prefixLength)
        parcel.writeString(dnsServer)
        parcel.writeInt(mtu)
        parcel.writeTypedList(routes)
        parcel.writeStringList(allowedApps)
        parcel.writeByte(if (isMetered) 1 else 0)
        parcel.writeByte(if (useTcp) 1 else 0)
        parcel.writeByte(if (useUdp) 1 else 0)
        parcel.writeInt(connectTimeoutMs)
        parcel.writeInt(keepAliveIntervalMs)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<ConnectionConfig> {
        override fun createFromParcel(parcel: Parcel): ConnectionConfig {
            return ConnectionConfig(parcel)
        }

        override fun newArray(size: Int): Array<ConnectionConfig?> {
            return arrayOfNulls(size)
        }
    }
}

/**
 * Route configuration for VPN tunnel
 */
data class Route(
    val address: String,
    val prefixLength: Int
) : Parcelable {

    constructor(parcel: Parcel) : this(
        address = parcel.readString() ?: "",
        prefixLength = parcel.readInt()
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(address)
        parcel.writeInt(prefixLength)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<Route> {
        override fun createFromParcel(parcel: Parcel): Route {
            return Route(parcel)
        }

        override fun newArray(size: Int): Array<Route?> {
            return arrayOfNulls(size)
        }
    }
}

/**
 * Server information from VPNGate or other sources
 */
data class ServerInfo(
    val ip: String,
    val port: Int,
    val hostname: String = "",
    val country: String = "",
    val score: Int = 0,
    val ping: Int = 0,
    val speed: Long = 0,
    val sessionCount: Int = 0,
    val uptime: Long = 0,
    val operator: String = "",
    val message: String = "",
    val supportsSoftEther: Boolean = true
)

/**
 * Connection state enumeration
 */
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    TLS_HANDSHAKE,
    PROTOCOL_HANDSHAKE,
    AUTHENTICATING,
    SESSION_SETUP,
    CONNECTED,
    DISCONNECTING
}
