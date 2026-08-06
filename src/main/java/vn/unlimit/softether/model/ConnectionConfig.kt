package vn.unlimit.softether.model

import android.os.Parcel
import android.os.Parcelable

/**
 * Authentication method for SoftEther VPN connection
 */
enum class AuthMethod {
    AUTO,           // Auto-detect: password if non-empty, else anonymous
    ANONYMOUS,      // Anonymous authentication (no password)
    PASSWORD,       // Hashed password authentication (CLIENT_AUTHTYPE_PASSWORD)
    PLAIN_PASSWORD  // Plain text password for RADIUS authentication (CLIENT_AUTHTYPE_PLAIN_PASSWORD)
}

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
    val localAddress: String = "10.21.0.2",
    val prefixLength: Int = 24,
    val dnsServer: String = "8.8.8.8",
    val secondaryDnsServer: String = "8.8.4.4",
    val mtu: Int = 1500,
    val routes: List<Route> = listOf(Route("0.0.0.0", 0)), // Default route all traffic
    val localAddressV6: String = "fd00::2",
    val prefixLengthV6: Int = 128,
    val dnsServerV6: String = "2001:4860:4860::8888",
    val routesV6: List<Route> = listOf(Route("::", 0)),
    val excludedApps: List<String> = emptyList(), // Apps excluded from VPN (bypass VPN tunnel)
    val isMetered: Boolean = false,
    val useTcp: Boolean = true,
    val useUdp: Boolean = false,
    val connectTimeoutMs: Int = 30000,
    val keepAliveIntervalMs: Int = 60000,
    val country: String = "",
    val isL2TPSupport: Boolean = false,
    val isSSTPSupport: Boolean = false,
    val authMethod: AuthMethod = AuthMethod.AUTO,
    val clientProductName: String = "VPN Gate Connector",
    val clientVersion: String = "1.0.0",
    val clientBuild: Int = 1
) : Parcelable {

    constructor(parcel: Parcel) : this(
        serverHost = parcel.readString() ?: "",
        serverPort = parcel.readInt(),
        username = parcel.readString() ?: "",
        password = parcel.readString() ?: "",
        virtualHub = parcel.readString() ?: "VPN",
        sessionName = parcel.readString() ?: "SoftEther VPN",
        localAddress = parcel.readString() ?: "10.21.0.2",
        prefixLength = parcel.readInt(),
        dnsServer = parcel.readString() ?: "8.8.8.8",
        secondaryDnsServer = parcel.readString() ?: "8.8.4.4",
        mtu = parcel.readInt(),
        routes = parcel.createTypedArrayList(Route.CREATOR) ?: listOf(Route("0.0.0.0", 0)),
        localAddressV6 = parcel.readString() ?: "fd00::2",
        prefixLengthV6 = parcel.readInt(),
        dnsServerV6 = parcel.readString() ?: "2001:4860:4860::8888",
        routesV6 = parcel.createTypedArrayList(Route.CREATOR) ?: listOf(Route("::", 0)),
        excludedApps = parcel.createStringArrayList() ?: emptyList(),
        isMetered = parcel.readByte() != 0.toByte(),
        useTcp = parcel.readByte() != 0.toByte(),
        useUdp = parcel.readByte() != 0.toByte(),
        connectTimeoutMs = parcel.readInt(),
        keepAliveIntervalMs = parcel.readInt(),
        country = parcel.readString() ?: "",
        isL2TPSupport = parcel.readByte() != 0.toByte(),
        isSSTPSupport = parcel.readByte() != 0.toByte(),
        authMethod = AuthMethod.valueOf(parcel.readString() ?: AuthMethod.AUTO.name),
        clientProductName = parcel.readString() ?: "VPN Gate Connector",
        clientVersion = parcel.readString() ?: "1.0.0",
        clientBuild = parcel.readInt()
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
        parcel.writeString(secondaryDnsServer)
        parcel.writeInt(mtu)
        parcel.writeTypedList(routes)
        parcel.writeString(localAddressV6)
        parcel.writeInt(prefixLengthV6)
        parcel.writeString(dnsServerV6)
        parcel.writeTypedList(routesV6)
        parcel.writeStringList(excludedApps)
        parcel.writeByte(if (isMetered) 1 else 0)
        parcel.writeByte(if (useTcp) 1 else 0)
        parcel.writeByte(if (useUdp) 1 else 0)
        parcel.writeInt(connectTimeoutMs)
        parcel.writeInt(keepAliveIntervalMs)
        parcel.writeString(country)
        parcel.writeByte(if (isL2TPSupport) 1 else 0)
        parcel.writeByte(if (isSSTPSupport) 1 else 0)
        parcel.writeString(authMethod.name)
        parcel.writeString(clientProductName)
        parcel.writeString(clientVersion)
        parcel.writeInt(clientBuild)
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
    DISCONNECTING,
    ERROR
}
