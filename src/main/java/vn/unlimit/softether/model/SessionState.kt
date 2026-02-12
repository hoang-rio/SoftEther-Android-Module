package vn.unlimit.softether.model

import android.os.Parcel
import android.os.Parcelable

/**
 * Session state information for SoftEther VPN connection
 */
data class SessionState(
    val sessionId: Long = 0,
    val isConnected: Boolean = false,
    val localIp: String = "",
    val remoteIp: String = "",
    val dnsServers: List<String> = emptyList(),
    val mtu: Int = 1500,
    val bytesSent: Long = 0,
    val bytesReceived: Long = 0,
    val packetsSent: Long = 0,
    val packetsReceived: Long = 0,
    val connectionTimeMs: Long = 0,
    val lastKeepaliveTimeMs: Long = 0,
    val virtualHubName: String = "",
    val serverHostname: String = ""
) : Parcelable {

    constructor(parcel: Parcel) : this(
        sessionId = parcel.readLong(),
        isConnected = parcel.readByte() != 0.toByte(),
        localIp = parcel.readString() ?: "",
        remoteIp = parcel.readString() ?: "",
        dnsServers = parcel.createStringArrayList() ?: emptyList(),
        mtu = parcel.readInt(),
        bytesSent = parcel.readLong(),
        bytesReceived = parcel.readLong(),
        packetsSent = parcel.readLong(),
        packetsReceived = parcel.readLong(),
        connectionTimeMs = parcel.readLong(),
        lastKeepaliveTimeMs = parcel.readLong(),
        virtualHubName = parcel.readString() ?: "",
        serverHostname = parcel.readString() ?: ""
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeLong(sessionId)
        parcel.writeByte(if (isConnected) 1 else 0)
        parcel.writeString(localIp)
        parcel.writeString(remoteIp)
        parcel.writeStringList(dnsServers)
        parcel.writeInt(mtu)
        parcel.writeLong(bytesSent)
        parcel.writeLong(bytesReceived)
        parcel.writeLong(packetsSent)
        parcel.writeLong(packetsReceived)
        parcel.writeLong(connectionTimeMs)
        parcel.writeLong(lastKeepaliveTimeMs)
        parcel.writeString(virtualHubName)
        parcel.writeString(serverHostname)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<SessionState> {
        override fun createFromParcel(parcel: Parcel): SessionState {
            return SessionState(parcel)
        }

        override fun newArray(size: Int): Array<SessionState?> {
            return arrayOfNulls(size)
        }
    }

    /**
     * Get a summary of the session state for logging
     */
    fun getSummary(): String {
        return buildString {
            append("SessionState[")
            append("id=0x${sessionId.toString(16)}, ")
            append("connected=$isConnected, ")
            append("local=$localIp, ")
            append("remote=$remoteIp, ")
            append("bytes=$bytesSent/$bytesReceived, ")
            append("packets=$packetsSent/$packetsReceived, ")
            append("time=${connectionTimeMs}ms")
            append("]")
        }
    }
}

/**
 * Session statistics for monitoring connection health
 */
data class SessionStatistics(
    val startTimeMs: Long = System.currentTimeMillis(),
    var lastActivityTimeMs: Long = System.currentTimeMillis(),
    var totalBytesSent: Long = 0,
    var totalBytesReceived: Long = 0,
    var totalPacketsSent: Long = 0,
    var totalPacketsReceived: Long = 0,
    var reconnectionCount: Int = 0,
    var errorCount: Int = 0
) {
    /**
     * Get duration of the session in milliseconds
     */
    fun getDurationMs(): Long {
        return System.currentTimeMillis() - startTimeMs
    }

    /**
     * Get time since last activity in milliseconds
     */
    fun getIdleTimeMs(): Long {
        return System.currentTimeMillis() - lastActivityTimeMs
    }

    /**
     * Update statistics with new data transfer
     */
    fun updateTransfer(bytesSent: Int, bytesReceived: Int) {
        totalBytesSent += bytesSent
        totalBytesReceived += bytesReceived
        if (bytesSent > 0) totalPacketsSent++
        if (bytesReceived > 0) totalPacketsReceived++
        lastActivityTimeMs = System.currentTimeMillis()
    }

    /**
     * Mark activity to keep session alive
     */
    fun markActivity() {
        lastActivityTimeMs = System.currentTimeMillis()
    }

    /**
     * Record a reconnection event
     */
    fun recordReconnection() {
        reconnectionCount++
    }

    /**
     * Record an error event
     */
    fun recordError() {
        errorCount++
    }

    /**
     * Get a summary of the statistics
     */
    fun getSummary(): String {
        return buildString {
            append("Stats[")
            append("duration=${getDurationMs()}ms, ")
            append("sent=$totalBytesSent, ")
            append("received=$totalBytesReceived, ")
            append("packets=$totalPacketsSent/$totalPacketsReceived, ")
            append("reconnects=$reconnectionCount, ")
            append("errors=$errorCount")
            append("]")
        }
    }
}
