package vn.unlimit.softether.test.model

import android.os.Parcel
import android.os.Parcelable

/**
 * Result data class for native instrumentation tests
 */
data class NativeTestResult(
    val success: Boolean,
    val errorCode: Int,
    val errorMessage: String,
    val connectTimeMs: Long,
    val bytesSent: Long,
    val bytesReceived: Long,
    val serverIp: String,
    val serverPort: Int
) : Parcelable {

    constructor(parcel: Parcel) : this(
        success = parcel.readByte() != 0.toByte(),
        errorCode = parcel.readInt(),
        errorMessage = parcel.readString() ?: "",
        connectTimeMs = parcel.readLong(),
        bytesSent = parcel.readLong(),
        bytesReceived = parcel.readLong(),
        serverIp = parcel.readString() ?: "",
        serverPort = parcel.readInt()
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeByte(if (success) 1 else 0)
        parcel.writeInt(errorCode)
        parcel.writeString(errorMessage)
        parcel.writeLong(connectTimeMs)
        parcel.writeLong(bytesSent)
        parcel.writeLong(bytesReceived)
        parcel.writeString(serverIp)
        parcel.writeInt(serverPort)
    }

    override fun describeContents(): Int = 0

    companion object {
        // Error codes (matching C defines)
        const val ERROR_NONE = 0
        const val ERROR_TCP_CONNECT = 1
        const val ERROR_TLS_HANDSHAKE = 2
        const val ERROR_PROTOCOL_VERSION = 3
        const val ERROR_AUTHENTICATION = 4
        const val ERROR_SESSION = 5
        const val ERROR_DATA_TRANSMISSION = 6
        const val ERROR_TIMEOUT = 7
        const val ERROR_UNKNOWN = 99

        @JvmField
        val CREATOR = object : Parcelable.Creator<NativeTestResult> {
            override fun createFromParcel(parcel: Parcel): NativeTestResult {
                return NativeTestResult(parcel)
            }

            override fun newArray(size: Int): Array<NativeTestResult?> {
                return arrayOfNulls(size)
            }
        }
    }

    fun getErrorString(): String {
        return when (errorCode) {
            ERROR_NONE -> "Success"
            ERROR_TCP_CONNECT -> "TCP connection failed"
            ERROR_TLS_HANDSHAKE -> "TLS handshake failed"
            ERROR_PROTOCOL_VERSION -> "Protocol version mismatch"
            ERROR_AUTHENTICATION -> "Authentication failed"
            ERROR_SESSION -> "Session establishment failed"
            ERROR_DATA_TRANSMISSION -> "Data transmission failed"
            ERROR_TIMEOUT -> "Operation timed out"
            ERROR_UNKNOWN -> "Unknown error"
            else -> "Unknown error code: $errorCode"
        }
    }
}
