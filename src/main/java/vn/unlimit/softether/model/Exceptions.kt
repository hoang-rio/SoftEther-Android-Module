package vn.unlimit.softether.model

/**
 * Custom exception for connection errors
 */
class ConnectionException(message: String, val errorCode: Int = SoftEtherError.ERR_UNKNOWN) : Exception(message)

/**
 * Authentication exception
 */
class AuthenticationException(message: String) : Exception(message)

/**
 * Protocol exception for protocol-related errors
 */
class ProtocolException(message: String) : Exception(message)

/**
 * Timeout exception
 */
class TimeoutException(message: String) : Exception(message)

/**
 * SoftEther error codes matching native implementation
 */
object SoftEtherError {
    const val ERR_NONE = 0
    const val ERR_TCP_CONNECT = 1
    const val ERR_TLS_HANDSHAKE = 2
    const val ERR_PROTOCOL_VERSION = 3
    const val ERR_AUTHENTICATION = 4
    const val ERR_SESSION = 5
    const val ERR_DATA_TRANSMISSION = 6
    const val ERR_TIMEOUT = 7
    const val ERR_UNKNOWN = 99

    fun getErrorString(code: Int): String {
        return when (code) {
            ERR_NONE -> "No error"
            ERR_TCP_CONNECT -> "TCP connection failed"
            ERR_TLS_HANDSHAKE -> "TLS handshake failed"
            ERR_PROTOCOL_VERSION -> "Protocol version mismatch"
            ERR_AUTHENTICATION -> "Authentication failed"
            ERR_SESSION -> "Session setup failed"
            ERR_DATA_TRANSMISSION -> "Data transmission failed"
            ERR_TIMEOUT -> "Operation timed out"
            ERR_UNKNOWN -> "Unknown error"
            else -> "Undefined error ($code)"
        }
    }
}
