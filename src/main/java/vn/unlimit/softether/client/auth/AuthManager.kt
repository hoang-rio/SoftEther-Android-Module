package vn.unlimit.softether.client.auth

import android.util.Log

/**
 * Manages authentication for SoftEther VPN
 */
class AuthManager {

    companion object {
        private const val TAG = "AuthManager"
    }

    private var authMethod: AuthMethod = AuthMethod.PASSWORD
    private var credentials: Credentials? = null

    /**
     * Set authentication credentials
     */
    fun setCredentials(username: String, password: String) {
        credentials = PasswordCredentials(username, password)
        authMethod = AuthMethod.PASSWORD
        Log.d(TAG, "Password credentials set for user: $username")
    }

    /**
     * Set certificate-based authentication
     */
    fun setCertificateCredentials(certificate: ByteArray, privateKey: ByteArray) {
        credentials = CertificateCredentials(certificate, privateKey)
        authMethod = AuthMethod.CERTIFICATE
        Log.d(TAG, "Certificate credentials set")
    }

    /**
     * Get current authentication method
     */
    fun getAuthMethod(): AuthMethod = authMethod

    /**
     * Get credentials
     */
    fun getCredentials(): Credentials? = credentials

    /**
     * Check if credentials are set
     */
    fun hasCredentials(): Boolean = credentials != null

    /**
     * Clear all credentials
     */
    fun clearCredentials() {
        credentials?.clear()
        credentials = null
        Log.d(TAG, "Credentials cleared")
    }

    /**
     * Build authentication payload for protocol
     */
    fun buildAuthPayload(): ByteArray? {
        return when (val creds = credentials) {
            is PasswordCredentials -> buildPasswordAuthPayload(creds)
            is CertificateCredentials -> buildCertificateAuthPayload(creds)
            else -> null
        }
    }

    private fun buildPasswordAuthPayload(creds: PasswordCredentials): ByteArray {
        val username = creds.username.toByteArray(Charsets.UTF_8)
        val password = creds.password.toByteArray(Charsets.UTF_8)

        // Format: [username_len:2][username][password_len:2][password]
        val payload = ByteArray(2 + username.size + 2 + password.size)
        var offset = 0

        // Username length
        payload[offset++] = (username.size shr 8).toByte()
        payload[offset++] = username.size.toByte()

        // Username
        System.arraycopy(username, 0, payload, offset, username.size)
        offset += username.size

        // Password length
        payload[offset++] = (password.size shr 8).toByte()
        payload[offset++] = password.size.toByte()

        // Password
        System.arraycopy(password, 0, payload, offset, password.size)

        return payload
    }

    private fun buildCertificateAuthPayload(creds: CertificateCredentials): ByteArray {
        // Certificate-based authentication payload
        // This is a simplified implementation
        return creds.certificate
    }
}

/**
 * Authentication method enumeration
 */
enum class AuthMethod {
    PASSWORD,
    CERTIFICATE,
    PASSWORD_CERTIFICATE // Both password and certificate
}

/**
 * Base credentials interface
 */
sealed interface Credentials {
    /**
     * Clear sensitive data from memory
     */
    fun clear()
}

/**
 * Password-based credentials
 */
data class PasswordCredentials(
    val username: String,
    val password: String
) : Credentials {
    override fun clear() {
        // Note: String immutability makes true clearing impossible
        // In production, use CharArray for passwords
    }
}

/**
 * Certificate-based credentials
 */
data class CertificateCredentials(
    val certificate: ByteArray,
    val privateKey: ByteArray
) : Credentials {
    override fun clear() {
        certificate.fill(0)
        privateKey.fill(0)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CertificateCredentials

        if (!certificate.contentEquals(other.certificate)) return false
        if (!privateKey.contentEquals(other.privateKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = certificate.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        return result
    }
}
