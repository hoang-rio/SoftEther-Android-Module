package vn.unlimit.softether.terminal

import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * Manages SSL/TLS connection for SoftEther VPN
 * This class handles the secure socket layer communication
 */
class SSLTerminal {

    companion object {
        private const val TAG = "SSLTerminal"
        private const val DEFAULT_TIMEOUT_MS = 30000
    }

    private var sslSocket: SSLSocket? = null
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    private var readChannel: FileChannel? = null
    private var writeChannel: FileChannel? = null

    /**
     * Create SSL context with default trust managers
     */
    fun createSSLContext(): SSLContext {
        return SSLContext.getInstance("TLS").apply {
            init(null, getTrustManagers(), null)
        }
    }

    /**
     * Create SSL context with custom trust manager (for certificate pinning)
     */
    fun createSSLContext(trustManager: X509TrustManager): SSLContext {
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustManager), null)
        }
    }

    /**
     * Get default trust managers
     */
    private fun getTrustManagers(): Array<TrustManager> {
        val trustManagerFactory = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        )
        trustManagerFactory.init(null as KeyStore?)
        return trustManagerFactory.trustManagers
    }

    /**
     * Connect to SSL server
     * Note: Actual SSL connection is handled by native layer
     * This class provides Java-side SSL utilities
     */
    fun connect(host: String, port: Int): Boolean {
        Log.d(TAG, "SSL connection initiated to $host:$port")
        // SSL connection is handled in native layer via OpenSSL
        return true
    }

    /**
     * Disconnect SSL connection
     */
    fun disconnect() {
        try {
            readChannel?.close()
            writeChannel?.close()
            inputStream?.close()
            outputStream?.close()
            sslSocket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error during SSL disconnect", e)
        }
        sslSocket = null
        inputStream = null
        outputStream = null
        readChannel = null
        writeChannel = null
    }

    /**
     * Check if connected
     */
    fun isConnected(): Boolean {
        return sslSocket?.isConnected == true && !sslSocket!!.isClosed
    }

    /**
     * Pin certificate for enhanced security
     */
    fun createPinnedTrustManager(expectedCertificate: X509Certificate): X509TrustManager {
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                // Not used for client connections
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) {
                    throw SSLException("Certificate chain is empty")
                }

                val serverCert = chain[0]

                // Check if certificate matches expected
                if (serverCert != expectedCertificate) {
                    throw SSLException("Certificate pinning failed")
                }

                // Verify certificate is not expired
                serverCert.checkValidity()
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return arrayOf(expectedCertificate)
            }
        }
    }

    /**
     * Create hostname verifier that validates against specific hostname
     */
    fun createHostnameVerifier(expectedHostname: String): HostnameVerifier {
        return HostnameVerifier { hostname, session ->
            hostname.equals(expectedHostname, ignoreCase = true)
        }
    }
}

/**
 * SSL configuration options
 */
data class SSLConfig(
    val enabledProtocols: Array<String> = arrayOf("TLSv1.2", "TLSv1.3"),
    val enabledCipherSuites: Array<String>? = null,
    val certificatePinning: Boolean = false,
    val pinnedCertificate: X509Certificate? = null,
    val hostnameVerification: Boolean = true,
    val expectedHostname: String? = null
)
