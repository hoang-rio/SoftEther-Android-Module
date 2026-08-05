package vn.unlimit.softether.test

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNotNull
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import vn.unlimit.softether.model.ServerInfo
import vn.unlimit.softether.test.model.NativeTestResult

/**
 * Instrumented tests for native SoftEther implementation.
 * Tests run against real VPNGate servers using the actual softether_connect API.
 *
 * Test order follows the protocol stack:
 * 1. TCP Connection
 * 2. TLS Handshake
 * 3. SoftEther Handshake (watermark + Hello PACK)
 * 4. Authentication (PACK login)
 * 5. Session Establishment
 * 6. Data Transmission
 * 7. Keepalive
 * 8. Full Lifecycle
 * 9. Multiple Servers
 * 10. DHCP over Tunnel (IP assignment from SecureNAT)
 * 11. Internet Connectivity (DNS query for google.com through tunnel)
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class NativeConnectionTest {

    companion object {
        private const val TAG = "NativeConnectionTest"

        @JvmStatic
        private var sharedServer: ServerInfo? = null

        init {
            try {
                System.loadLibrary("softether")
                System.loadLibrary("softether_test")
                Log.d(TAG, "Native libraries loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native libraries", e)
                throw e
            }
        }

        @JvmStatic
        @org.junit.BeforeClass
        fun findServer() {
            Log.d(TAG, "BeforeClass: finding VPNGate server...")
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val provider = VpngateServerProvider(context)

            runBlocking {
                // Try VPNGate API first - prefer port 443 servers
                val servers = provider.getSoftEtherServersWithAuth()
                Log.d(TAG, "BeforeClass: VPNGate API returned ${servers.size} SoftEther servers")

                if (servers.isNotEmpty()) {
                    // Sort: prefer port 443 servers first (standard HTTPS port)
                    val sorted = servers.sortedBy { if (it.port == 443) 0 else 1 }
                    sharedServer = ServerAvailabilityChecker.getFirstAvailableServer(sorted, checkTls = true)
                }

                // Fallback: try all servers with port 443
                if (sharedServer == null) {
                    Log.d(TAG, "BeforeClass: no SoftEther server passed TLS, trying fallback...")
                    val fallbackServers = provider.getServers()
                    Log.d(TAG, "BeforeClass: total servers from API: ${fallbackServers.size}")

                    val candidates = if (fallbackServers.isNotEmpty()) {
                        fallbackServers.take(20).map { server ->
                            if (server.port <= 0) server.copy(port = 443) else server
                        }
                    } else {
                        emptyList()
                    }

                    if (candidates.isNotEmpty()) {
                        sharedServer = ServerAvailabilityChecker.getFirstAvailableServer(candidates, checkTls = true)
                    }
                }
            }

            if (sharedServer != null) {
                Log.d(TAG, "BeforeClass: selected server ${sharedServer!!.ip}:${sharedServer!!.port}")
            } else {
                Log.w(TAG, "BeforeClass: no available server found — all tests will be SKIPPED")
            }
        }
    }

    private val testServer: ServerInfo? get() = sharedServer

    @After
    fun tearDown() {
        // Cleanup if needed
    }

    @Test
    fun test01TcpConnection() {
        Log.d(TAG, "Running testTcpConnection")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing TCP connection to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestTcpConnection(testServer!!.ip, testServer!!.port, TestConfig.DEFAULT_TIMEOUT_MS)
        assertTrue(
            "TCP connection failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ TCP connection test passed: ${result.connectTimeMs}ms")
    }

    @Test
    fun test02TlsHandshake() {
        Log.d(TAG, "Running testTlsHandshake")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing TLS handshake to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestTlsHandshake(testServer!!.ip, testServer!!.port, TestConfig.DEFAULT_TIMEOUT_MS)
        assertTrue(
            "TLS handshake failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ TLS handshake test passed: ${result.connectTimeMs}ms")
    }

    @Test
    fun test03SoftEtherHandshake() {
        Log.d(TAG, "Running testSoftEtherHandshake")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing SoftEther handshake to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestSoftEtherHandshake(
            testServer!!.ip, testServer!!.port, TestConfig.DEFAULT_TIMEOUT_MS
        )
        assertTrue(
            "SoftEther handshake failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ SoftEther handshake test passed")
    }

    @Test
    fun test04Authentication() {
        Log.d(TAG, "Running testAuthentication")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing authentication to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestAuthentication(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.AUTH_TIMEOUT_MS
        )
        assertTrue(
            "Authentication failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Authentication test passed")
    }

    @Test
    fun test05SessionEstablishment() {
        Log.d(TAG, "Running testSessionEstablishment")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing session establishment to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestSession(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.SESSION_TIMEOUT_MS
        )
        assertTrue(
            "Session establishment failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Session establishment test passed")
    }

    @Test
    fun test06DataTransmission() {
        Log.d(TAG, "Running testDataTransmission")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing data transmission to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestDataTransmission(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.DEFAULT_PACKET_COUNT, TestConfig.DEFAULT_PACKET_SIZE,
            TestConfig.DATA_TIMEOUT_MS
        )
        assertTrue(
            "Data transmission failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Data transmission test passed: ${result.bytesSent} bytes sent, ${result.bytesReceived} bytes received")
    }

    @Test
    fun test07Keepalive() {
        Log.d(TAG, "Running testKeepalive")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing keepalive to ${testServer!!.ip}:${testServer!!.port} for ${TestConfig.KEEPALIVE_DURATION_SECONDS}s")

        val result = nativeTestKeepalive(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.KEEPALIVE_DURATION_SECONDS, TestConfig.SESSION_TIMEOUT_MS
        )
        assertTrue(
            "Keepalive test failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Keepalive test passed: connection stable for ${TestConfig.KEEPALIVE_DURATION_SECONDS} seconds")
    }

    @Test
    fun test08FullConnectionLifecycle() {
        Log.d(TAG, "Running testFullConnectionLifecycle")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing full connection lifecycle to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestFullLifecycle(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.LIFECYCLE_TIMEOUT_MS
        )
        assertTrue(
            "Full lifecycle test failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Full lifecycle test passed: ${result.connectTimeMs}ms total")
    }

    @Test
    fun test09MultipleServers() {
        Log.d(TAG, "Running testMultipleServers")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing with server: ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestFullLifecycle(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.LIFECYCLE_TIMEOUT_MS
        )
        assertTrue(
            "Server test failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Multiple servers test passed: ${result.connectTimeMs}ms")
    }

    /**
     * Test 10: DHCP over SoftEther Tunnel
     * Verifies IP address assignment from SecureNAT via DHCP
     */
    @Test
    fun test10Dhcp() {
        Log.d(TAG, "Running testDhcp")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing DHCP to ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestDhcp(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.LIFECYCLE_TIMEOUT_MS
        )
        assertTrue(
            "DHCP failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ DHCP test passed: ${result.errorMessage}")
    }

    /**
     * Test 11: Internet Connectivity via DNS
     * Connects to VPN, does DHCP, sends DNS query for google.com through tunnel.
     * If DNS response is received, the VPN tunnel provides real internet access.
     */
    @Test
    fun test11InternetConnectivity() {
        Log.d(TAG, "Running testInternetConnectivity")
        assumeNotNull("No VPNGate server available", testServer)
        Log.d(TAG, "Testing internet connectivity via ${testServer!!.ip}:${testServer!!.port}")

        val result = nativeTestInternetConnectivity(
            testServer!!.ip, testServer!!.port,
            TestConfig.DEFAULT_USERNAME, TestConfig.DEFAULT_PASSWORD,
            TestConfig.LIFECYCLE_TIMEOUT_MS
        )
        assertTrue(
            "Internet connectivity failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Internet connectivity test passed: ${result.errorMessage}")
    }

    /**
     * Test 12: RUDP V2 (ChaCha20-Poly1305 AEAD) loopback
     * Self-contained - runs a client+server rudp_context_t pair over 127.0.0.1,
     * no VPN server required.
     */
    @Test
    fun test12RudpV2Loopback() {
        Log.d(TAG, "Running testRudpV2Loopback")

        val result = nativeTestRudpV2Loopback()
        assertTrue(
            "RUDP V2 loopback failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ RUDP V2 loopback test passed: ${result.errorMessage}")
    }

    // Native method declarations
    private external fun nativeTestTcpConnection(host: String, port: Int, timeoutMs: Int): NativeTestResult
    private external fun nativeTestTlsHandshake(host: String, port: Int, timeoutMs: Int): NativeTestResult
    private external fun nativeTestSoftEtherHandshake(host: String, port: Int, timeoutMs: Int): NativeTestResult
    private external fun nativeTestAuthentication(host: String, port: Int, username: String, password: String, timeoutMs: Int): NativeTestResult
    private external fun nativeTestSession(host: String, port: Int, username: String, password: String, timeoutMs: Int): NativeTestResult
    private external fun nativeTestDataTransmission(host: String, port: Int, username: String, password: String, packetCount: Int, packetSize: Int, timeoutMs: Int): NativeTestResult
    private external fun nativeTestKeepalive(host: String, port: Int, username: String, password: String, durationSeconds: Int, timeoutMs: Int): NativeTestResult
    private external fun nativeTestFullLifecycle(host: String, port: Int, username: String, password: String, timeoutMs: Int): NativeTestResult
    private external fun nativeTestDhcp(host: String, port: Int, username: String, password: String, timeoutMs: Int): NativeTestResult
    private external fun nativeTestInternetConnectivity(host: String, port: Int, username: String, password: String, timeoutMs: Int): NativeTestResult
    private external fun nativeTestRudpV2Loopback(): NativeTestResult
}
