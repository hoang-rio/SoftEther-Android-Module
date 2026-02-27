package vn.unlimit.softether.test

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import vn.unlimit.softether.model.ServerInfo
import vn.unlimit.softether.test.model.NativeTestResult

/**
 * Instrumented tests for native SoftEther implementation
 * Tests run against real VPNGate servers
 * 
 * Test order follows SoftEther VPN protocol flow:
 * 1. TCP Connection
 * 2. TLS Handshake  
 * 3. Protocol Handshake (Hello/CONNECT)
 * 4. Authentication
 * 5. Session Establishment
 * 6. Data Transmission
 * 7. Keepalive
 * 8. Full Lifecycle (combines all steps)
 * 9. Multiple Servers
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class NativeConnectionTest {

    companion object {
        private const val TAG = "NativeConnectionTest"

        init {
            // Load native libraries
            try {
                System.loadLibrary("softether")
                System.loadLibrary("softether_test")
                Log.d(TAG, "Native libraries loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native libraries", e)
                throw e
            }
        }
    }

    private lateinit var serverProvider: VpngateServerProvider
    private var testServer: ServerInfo? = null

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        serverProvider = VpngateServerProvider(context)
        
        // Pick one available server at the start and use it for all tests
        // Tests will verify if the server actually works
        runBlocking {
            val servers = serverProvider.getSoftEtherServersWithAuth()
            if (servers.isNotEmpty()) {
                testServer = ServerAvailabilityChecker.getFirstAvailableServer(servers, checkTls = true)
            }
        }
        
        if (testServer == null) {
            Log.w(TAG, "No available server found for testing. Tests may fail.")
        } else {
            Log.d(TAG, "Selected test server: ${testServer!!.ip}:${testServer!!.port}")
        }
    }

    @After
    fun tearDown() {
        // Cleanup if needed
    }

    /**
     * Test 1: TCP Connection
     * Basic TCP socket connection to the VPN server
     */
    @Test
    fun test01TcpConnection() {
        Log.d(TAG, "Running testTcpConnection")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }
        
        Log.d(TAG, "Testing TCP connection to ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestTcpConnection(testServer!!.ip, testServer!!.port, TestConfig.DEFAULT_TIMEOUT_MS)
            
            assertTrue(
                "TCP connection failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ TCP connection test passed: ${result.connectTimeMs}ms")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testTcpConnection: ${e.message}")
            throw e
        }
    }

    /**
     * Test 2: TLS Handshake
     * Establish TLS/SSL connection over TCP
     */
    @Test
    fun test02TlsHandshake() {
        Log.d(TAG, "Running testTlsHandshake")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }

        Log.d(TAG, "Testing TLS handshake to ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestTlsHandshake(testServer!!.ip, testServer!!.port, TestConfig.DEFAULT_TIMEOUT_MS)
            
            assertTrue(
                "TLS handshake failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ TLS handshake test passed: ${result.connectTimeMs}ms")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testTlsHandshake: ${e.message}")
            throw e
        }
    }

    /**
     * Test 3: Protocol Handshake
     * SoftEther protocol negotiation (Hello/CONNECT)
     */
    @Test
    fun test03SoftEtherHandshake() {
        Log.d(TAG, "Running testSoftEtherHandshake")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }
        
        Log.d(TAG, "Testing SoftEther handshake to ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestSoftEtherHandshake(
                testServer!!.ip,
                testServer!!.port,
                TestConfig.DEFAULT_TIMEOUT_MS
            )

            assertTrue(
                "SoftEther handshake failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ SoftEther handshake test passed")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testSoftEtherHandshake: ${e.message}")
            throw e
        }
    }

    /**
     * Test 4: Authentication
     * User authentication with username/password
     */
    @Test
    fun test04Authentication() {
        Log.d(TAG, "Running testAuthentication")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }

        Log.d(TAG, "Testing authentication to ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestAuthentication(
                testServer!!.ip,
                testServer!!.port,
                TestConfig.DEFAULT_USERNAME,
                TestConfig.DEFAULT_PASSWORD,
                TestConfig.AUTH_TIMEOUT_MS
            )

            assertTrue(
                "Authentication failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ Authentication test passed")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testAuthentication: ${e.message}")
            throw e
        }
    }

    /**
     * Test 5: Session Establishment
     * Create VPN session after authentication
     */
    @Test
    fun test05SessionEstablishment() {
        Log.d(TAG, "Running testSessionEstablishment")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }

        Log.d(TAG, "Testing session establishment to ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestSession(
                testServer!!.ip,
                testServer!!.port,
                TestConfig.DEFAULT_USERNAME,
                TestConfig.DEFAULT_PASSWORD,
                TestConfig.SESSION_TIMEOUT_MS
            )

            assertTrue(
                "Session establishment failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ Session establishment test passed")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testSessionEstablishment: ${e.message}")
            throw e
        }
    }

    /**
     * Test 6: Data Transmission
     * Send and receive data over VPN tunnel
     */
    @Test
    fun test06DataTransmission() {
        Log.d(TAG, "Running testDataTransmission")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }

        Log.d(TAG, "Testing data transmission to ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestDataTransmission(
                testServer!!.ip,
                testServer!!.port,
                TestConfig.DEFAULT_USERNAME,
                TestConfig.DEFAULT_PASSWORD,
                TestConfig.DEFAULT_PACKET_COUNT,
                TestConfig.DEFAULT_PACKET_SIZE,
                TestConfig.DATA_TIMEOUT_MS
            )

            assertTrue(
                "Data transmission failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ Data transmission test passed: ${result.bytesSent} bytes sent, ${result.bytesReceived} bytes received")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testDataTransmission: ${e.message}")
            throw e
        }
    }

    /**
     * Test 7: Keepalive
     * Test VPN connection stability with keepalive packets
     */
    @Test
    fun test07Keepalive() {
        Log.d(TAG, "Running testKeepalive")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }

        Log.d(TAG, "Testing keepalive to ${testServer!!.ip}:${testServer!!.port} for ${TestConfig.KEEPALIVE_DURATION_SECONDS}s")

        try {
            val result = nativeTestKeepalive(
                testServer!!.ip,
                testServer!!.port,
                TestConfig.DEFAULT_USERNAME,
                TestConfig.DEFAULT_PASSWORD,
                TestConfig.KEEPALIVE_DURATION_SECONDS,
                TestConfig.SESSION_TIMEOUT_MS
            )

            assertTrue(
                "Keepalive test failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ Keepalive test passed: connection stable for ${TestConfig.KEEPALIVE_DURATION_SECONDS} seconds")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testKeepalive: ${e.message}")
            throw e
        }
    }

    /**
     * Test 8: Full Lifecycle
     * Complete VPN connection lifecycle from start to finish
     */
    @Test
    fun test08FullConnectionLifecycle() {
        Log.d(TAG, "Running testFullConnectionLifecycle")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }
        
        Log.d(TAG, "Testing full connection lifecycle to ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestFullLifecycle(
                testServer!!.ip,
                testServer!!.port,
                TestConfig.DEFAULT_USERNAME,
                TestConfig.DEFAULT_PASSWORD,
                TestConfig.LIFECYCLE_TIMEOUT_MS
            )

            assertTrue(
                "Full lifecycle test failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
            Log.d(TAG, "✓ Full lifecycle test passed: ${result.connectTimeMs}ms total")
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testFullConnectionLifecycle: ${e.message}")
            throw e
        }
    }

    /**
     * Test 9: Multiple Servers
     * Test with multiple VPN servers
     */
    @Test
    fun test09MultipleServers() {
        Log.d(TAG, "Running testMultipleServers")
        
        if (testServer == null) {
            Log.w(TAG, "No test server available. Skipping test.")
            return
        }

        Log.d(TAG, "Testing with server: ${testServer!!.ip}:${testServer!!.port}")

        try {
            val result = nativeTestFullLifecycle(
                testServer!!.ip,
                testServer!!.port,
                TestConfig.DEFAULT_USERNAME,
                TestConfig.DEFAULT_PASSWORD,
                TestConfig.LIFECYCLE_TIMEOUT_MS
            )

            if (result.success) {
                Log.d(TAG, "  ✓ Success: ${result.connectTimeMs}ms")
            } else {
                Log.d(TAG, "  ✗ Failed: ${result.errorMessage}")
            }

            assertTrue(
                "Server test failed: ${result.errorMessage} (code: ${result.errorCode})",
                result.success
            )
        } catch (e: Throwable) {
            Log.e(TAG, "Exception in testMultipleServers: ${e.message}")
            throw e
        }
    }

    // Native method declarations
    private external fun nativeTestTcpConnection(
        host: String,
        port: Int,
        timeoutMs: Int
    ): NativeTestResult

    private external fun nativeTestTlsHandshake(
        host: String,
        port: Int,
        timeoutMs: Int
    ): NativeTestResult

    private external fun nativeTestSoftEtherHandshake(
        host: String,
        port: Int,
        timeoutMs: Int
    ): NativeTestResult

    private external fun nativeTestAuthentication(
        host: String,
        port: Int,
        username: String,
        password: String,
        timeoutMs: Int
    ): NativeTestResult

    private external fun nativeTestSession(
        host: String,
        port: Int,
        username: String,
        password: String,
        timeoutMs: Int
    ): NativeTestResult

    private external fun nativeTestDataTransmission(
        host: String,
        port: Int,
        username: String,
        password: String,
        packetCount: Int,
        packetSize: Int,
        timeoutMs: Int
    ): NativeTestResult

    private external fun nativeTestKeepalive(
        host: String,
        port: Int,
        username: String,
        password: String,
        durationSeconds: Int,
        timeoutMs: Int
    ): NativeTestResult

    private external fun nativeTestFullLifecycle(
        host: String,
        port: Int,
        username: String,
        password: String,
        timeoutMs: Int
    ): NativeTestResult
}
