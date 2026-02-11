package vn.unlimit.softether.test

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import vn.unlimit.softether.test.model.NativeTestResult

/**
 * Instrumented tests for native SoftEther implementation
 * Tests run against real VPNGate servers
 */
@RunWith(AndroidJUnit4::class)
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

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        serverProvider = VpngateServerProvider(context)
    }

    @After
    fun tearDown() {
        // Cleanup if needed
    }

    @Test
    fun testTcpConnection() {
        Log.d(TAG, "Running testTcpConnection")
        val servers = serverProvider.getServers()
        assertTrue("No servers available from vpngate.net", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing TCP connection to ${server.ip}:${server.port}")

        val result = nativeTestTcpConnection(server.ip, server.port, TestConfig.DEFAULT_TIMEOUT_MS)

        assertTrue(
            "TCP connection failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ TCP connection test passed: ${result.connectTimeMs}ms")
    }

    @Test
    fun testTlsHandshake() {
        Log.d(TAG, "Running testTlsHandshake")
        val servers = serverProvider.getServers()
        assertTrue("No servers available", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing TLS handshake to ${server.ip}:${server.port}")

        val result = nativeTestTlsHandshake(server.ip, server.port, TestConfig.DEFAULT_TIMEOUT_MS)

        assertTrue(
            "TLS handshake failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ TLS handshake test passed: ${result.connectTimeMs}ms")
    }

    @Test
    fun testSoftEtherHandshake() {
        Log.d(TAG, "Running testSoftEtherHandshake")
        val servers = serverProvider.getSoftEtherServers()
        assertTrue("No SoftEther servers found", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing SoftEther handshake to ${server.ip}:${server.port}")

        val result = nativeTestSoftEtherHandshake(
            server.ip,
            server.port,
            TestConfig.DEFAULT_TIMEOUT_MS
        )

        assertTrue(
            "SoftEther handshake failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ SoftEther handshake test passed")
    }

    @Test
    fun testAuthentication() {
        Log.d(TAG, "Running testAuthentication")
        val servers = serverProvider.getSoftEtherServersWithAuth()
        assertTrue("No SoftEther servers found", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing authentication to ${server.ip}:${server.port}")

        val result = nativeTestAuthentication(
            server.ip,
            server.port,
            TestConfig.DEFAULT_USERNAME,
            TestConfig.DEFAULT_PASSWORD,
            TestConfig.AUTH_TIMEOUT_MS
        )

        assertTrue(
            "Authentication failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Authentication test passed")
    }

    @Test
    fun testSessionEstablishment() {
        Log.d(TAG, "Running testSessionEstablishment")
        val servers = serverProvider.getSoftEtherServersWithAuth()
        assertTrue("No SoftEther servers found", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing session establishment to ${server.ip}:${server.port}")

        val result = nativeTestSession(
            server.ip,
            server.port,
            TestConfig.DEFAULT_USERNAME,
            TestConfig.DEFAULT_PASSWORD,
            TestConfig.SESSION_TIMEOUT_MS
        )

        assertTrue(
            "Session establishment failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Session establishment test passed")
    }

    @Test
    fun testDataTransmission() {
        Log.d(TAG, "Running testDataTransmission")
        val servers = serverProvider.getSoftEtherServersWithAuth()
        assertTrue("No SoftEther servers found", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing data transmission to ${server.ip}:${server.port}")

        val result = nativeTestDataTransmission(
            server.ip,
            server.port,
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
    }

    @Test
    fun testKeepalive() {
        Log.d(TAG, "Running testKeepalive")
        val servers = serverProvider.getSoftEtherServersWithAuth()
        assertTrue("No SoftEther servers found", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing keepalive to ${server.ip}:${server.port} for ${TestConfig.KEEPALIVE_DURATION_SECONDS}s")

        val result = nativeTestKeepalive(
            server.ip,
            server.port,
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
    }

    @Test
    fun testFullConnectionLifecycle() {
        Log.d(TAG, "Running testFullConnectionLifecycle")
        val servers = serverProvider.getSoftEtherServersWithAuth()
        assertTrue("No SoftEther servers found", servers.isNotEmpty())

        val server = servers.first()
        Log.d(TAG, "Testing full connection lifecycle to ${server.ip}:${server.port}")

        val result = nativeTestFullLifecycle(
            server.ip,
            server.port,
            TestConfig.DEFAULT_USERNAME,
            TestConfig.DEFAULT_PASSWORD,
            TestConfig.LIFECYCLE_TIMEOUT_MS
        )

        assertTrue(
            "Full lifecycle test failed: ${result.errorMessage} (code: ${result.errorCode})",
            result.success
        )
        Log.d(TAG, "✓ Full lifecycle test passed: ${result.connectTimeMs}ms total")
    }

    @Test
    fun testMultipleServers() {
        Log.d(TAG, "Running testMultipleServers")
        val servers = serverProvider.getSoftEtherServersWithAuth()
        assertTrue("No SoftEther servers found", servers.isNotEmpty())

        val maxServers = minOf(TestConfig.MAX_SERVERS_TO_TEST, servers.size)
        var successCount = 0
        val results = mutableListOf<Pair<String, Boolean>>()

        Log.d(TAG, "Testing $maxServers servers")

        for (i in 0 until maxServers) {
            val server = servers[i]
            Log.d(TAG, "Testing server ${i + 1}/$maxServers: ${server.ip}:${server.port} (${server.country})")

            val result = nativeTestFullLifecycle(
                server.ip,
                server.port,
                TestConfig.DEFAULT_USERNAME,
                TestConfig.DEFAULT_PASSWORD,
                20000
            )

            val success = result.success
            if (success) {
                successCount++
                Log.d(TAG, "  ✓ Success: ${result.connectTimeMs}ms")
            } else {
                Log.d(TAG, "  ✗ Failed: ${result.errorMessage}")
            }
            results.add("${server.ip}:${server.port}" to success)
        }

        Log.d(TAG, "Results: $successCount/$maxServers servers succeeded")

        // At least one server should succeed
        assertTrue(
            "All $maxServers server tests failed. Results: $results",
            successCount > 0
        )
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
