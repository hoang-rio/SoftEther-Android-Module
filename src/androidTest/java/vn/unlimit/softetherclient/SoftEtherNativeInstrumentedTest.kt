package vn.unlimit.softetherclient

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Android Instrumented Test for SoftEther Native
 *
 * These tests run on an Android device/emulator and can load the native library.
 * Tests verify that native methods work correctly.
 *
 * Run with: ./gradlew :SoftEtherClient:connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class SoftEtherNativeInstrumentedTest {

    companion object {
        private const val TAG = "SoftEtherInstrumented"

        // Test server configuration
        const val TEST_SERVER_HOST = "106.174.122.123"
        const val TEST_SERVER_PORT = 443
        const val TEST_HUB_NAME = "VPN"
        const val TEST_USERNAME = "vpn"
        const val TEST_PASSWORD = "vpn"
    }

    private lateinit var softEtherNative: SoftEtherNative

    @Before
    fun setUp() {
        softEtherNative = SoftEtherNative()
        Log.d(TAG, "=== Test Setup ===")
        Log.d(TAG, "Native library available: ${SoftEtherNative.isNativeLibraryAvailable}")
    }

    /**
     * Test 1: Verify native library loads on Android device
     */
    @Test
    fun test01_NativeLibraryLoads() {
        Log.d(TAG, "Test: Native library loads")

        assertTrue("Native library should be available on Android device",
                   SoftEtherNative.isNativeLibraryAvailable)

        val isLoaded = softEtherNative.isLibraryLoaded()
        Log.d(TAG, "nativeIsLibraryLoaded returned: $isLoaded")
        assertTrue("Library should report loaded", isLoaded)
    }

    /**
     * Test 2: Test native echo function
     */
    @Test
    fun test02_NativeEcho() {
        Log.d(TAG, "Test: Native echo")

        val message = "Hello from Android Test"
        val response = softEtherNative.testEcho(message)

        Log.d(TAG, "testEcho response: $response")
        assertTrue("Response should contain 'Native echo'", response.contains("Native echo"))
        assertTrue("Response should contain original message", response.contains(message))
    }

    /**
     * Test 3: Test native protocol version
     */
    @Test
    fun test03_ProtocolVersion() {
        Log.d(TAG, "Test: Protocol version")

        val version = softEtherNative.getProtocolVersion()
        Log.d(TAG, "Protocol version: $version")

        assertTrue("Protocol version should be > 0", version > 0)

        val major = (version shr 16) and 0xFF
        val minor = (version shr 8) and 0xFF
        val build = version and 0xFF

        Log.d(TAG, "Version: $major.$minor.$build")
        assertTrue("Major version should be >= 4", major >= 4)
    }

    /**
     * Test 4: Initialize and cleanup native client
     */
    @Test
    fun test04_InitializeAndCleanup() {
        Log.d(TAG, "Test: Initialize and cleanup")

        val initResult = softEtherNative.initialize()
        Log.d(TAG, "Initialize result: $initResult")
        assertTrue("Initialize should succeed", initResult)

        val state = softEtherNative.getState()
        Log.d(TAG, "State after init: $state")
        assertEquals("State should be DISCONNECTED",
                     SoftEtherNative.STATE_DISCONNECTED, state)

        softEtherNative.cleanup()
        Log.d(TAG, "Cleanup completed")
    }

    /**
     * Test 5: Test connection to real server using testConnect
     * This actually calls the native connection code
     */
    @Test
    fun test05_TestConnectToRealServer() {
        Log.d(TAG, "Test: Test connect to real server")

        val params = SoftEtherNative.ConnectionParams(
            serverHost = TEST_SERVER_HOST,
            serverPort = TEST_SERVER_PORT,
            hubName = TEST_HUB_NAME,
            username = TEST_USERNAME,
            password = TEST_PASSWORD,
            useEncrypt = true,
            useCompress = false,
            checkServerCert = false
        )

        Log.d(TAG, "Calling testConnect to $TEST_SERVER_HOST:$TEST_SERVER_PORT...")
        val result = softEtherNative.testConnect(params)

        Log.d(TAG, "testConnect returned: $result")

        // The test passes if native code executed (result >= 0)
        // Connection may succeed (0) or fail with various errors (>0)
        assertTrue("Native code should execute (result == 0)", result == 0)

        // Log the specific result
        when (result) {
            0 -> Log.i(TAG, "SUCCESS: Connection established!")
            1 -> Log.w(TAG, "Connection failed (server unreachable)")
            2 -> Log.w(TAG, "Authentication failed")
            3 -> Log.w(TAG, "SSL handshake failed")
            4 -> Log.w(TAG, "DHCP failed")
            5 -> Log.w(TAG, "TUN failed")
            else -> Log.w(TAG, "Unknown error: $result")
        }
    }

    /**
     * Test 6: Test connection to invalid server
     */
    @Test
    fun test06_TestConnectInvalidServer() {
        Log.d(TAG, "Test: Test connect to invalid server")

        val params = SoftEtherNative.ConnectionParams(
            serverHost = "192.0.2.1",  // TEST-NET-1, should not be routable
            serverPort = 443,
            hubName = "VPN",
            username = "test",
            password = "test",
            useEncrypt = true
        )

        Log.d(TAG, "Calling testConnect to invalid server...")
        val result = softEtherNative.testConnect(params)

        Log.d(TAG, "testConnect returned: $result")

        // Should fail with connection error
        assertTrue("Should return error (>0) for invalid server", result > 0)
    }

    /**
     * Test 7: Test connection parameters validation
     */
    @Test
    fun test07_ConnectionParams() {
        Log.d(TAG, "Test: Connection params validation")

        val params = SoftEtherNative.ConnectionParams(
            serverHost = TEST_SERVER_HOST,
            serverPort = TEST_SERVER_PORT,
            hubName = TEST_HUB_NAME,
            username = TEST_USERNAME,
            password = TEST_PASSWORD,
            useEncrypt = true,
            useCompress = false,
            checkServerCert = false,
            mtu = 1400
        )

        assertEquals(TEST_SERVER_HOST, params.serverHost)
        assertEquals(TEST_SERVER_PORT, params.serverPort)
        assertEquals(TEST_HUB_NAME, params.hubName)
        assertEquals(TEST_USERNAME, params.username)
        assertEquals(TEST_PASSWORD, params.password)
        assertTrue(params.useEncrypt)
        assertFalse(params.useCompress)
        assertFalse(params.checkServerCert)
        assertEquals(1400, params.mtu)

        Log.d(TAG, "All params validated successfully")
    }

    /**
     * Test 8: Test multiple init/cleanup cycles
     */
    @Test
    fun test08_MultipleInitCleanupCycles() {
        Log.d(TAG, "Test: Multiple init/cleanup cycles")

        repeat(3) { cycle ->
            Log.d(TAG, "Cycle ${cycle + 1}")

            val initResult = softEtherNative.initialize()
            assertTrue("Initialize should succeed (cycle $cycle)", initResult)

            val state = softEtherNative.getState()
            assertEquals("State should be DISCONNECTED",
                         SoftEtherNative.STATE_DISCONNECTED, state)

            softEtherNative.cleanup()
        }

        Log.d(TAG, "All cycles completed successfully")
    }

    /**
     * Test 9: Test native methods with initialized client
     */
    @Test
    fun test09_NativeMethodsWithInit() {
        Log.d(TAG, "Test: Native methods with initialized client")

        val initResult = softEtherNative.initialize()
        assertTrue("Initialize should succeed", initResult)

        // Test getStatistics
        val stats = softEtherNative.getStatistics()
        Log.d(TAG, "Statistics: sent=${stats.first}, received=${stats.second}")
        assertEquals(0L, stats.first)
        assertEquals(0L, stats.second)

        // Test getLastError
        val errorCode = softEtherNative.getLastError()
        val errorString = softEtherNative.getLastErrorString()
        Log.d(TAG, "Last error: code=$errorCode, msg='$errorString'")
        assertTrue("Error code should be >= 0", errorCode >= 0)

        softEtherNative.cleanup()
    }

    /**
     * Test 10: Verify state constants
     */
    @Test
    fun test10_StateConstants() {
        Log.d(TAG, "Test: State constants")

        assertEquals(0, SoftEtherNative.STATE_DISCONNECTED)
        assertEquals(1, SoftEtherNative.STATE_CONNECTING)
        assertEquals(2, SoftEtherNative.STATE_CONNECTED)
        assertEquals(3, SoftEtherNative.STATE_DISCONNECTING)
        assertEquals(4, SoftEtherNative.STATE_ERROR)

        Log.d(TAG, "State constants verified")
    }

    /**
     * Test 11: Verify error constants
     */
    @Test
    fun test11_ErrorConstants() {
        Log.d(TAG, "Test: Error constants")

        assertEquals(0, SoftEtherNative.ERR_NO_ERROR)
        assertEquals(1, SoftEtherNative.ERR_CONNECT_FAILED)
        assertEquals(2, SoftEtherNative.ERR_AUTH_FAILED)
        assertEquals(3, SoftEtherNative.ERR_SERVER_CERT_INVALID)
        assertEquals(4, SoftEtherNative.ERR_DHCP_FAILED)
        assertEquals(5, SoftEtherNative.ERR_TUN_CREATE_FAILED)

        Log.d(TAG, "Error constants verified")
    }
}
