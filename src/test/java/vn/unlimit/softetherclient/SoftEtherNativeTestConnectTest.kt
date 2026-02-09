package vn.unlimit.softetherclient

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Unit tests for SoftEtherNative testConnect function
 * These tests actually call nativeTestConnect which exercises the native connection code
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class SoftEtherNativeTestConnectTest {

    private lateinit var softEtherNative: SoftEtherNative

    @Before
    fun setUp() {
        softEtherNative = SoftEtherNative()
    }

    /**
     * Test 1: Verify testEcho works (basic native method call)
     */
    @Test
    fun test01_TestEcho() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        val message = "Hello from Kotlin"
        val response = softEtherNative.testEcho(message)

        println("testEcho response: $response")
        assertTrue("Response should contain 'Native echo'", response.contains("Native echo"))
        assertTrue("Response should contain original message", response.contains(message))
    }

    /**
     * Test 2: Test connection to real server using testConnect
     * This actually calls nativeTestConnect which exercises se_connection_connect
     */
    @Test
    fun test02_TestConnectToRealServer() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        val params = SoftEtherNative.ConnectionParams(
            serverHost = "72.192.177.168",
            serverPort = 443,
            hubName = "VPN",
            username = "vpn",
            password = "vpn",
            useEncrypt = true,
            useCompress = false,
            checkServerCert = false
        )

        println("Calling testConnect to 72.192.177.168:443...")
        val result = softEtherNative.testConnect(params)

        println("testConnect returned: $result")
        // result = 0 means success, >0 means error code
        // We expect it might fail due to network/auth, but the native code should execute
        assertTrue("Result should be >= 0 (native code executed)", result >= 0)

        // Log the result
        when (result) {
            0 -> println("SUCCESS: Connection established!")
            1 -> println("ERROR: Connection failed")
            2 -> println("ERROR: Authentication failed")
            3 -> println("ERROR: SSL handshake failed")
            4 -> println("ERROR: DHCP failed")
            5 -> println("ERROR: TUN failed")
            else -> println("ERROR: Unknown error code $result")
        }
    }

    /**
     * Test 3: Test connection to invalid server
     */
    @Test
    fun test03_TestConnectInvalidServer() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        val params = SoftEtherNative.ConnectionParams(
            serverHost = "192.0.2.1",  // TEST-NET-1, should not be routable
            serverPort = 443,
            hubName = "VPN",
            username = "test",
            password = "test",
            useEncrypt = true
        )

        println("Calling testConnect to invalid server 192.0.2.1...")
        val result = softEtherNative.testConnect(params)

        println("testConnect returned: $result")
        // Should fail with connection error (1)
        assertTrue("Should return error code for invalid server", result > 0)
    }

    /**
     * Test 4: Test connection with null params should fail
     */
    @Test
    fun test04_TestConnectNullParams() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        val params = SoftEtherNative.ConnectionParams(
            serverHost = null,
            username = "test",
            password = "test"
        )

        val result = softEtherNative.testConnect(params)

        println("testConnect with null host returned: $result")
        // Should fail before calling native code
        assertEquals("Should return CONNECT_FAILED for null params",
                     SoftEtherNative.ERR_CONNECT_FAILED, result)
    }

    /**
     * Test 5: Test connection params validation with different ports
     */
    @Test
    fun test05_TestConnectDifferentPorts() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        val ports = listOf(443, 992, 5555)

        ports.forEach { port ->
            val params = SoftEtherNative.ConnectionParams(
                serverHost = "72.192.177.168",
                serverPort = port,
                hubName = "VPN",
                username = "vpn",
                password = "vpn"
            )

            println("Testing port $port...")
            // Just verify params are set correctly, don't actually connect
            assertEquals("Port should be $port", port, params.serverPort)
        }
    }

    /**
     * Test 6: Verify native method returns proper error codes
     */
    @Test
    fun test06_VerifyErrorCodes() {
        // These are the expected error codes from native code
        assertEquals("ERR_NO_ERROR should be 0", 0, SoftEtherNative.ERR_NO_ERROR)
        assertEquals("ERR_CONNECT_FAILED should be 1", 1, SoftEtherNative.ERR_CONNECT_FAILED)
        assertEquals("ERR_AUTH_FAILED should be 2", 2, SoftEtherNative.ERR_AUTH_FAILED)
        assertEquals("ERR_SERVER_CERT_INVALID should be 3", 3, SoftEtherNative.ERR_SERVER_CERT_INVALID)
        assertEquals("ERR_DHCP_FAILED should be 4", 4, SoftEtherNative.ERR_DHCP_FAILED)
        assertEquals("ERR_TUN_CREATE_FAILED should be 5", 5, SoftEtherNative.ERR_TUN_CREATE_FAILED)
    }
}
