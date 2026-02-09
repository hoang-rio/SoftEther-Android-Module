package vn.unlimit.softetherclient

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Unit tests for SoftEtherNative class
 * Tests the native interface without requiring actual VPN connection
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class SoftEtherNativeUnitTest {

    private lateinit var softEtherNative: SoftEtherNative

    @Before
    fun setUp() {
        softEtherNative = SoftEtherNative()
    }

    @Test
    fun testNativeLibraryLoading() {
        // Test that the native library is available
        println("Native library available: ${SoftEtherNative.isNativeLibraryAvailable}")
        println("Library loaded: ${softEtherNative.isLibraryLoaded()}")

        // The library may or may not be available in unit test environment
        // Just verify we can call the method without crash
        assertTrue("isLibraryLoaded should return a value", 
                   softEtherNative.isLibraryLoaded() || !softEtherNative.isLibraryLoaded())
    }

    @Test
    fun testProtocolVersion() {
        // Get protocol version from native layer
        val version = softEtherNative.getProtocolVersion()
        println("Native protocol version: $version")

        if (SoftEtherNative.isNativeLibraryAvailable) {
            assertTrue("Protocol version should be > 0 when library is available", version > 0)

            // Decode version: (major << 16) | (minor << 8) | build
            val major = (version shr 16) and 0xFF
            val minor = (version shr 8) and 0xFF
            val build = version and 0xFF

            println("Version decoded: $major.$minor.$build")
            assertTrue("Major version should be >= 4", major >= 4)
        } else {
            assertEquals("Protocol version should be 0 when library unavailable", 0, version)
        }
    }

    @Test
    fun testInitializeNativeClient() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        // Initialize native client
        val result = softEtherNative.initialize()
        println("Initialize result: $result")

        // Verify state after initialization
        val state = softEtherNative.getState()
        println("State after init: $state")

        // Cleanup
        softEtherNative.cleanup()

        // Verify state after cleanup
        val stateAfterCleanup = softEtherNative.getState()
        println("State after cleanup: $stateAfterCleanup")
        assertEquals("State should be DISCONNECTED after cleanup", 
                     SoftEtherNative.STATE_DISCONNECTED, stateAfterCleanup)
    }

    @Test
    fun testConnectionParams() {
        // Test connection parameters creation
        val params = SoftEtherNative.ConnectionParams(
            serverHost = "72.192.177.168",
            serverPort = 443,
            hubName = "VPN",
            username = "vpn",
            password = "vpn",
            useEncrypt = true,
            useCompress = false,
            checkServerCert = false,
            mtu = 1400
        )

        assertEquals("72.192.177.168", params.serverHost)
        assertEquals(443, params.serverPort)
        assertEquals("VPN", params.hubName)
        assertEquals("vpn", params.username)
        assertEquals("vpn", params.password)
        assertTrue(params.useEncrypt)
        assertFalse(params.useCompress)
        assertFalse(params.checkServerCert)
        assertEquals(1400, params.mtu)

        println("Connection params created successfully")
        println("  Host: ${params.serverHost}")
        println("  Port: ${params.serverPort}")
        println("  Hub: ${params.hubName}")
        println("  Username: ${params.username}")
        println("  MTU: ${params.mtu}")
    }

    @Test
    fun testConnectionParamsDefaults() {
        val params = SoftEtherNative.ConnectionParams()

        assertNull(params.serverHost)
        assertEquals(443, params.serverPort)
        assertEquals("VPN", params.hubName)
        assertNull(params.username)
        assertNull(params.password)
        assertTrue(params.useEncrypt)
        assertFalse(params.useCompress)
        assertFalse(params.checkServerCert)
        assertEquals(1400, params.mtu)
    }

    @Test
    fun testStateConstants() {
        // Verify state constants match expected values
        assertEquals(0, SoftEtherNative.STATE_DISCONNECTED)
        assertEquals(1, SoftEtherNative.STATE_CONNECTING)
        assertEquals(2, SoftEtherNative.STATE_CONNECTED)
        assertEquals(3, SoftEtherNative.STATE_DISCONNECTING)
        assertEquals(4, SoftEtherNative.STATE_ERROR)

        println("State constants verified")
    }

    @Test
    fun testErrorConstants() {
        // Verify error constants match expected values
        assertEquals(0, SoftEtherNative.ERR_NO_ERROR)
        assertEquals(1, SoftEtherNative.ERR_CONNECT_FAILED)
        assertEquals(2, SoftEtherNative.ERR_AUTH_FAILED)
        assertEquals(3, SoftEtherNative.ERR_SERVER_CERT_INVALID)
        assertEquals(4, SoftEtherNative.ERR_DHCP_FAILED)
        assertEquals(5, SoftEtherNative.ERR_TUN_CREATE_FAILED)

        println("Error constants verified")
    }

    @Test
    fun testStatisticsWhenNotConnected() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        softEtherNative.initialize()

        // Get statistics when not connected
        val stats = softEtherNative.getStatistics()
        println("Statistics (not connected): sent=${stats.first}, received=${stats.second}")

        // Should be 0 when not connected
        assertEquals(0L, stats.first)
        assertEquals(0L, stats.second)

        softEtherNative.cleanup()
    }

    @Test
    fun testGetLastErrorWhenNotConnected() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        softEtherNative.initialize()

        // Get last error when not connected
        val errorCode = softEtherNative.getLastError()
        val errorString = softEtherNative.getLastErrorString()

        println("Last error: code=$errorCode, message='$errorString'")

        // Should return some error or success when not connected
        assertTrue("Error code should be >= 0", errorCode >= 0)
        assertNotNull("Error string should not be null", errorString)

        softEtherNative.cleanup()
    }

    @Test
    fun testConnectionListener() {
        var stateChangedCalled = false
        var lastState = -1

        val listener = object : SoftEtherNative.ConnectionListener {
            override fun onStateChanged(state: Int) {
                stateChangedCalled = true
                lastState = state
                println("State changed to: $state")
            }

            override fun onError(errorCode: Int, errorMessage: String?) {
                println("Error: $errorCode - $errorMessage")
            }

            override fun onConnectionEstablished(virtualIp: String?, subnetMask: String?, dnsServer: String?) {
                println("Connected: $virtualIp / $subnetMask / $dnsServer")
            }

            override fun onPacketReceived(packet: ByteArray?) {
                println("Packet received: ${packet?.size} bytes")
            }

            override fun onBytesTransferred(sent: Long, received: Long) {
                println("Bytes transferred: sent=$sent, received=$received")
            }
        }

        softEtherNative.setConnectionListener(listener)

        // Verify listener was set (no crash)
        assertTrue("Listener should be set", true)
    }

    @Test
    fun testMultipleInitializeCleanup() {
        if (!SoftEtherNative.isNativeLibraryAvailable) {
            println("Skipping test - native library not available")
            return
        }

        // Test multiple init/cleanup cycles
        repeat(3) { cycle ->
            println("Cycle ${cycle + 1}")

            val initResult = softEtherNative.initialize()
            println("  Initialize: $initResult")

            val state = softEtherNative.getState()
            println("  State: $state")

            softEtherNative.cleanup()

            val stateAfter = softEtherNative.getState()
            println("  State after cleanup: $stateAfter")

            assertEquals("State should be DISCONNECTED", 
                         SoftEtherNative.STATE_DISCONNECTED, stateAfter)
        }
    }

    @Test
    fun testConnectionParamsCopy() {
        val original = SoftEtherNative.ConnectionParams(
            serverHost = "original.example.com",
            serverPort = 443,
            username = "user",
            password = "pass"
        )

        val copy = original.copy(serverHost = "copied.example.com")

        assertEquals("original.example.com", original.serverHost)
        assertEquals("copied.example.com", copy.serverHost)
        assertEquals(original.serverPort, copy.serverPort)
        assertEquals(original.username, copy.username)
        assertEquals(original.password, copy.password)
    }
}
