package vn.unlimit.softether.test

/**
 * Test configuration constants for SoftEther instrumentation tests
 */
object TestConfig {

    // Timeouts (in milliseconds)
    const val DEFAULT_TIMEOUT_MS = 10000
    const val AUTH_TIMEOUT_MS = 20000
    const val SESSION_TIMEOUT_MS = 25000
    const val DATA_TIMEOUT_MS = 30000
    const val LIFECYCLE_TIMEOUT_MS = 40000

    // Test parameters
    const val DEFAULT_PACKET_COUNT = 10
    const val DEFAULT_PACKET_SIZE = 1024
    const val KEEPALIVE_DURATION_SECONDS = 30
    const val MAX_SERVERS_TO_TEST = 5

    // Retry settings
    const val MAX_RETRIES = 3
    const val RETRY_DELAY_MS = 2000L

    // Server filters
    const val MIN_SCORE = 1000
    const val MAX_PING = 500
    const val MIN_SPEED = 1000000L // 1 Mbps

    // VPNGate default credentials
    const val DEFAULT_USERNAME = "vpn"
    const val DEFAULT_PASSWORD = "vpn"

    // Default SoftEther ports
    val SOFTETHER_PORTS = listOf(443, 992, 5555, 5556)
}
