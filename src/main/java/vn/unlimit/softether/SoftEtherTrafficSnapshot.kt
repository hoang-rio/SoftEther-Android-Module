package vn.unlimit.softether

data class SoftEtherTrafficSnapshot(
    val inBytes: Long,
    val outBytes: Long,
    val diffInBytes: Long,
    val diffOutBytes: Long,
    val packetsIn: Long,
    val packetsOut: Long,
    val intervalMs: Long,
    val timestampMs: Long
) {
    fun inBytesPerSecond(): Long = if (intervalMs > 0) diffInBytes * 1000L / intervalMs else 0L

    fun outBytesPerSecond(): Long = if (intervalMs > 0) diffOutBytes * 1000L / intervalMs else 0L

    companion object {
        val EMPTY = SoftEtherTrafficSnapshot(
            inBytes = 0L,
            outBytes = 0L,
            diffInBytes = 0L,
            diffOutBytes = 0L,
            packetsIn = 0L,
            packetsOut = 0L,
            intervalMs = 1000L,
            timestampMs = 0L
        )
    }
}
