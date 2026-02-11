package vn.unlimit.softether.terminal

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Manages TUN interface for VPN tunnel
 * Handles reading from and writing to the VPN interface
 */
class TunTerminal(
    private val vpnInterface: ParcelFileDescriptor,
    private val scope: CoroutineScope
) {

    companion object {
        private const val TAG = "TunTerminal"
        private const val MAX_PACKET_SIZE = 32767 // Max VPN packet size
        private const val BUFFER_SIZE = 8192 // 8KB buffer
    }

    private val inputStream = FileInputStream(vpnInterface.fileDescriptor)
    private val outputStream = FileOutputStream(vpnInterface.fileDescriptor)
    private val isRunning = AtomicBoolean(false)

    private var onPacketReceived: ((ByteArray) -> Unit)? = null
    private var onError: ((Exception) -> Unit)? = null

    /**
     * Start reading from TUN interface
     */
    fun start(onPacket: (ByteArray) -> Unit, onError: (Exception) -> Unit) {
        if (isRunning.getAndSet(true)) {
            Log.w(TAG, "TUN terminal already running")
            return
        }

        this.onPacketReceived = onPacket
        this.onError = onError

        scope.launch(Dispatchers.IO) {
            readLoop()
        }

        Log.d(TAG, "TUN terminal started")
    }

    /**
     * Stop TUN terminal
     */
    fun stop() {
        if (!isRunning.getAndSet(false)) return

        Log.d(TAG, "Stopping TUN terminal")

        try {
            inputStream.close()
            outputStream.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing TUN streams", e)
        }
    }

    /**
     * Write packet to TUN interface
     * @param packet IP packet to write
     * @return Number of bytes written
     */
    fun write(packet: ByteArray): Int {
        if (!isRunning.get()) return -1

        return try {
            outputStream.write(packet)
            outputStream.flush()
            packet.size
        } catch (e: Exception) {
            Log.e(TAG, "Error writing to TUN", e)
            -1
        }
    }

    /**
     * Read loop for TUN interface
     */
    private suspend fun readLoop() {
        val buffer = ByteArray(BUFFER_SIZE)

        while (isRunning.get() && scope.isActive) {
            try {
                val length = withContext(Dispatchers.IO) {
                    inputStream.read(buffer)
                }

                when {
                    length > 0 -> {
                        // Got a packet
                        val packet = buffer.copyOf(length)
                        onPacketReceived?.invoke(packet)
                    }
                    length < 0 -> {
                        // EOF - connection closed
                        Log.d(TAG, "TUN interface closed")
                        break
                    }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e(TAG, "Error reading from TUN", e)
                    onError?.invoke(e)
                }
                break
            }
        }

        isRunning.set(false)
        Log.d(TAG, "TUN read loop ended")
    }

    /**
     * Check if running
     */
    fun isRunning(): Boolean = isRunning.get()

    /**
     * Get VPN interface MTU
     */
    fun getMtu(): Int {
        // MTU is typically set during VPN interface establishment
        return 1500 // Default MTU
    }

    /**
     * Get VPN interface file descriptor
     */
    fun getFileDescriptor(): Int {
        return vpnInterface.fd
    }
}

/**
 * TUN packet information
 */
data class TunPacket(
    val data: ByteArray,
    val timestamp: Long = System.currentTimeMillis()
) {
    /**
     * Get IP version (4 or 6)
     */
    fun getIpVersion(): Int {
        return if (data.isNotEmpty()) {
            (data[0].toInt() ushr 4) and 0x0F
        } else {
            0
        }
    }

    /**
     * Get protocol type
     */
    fun getProtocol(): Int {
        return if (data.size > 9) {
            data[9].toInt() and 0xFF
        } else {
            0
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TunPacket

        if (timestamp != other.timestamp) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}
