package vn.unlimit.softether.client.protocol

import android.util.Log
import vn.unlimit.softether.client.SoftEtherClient
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Handles packet encapsulation/decapsulation for SoftEther protocol
 */
class PacketHandler(private val client: SoftEtherClient) {

    companion object {
        private const val TAG = "PacketHandler"
        private const val MAX_PACKET_SIZE = 65535
        private const val HEADER_SIZE = 20 // SoftEther protocol header
    }

    private val sendQueue = ConcurrentLinkedQueue<ByteArray>()
    private val receiveQueue = ConcurrentLinkedQueue<ByteArray>()

    /**
     * Queue packet for sending through VPN tunnel
     */
    fun queuePacket(packet: ByteArray) {
        if (packet.size > MAX_PACKET_SIZE) {
            Log.w(TAG, "Packet too large, dropping: ${packet.size} bytes")
            return
        }
        sendQueue.offer(packet)
    }

    /**
     * Poll next packet from send queue (non-blocking)
     * @return Next packet or null if queue is empty
     */
    fun pollSendQueue(): ByteArray? {
        return sendQueue.poll()
    }

    /**
     * Process and send all queued packets
     * @return Number of packets sent
     */
    fun processSendQueue(): Int {
        var count = 0
        while (sendQueue.isNotEmpty()) {
            val packet = sendQueue.poll() ?: break

            val result = sendPacket(packet)
            if (result > 0) {
                count++
            } else {
                Log.w(TAG, "Failed to send packet, requeueing")
                sendQueue.offer(packet)
                break
            }
        }
        return count
    }

    /**
     * Send a single packet through the VPN connection
     */
    private fun sendPacket(packet: ByteArray): Int {
        return try {
            val result = client.send(packet)
            if (result > 0) {
                Log.v(TAG, "Sent packet: $result bytes")
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Error sending packet", e)
            -1
        }
    }

    /**
     * Receive packet from VPN connection
     * @param buffer Buffer to store received data
     * @return Number of bytes received, 0 for keepalive, -1 for error
     */
    fun receivePacket(buffer: ByteArray): Int {
        return try {
            val result = client.receive(buffer)
            when {
                result > 0 -> {
                    Log.v(TAG, "Received packet: $result bytes")
                    receiveQueue.offer(buffer.copyOf(result))
                }
                result == 0 -> {
                    // Keepalive received
                    Log.v(TAG, "Keepalive received")
                }
                else -> {
                    Log.w(TAG, "Receive error: $result")
                }
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Error receiving packet", e)
            -1
        }
    }

    /**
     * Get next received packet from queue
     */
    fun pollReceivedPacket(): ByteArray? {
        return receiveQueue.poll()
    }

    /**
     * Check if there are packets waiting to be sent
     */
    fun hasQueuedPackets(): Boolean = sendQueue.isNotEmpty()

    /**
     * Get number of queued packets
     */
    fun getQueuedPacketCount(): Int = sendQueue.size

    /**
     * Clear all queued packets
     */
    fun clearQueues() {
        sendQueue.clear()
        receiveQueue.clear()
    }
}

/**
 * Packet structure for SoftEther protocol
 */
data class SoftEtherPacket(
    val signature: Int = 0x53455448, // 'SETH'
    val version: Short = 1,
    val command: Short,
    val payloadLength: Int,
    val sessionId: Int,
    val sequenceNumber: Int,
    val payload: ByteArray
) {
    companion object {
        const val CMD_CONNECT: Short = 0x0001
        const val CMD_CONNECT_ACK: Short = 0x0002
        const val CMD_AUTH: Short = 0x0003
        const val CMD_AUTH_CHALLENGE: Short = 0x0004
        const val CMD_AUTH_RESPONSE: Short = 0x0005
        const val CMD_AUTH_SUCCESS: Short = 0x0006
        const val CMD_AUTH_FAIL: Short = 0x0007
        const val CMD_SESSION_REQUEST: Short = 0x0008
        const val CMD_SESSION_ASSIGN: Short = 0x0009
        const val CMD_CONFIG_REQUEST: Short = 0x000A
        const val CMD_CONFIG_RESPONSE: Short = 0x000B
        const val CMD_DATA: Short = 0x000C
        const val CMD_KEEPALIVE: Short = 0x000D
        const val CMD_KEEPALIVE_ACK: Short = 0x000E
        const val CMD_DISCONNECT: Short = 0x000F
        const val CMD_DISCONNECT_ACK: Short = 0x0010
        const val CMD_ERROR: Short = 0x00FF

        /**
         * Parse packet from byte array
         */
        fun fromBytes(data: ByteArray): SoftEtherPacket? {
            return try {
                val buffer = ByteBuffer.wrap(data)
                val signature = buffer.int
                val version = buffer.short
                val command = buffer.short
                val payloadLength = buffer.int
                val sessionId = buffer.int
                val sequenceNumber = buffer.int

                val payload = ByteArray(payloadLength)
                buffer.get(payload)

                SoftEtherPacket(
                    signature = signature,
                    version = version,
                    command = command,
                    payloadLength = payloadLength,
                    sessionId = sessionId,
                    sequenceNumber = sequenceNumber,
                    payload = payload
                )
            } catch (e: Exception) {
                null
            }
        }
    }

    /**
     * Convert packet to byte array
     */
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(20 + payload.size)
        buffer.putInt(signature)
        buffer.putShort(version)
        buffer.putShort(command)
        buffer.putInt(payload.size)
        buffer.putInt(sessionId)
        buffer.putInt(sequenceNumber)
        buffer.put(payload)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SoftEtherPacket

        if (signature != other.signature) return false
        if (version != other.version) return false
        if (command != other.command) return false
        if (payloadLength != other.payloadLength) return false
        if (sessionId != other.sessionId) return false
        if (sequenceNumber != other.sequenceNumber) return false
        if (!payload.contentEquals(other.payload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signature
        result = 31 * result + version
        result = 31 * result + command
        result = 31 * result + payloadLength
        result = 31 * result + sessionId
        result = 31 * result + sequenceNumber
        result = 31 * result + payload.contentHashCode()
        return result
    }
}
