package vn.unlimit.softether.util

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Utility class for ByteBuffer operations
 */
object ByteBufferUtil {

    /**
     * Read unsigned short from ByteBuffer (big-endian)
     */
    fun readUInt16(buffer: ByteBuffer): Int {
        return buffer.short.toInt() and 0xFFFF
    }

    /**
     * Read unsigned int from ByteBuffer (big-endian)
     */
    fun readUInt32(buffer: ByteBuffer): Long {
        return buffer.int.toLong() and 0xFFFFFFFFL
    }

    /**
     * Write unsigned short to ByteBuffer (big-endian)
     */
    fun writeUInt16(buffer: ByteBuffer, value: Int) {
        buffer.putShort((value and 0xFFFF).toShort())
    }

    /**
     * Write unsigned int to ByteBuffer (big-endian)
     */
    fun writeUInt32(buffer: ByteBuffer, value: Long) {
        buffer.putInt((value and 0xFFFFFFFFL).toInt())
    }

    /**
     * Create a ByteBuffer with native byte order
     */
    fun createBuffer(size: Int): ByteBuffer {
        return ByteBuffer.allocate(size).order(ByteOrder.nativeOrder())
    }

    /**
     * Create a ByteBuffer with big-endian order (network byte order)
     */
    fun createNetworkBuffer(size: Int): ByteBuffer {
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN)
    }

    /**
     * Convert short to byte array (big-endian)
     */
    fun shortToBytes(value: Short): ByteArray {
        return byteArrayOf(
            (value.toInt() ushr 8).toByte(),
            value.toByte()
        )
    }

    /**
     * Convert int to byte array (big-endian)
     */
    fun intToBytes(value: Int): ByteArray {
        return byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte()
        )
    }

    /**
     * Convert byte array to short (big-endian)
     */
    fun bytesToShort(bytes: ByteArray, offset: Int = 0): Short {
        require(bytes.size >= offset + 2) { "Byte array too small" }
        return ((bytes[offset].toInt() and 0xFF) shl 8 or
                (bytes[offset + 1].toInt() and 0xFF)).toShort()
    }

    /**
     * Convert byte array to int (big-endian)
     */
    fun bytesToInt(bytes: ByteArray, offset: Int = 0): Int {
        require(bytes.size >= offset + 4) { "Byte array too small" }
        return ((bytes[offset].toInt() and 0xFF) shl 24) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
                (bytes[offset + 3].toInt() and 0xFF)
    }

    /**
     * Hex dump of byte array for debugging
     */
    fun hexDump(bytes: ByteArray, maxLength: Int = 64): String {
        if (bytes.isEmpty()) return "<empty>"

        val length = minOf(bytes.size, maxLength)
        val hex = StringBuilder()
        val ascii = StringBuilder()

        for (i in 0 until length) {
            if (i > 0 && i % 16 == 0) {
                hex.append("  ").append(ascii).append("\n")
                ascii.clear()
            }

            val b = bytes[i].toInt() and 0xFF
            hex.append(String.format("%02X ", b))

            ascii.append(
                if (b in 32..126) {
                    b.toChar()
                } else {
                    '.'
                }
            )
        }

        // Pad last line
        val remaining = length % 16
        if (remaining != 0) {
            for (i in remaining until 16) {
                hex.append("   ")
            }
        }
        hex.append("  ").append(ascii)

        if (bytes.size > maxLength) {
            hex.append("\n... (").append(bytes.size - maxLength).append(" more bytes)")
        }

        return hex.toString()
    }

    /**
     * Parse MAC address from bytes
     */
    fun parseMacAddress(bytes: ByteArray, offset: Int = 0): String {
        require(bytes.size >= offset + 6) { "Byte array too small for MAC address" }
        return buildString {
            for (i in 0 until 6) {
                if (i > 0) append(':')
                append(String.format("%02X", bytes[offset + i]))
            }
        }
    }

    /**
     * Parse IPv4 address from bytes
     */
    fun parseIPv4Address(bytes: ByteArray, offset: Int = 0): String {
        require(bytes.size >= offset + 4) { "Byte array too small for IPv4 address" }
        return buildString {
            for (i in 0 until 4) {
                if (i > 0) append('.')
                append(bytes[offset + i].toInt() and 0xFF)
            }
        }
    }
}
