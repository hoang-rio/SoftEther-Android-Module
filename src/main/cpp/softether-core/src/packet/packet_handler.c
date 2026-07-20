/*
 * SoftEther VPN Data Channel - Block Format
 *
 * Real SoftEther uses a simple block-count + length-prefixed format for data
 * after the HTTP-based authentication phase:
 *
 *   [uint32 block_count]              -- number of blocks, big-endian
 *   [uint32 block_size_1][block_data_1]
 *   [uint32 block_size_2][block_data_2]
 *   ...
 *
 * Keepalive uses a special magic value:
 *   [0xFFFFFFFF]                      -- KEEP_ALIVE_MAGIC
 *   [uint32 keepalive_size][keepalive_data]
 */
#include "softether_protocol.h"
#include "softether_socket.h"
#include "softether_crypto.h"
#include "softether_compress.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <android/log.h>

#define TAG "SoftEtherPacket"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define KEEP_ALIVE_MAGIC 0xFFFFFFFF
#define MAX_BLOCK_SIZE   (1600 * 1600)  // same as SoftEther MAX_PACKET_SIZE safety
#define COMPRESS_MAGIC   0xDEADBEEFCAFEFACELL

// Read exactly `len` bytes from the SSL connection. Returns 0 on success, -1 on error.
static int ssl_read_all(softether_connection_t* conn, uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        if (conn->state == STATE_DISCONNECTED || conn->state == STATE_DISCONNECTING) {
            return -1;
        }
        int ret = ssl_read((ssl_context_t*)conn->ssl, buf + total, len - total);
        if (ret <= 0) {
            return -1;
        }
        total += ret;
    }
    return 0;
}

// Write exactly `len` bytes to the SSL connection. Returns 0 on success, -1 on error.
static int ssl_write_all(softether_connection_t* conn, const uint8_t* buf, int len) {
    int total = 0;
    LOGD("ssl_write_all: writing %d bytes (first 8: %02X %02X %02X %02X %02X %02X %02X %02X)",
         len,
         len > 0 ? buf[0] : 0, len > 1 ? buf[1] : 0,
         len > 2 ? buf[2] : 0, len > 3 ? buf[3] : 0,
         len > 4 ? buf[4] : 0, len > 5 ? buf[5] : 0,
         len > 6 ? buf[6] : 0, len > 7 ? buf[7] : 0);
    while (total < len) {
        if (conn->state == STATE_DISCONNECTED || conn->state == STATE_DISCONNECTING) {
            LOGE("ssl_write_all: connection state %d", conn->state);
            return -1;
        }
        int ret = ssl_write((ssl_context_t*)conn->ssl, buf + total, len - total);
        if (ret <= 0) {
            LOGE("ssl_write_all: ssl_write returned %d (wrote %d/%d)", ret, total, len);
            return -1;
        }
        LOGD("ssl_write_all: ssl_write returned %d (progress %d/%d)", ret, total + ret, len);
        total += ret;
    }
    return 0;
}

// Read exactly `len` bytes from raw TCP socket. Returns 0 on success, -1 on error.
static int raw_read_all(softether_connection_t* conn, uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        if (conn->state == STATE_DISCONNECTED || conn->state == STATE_DISCONNECTING) {
            return -1;
        }
        int ret = (int)recv(conn->socket_fd, buf + total, len - total, 0);
        if (ret <= 0) {
            if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            LOGE("raw_read_all: recv returned %d (errno=%d)", ret, errno);
            return -1;
        }
        total += ret;
    }
    return 0;
}

// Write exactly `len` bytes to raw TCP socket. Returns 0 on success, -1 on error.
static int raw_write_all(softether_connection_t* conn, const uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        if (conn->state == STATE_DISCONNECTED || conn->state == STATE_DISCONNECTING) {
            return -1;
        }
        int ret = (int)send(conn->socket_fd, buf + total, len - total, 0);
        if (ret <= 0) {
            if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            LOGE("raw_write_all: send returned %d (errno=%d)", ret, errno);
            return -1;
        }
        total += ret;
    }
    return 0;
}

// Read `len` bytes using the appropriate channel (SSL or raw TCP)
static int data_read_all(softether_connection_t* conn, uint8_t* buf, int len) {
    if (conn->use_ssl_data) {
        return ssl_read_all(conn, buf, len);
    } else {
        return raw_read_all(conn, buf, len);
    }
}

// Write `len` bytes using the appropriate channel (SSL or raw TCP)
static int data_write_all(softether_connection_t* conn, const uint8_t* buf, int len) {
    if (conn->use_ssl_data) {
        return ssl_write_all(conn, buf, len);
    } else {
        return raw_write_all(conn, buf, len);
    }
}

// Read a big-endian uint32 from the data channel.
static int read_uint32(softether_connection_t* conn, uint32_t* out) {
    uint8_t buf[4];
    if (data_read_all(conn, buf, 4) != 0) return -1;
    *out = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    return 0;
}


// Send one data block (Ethernet frame) using the real SoftEther block format.
// Format: [block_count=1][block_size][block_data]
// Thread-safe: locks write_mutex to prevent interleaving with keepalive responses
int softether_send_packet(softether_connection_t* conn, uint16_t command,
                          const uint8_t* payload, uint32_t payload_len) {
    if (conn == NULL || conn->ssl == NULL) {
        LOGE("Connection or SSL is NULL");
        return -1;
    }
    if (conn->state == STATE_DISCONNECTED || conn->state == STATE_DISCONNECTING) {
        LOGE("Cannot send: connection state %d", conn->state);
        return -1;
    }

    // For keepalive, use the magic format (has its own mutex lock)
    if (command == CMD_KEEPALIVE || command == CMD_KEEPALIVE_ACK) {
        return softether_send_keepalive(conn);
    }

    pthread_mutex_lock(&conn->write_mutex);

    // TCP path: session-level compression (no per-block magic signature)
    // The server knows to decompress because use_compress was negotiated.
    const uint8_t* send_payload = payload;
    uint32_t send_len = payload_len;
    uint8_t* comp_buf = NULL;

    if (conn->server_use_compress && payload_len > 1) {
        uint32_t comp_bound = calc_compress_bound(payload_len);
        comp_buf = (uint8_t*)malloc(comp_bound);
        if (comp_buf != NULL) {
            uint32_t comp_len = comp_bound;
            if (compress_data(payload, payload_len, comp_buf, &comp_len) == 0 &&
                comp_len < payload_len) {
                send_payload = comp_buf;
                send_len = comp_len;
            }
        }
    }

    // Build entire data block as single buffer (matching reference ConnectionSend)
    // Format: [block_count=1(4)][block_size(4)][block_data(send_len)]
    uint32_t total_size = 4 + 4 + send_len;
    uint8_t* buf = (uint8_t*)malloc(total_size);
    if (buf == NULL) {
        LOGE("Failed to allocate send buffer");
        free(comp_buf);
        pthread_mutex_unlock(&conn->write_mutex);
        return -1;
    }

    // block_count = 1 in big-endian
    buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 1;
    // block_size in big-endian
    buf[4] = (send_len >> 24) & 0xFF;
    buf[5] = (send_len >> 16) & 0xFF;
    buf[6] = (send_len >> 8) & 0xFF;
    buf[7] = send_len & 0xFF;
    // block data
    if (send_len > 0 && send_payload != NULL) {
        memcpy(buf + 8, send_payload, send_len);
    }

    int ret = data_write_all(conn, buf, (int)total_size);
    free(buf);
    free(comp_buf);

    if (ret != 0) {
        LOGE("Failed to send data block");
        pthread_mutex_unlock(&conn->write_mutex);
        return -1;
    }

    pthread_mutex_unlock(&conn->write_mutex);
    LOGD("Sent 1 data block (%u bytes, compressed=%d)", payload_len, (send_len < payload_len) ? 1 : 0);
    return (int)total_size;
}

// Receive data blocks from the connection.
// Returns the first data block in `payload`, sets `payload_len`.
// Sets `command` to CMD_DATA for data blocks, CMD_KEEPALIVE for keepalive.
// Returns total bytes read on success, -1 on error.
int softether_receive_packet(softether_connection_t* conn, uint16_t* command,
                             uint8_t* payload, uint32_t* payload_len, uint32_t max_payload) {
    if (conn == NULL || command == NULL) {
        LOGE("Invalid parameters");
        return -1;
    }
    if (conn->ssl == NULL || conn->socket_fd < 0) {
        LOGE("Socket/SSL not connected");
        return -1;
    }
    if (conn->state == STATE_DISCONNECTED || conn->state == STATE_DISCONNECTING) {
        return -1;
    }

    // Read block count (or keepalive magic)
    uint32_t block_count = 0;
    if (read_uint32(conn, &block_count) != 0) {
        LOGE("Failed to read block count");
        return -1;
    }

    if (block_count == KEEP_ALIVE_MAGIC) {
        // Keepalive: read size + data
        uint32_t ka_size = 0;
        if (read_uint32(conn, &ka_size) != 0) {
            LOGE("Failed to read keepalive size");
            return -1;
        }
        if (ka_size > 512) ka_size = 512;  // safety cap
        if (ka_size > 0) {
            uint8_t ka_buf[512];
            if (data_read_all(conn, ka_buf, (int)ka_size) != 0) {
                LOGE("Failed to read keepalive data");
                return -1;
            }
        }
        *command = CMD_KEEPALIVE;
        if (payload_len) *payload_len = 0;
        LOGD("Received keepalive (%u bytes)", ka_size);
        return (int)(8 + ka_size);
    }

    // Regular data blocks
    if (block_count == 0) {
        *command = CMD_DATA;
        if (payload_len) *payload_len = 0;
        return 4;
    }

    LOGD("Receiving %u data block(s)", block_count);

    int total_read = 4;
    int first_block_stored = 0;

    for (uint32_t i = 0; i < block_count; i++) {
        uint32_t block_size = 0;
        if (read_uint32(conn, &block_size) != 0) {
            LOGE("Failed to read block %u size", i);
            return -1;
        }
        total_read += 4;

        if (block_size > MAX_BLOCK_SIZE) {
            LOGE("Block %u size too large: %u", i, block_size);
            return -1;
        }

        if (!first_block_stored && payload != NULL && payload_len != NULL && block_size <= max_payload) {
            // Store first block in caller's buffer
            if (block_size > 0) {
                // Read into temp buffer to check for compression magic
                uint8_t* tmp_block = (uint8_t*)malloc(block_size);
                if (tmp_block == NULL) {
                    LOGE("Failed to allocate block buffer");
                    return -1;
                }
                if (data_read_all(conn, tmp_block, (int)block_size) != 0) {
                    LOGE("Failed to read block %u data", i);
                    free(tmp_block);
                    return -1;
                }

                // TCP path: session-level compression (no per-block magic)
                // If server accepted compression, ALL blocks are compressed.
                if (conn->server_use_compress) {
                    // Decompress entire block
                    uint32_t raw_len = max_payload;
                    if (uncompress_data(tmp_block, block_size,
                                        payload, &raw_len) != 0) {
                        LOGE("Failed to decompress block %u (session compress)", i);
                        free(tmp_block);
                        return -1;
                    }
                    LOGD("receive_packet: decompressed block %u: %u -> %u bytes",
                         i, block_size, raw_len);
                    *payload_len = raw_len;
                    free(tmp_block);
                    first_block_stored = 1;
                    total_read += (int)block_size;
                    continue;  // skip the general block_size assignment below
                }

                // Uncompressed — copy as-is
                memcpy(payload, tmp_block, block_size);
                free(tmp_block);
            }
            *payload_len = block_size;
            first_block_stored = 1;
        } else {
            // Skip subsequent blocks (or if buffer too small)
            uint8_t skip_buf[2048];
            uint32_t remaining = block_size;
            while (remaining > 0) {
                uint32_t chunk = remaining > sizeof(skip_buf) ? sizeof(skip_buf) : remaining;
                if (data_read_all(conn, skip_buf, (int)chunk) != 0) {
                    LOGE("Failed to skip block %u data", i);
                    return -1;
                }
                remaining -= chunk;
            }
        }
        total_read += (int)block_size;
    }

    *command = CMD_DATA;
    LOGD("Received %u block(s), first block %u bytes, total %d bytes",
         block_count, payload_len ? *payload_len : 0, total_read);
    return total_read;
}

// Send keepalive using the real SoftEther format: [0xFFFFFFFF][size][random_data]
// Thread-safe: locks write_mutex since this may be called from the receive thread
int softether_send_keepalive(softether_connection_t* conn) {
    if (conn == NULL || conn->ssl == NULL) {
        return -1;
    }
    if (conn->state != STATE_CONNECTED) {
        return -1;
    }

    pthread_mutex_lock(&conn->write_mutex);

    // Build keepalive as a single buffer (matching reference ConnectionSend behavior)
    // Format: [KEEP_ALIVE_MAGIC(4)][ka_size(4)][random_data(ka_size)]
    uint32_t ka_size = (uint32_t)(rand() % 64);
    uint32_t total_size = 4 + 4 + ka_size;
    uint8_t ka_buf[136]; // 4+4+64 max

    // KEEP_ALIVE_MAGIC in big-endian
    uint32_t magic = KEEP_ALIVE_MAGIC;
    ka_buf[0] = (magic >> 24) & 0xFF;
    ka_buf[1] = (magic >> 16) & 0xFF;
    ka_buf[2] = (magic >> 8) & 0xFF;
    ka_buf[3] = magic & 0xFF;

    // ka_size in big-endian
    ka_buf[4] = (ka_size >> 24) & 0xFF;
    ka_buf[5] = (ka_size >> 16) & 0xFF;
    ka_buf[6] = (ka_size >> 8) & 0xFF;
    ka_buf[7] = ka_size & 0xFF;

    // Random payload
    for (uint32_t i = 0; i < ka_size; i++) {
        ka_buf[8 + i] = (uint8_t)(rand() & 0xFF);
    }

    // Send entire keepalive as one SSL_write (single TLS record)
    int ret = data_write_all(conn, ka_buf, (int)total_size);
    pthread_mutex_unlock(&conn->write_mutex);

    if (ret != 0) {
        LOGE("Failed to send keepalive");
        return -1;
    }
    LOGD("Sent keepalive (%u bytes payload)", ka_size);
    return (int)total_size;
}

// Process keepalive — receive and handle if the next message is a keepalive.
int softether_process_keepalive(softether_connection_t* conn) {
    if (conn == NULL) return -1;

    uint16_t command;
    uint8_t buffer[256];
    uint32_t payload_len = 0;

    int result = softether_receive_packet(conn, &command, buffer, &payload_len, sizeof(buffer));
    if (result < 0) return -1;

    if (command == CMD_KEEPALIVE) {
        // Respond with our own keepalive
        softether_send_keepalive(conn);
        LOGD("Keepalive exchanged");
        return 0;
    }

    LOGD("Expected keepalive, got command 0x%04X", command);
    return 0;
}

// ---- Receive queue helpers ----

// Read one protocol message and queue ALL blocks into the receive queue.
// Returns: 1 = data queued, 0 = keepalive/no data/timeout, -1 = error
int softether_fill_recv_queue(softether_connection_t* conn) {
    if (conn == NULL || conn->ssl == NULL) return -1;
    if (conn->state == STATE_DISCONNECTED || conn->state == STATE_DISCONNECTING) return -1;

    // Check for queued RUDP data first (non-blocking)
    if (conn->rudp && conn->rudp_enabled) {
        rudp_poll(conn->rudp);

        uint32_t rudp_len = 0;
        uint8_t rudp_buf[MAX_QUEUED_FRAME];
        int r = rudp_recv(conn->rudp, rudp_buf, &rudp_len, sizeof(rudp_buf));
        if (r > 0 && rudp_len > 0 && conn->recv_queue_count < RECV_QUEUE_SIZE) {
            queued_frame_t* entry = &conn->recv_queue[conn->recv_queue_tail];
            uint32_t copy_len = rudp_len < MAX_QUEUED_FRAME ? rudp_len : MAX_QUEUED_FRAME;
            memcpy(entry->data, rudp_buf, copy_len);
            entry->len = copy_len;
            conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
            conn->recv_queue_count++;
            LOGD("fill_recv_queue: queued %u bytes from RUDP (buffered)", copy_len);
            return 1;
        }
    }

    // Check if SSL has buffered data first (may not show up in poll)
    int ssl_pending = conn->use_ssl_data ? ssl_has_pending((ssl_context_t*)conn->ssl) : 0;

    if (ssl_pending <= 0) {
        // No SSL-buffered data — poll socket(s) for new data.
        // When RUDP is active, poll BOTH UDP and TCP simultaneously so we
        // don't miss data arriving on either channel.  Use a reasonable
        // timeout (100 ms) instead of the previous 0 ms / 5 ms which was
        // too short and caused the receive loop to spin without ever
        // seeing data on the RUDP channel.
        struct pollfd fds[2];
        nfds_t nfds = 0;

        if (conn->rudp && conn->rudp_enabled) {
            int udp_fd = rudp_get_udp_fd(conn->rudp);
            if (udp_fd >= 0) {
                fds[nfds].fd = udp_fd;
                fds[nfds].events = POLLIN;
                fds[nfds].revents = 0;
                nfds++;
            }
        }

        fds[nfds].fd = conn->socket_fd;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        nfds++;

        int poll_timeout_ms = (conn->rudp && conn->rudp_enabled) ? 100 : 50;
        int poll_ret = poll(fds, nfds, poll_timeout_ms);

        if (poll_ret == 0) {
            return 0;  // No data available — normal timeout
        }
        if (poll_ret < 0) {
            LOGE("fill_recv_queue: poll error: %d", poll_ret);
            return -1;
        }

        // Check which socket(s) have data
        int have_tcp_data = 0;
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].revents & POLLNVAL) {
                LOGE("fill_recv_queue: socket fd=%d invalid (revents=0x%x)", fds[i].fd, fds[i].revents);
                return -1;
            }
            if ((fds[i].revents & (POLLERR | POLLHUP)) && !(fds[i].revents & POLLIN)) {
                LOGE("fill_recv_queue: socket fd=%d error (revents=0x%x)", fds[i].fd, fds[i].revents);
                return -1;
            }
            if (fds[i].revents & POLLIN) {
                // Is this the UDP (RUDP) socket?
                if (conn->rudp && conn->rudp_enabled) {
                    int udp_fd = rudp_get_udp_fd(conn->rudp);
                    if (udp_fd >= 0 && fds[i].fd == udp_fd) {
                        // UDP socket has data — process via RUDP
                        rudp_poll(conn->rudp);
                        uint32_t rudp_len = 0;
                        uint8_t rudp_buf[MAX_QUEUED_FRAME];
                        int r = rudp_recv(conn->rudp, rudp_buf, &rudp_len, sizeof(rudp_buf));
                        if (r > 0 && rudp_len > 0 && conn->recv_queue_count < RECV_QUEUE_SIZE) {
                            queued_frame_t* entry = &conn->recv_queue[conn->recv_queue_tail];
                            uint32_t copy_len = rudp_len < MAX_QUEUED_FRAME ? rudp_len : MAX_QUEUED_FRAME;
                            memcpy(entry->data, rudp_buf, copy_len);
                            entry->len = copy_len;
                            conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
                            conn->recv_queue_count++;
                            LOGD("fill_recv_queue: queued %u bytes from RUDP (poll)", copy_len);
                            return 1;
                        }
                    } else {
                        // TCP socket has data
                        have_tcp_data = 1;
                    }
                } else {
                    have_tcp_data = 1;
                }
            }
        }

        // If RUDP is not active, we reach here when TCP has data (or error handled above).
        // If RUDP is active but UDP socket had no data and TCP has data, read from TCP.
        if (!have_tcp_data) {
            return 0;  // No usable data
        }
    }

    // Read block count (or keepalive magic)
    uint32_t block_count = 0;
    if (read_uint32(conn, &block_count) != 0) {
        LOGE("fill_recv_queue: failed to read block count");
        return -1;
    }

    if (block_count == KEEP_ALIVE_MAGIC) {
        // Keepalive: read size + data, respond
        uint32_t ka_size = 0;
        if (read_uint32(conn, &ka_size) != 0) return -1;
        if (ka_size > 512) ka_size = 512;
        if (ka_size > 0) {
            uint8_t ka_buf[512];
            if (data_read_all(conn, ka_buf, (int)ka_size) != 0) return -1;
        }
        LOGD("fill_recv_queue: keepalive (%u bytes)", ka_size);
        softether_send_keepalive(conn);
        return 0;
    }

    if (block_count == 0) {
        return 0; // Empty message
    }

    LOGD("fill_recv_queue: reading %u block(s)", block_count);

    for (uint32_t i = 0; i < block_count; i++) {
        uint32_t block_size = 0;
        if (read_uint32(conn, &block_size) != 0) {
            LOGE("fill_recv_queue: failed to read block %u size", i);
            return -1;
        }

        if (block_size > MAX_BLOCK_SIZE) {
            LOGE("fill_recv_queue: block %u too large: %u", i, block_size);
            return -1;
        }

        if (block_size == 0) continue;

        if (block_size <= MAX_QUEUED_FRAME && conn->recv_queue_count < RECV_QUEUE_SIZE) {
            // Read into temp buffer to check for compression magic
            uint8_t* tmp_block = (uint8_t*)malloc(block_size);
            if (tmp_block == NULL) {
                LOGE("fill_recv_queue: allocation failed for block %u", i);
                return -1;
            }
            if (data_read_all(conn, tmp_block, (int)block_size) != 0) {
                LOGE("fill_recv_queue: failed to read block %u", i);
                free(tmp_block);
                return -1;
            }

            queued_frame_t* entry = &conn->recv_queue[conn->recv_queue_tail];

            // TCP path: session-level compression (no per-block magic)
            // If server accepted compression, ALL blocks are compressed.
            if (conn->server_use_compress) {
                uint32_t raw_len = MAX_QUEUED_FRAME;
                if (uncompress_data(tmp_block, block_size,
                                    entry->data, &raw_len) != 0) {
                    LOGE("fill_recv_queue: decompression failed for block %u (session compress)", i);
                    free(tmp_block);
                    return -1;
                }
                entry->len = raw_len;
                LOGD("fill_recv_queue: decompressed block %u: %u -> %u bytes, first8: %02X %02X %02X %02X %02X %02X %02X %02X",
                     i, block_size, raw_len,
                     raw_len > 0 ? entry->data[0] : 0, raw_len > 1 ? entry->data[1] : 0,
                     raw_len > 2 ? entry->data[2] : 0, raw_len > 3 ? entry->data[3] : 0,
                     raw_len > 4 ? entry->data[4] : 0, raw_len > 5 ? entry->data[5] : 0,
                     raw_len > 6 ? entry->data[6] : 0, raw_len > 7 ? entry->data[7] : 0);
                free(tmp_block);
                conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
                conn->recv_queue_count++;
                continue;
            }

            // Fallback: check for RUDP-style compression magic
            if (block_size > 8) {
                uint64_t sig = 0;
                for (int b = 0; b < 8; b++) {
                    sig = (sig << 8) | tmp_block[b];
                }
                if (sig == COMPRESS_MAGIC) {
                    // Decompress
                    uint32_t raw_len = MAX_QUEUED_FRAME;
                    if (uncompress_data(tmp_block + 8, block_size - 8,
                                        entry->data, &raw_len) != 0) {
                        LOGE("fill_recv_queue: decompression failed for block %u", i);
                        free(tmp_block);
                        return -1;
                    }
                    entry->len = raw_len;
                    LOGD("fill_recv_queue: decompressed block %u (magic): %u -> %u bytes",
                         i, block_size - 8, raw_len);
                    free(tmp_block);
                    conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
                    conn->recv_queue_count++;
                    continue;
                }
            }

            // Uncompressed — copy as-is
            memcpy(entry->data, tmp_block, block_size);
            free(tmp_block);
            entry->len = block_size;
            conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
            conn->recv_queue_count++;
        } else {
            // Queue full or frame too large — skip this block
            uint8_t skip_buf[2048];
            uint32_t remaining = block_size;
            while (remaining > 0) {
                uint32_t chunk = remaining > sizeof(skip_buf) ? sizeof(skip_buf) : remaining;
                if (data_read_all(conn, skip_buf, (int)chunk) != 0) return -1;
                remaining -= chunk;
            }
            LOGD("fill_recv_queue: skipped block %u (%u bytes, queue_count=%d)", i, block_size, conn->recv_queue_count);
        }
    }

    LOGD("fill_recv_queue: queued %d frames total", conn->recv_queue_count);
    return (conn->recv_queue_count > 0) ? 1 : 0;
}
