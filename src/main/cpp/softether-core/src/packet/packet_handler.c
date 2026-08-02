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
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
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

// ---- Socket-specific read helpers (for multi-connection) ----

// Read exactly `len` bytes from a specific SSL context (not conn->ssl).
static int ssl_read_all_ctx(ssl_context_t* ssl, uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        int ret = ssl_read(ssl, buf + total, len - total);
        if (ret <= 0) {
            return -1;
        }
        total += ret;
    }
    return 0;
}

// Read exactly `len` bytes from a specific raw TCP fd (not conn->socket_fd).
static int raw_read_all_fd(int fd, uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        int ret = (int)recv(fd, buf + total, len - total, 0);
        if (ret <= 0) {
            if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            return -1;
        }
        total += ret;
    }
    return 0;
}

// Read `len` bytes from a specific socket (SSL or raw).
static int data_read_all_sock(softether_connection_t* conn,
                              void* ssl, int socket_fd,
                              uint8_t* buf, int len) {
    if (conn->use_ssl_data) {
        return ssl_read_all_ctx((ssl_context_t*)ssl, buf, len);
    } else {
        return raw_read_all_fd(socket_fd, buf, len);
    }
}

// Read a big-endian uint32 from a specific socket.
static int read_uint32_sock(softether_connection_t* conn,
                            void* ssl, int socket_fd,
                            uint32_t* out) {
    uint8_t buf[4];
    if (data_read_all_sock(conn, ssl, socket_fd, buf, 4) != 0) return -1;
    *out = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    return 0;
}

// Write exactly `len` bytes to a specific socket (SSL or raw).
static int data_write_all_sock(softether_connection_t* conn,
                               void* ssl, int socket_fd,
                               const uint8_t* buf, int len) {
    if (conn->use_ssl_data) {
        int total = 0;
        while (total < len) {
            int ret = ssl_write((ssl_context_t*)ssl, buf + total, len - total);
            if (ret <= 0) return -1;
            total += ret;
        }
        return 0;
    } else {
        int total = 0;
        while (total < len) {
            int ret = (int)send(socket_fd, buf + total, len - total, 0);
            if (ret <= 0) {
                if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                return -1;
            }
            total += ret;
        }
        return 0;
    }
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
    if (conn == NULL) {
        LOGE("Connection is NULL");
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

    // Recheck state and SSL inside mutex (disconnect may have freed them)
    if (conn->state == STATE_DISCONNECTING || conn->ssl == NULL) {
        pthread_mutex_unlock(&conn->write_mutex);
        return -1;
    }

    // TCP path: session-level compression (raw zlib, no magic prefix)
    // VPN Gate server fork sends/receives raw zlib when use_compress is set.
    const uint8_t* send_payload = payload;
    uint32_t send_len = payload_len;
    uint8_t* comp_buf = NULL;

    if (conn->server_use_compress && payload_len > 1) {
        uint32_t comp_bound = calc_compress_bound(payload_len);
        comp_buf = (uint8_t*)malloc(comp_bound);
        if (comp_buf != NULL) {
            uint32_t comp_len = comp_bound;
            if (compress_data(payload, payload_len, comp_buf, &comp_len) == 0) {
                send_payload = comp_buf;
                send_len = comp_len;
            } else {
                free(comp_buf);
                comp_buf = NULL;
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

    // Select best socket for multi-connection send
    int send_idx = softether_select_send_socket(conn);
    void* send_ssl = (send_idx == 0) ? conn->ssl : conn->additional[send_idx - 1].ssl;
    int send_fd = (send_idx == 0) ? conn->socket_fd : conn->additional[send_idx - 1].socket_fd;
    __sync_synchronize();  // load-acquire: ensure ssl/fd reads are ordered

    // Revalidate: if using additional, verify it's still active
    if (send_idx > 0) {
        softether_tcp_sock_t* ts = &conn->additional[send_idx - 1];
        if (!ts->active || send_ssl == NULL) {
            free(buf);
            free(comp_buf);
            pthread_mutex_unlock(&conn->write_mutex);
            return -1;
        }
    }

    int ret;
    if (send_idx > 0 && send_ssl != NULL) {
        // Send via additional connection
        ret = data_write_all_sock(conn, send_ssl, send_fd, buf, (int)total_size);
    } else {
        // Send via primary connection
        ret = data_write_all(conn, buf, (int)total_size);
    }

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

                int compressed_ok = 0;
                if (conn->server_use_compress) {
                    // Session-level compression: VPN Gate server sends raw zlib
                    uint32_t raw_len = max_payload;
                    if (uncompress_data(tmp_block, block_size,
                                        payload, &raw_len) == 0) {
                        *payload_len = raw_len;
                        free(tmp_block);
                        first_block_stored = 1;
                        total_read += (int)block_size;
                        compressed_ok = 1;
                        LOGD("receive_packet: session-decompressed block %u: %u -> %u bytes",
                             i, block_size, raw_len);
                        continue;
                    }
                    // Fallback: check for CONNECTION_BULK_COMPRESS_SIGNATURE
                    if (block_size > 8) {
                        uint64_t sig = 0;
                        for (int b = 0; b < 8; b++) {
                            sig = (sig << 8) | tmp_block[b];
                        }
                        if (sig == COMPRESS_MAGIC) {
                            raw_len = max_payload;
                            if (uncompress_data(tmp_block + 8, block_size - 8,
                                                payload, &raw_len) == 0) {
                                *payload_len = raw_len;
                                free(tmp_block);
                                first_block_stored = 1;
                                total_read += (int)block_size;
                                compressed_ok = 1;
                                LOGD("receive_packet: magic-decompressed block %u: %u -> %u bytes",
                                     i, block_size - 8, raw_len);
                                continue;
                            }
                        }
                    }
                    LOGD("receive_packet: block %u not compressed (%u bytes, first8: %02X %02X %02X %02X %02X %02X %02X %02X)",
                         i, block_size,
                         block_size > 0 ? tmp_block[0] : 0,
                         block_size > 1 ? tmp_block[1] : 0,
                         block_size > 2 ? tmp_block[2] : 0,
                         block_size > 3 ? tmp_block[3] : 0,
                         block_size > 4 ? tmp_block[4] : 0,
                         block_size > 5 ? tmp_block[5] : 0,
                         block_size > 6 ? tmp_block[6] : 0,
                         block_size > 7 ? tmp_block[7] : 0);
                }

                if (!compressed_ok) {
                    // Uncompressed — copy as-is
                    memcpy(payload, tmp_block, block_size);
                    free(tmp_block);
                }
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

// Send keepalive over a specific TCP socket using the real SoftEther format:
// [0xFFFFFFFF][size][random_data]. Thread-safe: locks write_mutex since this may
// be called from the receive thread.
static int softether_send_keepalive_sock(softether_connection_t* conn,
                                         void* ssl, int socket_fd) {
    if (conn == NULL || ssl == NULL) {
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
    int ret = data_write_all_sock(conn, ssl, socket_fd, ka_buf, (int)total_size);
    pthread_mutex_unlock(&conn->write_mutex);

    if (ret != 0) {
        LOGE("Failed to send keepalive");
        return -1;
    }
    LOGD("Sent keepalive (%u bytes payload)", ka_size);
    return (int)total_size;
}

// Send keepalive using the real SoftEther format: [0xFFFFFFFF][size][random_data]
// Thread-safe: locks write_mutex since this may be called from the receive thread
int softether_send_keepalive(softether_connection_t* conn) {
    if (conn == NULL || conn->ssl == NULL) {
        return -1;
    }
    return softether_send_keepalive_sock(conn, conn->ssl, conn->socket_fd);
}

// Periodically send keepalives over ALL send-capable TCP sockets (primary +
// additional C2S/BOTH). Mirrors the reference client, which sends keepalives over
// every IS_SEND_TCP_SOCK socket every GenNextKeepAliveSpan().
//
// Without this, when UDP acceleration (RUDP) carries all VPN data, the client
// never sends anything over additional uplink (C2S) TCP sockets. The server
// expects to receive on those sockets and times them out after s->Timeout
// (default 30s), which is the "lost uplink connection" symptom. The server's
// keepalives can't keep them alive because the server cannot send on C2S sockets.
int softether_send_keepalive_all(softether_connection_t* conn) {
    if (conn == NULL || conn->ssl == NULL) {
        return -1;
    }
    if (conn->state != STATE_CONNECTED) {
        return -1;
    }

    uint64_t now = softether_tick_ms();

    if (conn->next_tcp_keepalive_time == 0) {
        conn->next_tcp_keepalive_time = now;
        return 0;
    }
    if (now < conn->next_tcp_keepalive_time) {
        return 0;
    }

    // Keepalive must arrive more often than the server's per-socket timeout.
    // The server advertises its session timeout ("timeout") in the Welcome PACK.
    uint32_t timeout = conn->server_timeout != 0 ? conn->server_timeout : 30000;
    uint32_t interval = timeout / 3;
    if (interval < 2000) interval = 2000;
    if (interval > 12000) interval = 12000;

    conn->next_tcp_keepalive_time = now + interval;

    // Primary socket: send-capable if direction is BOTH or C2S
    if (conn->socket_fd >= 0 && conn->ssl != NULL) {
        int pd = conn->primary_direction;
        if (pd == TCP_DIRECTION_BOTH || pd == TCP_DIRECTION_CLIENT_TO_SERVER) {
            softether_send_keepalive_sock(conn, conn->ssl, conn->socket_fd);
        }
    }

    // Additional sockets: send-capable if direction is BOTH or C2S
    for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
        softether_tcp_sock_t* ts = &conn->additional[i];
        if (!ts->active) continue;
        int d = ts->direction;
        if (d != TCP_DIRECTION_BOTH && d != TCP_DIRECTION_CLIENT_TO_SERVER) continue;

        // Capture SSL and fd atomically — recheck active after capture
        void* cap_ssl = ts->ssl;
        int cap_fd = ts->socket_fd;
        __sync_synchronize();  // load-acquire: ensure ssl/fd stores are visible
        if (!ts->active || cap_ssl == NULL || cap_fd < 0) continue;

        softether_send_keepalive_sock(conn, cap_ssl, cap_fd);
    }

    return 0;
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
// Supports multi-connection: polls all active TCP sockets + optional UDP socket.
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

    // Build pollfd array: [UDP (optional)] + [primary TCP] + [additional TCP 0..N-1]
    // Max: 1 (UDP) + 1 (primary) + MAX_SE_CONNECTIONS (additional) = 10
    struct pollfd fds[1 + 1 + MAX_SE_CONNECTIONS];
    nfds_t nfds = 0;

    // Track which pollfd index maps to which TCP socket
    // TCP_SOCK_INFO: maps a pollfd index to ssl/fd pair
    typedef struct { void* ssl; int fd; int is_additional; int additional_idx; } tcp_sock_info_t;
    tcp_sock_info_t tcp_info[1 + MAX_SE_CONNECTIONS];
    int tcp_count = 0;

    int udp_fd = -1;

    // UDP socket (RUDP)
    if (conn->rudp && conn->rudp_enabled) {
        udp_fd = rudp_get_udp_fd(conn->rudp);
        if (udp_fd >= 0) {
            fds[nfds].fd = udp_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
    }

    // Primary TCP socket — only add if direction allows receiving (client: BOTH or S2C)
    if (conn->socket_fd >= 0) {
        int pd = conn->primary_direction;
        if (pd == TCP_DIRECTION_BOTH || pd == TCP_DIRECTION_SERVER_TO_CLIENT) {
            fds[nfds].fd = conn->socket_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            tcp_info[tcp_count].ssl = conn->ssl;
            tcp_info[tcp_count].fd = conn->socket_fd;
            tcp_info[tcp_count].is_additional = 0;
            tcp_info[tcp_count].additional_idx = -1;
            tcp_count++;
            nfds++;
        }
    }

    // Additional TCP sockets — only add if direction allows receiving (client: BOTH or S2C)
    for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
        softether_tcp_sock_t* ts = &conn->additional[i];
        if (!ts->active || ts->socket_fd < 0) continue;

        // Client mode: can receive on TCP_BOTH or TCP_SERVER_TO_CLIENT
        int d = ts->direction;
        if (d != TCP_DIRECTION_BOTH && d != TCP_DIRECTION_SERVER_TO_CLIENT) continue;

        // Capture SSL and fd atomically — recheck active after capture
        void* cap_ssl = ts->ssl;
        int cap_fd = ts->socket_fd;
        __sync_synchronize();  // load-acquire: ensure ssl/fd stores are visible
        if (!ts->active || cap_ssl == NULL || cap_fd < 0) continue;

        fds[nfds].fd = cap_fd;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        tcp_info[tcp_count].ssl = cap_ssl;
        tcp_info[tcp_count].fd = cap_fd;
        tcp_info[tcp_count].is_additional = 1;
        tcp_info[tcp_count].additional_idx = i;
        tcp_count++;
        nfds++;
    }

    if (nfds == 0) return -1;

    // Memory barrier + state check before using any captured SSL pointers
    __sync_synchronize();
    if (conn->state == STATE_DISCONNECTING) return -1;

    // Check for SSL-buffered data on any TCP socket before polling
    int ssl_pending_idx = -1;
    for (int t = 0; t < tcp_count; t++) {
        if (conn->use_ssl_data && ssl_has_pending((ssl_context_t*)tcp_info[t].ssl)) {
            ssl_pending_idx = t;
            break;
        }
    }

    if (ssl_pending_idx < 0) {
        // No SSL-buffered data — poll all sockets
        int poll_timeout_ms = (conn->rudp && conn->rudp_enabled) ? 100 : 50;
        int poll_ret = poll(fds, nfds, poll_timeout_ms);

        if (poll_ret == 0) {
            return 0;  // No data available
        }
        if (poll_ret < 0) {
            LOGE("fill_recv_queue: poll error: %d", errno);
            return -1;
        }

        // After blocking poll, recheck state — disconnect may have freed SSL pointers
        __sync_synchronize();
        if (conn->state == STATE_DISCONNECTING) return -1;

        // Check for UDP data first
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].revents & POLLNVAL) {
                LOGE("fill_recv_queue: socket fd=%d invalid", fds[i].fd);
                return -1;
            }
            if ((fds[i].revents & (POLLERR | POLLHUP)) && !(fds[i].revents & POLLIN)) {
                LOGE("fill_recv_queue: socket fd=%d error (revents=0x%x)", fds[i].fd, fds[i].revents);
                // If this is an additional socket, mark it as failed but don't kill the connection
                int is_additional = 0;
                for (int t = 0; t < tcp_count; t++) {
                    if (tcp_info[t].fd == fds[i].fd && tcp_info[t].is_additional) {
                        is_additional = 1;
                        break;
                    }
                }
                if (is_additional) {
                    LOGW("Additional socket fd=%d failed, will be cleaned up", fds[i].fd);
                    continue;  // Don't return error for additional socket failures
                }
                return -1;
            }
        }

        // Process UDP data if available
        if (conn->rudp && conn->rudp_enabled && udp_fd >= 0) {
            for (nfds_t i = 0; i < nfds; i++) {
                if (fds[i].fd == udp_fd && (fds[i].revents & POLLIN)) {
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
                }
            }
        }

        // Find which TCP socket has data
        ssl_pending_idx = -1;
        for (int t = 0; t < tcp_count; t++) {
            // Map tcp_info[t] back to the pollfd index
            int pfd_idx = -1;
            for (nfds_t i = 0; i < nfds; i++) {
                if (fds[i].fd == tcp_info[t].fd) {
                    pfd_idx = (int)i;
                    break;
                }
            }
            if (pfd_idx >= 0 && (fds[pfd_idx].revents & POLLIN)) {
                ssl_pending_idx = t;
                break;
            }
        }

        if (ssl_pending_idx < 0) {
            return 0;  // No TCP data
        }
    }

    // Read from the selected TCP socket
    {
        void* sel_ssl = tcp_info[ssl_pending_idx].ssl;
        int sel_fd = tcp_info[ssl_pending_idx].fd;
        int sel_is_additional = tcp_info[ssl_pending_idx].is_additional;
        int sel_add_idx = tcp_info[ssl_pending_idx].additional_idx;

        // Revalidate: check that the SSL pointer is still valid (not freed by disconnect)
        if (sel_ssl == NULL) {
            LOGW("fill_recv_queue: SSL became NULL for fd=%d, skipping", sel_fd);
            return 0;
        }
        if (sel_is_additional && sel_add_idx >= 0) {
            softether_tcp_sock_t* check_ts = &conn->additional[sel_add_idx];
            if (!check_ts->active || check_ts->ssl != sel_ssl) {
                LOGW("fill_recv_queue: additional socket [%d] ssl mismatch, skipping", sel_add_idx);
                return 0;
            }
        }
        __sync_synchronize();  // load-acquire before using sel_ssl

        // Helper macro to close and deactivate a failed additional socket.
        // Mark inactive BEFORE destroying to prevent use-after-free by other threads.
        // Returns 0 to keep connection alive, or propagates -1 for primary socket failures
        #define CLOSE_FAILED_ADDITIONAL_SOCKET() do { \
            if (sel_is_additional && sel_add_idx >= 0) { \
                LOGW("Additional socket fd=%d read failure, marking inactive", sel_fd); \
                softether_tcp_sock_t* _ts = &conn->additional[sel_add_idx]; \
                _ts->active = 0; \
                _ts->ssl = NULL; \
                _ts->socket_fd = -1; \
                __sync_synchronize(); \
                if (_ts->ssl_ctx != NULL) { \
                    ssl_shutdown((ssl_context_t*)_ts->ssl_ctx); \
                    ssl_destroy((ssl_context_t*)_ts->ssl_ctx); \
                    _ts->ssl_ctx = NULL; \
                } \
                conn->num_additional--; \
                return 0; \
            } \
            return -1; \
        } while(0)

        // Update last_recv timestamp for additional sockets
        if (sel_is_additional && sel_add_idx >= 0) {
            conn->additional[sel_add_idx].last_recv = softether_tick_ms();
        }

        LOGD("fill_recv_queue: reading from %s socket fd=%d",
             sel_is_additional ? "additional" : "primary", sel_fd);

        // Read block count (or keepalive magic)
        uint32_t block_count = 0;
        if (read_uint32_sock(conn, sel_ssl, sel_fd, &block_count) != 0) {
            LOGE("fill_recv_queue: failed to read block count from fd=%d", sel_fd);
            CLOSE_FAILED_ADDITIONAL_SOCKET();
        }

        if (block_count == KEEP_ALIVE_MAGIC) {
            // Keepalive: read size + data, respond
            uint32_t ka_size = 0;
            if (read_uint32_sock(conn, sel_ssl, sel_fd, &ka_size) != 0) {
                CLOSE_FAILED_ADDITIONAL_SOCKET();
            }
            if (ka_size > 512) ka_size = 512;
            if (ka_size > 0) {
                uint8_t ka_buf[512];
                if (data_read_all_sock(conn, sel_ssl, sel_fd, ka_buf, (int)ka_size) != 0) {
                    CLOSE_FAILED_ADDITIONAL_SOCKET();
                }
            }
            LOGD("fill_recv_queue: keepalive (%u bytes) from fd=%d", ka_size, sel_fd);
            softether_send_keepalive(conn);
            return 0;
        }

        if (block_count == 0) {
            return 0; // Empty message
        }

        LOGD("fill_recv_queue: reading %u block(s) from fd=%d", block_count, sel_fd);

        for (uint32_t i = 0; i < block_count; i++) {
            uint32_t block_size = 0;
            if (read_uint32_sock(conn, sel_ssl, sel_fd, &block_size) != 0) {
                LOGE("fill_recv_queue: failed to read block %u size from fd=%d", i, sel_fd);
                CLOSE_FAILED_ADDITIONAL_SOCKET();
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
                if (data_read_all_sock(conn, sel_ssl, sel_fd, tmp_block, (int)block_size) != 0) {
                    LOGE("fill_recv_queue: failed to read block %u from fd=%d", i, sel_fd);
                    free(tmp_block);
                    CLOSE_FAILED_ADDITIONAL_SOCKET();
                }

                queued_frame_t* entry = &conn->recv_queue[conn->recv_queue_tail];

                int compressed_ok = 0;
                if (conn->server_use_compress) {
                    // Session-level compression: VPN Gate server sends raw zlib
                    uint32_t raw_len = MAX_QUEUED_FRAME;
                    if (uncompress_data(tmp_block, block_size,
                                        entry->data, &raw_len) == 0) {
                        entry->len = raw_len;
                        LOGD("fill_recv_queue: session-decompressed block %u: %u -> %u bytes", i, block_size, raw_len);
                        free(tmp_block);
                        conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
                        conn->recv_queue_count++;
                        compressed_ok = 1;
                        continue;
                    }
                    // Fallback: check for CONNECTION_BULK_COMPRESS_SIGNATURE
                    if (block_size > 8) {
                        uint64_t sig = 0;
                        for (int b = 0; b < 8; b++) {
                            sig = (sig << 8) | tmp_block[b];
                        }
                        if (sig == COMPRESS_MAGIC) {
                            raw_len = MAX_QUEUED_FRAME;
                            if (uncompress_data(tmp_block + 8, block_size - 8,
                                                entry->data, &raw_len) == 0) {
                                entry->len = raw_len;
                                LOGD("fill_recv_queue: magic-decompressed block %u: %u -> %u bytes",
                                     i, block_size - 8, raw_len);
                                free(tmp_block);
                                conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
                                conn->recv_queue_count++;
                                compressed_ok = 1;
                                continue;
                            }
                        }
                    }
                }

                if (!compressed_ok) {
                    // Uncompressed — copy as-is
                    memcpy(entry->data, tmp_block, block_size);
                    free(tmp_block);
                    entry->len = block_size;
                    conn->recv_queue_tail = (conn->recv_queue_tail + 1) % RECV_QUEUE_SIZE;
                    conn->recv_queue_count++;
                }
            } else {
                // Queue full or frame too large — skip this block
                uint8_t skip_buf[2048];
                uint32_t remaining = block_size;
                while (remaining > 0) {
                    uint32_t chunk = remaining > sizeof(skip_buf) ? sizeof(skip_buf) : remaining;
                    if (data_read_all_sock(conn, sel_ssl, sel_fd, skip_buf, (int)chunk) != 0) {
                        CLOSE_FAILED_ADDITIONAL_SOCKET();
                    }
                    remaining -= chunk;
                }
                LOGD("fill_recv_queue: skipped block %u (%u bytes)", i, block_size);
            }
        }
    }

    #undef CLOSE_FAILED_ADDITIONAL_SOCKET

    LOGD("fill_recv_queue: queued %d frames total", conn->recv_queue_count);
    return (conn->recv_queue_count > 0) ? 1 : 0;
}
