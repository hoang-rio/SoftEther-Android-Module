#include "softether_rudp.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <endian.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/rc4.h>
#include <openssl/sha.h>

#define TAG "SoftEtherRUDP"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Get current timestamp in milliseconds
static uint64_t tick64(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

// Calculate RUDP key: SHA1(common_key || IV)
static void calc_key(uint8_t* key, const uint8_t* common_key, const uint8_t* iv) {
    uint8_t tmp[RUDP_COMMON_KEY_SIZE_V1 + RUDP_PACKET_IV_SIZE_V1];
    memcpy(tmp, common_key, RUDP_COMMON_KEY_SIZE_V1);
    memcpy(tmp + RUDP_COMMON_KEY_SIZE_V1, iv, RUDP_PACKET_IV_SIZE_V1);
    SHA1(tmp, sizeof(tmp), key);
}

rudp_context_t* rudp_create(int is_client) {
    rudp_context_t* ctx = (rudp_context_t*)calloc(1, sizeof(rudp_context_t));
    if (ctx == NULL) return NULL;

    ctx->is_client_mode = is_client;
    ctx->version = 1;
    ctx->mss = RUDP_DEFAULT_MSS;
    ctx->max_udp_packet_size = 1500 - 20 - 8;  // MTU - IPv4 - UDP

    // Create UDP socket
    ctx->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->udp_fd < 0) {
        LOGE("rudp_create: failed to create UDP socket");
        free(ctx);
        return NULL;
    }

    // Bind to any available port
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    if (bind(ctx->udp_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        LOGE("rudp_create: bind failed");
        close(ctx->udp_fd);
        free(ctx);
        return NULL;
    }

    // Get the bound port
    {
        struct sockaddr_in sa;
        socklen_t sa_len = sizeof(sa);
        if (getsockname(ctx->udp_fd, (struct sockaddr*)&sa, &sa_len) == 0) {
            ctx->my_port = ntohs(sa.sin_port);
        }
    }

    // Non-blocking
    int flags = fcntl(ctx->udp_fd, F_GETFL, 0);
    fcntl(ctx->udp_fd, F_SETFL, flags | O_NONBLOCK);

    // Generate random keys and IVs
    for (int i = 0; i < (int)sizeof(ctx->my_key); i++)
        ctx->my_key[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < (int)sizeof(ctx->your_key); i++)
        ctx->your_key[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < (int)sizeof(ctx->my_key_v2); i++)
        ctx->my_key_v2[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < (int)sizeof(ctx->your_key_v2); i++)
        ctx->your_key_v2[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < (int)sizeof(ctx->next_iv); i++)
        ctx->next_iv[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < (int)sizeof(ctx->next_iv_v2); i++)
        ctx->next_iv_v2[i] = (uint8_t)(rand() & 0xFF);

    do {
        ctx->my_cookie = (uint32_t)(rand() & 0xFFFFFFFF);
    } while (ctx->my_cookie == 0);

    do {
        ctx->your_cookie = (uint32_t)(rand() & 0xFFFFFFFF);
    } while (ctx->your_cookie == 0 || ctx->your_cookie == ctx->my_cookie);

    ctx->now = tick64();

    LOGD("rudp_create: fd=%d, my_cookie=0x%08X", ctx->udp_fd, ctx->my_cookie);
    return ctx;
}

void rudp_destroy(rudp_context_t* ctx) {
    if (ctx == NULL) return;
    if (ctx->udp_fd >= 0) {
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
    }
    free(ctx);
}

int rudp_init_client(rudp_context_t* ctx,
                     const uint8_t* server_key, int server_key_size,
                     const char* server_ip, uint16_t server_port,
                     uint32_t server_cookie,
                     uint32_t client_cookie) {
    if (ctx == NULL || server_ip == NULL) return -1;

    // Setup peer address
    memset(&ctx->peer_addr, 0, sizeof(ctx->peer_addr));
    ctx->peer_addr.sin_family = AF_INET;
    ctx->peer_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &ctx->peer_addr.sin_addr) <= 0) {
        LOGE("rudp_init_client: invalid server IP: %s", server_ip);
        return -1;
    }
    ctx->peer_addr_set = 1;

    // Copy server's key as our encryption key (sending direction)
    // Server's "MyKey" = our "YourKey" (receiving direction)
    // Server's "YourKey" = our "MyKey" (sending direction)
    // The server sends us its MyKey as server_key, and receives using YourKey
    if (server_key_size >= RUDP_COMMON_KEY_SIZE_V1) {
        // Our send key = server's YourKey (we send encrypted with what the server can decrypt)
        // Our recv key = server's MyKey (we decrypt what the server sent with its MyKey)
        // In the client-side init, the server sends its MyKey
        memcpy(ctx->your_key, server_key, RUDP_COMMON_KEY_SIZE_V1);
        // MyKey stays as the randomly generated one - the server will receive it 
        // during the handshake and use it as its YourKey
        if (server_key_size >= RUDP_COMMON_KEY_SIZE_V2) {
            memcpy(ctx->your_key_v2, server_key, RUDP_COMMON_KEY_SIZE_V2);
        }
    }

    ctx->your_cookie = server_cookie;
    ctx->my_cookie = client_cookie;
    ctx->inited = 1;
    ctx->now = tick64();

    LOGD("rudp_init_client: server=%s:%u, cookie=0x%08X/0x%08X",
         server_ip, server_port, ctx->my_cookie, ctx->your_cookie);
    return 0;
}

int rudp_init_server(rudp_context_t* ctx,
                     const uint8_t* client_key, int client_key_size,
                     const char* client_ip, uint16_t client_port) {
    if (ctx == NULL || client_ip == NULL) return -1;

    memset(&ctx->peer_addr, 0, sizeof(ctx->peer_addr));
    ctx->peer_addr.sin_family = AF_INET;
    ctx->peer_addr.sin_port = htons(client_port);
    if (inet_pton(AF_INET, client_ip, &ctx->peer_addr.sin_addr) <= 0) {
        LOGE("rudp_init_server: invalid client IP: %s", client_ip);
        return -1;
    }
    ctx->peer_addr_set = 1;

    if (client_key_size >= RUDP_COMMON_KEY_SIZE_V1) {
        memcpy(ctx->your_key, client_key, RUDP_COMMON_KEY_SIZE_V1);
        if (client_key_size >= RUDP_COMMON_KEY_SIZE_V2) {
            memcpy(ctx->your_key_v2, client_key, RUDP_COMMON_KEY_SIZE_V2);
        }
    }

    ctx->inited = 1;
    ctx->now = tick64();

    LOGD("rudp_init_server: client=%s:%u", client_ip, client_port);
    return 0;
}

void rudp_set_tick(rudp_context_t* ctx, uint64_t tick) {
    if (ctx == NULL) return;
    ctx->now = tick;
}

void rudp_set_version(rudp_context_t* ctx, int version) {
    if (ctx == NULL) return;
    ctx->version = 1; // only V1 implemented
}

void rudp_set_fast_detect(rudp_context_t* ctx, int fast) {
    if (ctx == NULL) return;
    // Store in mss field (reusing as flags) — actual fast detect is handled by
    // the caller adjusting keepalive interval
    if (fast) {
        ctx->mss |= 0x80000000;
    } else {
        ctx->mss &= ~0x80000000;
    }
}

int rudp_get_udp_fd(rudp_context_t* ctx) {
    if (ctx == NULL) return -1;
    return ctx->udp_fd;
}

int rudp_is_active(rudp_context_t* ctx) {
    if (ctx == NULL) return 0;
    if (!ctx->inited) return 0;
    if (!ctx->peer_addr_set) return 0;
    if (ctx->fatal_error) return 0;
    // Must have received at least one valid packet
    if (ctx->first_stable_receive_tick == 0) return 0;
    return 1;
}

uint32_t rudp_calc_mss(rudp_context_t* ctx) {
    return RUDP_DEFAULT_MSS;
}

int rudp_is_send_ready(rudp_context_t* ctx, int check_keepalive) {
    if (ctx == NULL) return 0;
    if (!ctx->inited) return 0;
    if (!ctx->peer_addr_set) return 0;

    uint64_t timeout_value = (ctx->mss & 0x80000000) ? RUDP_KA_TIMEOUT_FAST : RUDP_KA_TIMEOUT;

    if (check_keepalive) {
        if (ctx->last_recv_tick == 0 ||
            (ctx->last_recv_tick + timeout_value) < ctx->now) {
            ctx->first_stable_receive_tick = 0;
            return 0;
        } else {
            if ((ctx->first_stable_receive_tick + RUDP_REQUIRE_CONTINUOUS) <= ctx->now) {
                return 1;
            }
            return 0;
        }
    }

    return 1;
}

void rudp_poll(rudp_context_t* ctx) {
    if (ctx == NULL || !ctx->inited) return;

    ctx->now = tick64();

    uint64_t timeout_value = (ctx->mss & 0x80000000) ? RUDP_KA_TIMEOUT_FAST : RUDP_KA_TIMEOUT;

    if (ctx->last_recv_tick != 0 &&
        (ctx->last_recv_tick + timeout_value) < ctx->now) {
        // Timeout - reset state
        ctx->first_stable_receive_tick = 0;
    }

    // Send keepalive if needed
    if (ctx->next_send_keepalive == 0 ||
        ctx->next_send_keepalive <= ctx->now) {
        if (ctx->peer_addr_set) {
            rudp_send_keepalive(ctx);
        }
        uint64_t ka_min, ka_max;
        if (ctx->mss & 0x80000000) {
            ka_min = RUDP_KA_INTERVAL_MIN_FAST;
            ka_max = RUDP_KA_INTERVAL_MAX_FAST;
        } else {
            ka_min = RUDP_KA_INTERVAL_MIN;
            ka_max = RUDP_KA_INTERVAL_MAX;
        }
        ctx->next_send_keepalive = ctx->now +
            (uint64_t)(ka_min + (rand() % (uint32_t)(ka_max - ka_min)));
    }

    // Read all available UDP packets
    uint8_t tmp[RUDP_TMP_BUF_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    while (1) {
        int ret = (int)recvfrom(ctx->udp_fd, tmp, sizeof(tmp), 0,
                                (struct sockaddr*)&from_addr, &from_len);
        if (ret <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // No more data
            }
            break;
        }

        if ((uint32_t)ret < RUDP_PACKET_IV_SIZE_V1 + sizeof(uint32_t) + 1) {
            continue;  // Too small
        }

        ctx->now = tick64();

        // Process V1 packet (V2 support can be added later)
        if (ctx->version == 1) {
            uint8_t* buf = tmp;
            uint32_t size = (uint32_t)ret;

            // Extract IV
            uint8_t* iv = buf;
            buf += RUDP_PACKET_IV_SIZE_V1;
            size -= RUDP_PACKET_IV_SIZE_V1;

            // Derive decryption key
            uint8_t key[RUDP_PACKET_KEY_SIZE_V1];
            calc_key(key, ctx->your_key, iv);

            // Decrypt (everything after IV)
            RC4_KEY rc4_key;
            RC4_set_key(&rc4_key, RUDP_PACKET_KEY_SIZE_V1, key);
            RC4(&rc4_key, size, buf, buf);

            // Parse fields
            if (size < sizeof(uint32_t)) continue;
            uint32_t cookie;
            memcpy(&cookie, buf, sizeof(uint32_t));
            cookie = ntohl(cookie);
            buf += sizeof(uint32_t);
            size -= sizeof(uint32_t);

            if (cookie != ctx->my_cookie) continue;

            if (size < sizeof(uint64_t)) continue;
            uint64_t my_tick;
            memcpy(&my_tick, buf, sizeof(uint64_t));
            my_tick = be64toh(my_tick);
            buf += sizeof(uint64_t);
            size -= sizeof(uint64_t);

            if (size < sizeof(uint64_t)) continue;
            uint64_t your_tick;
            memcpy(&your_tick, buf, sizeof(uint64_t));
            your_tick = be64toh(your_tick);
            buf += sizeof(uint64_t);
            size -= sizeof(uint64_t);

            if (size < sizeof(uint16_t)) continue;
            uint16_t inner_size;
            memcpy(&inner_size, buf, sizeof(uint16_t));
            inner_size = ntohs(inner_size);
            buf += sizeof(uint16_t);
            size -= sizeof(uint16_t);

            if (size < sizeof(uint8_t)) continue;
            uint8_t flag = buf[0];
            buf += sizeof(uint8_t);
            size -= sizeof(uint8_t);

            if (size < inner_size) continue;
            uint8_t* inner_data = NULL;
            if (inner_size > 0) {
                inner_data = buf;
                buf += inner_size;
                size -= inner_size;
            }

            // Skip padding
            if (size >= RUDP_PACKET_IV_SIZE_V1) {
                // Verify the 20-byte zero verify field
                uint32_t pad_size = size - RUDP_PACKET_IV_SIZE_V1;
                uint8_t* verify = buf + pad_size;
                int verify_ok = 1;
                for (uint32_t z = 0; z < RUDP_PACKET_IV_SIZE_V1; z++) {
                    if (verify[z] != 0) { verify_ok = 0; break; }
                }
                if (!verify_ok) continue;
            } else {
                continue;
            }

            // Window check
            if (my_tick < ctx->last_recv_your_tick &&
                (ctx->last_recv_your_tick - my_tick) >= RUDP_WINDOW_SIZE_MSEC) {
                // LOGD("rudp_poll: packet outside window, dropping");
                continue;
            }

            ctx->last_recv_my_tick = (your_tick > ctx->last_recv_my_tick) ? your_tick : ctx->last_recv_my_tick;
            ctx->last_recv_your_tick = (my_tick > ctx->last_recv_your_tick) ? my_tick : ctx->last_recv_your_tick;

            // Update peer address from received packet
            ctx->peer_addr = from_addr;
            ctx->peer_addr_set = 1;

            // Update receive timing
            if (ctx->last_recv_my_tick != 0 &&
                (ctx->last_recv_my_tick + RUDP_WINDOW_SIZE_MSEC) >= ctx->now) {
                ctx->last_recv_tick = ctx->now;
                if (ctx->first_stable_receive_tick == 0) {
                    ctx->first_stable_receive_tick = ctx->now;
                }
            }

            // Queue the data if present
            if (inner_size > 0 && inner_data != NULL) {
                if (inner_size <= RUDP_MAX_PAYLOAD_SIZE &&
                    ctx->recv_queue_count < RUDP_RECV_QUEUE_SIZE) {
                    rudp_queued_block_t* entry = &ctx->recv_queue[ctx->recv_queue_tail];
                    memcpy(entry->data, inner_data, inner_size);
                    entry->len = inner_size;
                    ctx->recv_queue_tail = (ctx->recv_queue_tail + 1) % RUDP_RECV_QUEUE_SIZE;
                    ctx->recv_queue_count++;
                    LOGD("rudp_poll: queued %u bytes", inner_size);
                }
            }
        }
    }
}

int rudp_send(rudp_context_t* ctx, const uint8_t* data, uint32_t data_size, uint8_t flag) {
    if (ctx == NULL || !ctx->inited || !ctx->peer_addr_set) return -1;
    if (data_size > 0 && data == NULL) return -1;

    ctx->now = tick64();

    uint8_t tmp[RUDP_TMP_BUF_SIZE];
    uint8_t* buf = tmp;
    uint32_t size = 0;

    // IV (plaintext)
    if (ctx->version == 1) {
        memcpy(buf, ctx->next_iv, RUDP_PACKET_IV_SIZE_V1);
        buf += RUDP_PACKET_IV_SIZE_V1;
        size += RUDP_PACKET_IV_SIZE_V1;
    } else {
        // V2
        memcpy(buf, ctx->next_iv_v2, RUDP_PACKET_IV_SIZE_V2);
        buf += RUDP_PACKET_IV_SIZE_V2;
        size += RUDP_PACKET_IV_SIZE_V2;
    }

    // Cookie (encrypted)
    uint32_t cookie_be = htonl(ctx->your_cookie);
    memcpy(buf, &cookie_be, sizeof(uint32_t));
    buf += sizeof(uint32_t);
    size += sizeof(uint32_t);

    // My Tick
    uint64_t my_tick_be = htobe64(ctx->now == 0 ? 1ULL : ctx->now);
    memcpy(buf, &my_tick_be, sizeof(uint64_t));
    buf += sizeof(uint64_t);
    size += sizeof(uint64_t);

    // Your Tick
    uint64_t your_tick_be = htobe64(ctx->last_recv_your_tick);
    memcpy(buf, &your_tick_be, sizeof(uint64_t));
    buf += sizeof(uint64_t);
    size += sizeof(uint64_t);

    // Size
    uint16_t inner_size_be = htons((uint16_t)data_size);
    memcpy(buf, &inner_size_be, sizeof(uint16_t));
    buf += sizeof(uint16_t);
    size += sizeof(uint16_t);

    // Flag
    *buf = flag;
    buf += sizeof(uint8_t);
    size += sizeof(uint8_t);

    // Data
    if (data_size > 0) {
        if (size + data_size > RUDP_TMP_BUF_SIZE - RUDP_PACKET_IV_SIZE_V1 - 8) {
            LOGE("rudp_send: data too large (%u bytes)", data_size);
            return -1;
        }
        memcpy(buf, data, data_size);
        buf += data_size;
        size += data_size;
    }

    if (ctx->version == 1) {
        // Padding + Verify
        uint32_t current_size = RUDP_PACKET_IV_SIZE_V1 + sizeof(uint32_t) +
            sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint8_t) +
            data_size + RUDP_PACKET_IV_SIZE_V1;

        if (current_size < ctx->max_udp_packet_size) {
            uint32_t pad_size = ctx->max_udp_packet_size - current_size;
            if (pad_size > RUDP_MAX_PADDING_SIZE) pad_size = RUDP_MAX_PADDING_SIZE;
            pad_size = (uint32_t)(rand() % (pad_size + 1));
            memset(buf, 0, pad_size);
            buf += pad_size;
            size += pad_size;
        }

        // Verify bytes (20 zeros)
        memset(buf, 0, RUDP_PACKET_IV_SIZE_V1);
        buf += RUDP_PACKET_IV_SIZE_V1;
        size += RUDP_PACKET_IV_SIZE_V1;

        // Derive key and encrypt (everything after IV)
        uint8_t key[RUDP_PACKET_KEY_SIZE_V1];
        calc_key(key, ctx->my_key, ctx->next_iv);

        RC4_KEY rc4_key;
        RC4_set_key(&rc4_key, RUDP_PACKET_KEY_SIZE_V1, key);
        RC4(&rc4_key, size - RUDP_PACKET_IV_SIZE_V1,
            tmp + RUDP_PACKET_IV_SIZE_V1, tmp + RUDP_PACKET_IV_SIZE_V1);

        // Update IV for next packet
        memcpy(ctx->next_iv, buf - RUDP_PACKET_IV_SIZE_V1, RUDP_PACKET_IV_SIZE_V1);
    } else {
        // V2 not implemented yet
        LOGE("rudp_send: V2 not implemented");
        return -1;
    }

    // Send
    int ret = (int)sendto(ctx->udp_fd, tmp, size, 0,
                          (struct sockaddr*)&ctx->peer_addr, sizeof(ctx->peer_addr));
    if (ret < 0) {
        LOGE("rudp_send: sendto failed (errno=%d)", errno);
        return -1;
    }

    LOGD("rudp_send: %u bytes -> %u bytes (flag=0x%02X)", data_size, size, flag);
    return (int)size;
}

int rudp_send_keepalive(rudp_context_t* ctx) {
    if (ctx == NULL) return -1;
    return rudp_send(ctx, NULL, 0, 0);
}

int rudp_recv(rudp_context_t* ctx, uint8_t* buffer, uint32_t* len, uint32_t max_len) {
    if (ctx == NULL || buffer == NULL || len == NULL) return -1;

    if (ctx->recv_queue_count <= 0) return 0;

    rudp_queued_block_t* entry = &ctx->recv_queue[ctx->recv_queue_head];
    if (entry->len > max_len) {
        *len = 0;
        return -1;
    }

    memcpy(buffer, entry->data, entry->len);
    *len = entry->len;

    ctx->recv_queue_head = (ctx->recv_queue_head + 1) % RUDP_RECV_QUEUE_SIZE;
    ctx->recv_queue_count--;

    return (int)entry->len;
}
