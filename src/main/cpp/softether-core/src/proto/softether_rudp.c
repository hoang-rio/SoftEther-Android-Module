#include "softether_rudp.h"
#include "softether_compress.h"
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

// Create (or re-create) the UDP socket for the given address family, bind it
// to an ephemeral port, and refresh ctx->my_port. Used by rudp_create (AF_INET)
// and by rudp_init_* / rudp_set_udp_family when the peer is IPv6.
static int rudp_create_udp_socket(rudp_context_t* ctx, int family) {
    if (ctx == NULL || (family != AF_INET && family != AF_INET6)) {
        return -1;
    }

    if (ctx->udp_fd >= 0) {
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
    }

    ctx->udp_fd = socket(family, SOCK_DGRAM, 0);
    if (ctx->udp_fd < 0) {
        LOGE("rudp_create_udp_socket: failed to create UDP socket family=%d (errno=%d)",
             family, errno);
        return -1;
    }

    // Bind to any available port
    struct sockaddr_storage bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    if (family == AF_INET6) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&bind_addr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_addr = in6addr_any;
        sa6->sin6_port = 0;
    } else {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&bind_addr;
        sa4->sin_family = AF_INET;
        sa4->sin_addr.s_addr = INADDR_ANY;
        sa4->sin_port = 0;
    }
    if (bind(ctx->udp_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        LOGE("rudp_create_udp_socket: bind failed family=%d (errno=%d)", family, errno);
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
        return -1;
    }

    // Get the bound port
    {
        struct sockaddr_storage sa;
        socklen_t sa_len = sizeof(sa);
        if (getsockname(ctx->udp_fd, (struct sockaddr*)&sa, &sa_len) == 0) {
            if (sa.ss_family == AF_INET6) {
                ctx->my_port = ntohs(((struct sockaddr_in6*)&sa)->sin6_port);
            } else {
                ctx->my_port = ntohs(((struct sockaddr_in*)&sa)->sin_port);
            }
        }
    }

    // Non-blocking
    int flags = fcntl(ctx->udp_fd, F_GETFL, 0);
    fcntl(ctx->udp_fd, F_SETFL, flags | O_NONBLOCK);

    ctx->is_ipv6 = (family == AF_INET6);
    LOGD("rudp_create_udp_socket: fd=%d family=%d my_port=%u", ctx->udp_fd, family, ctx->my_port);
    return 0;
}

rudp_context_t* rudp_create(int is_client) {
    rudp_context_t* ctx = (rudp_context_t*)calloc(1, sizeof(rudp_context_t));
    if (ctx == NULL) return NULL;

    ctx->is_client_mode = is_client;
    ctx->version = 1;
    ctx->mss = RUDP_DEFAULT_MSS;
    ctx->max_udp_packet_size = RUDP_MAX_UDP_PACKET_IPV4;  // MTU - IPv4 - UDP

    // udp_fd must start at -1: calloc zero-initializes it to 0, and
    // rudp_create_udp_socket() closes it when >= 0 — closing fd 0 would
    // trigger an fdsan abort (fd 0 is owned by the JVM's SocketImpl).
    ctx->udp_fd = -1;

    // Create UDP socket (AF_INET by default; recreated as AF_INET6 for IPv6 peers)
    if (rudp_create_udp_socket(ctx, AF_INET) != 0) {
        free(ctx);
        return NULL;
    }

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
    if (ctx->evp_encrypt_ctx) EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx->evp_encrypt_ctx);
    if (ctx->evp_decrypt_ctx) EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx->evp_decrypt_ctx);
    if (ctx->udp_fd >= 0) {
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
    }
    free(ctx);
}

// Initialize the V2 ChaCha20-Poly1305 cipher contexts from the established keys.
// Send uses my_key_v2, recv uses your_key_v2. Falls back to v2_cipher_inited=0
// if OpenSSL context allocation fails.
static void rudp_init_v2_cipher(rudp_context_t* ctx) {
    EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* dec = EVP_CIPHER_CTX_new();
    if (enc == NULL || dec == NULL) {
        if (enc) EVP_CIPHER_CTX_free(enc);
        if (dec) EVP_CIPHER_CTX_free(dec);
        ctx->evp_encrypt_ctx = NULL;
        ctx->evp_decrypt_ctx = NULL;
        ctx->v2_cipher_inited = 0;
        return;
    }
    EVP_EncryptInit_ex(enc, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IVLEN, RUDP_PACKET_IV_SIZE_V2, NULL);
    EVP_EncryptInit_ex(enc, NULL, NULL, ctx->my_key_v2, NULL);
    EVP_DecryptInit_ex(dec, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_IVLEN, RUDP_PACKET_IV_SIZE_V2, NULL);
    EVP_DecryptInit_ex(dec, NULL, NULL, ctx->your_key_v2, NULL);
    ctx->evp_encrypt_ctx = enc;
    ctx->evp_decrypt_ctx = dec;
    ctx->v2_cipher_inited = 1;
}

int rudp_init_client(rudp_context_t* ctx,
                     const uint8_t* server_key, int server_key_size,
                     const char* server_ip, uint16_t server_port,
                     uint32_t server_cookie,
                     uint32_t client_cookie) {
    if (ctx == NULL || server_ip == NULL) return -1;

    // Determine the peer's address family and (re)create the UDP socket to match
    struct in_addr in4;
    struct in6_addr in6;
    int ipv6 = (inet_pton(AF_INET6, server_ip, &in6) == 1);
    if (!ipv6 && inet_pton(AF_INET, server_ip, &in4) != 1) {
        LOGE("rudp_init_client: invalid server IP: %s", server_ip);
        return -1;
    }
    if (ipv6 != ctx->is_ipv6) {
        if (rudp_create_udp_socket(ctx, ipv6 ? AF_INET6 : AF_INET) != 0) {
            return -1;
        }
    }

    // Setup peer address
    memset(&ctx->peer_addr, 0, sizeof(ctx->peer_addr));
    if (ipv6) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&ctx->peer_addr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(server_port);
        if (inet_pton(AF_INET6, server_ip, &sa6->sin6_addr) <= 0) {
            LOGE("rudp_init_client: invalid IPv6 server IP: %s", server_ip);
            return -1;
        }
        ctx->peer_addr_len = sizeof(*sa6);
    } else {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&ctx->peer_addr;
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(server_port);
        if (inet_pton(AF_INET, server_ip, &sa4->sin_addr) <= 0) {
            LOGE("rudp_init_client: invalid IPv4 server IP: %s", server_ip);
            return -1;
        }
        ctx->peer_addr_len = sizeof(*sa4);
    }
    ctx->peer_addr_set = 1;

    // Adjust MTU/MSS for the IPv6 header (40 bytes vs 20 for IPv4)
    if (ipv6) {
        ctx->mss = RUDP_DEFAULT_MSS_IPV6;
        ctx->max_udp_packet_size = RUDP_MAX_UDP_PACKET_IPV6;
        LOGD("rudp_init_client: IPv6 peer, MSS=%u max_udp=%u", ctx->mss, ctx->max_udp_packet_size);
    } else {
        ctx->mss = RUDP_DEFAULT_MSS;
        ctx->max_udp_packet_size = RUDP_MAX_UDP_PACKET_IPV4;
    }

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

    if (server_key_size >= RUDP_COMMON_KEY_SIZE_V2) {
        rudp_init_v2_cipher(ctx);
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

    // Determine the peer's address family and (re)create the UDP socket to match
    struct in_addr in4;
    struct in6_addr in6;
    int ipv6 = (inet_pton(AF_INET6, client_ip, &in6) == 1);
    if (!ipv6 && inet_pton(AF_INET, client_ip, &in4) != 1) {
        LOGE("rudp_init_server: invalid client IP: %s", client_ip);
        return -1;
    }
    if (ipv6 != ctx->is_ipv6) {
        if (rudp_create_udp_socket(ctx, ipv6 ? AF_INET6 : AF_INET) != 0) {
            return -1;
        }
    }

    // Setup peer address
    memset(&ctx->peer_addr, 0, sizeof(ctx->peer_addr));
    if (ipv6) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&ctx->peer_addr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(client_port);
        if (inet_pton(AF_INET6, client_ip, &sa6->sin6_addr) <= 0) {
            LOGE("rudp_init_server: invalid IPv6 client IP: %s", client_ip);
            return -1;
        }
        ctx->peer_addr_len = sizeof(*sa6);
        ctx->mss = RUDP_DEFAULT_MSS_IPV6;
        ctx->max_udp_packet_size = RUDP_MAX_UDP_PACKET_IPV6;
    } else {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&ctx->peer_addr;
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(client_port);
        if (inet_pton(AF_INET, client_ip, &sa4->sin_addr) <= 0) {
            LOGE("rudp_init_server: invalid IPv4 client IP: %s", client_ip);
            return -1;
        }
        ctx->peer_addr_len = sizeof(*sa4);
        ctx->mss = RUDP_DEFAULT_MSS;
        ctx->max_udp_packet_size = RUDP_MAX_UDP_PACKET_IPV4;
    }
    ctx->peer_addr_set = 1;

    if (client_key_size >= RUDP_COMMON_KEY_SIZE_V1) {
        memcpy(ctx->your_key, client_key, RUDP_COMMON_KEY_SIZE_V1);
        if (client_key_size >= RUDP_COMMON_KEY_SIZE_V2) {
            memcpy(ctx->your_key_v2, client_key, RUDP_COMMON_KEY_SIZE_V2);
        }
    }

    if (client_key_size >= RUDP_COMMON_KEY_SIZE_V2) {
        rudp_init_v2_cipher(ctx);
    }

    ctx->inited = 1;
    ctx->now = tick64();

    LOGD("rudp_init_server: client=%s:%u", client_ip, client_port);
    return 0;
}

int rudp_set_udp_family(rudp_context_t* ctx, int family) {
    if (ctx == NULL || (family != AF_INET && family != AF_INET6)) {
        return -1;
    }
    if (ctx->is_ipv6 == (family == AF_INET6)) {
        return 0;
    }
    return rudp_create_udp_socket(ctx, family);
}

void rudp_set_tick(rudp_context_t* ctx, uint64_t tick) {
    if (ctx == NULL) return;
    ctx->now = tick;
}

void rudp_set_version(rudp_context_t* ctx, int version) {
    if (ctx == NULL) return;
    ctx->version = (version >= 2 && ctx->v2_cipher_inited) ? 2 : 1;
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
    if (ctx == NULL) return RUDP_DEFAULT_MSS;
    if (ctx->is_ipv6) {
        return (ctx->version >= 2) ? RUDP_DEFAULT_MSS_V2_IPV6 : RUDP_DEFAULT_MSS_IPV6;
    }
    return (ctx->version >= 2) ? RUDP_DEFAULT_MSS_V2 : RUDP_DEFAULT_MSS;
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

// Parse and validate the decrypted inner fields of a received RUDP packet.
// buf/size must cover everything after the IV. verify_padding is 1 for V1
// (trailing 20-byte zero-verify) and 0 for V2 (padding is ignored).
// Returns 0 if accepted, -1 if the packet must be dropped.
static int rudp_process_inner(rudp_context_t* ctx, uint8_t* buf, uint32_t size,
                              const struct sockaddr_storage* from_addr,
                              socklen_t from_len,
                              int verify_padding) {
    if (size < sizeof(uint32_t)) return -1;
    uint32_t cookie;
    memcpy(&cookie, buf, sizeof(uint32_t));
    cookie = ntohl(cookie);
    buf += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    if (cookie != ctx->my_cookie) return -1;

    if (size < sizeof(uint64_t)) return -1;
    uint64_t my_tick;
    memcpy(&my_tick, buf, sizeof(uint64_t));
    my_tick = be64toh(my_tick);
    buf += sizeof(uint64_t);
    size -= sizeof(uint64_t);

    if (size < sizeof(uint64_t)) return -1;
    uint64_t your_tick;
    memcpy(&your_tick, buf, sizeof(uint64_t));
    your_tick = be64toh(your_tick);
    buf += sizeof(uint64_t);
    size -= sizeof(uint64_t);

    if (size < sizeof(uint16_t)) return -1;
    uint16_t inner_size;
    memcpy(&inner_size, buf, sizeof(uint16_t));
    inner_size = ntohs(inner_size);
    buf += sizeof(uint16_t);
    size -= sizeof(uint16_t);

    if (size < sizeof(uint8_t)) return -1;
    uint8_t flag = buf[0];
    buf += sizeof(uint8_t);
    size -= sizeof(uint8_t);

    if (size < inner_size) return -1;
    uint8_t* inner_data = NULL;
    if (inner_size > 0) {
        inner_data = buf;
        buf += inner_size;
        size -= inner_size;
    }

    if (verify_padding) {
        // Verify the 20-byte zero verify field
        if (size >= RUDP_PACKET_IV_SIZE_V1) {
            uint32_t pad_size = size - RUDP_PACKET_IV_SIZE_V1;
            uint8_t* verify = buf + pad_size;
            int verify_ok = 1;
            for (uint32_t z = 0; z < RUDP_PACKET_IV_SIZE_V1; z++) {
                if (verify[z] != 0) { verify_ok = 0; break; }
            }
            if (!verify_ok) return -1;
        } else {
            return -1;
        }
    }

    // Window check
    if (my_tick < ctx->last_recv_your_tick &&
        (ctx->last_recv_your_tick - my_tick) >= RUDP_WINDOW_SIZE_MSEC) {
        // LOGD("rudp_poll: packet outside window, dropping");
        return -1;
    }

    ctx->last_recv_my_tick = (your_tick > ctx->last_recv_my_tick) ? your_tick : ctx->last_recv_my_tick;
    ctx->last_recv_your_tick = (my_tick > ctx->last_recv_your_tick) ? my_tick : ctx->last_recv_your_tick;

    // Update peer address from received packet
    ctx->peer_addr = *from_addr;
    ctx->peer_addr_len = from_len;
    ctx->peer_addr_set = 1;
    ctx->is_ipv6 = (from_addr->ss_family == AF_INET6);

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
        // Decompress if RUDP_FLAG_COMPRESSED is set
        const uint8_t* queue_data = inner_data;
        uint32_t queue_len = inner_size;
        uint8_t decomp_buf[RUDP_MAX_PAYLOAD_SIZE + 256];

        if (flag & RUDP_FLAG_COMPRESSED) {
            uint32_t decomp_len = sizeof(decomp_buf);
            if (uncompress_data(inner_data, inner_size,
                                decomp_buf, &decomp_len) != 0) {
                LOGE("rudp_poll: decompression failed (%u bytes)", inner_size);
                return -1;
            }
            queue_data = decomp_buf;
            queue_len = decomp_len;
        }

        if (queue_len <= RUDP_MAX_PAYLOAD_SIZE &&
            ctx->recv_queue_count < RUDP_RECV_QUEUE_SIZE) {
            rudp_queued_block_t* entry = &ctx->recv_queue[ctx->recv_queue_tail];
            memcpy(entry->data, queue_data, queue_len);
            entry->len = queue_len;
            ctx->recv_queue_tail = (ctx->recv_queue_tail + 1) % RUDP_RECV_QUEUE_SIZE;
            ctx->recv_queue_count++;
            LOGD("rudp_poll: queued %u bytes (compressed=%d)", queue_len,
                 (flag & RUDP_FLAG_COMPRESSED) ? 1 : 0);
        }
    }
    return 0;
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
    struct sockaddr_storage from_addr;
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

        // Process V1 packet
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

            // Decrypt (everything after IV) via EVP (low-level RC4() is
            // deprecated in OpenSSL 3.x)
            EVP_CIPHER_CTX* rc4_ctx = EVP_CIPHER_CTX_new();
            if (rc4_ctx == NULL) {
                continue;
            }
            EVP_DecryptInit_ex(rc4_ctx, EVP_rc4(), NULL, key, NULL);
            int rc4_outlen = 0;
            EVP_DecryptUpdate(rc4_ctx, buf, &rc4_outlen, buf, (int)size);
            EVP_CIPHER_CTX_free(rc4_ctx);

            if (rudp_process_inner(ctx, buf, size, &from_addr, from_len, 1) != 0) {
                continue;
            }
        } else if (ctx->version == 2) {
            // V2: ChaCha20-Poly1305 AEAD
            if ((uint32_t)ret < RUDP_PACKET_IV_SIZE_V2 + RUDP_PACKET_MAC_SIZE_V2 +
                               sizeof(uint32_t) + 1) {
                continue;  // Too small
            }

            uint8_t* iv = tmp;
            uint8_t* buf = tmp + RUDP_PACKET_IV_SIZE_V2;
            uint32_t size = (uint32_t)ret - RUDP_PACKET_IV_SIZE_V2;

            // AEAD decrypt (ciphertext + MAC) in place with YourKey_V2 + packet IV
            int outlen = 0;
            EVP_DecryptInit_ex((EVP_CIPHER_CTX*)ctx->evp_decrypt_ctx, NULL, NULL,
                               NULL, iv);
            EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx->evp_decrypt_ctx,
                                EVP_CTRL_AEAD_SET_TAG, RUDP_PACKET_MAC_SIZE_V2,
                                tmp + ret - RUDP_PACKET_MAC_SIZE_V2);
            EVP_DecryptUpdate((EVP_CIPHER_CTX*)ctx->evp_decrypt_ctx, buf, &outlen,
                              buf, size - RUDP_PACKET_MAC_SIZE_V2);
            if (EVP_DecryptFinal_ex((EVP_CIPHER_CTX*)ctx->evp_decrypt_ctx,
                                    buf + outlen, &outlen) != 1) {
                continue;  // MAC failure - drop
            }
            size -= RUDP_PACKET_MAC_SIZE_V2;

            if (rudp_process_inner(ctx, buf, size, &from_addr, from_len, 0) != 0) {
                continue;
            }
        }
    }
}

int rudp_send(rudp_context_t* ctx, const uint8_t* data, uint32_t data_size, uint8_t flag) {
    if (ctx == NULL || !ctx->inited || !ctx->peer_addr_set) return -1;
    if (data_size > 0 && data == NULL) return -1;

    ctx->now = tick64();

    // Attempt zlib compression on payload
    const uint8_t* send_data = data;
    uint32_t send_size = data_size;
    uint8_t compress_buf[RUDP_MAX_PAYLOAD_SIZE + 256];
    uint8_t send_flag = flag;

    if (data_size > 1) {
        uint32_t comp_len = sizeof(compress_buf);
        if (compress_data(data, data_size, compress_buf, &comp_len) == 0) {
            send_data = compress_buf;
            send_size = comp_len;
            send_flag |= RUDP_FLAG_COMPRESSED;
        }
    }

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
    uint16_t inner_size_be = htons((uint16_t)send_size);
    memcpy(buf, &inner_size_be, sizeof(uint16_t));
    buf += sizeof(uint16_t);
    size += sizeof(uint16_t);

    // Flag
    *buf = send_flag;
    buf += sizeof(uint8_t);
    size += sizeof(uint8_t);

    // Data
    if (send_size > 0) {
        if (size + send_size > RUDP_TMP_BUF_SIZE - RUDP_PACKET_IV_SIZE_V1 - 8) {
            LOGE("rudp_send: data too large (%u bytes)", send_size);
            return -1;
        }
        memcpy(buf, send_data, send_size);
        buf += send_size;
        size += send_size;
    }

    if (ctx->version == 1) {
        // Padding + Verify
        uint32_t current_size = RUDP_PACKET_IV_SIZE_V1 + sizeof(uint32_t) +
            sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint8_t) +
            send_size + RUDP_PACKET_IV_SIZE_V1;

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

        // Derive key and encrypt (everything after IV) via EVP (low-level
        // RC4() is deprecated in OpenSSL 3.x)
        uint8_t key[RUDP_PACKET_KEY_SIZE_V1];
        calc_key(key, ctx->my_key, ctx->next_iv);

        EVP_CIPHER_CTX* rc4_ctx = EVP_CIPHER_CTX_new();
        if (rc4_ctx != NULL) {
            EVP_EncryptInit_ex(rc4_ctx, EVP_rc4(), NULL, key, NULL);
            int rc4_outlen = 0;
            EVP_EncryptUpdate(rc4_ctx, tmp + RUDP_PACKET_IV_SIZE_V1, &rc4_outlen,
                              tmp + RUDP_PACKET_IV_SIZE_V1,
                              (int)(size - RUDP_PACKET_IV_SIZE_V1));
            EVP_CIPHER_CTX_free(rc4_ctx);
        }

        // Update IV for next packet
        memcpy(ctx->next_iv, buf - RUDP_PACKET_IV_SIZE_V1, RUDP_PACKET_IV_SIZE_V1);
    } else {
        // V2: ChaCha20-Poly1305 AEAD
        uint32_t current_size = RUDP_PACKET_IV_SIZE_V2 + sizeof(uint32_t) +
            sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint8_t) +
            send_size + RUDP_PACKET_MAC_SIZE_V2;

        if (current_size < ctx->max_udp_packet_size) {
            uint32_t pad_size = ctx->max_udp_packet_size - current_size;
            if (pad_size > RUDP_MAX_PADDING_SIZE) pad_size = RUDP_MAX_PADDING_SIZE;
            pad_size = (uint32_t)(rand() % (pad_size + 1));
            memset(buf, 0, pad_size);
            buf += pad_size;
            size += pad_size;
            current_size += pad_size;
        }

        // Guard: total packet (IV + inner + MAC) must fit the temp buffer
        if (current_size > RUDP_TMP_BUF_SIZE) {
            LOGE("rudp_send: V2 packet too large (%u bytes)", current_size);
            return -1;
        }

        // Encrypt inner (everything after IV) in place
        uint32_t inner_len = size - RUDP_PACKET_IV_SIZE_V2;
        int outlen = 0;
        EVP_EncryptInit_ex((EVP_CIPHER_CTX*)ctx->evp_encrypt_ctx, NULL, NULL,
                           NULL, ctx->next_iv_v2);
        EVP_EncryptUpdate((EVP_CIPHER_CTX*)ctx->evp_encrypt_ctx,
                          tmp + RUDP_PACKET_IV_SIZE_V2, &outlen,
                          tmp + RUDP_PACKET_IV_SIZE_V2, inner_len);
        EVP_EncryptFinal_ex((EVP_CIPHER_CTX*)ctx->evp_encrypt_ctx,
                            tmp + RUDP_PACKET_IV_SIZE_V2 + inner_len, &outlen);
        EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx->evp_encrypt_ctx,
                            EVP_CTRL_AEAD_GET_TAG, RUDP_PACKET_MAC_SIZE_V2,
                            tmp + size);
        size += RUDP_PACKET_MAC_SIZE_V2;

        // Update IV for next packet (first 12 bytes of the ciphertext)
        memcpy(ctx->next_iv_v2, tmp + RUDP_PACKET_IV_SIZE_V2,
               RUDP_PACKET_IV_SIZE_V2);
    }

    // Send
    int ret = (int)sendto(ctx->udp_fd, tmp, size, 0,
                          (struct sockaddr*)&ctx->peer_addr,
                          ctx->peer_addr_len > 0 ? ctx->peer_addr_len : sizeof(ctx->peer_addr));
    if (ret < 0) {
        LOGE("rudp_send: sendto failed (errno=%d)", errno);
        return -1;
    }

    LOGD("rudp_send: %u bytes -> %u bytes (flag=0x%02X)", data_size, size, send_flag);
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
