#ifndef SOFTETHER_RUDP_H
#define SOFTETHER_RUDP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// RUDP V1 constants (matching SoftEther UdpAccel.h)
#define RUDP_COMMON_KEY_SIZE_V1     20
#define RUDP_PACKET_KEY_SIZE_V1     20
#define RUDP_PACKET_IV_SIZE_V1      20

// RUDP V2 constants
#define RUDP_COMMON_KEY_SIZE_V2     128
#define RUDP_PACKET_IV_SIZE_V2      12
#define RUDP_PACKET_MAC_SIZE_V2     16

#define RUDP_TMP_BUF_SIZE           2048
#define RUDP_WINDOW_SIZE_MSEC       (30 * 1000)
#define RUDP_MAX_PAYLOAD_SIZE       1600
#define RUDP_MAX_PADDING_SIZE       32
#define RUDP_REQUIRE_CONTINUOUS     (10 * 1000)

// Keep-alive timing (normal)
#define RUDP_KA_INTERVAL_MIN        1000
#define RUDP_KA_INTERVAL_MAX        3000
#define RUDP_KA_TIMEOUT             9000

// Keep-alive timing (fast - Build 8535+)
#define RUDP_KA_INTERVAL_MIN_FAST   500
#define RUDP_KA_INTERVAL_MAX_FAST   1000
#define RUDP_KA_TIMEOUT_FAST        2100

#define RUDP_MSS_OVERHEAD_V1        145  // IV(20)+Cookie(4)+MyTick(8)+YourTick(8)+Size(2)+Flag(1)+Verify(20)+Eth(14)+IP(20)+TCP(20)+UDP(8)
#define RUDP_DEFAULT_MSS            1355 // 1500 - 145
#define RUDP_MSS_OVERHEAD_V2        137  // IV(12)+Cookie(4)+MyTick(8)+YourTick(8)+Size(2)+Flag(1)+MAC(16)+Eth(14)+IP(20)+TCP(20)+UDP(8)
#define RUDP_DEFAULT_MSS_V2         1363 // 1500 - 137

// IPv6 variants (IPv6 header is 40 bytes vs 20 for IPv4)
#define RUDP_MSS_OVERHEAD_V1_IPV6   165  // RUDP_MSS_OVERHEAD_V1 + 20
#define RUDP_DEFAULT_MSS_IPV6       1335 // 1500 - 165
#define RUDP_MSS_OVERHEAD_V2_IPV6   157  // RUDP_MSS_OVERHEAD_V2 + 20
#define RUDP_DEFAULT_MSS_V2_IPV6    1343 // 1500 - 157

// Max UDP payload (MTU - IP header - UDP header)
#define RUDP_MAX_UDP_PACKET_IPV4    1472 // 1500 - 20 - 8
#define RUDP_MAX_UDP_PACKET_IPV6    1452 // 1500 - 40 - 8

// RUDP flags
#define RUDP_FLAG_COMPRESSED        0x01

// Receive queue
#define RUDP_RECV_QUEUE_SIZE        64

typedef struct {
    uint8_t data[RUDP_MAX_PAYLOAD_SIZE];
    uint32_t len;
} rudp_queued_block_t;

// RUDP context (simplified version of SoftEther's UDP_ACCEL)
typedef struct {
    int udp_fd;
    int is_client_mode;
    int inited;
    int version;

    // Keys
    uint8_t my_key[RUDP_COMMON_KEY_SIZE_V1];
    uint8_t your_key[RUDP_COMMON_KEY_SIZE_V1];
    uint8_t my_key_v2[RUDP_COMMON_KEY_SIZE_V2];
    uint8_t your_key_v2[RUDP_COMMON_KEY_SIZE_V2];

    // IVs
    uint8_t next_iv[RUDP_PACKET_IV_SIZE_V1];
    uint8_t next_iv_v2[RUDP_PACKET_IV_SIZE_V2];

    // V2 cipher contexts (EVP_CIPHER_CTX* for ChaCha20-Poly1305)
    void* evp_encrypt_ctx;
    void* evp_decrypt_ctx;
    int v2_cipher_inited;

    // Cookies
    uint32_t my_cookie;
    uint32_t your_cookie;

    // My bound port
    uint16_t my_port;

    // Peer address
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    int peer_addr_set;
    int is_ipv6;             // 1 if the UDP socket / peer is IPv6

    // Timing
    uint64_t now;
    uint64_t last_recv_tick;
    uint64_t last_recv_your_tick;
    uint64_t last_recv_my_tick;
    uint64_t next_send_keepalive;
    uint64_t first_stable_receive_tick;

    // MSS/MTU
    uint32_t mss;
    uint32_t max_udp_packet_size;

    // Receive queue (decoded blocks from UDP)
    rudp_queued_block_t recv_queue[RUDP_RECV_QUEUE_SIZE];
    int recv_queue_head;
    int recv_queue_tail;
    int recv_queue_count;

    // Error tracking
    int fatal_error;
} rudp_context_t;

// API functions
rudp_context_t* rudp_create(int is_client);
void rudp_destroy(rudp_context_t* ctx);

int rudp_init_client(rudp_context_t* ctx,
                     const uint8_t* server_key, int server_key_size,
                     const char* server_ip, uint16_t server_port,
                     uint32_t server_cookie,
                     uint32_t client_cookie);

int rudp_init_server(rudp_context_t* ctx,
                     const uint8_t* client_key, int client_key_size,
                     const char* client_ip, uint16_t client_port);

// Recreate the UDP socket for the given address family (AF_INET or AF_INET6),
// re-binding to a fresh ephemeral port. Use before the login PACK is sent so
// the advertised client port matches the socket actually used.
int rudp_set_udp_family(rudp_context_t* ctx, int family);

void rudp_poll(rudp_context_t* ctx);
void rudp_set_tick(rudp_context_t* ctx, uint64_t tick);

int rudp_is_send_ready(rudp_context_t* ctx, int check_keepalive);
uint32_t rudp_calc_mss(rudp_context_t* ctx);

int rudp_send(rudp_context_t* ctx, const uint8_t* data, uint32_t data_size, uint8_t flag);
int rudp_send_keepalive(rudp_context_t* ctx);

// Receive decoded blocks from the queue
int rudp_recv(rudp_context_t* ctx, uint8_t* buffer, uint32_t* len, uint32_t max_len);

// Utility
void rudp_set_version(rudp_context_t* ctx, int version);
void rudp_set_fast_detect(rudp_context_t* ctx, int fast);
int rudp_get_udp_fd(rudp_context_t* ctx);
int rudp_is_active(rudp_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_RUDP_H
