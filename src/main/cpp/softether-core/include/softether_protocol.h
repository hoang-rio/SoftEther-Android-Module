#ifndef SOFTETHER_PROTOCOL_H
#define SOFTETHER_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "softether_rudp.h"

#ifdef __cplusplus
extern "C" {
#endif

// Client authentication types (matching SoftEther Cedar.h)
#define CLIENT_AUTHTYPE_ANONYMOUS       0
#define CLIENT_AUTHTYPE_PASSWORD        1
#define CLIENT_AUTHTYPE_PLAIN_PASSWORD  2

// Real SoftEther data channel constants
#define KEEP_ALIVE_MAGIC        0xFFFFFFFF
#define SOFTETHER_MAX_BLOCK     (1600 * 1600)

// Multi-connection constants (matching Cedar.h)
#define MAX_SE_CONNECTIONS                  8
#define MAX_SEND_SOCKET_QUEUE_SIZE          (1600 * 1600)
#define MIN_SEND_SOCKET_QUEUE_SIZE          (1600 * 200)
#define ADDITIONAL_CONNECT_INTERVAL_MS      1000
#define TCP_DIRECTION_BOTH                  0
#define TCP_DIRECTION_SERVER_TO_CLIENT      1
#define TCP_DIRECTION_CLIENT_TO_SERVER      2

// Monotonic time in milliseconds (for multi-connection timing)
static inline uint64_t softether_tick_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// Legacy command types (used internally for dispatch, not on wire)
#define CMD_DATA                0x000C
#define CMD_KEEPALIVE           0x000D
#define CMD_KEEPALIVE_ACK       0x000E
#define CMD_DISCONNECT          0x000F

// Error codes
#define ERR_NONE                0
#define ERR_TCP_CONNECT         1
#define ERR_TLS_HANDSHAKE       2
#define ERR_PROTOCOL_VERSION    3
#define ERR_AUTHENTICATION      4
#define ERR_SESSION             5
#define ERR_DATA_TRANSMISSION   6
#define ERR_TIMEOUT             7
#define ERR_UNKNOWN             99

// Connection state
typedef enum {
    STATE_DISCONNECTED = 0,
    STATE_CONNECTING,
    STATE_TLS_HANDSHAKE,
    STATE_PROTOCOL_HANDSHAKE,
    STATE_AUTHENTICATING,
    STATE_SESSION_SETUP,
    STATE_CONNECTED,
    STATE_DISCONNECTING
} softether_state_t;

// Receive queue for multi-block messages
#define RECV_QUEUE_SIZE 64
#define MAX_QUEUED_FRAME 1600

typedef struct {
    uint8_t data[MAX_QUEUED_FRAME];
    uint32_t len;
} queued_frame_t;

// Additional TCP socket for multi-connection support
typedef struct {
    int socket_fd;
    void* ssl_ctx;       // ssl_context_t*
    void* ssl;           // ssl_context_t* (same pointer, used for I/O)
    int direction;       // TCP_DIRECTION_*
    uint64_t last_recv;  // monotonic timestamp of last recv (ms)
    uint32_t late_count; // number of times this socket had no data when polled
    int active;          // 1 if slot is in use, 0 if free
} softether_tcp_sock_t;

// Connection context
typedef struct softether_connection {
    int socket_fd;
    void* ssl_ctx;
    void* ssl;
    softether_state_t state;
    uint32_t session_id;
    uint32_t sequence_num;
    char server_ip[64];
    int server_port;
    char username[256];
    char password[256];
    char hub_name[256];  // Virtual Hub name (required for CONNECT)
    int timeout_ms;
    // Server Hello data (from /vpnsvc/connect.cgi response)
    uint8_t server_random[20];  // 20-byte random from server Hello PACK
    int has_server_random;
    // Session data (from Welcome PACK after authentication)
    char session_name[128];
    char connection_name[128];
    uint8_t session_key[20];    // SHA1_SIZE
    uint32_t session_key_32;
    uint32_t server_max_connection;
    uint32_t server_use_encrypt;
    uint32_t server_use_compress;  // 1 if server accepted compression
    uint32_t server_use_fast_rc4;
    uint32_t server_timeout;
    int use_ssl_data;  // 1 = SSL for data, 0 = raw TCP
    int session_established;    // 1 if Welcome PACK was parsed successfully
    int forced_auth_type;  // 0=auto-detect, 1=hashed password, 2=plain password (RADIUS)
    // Client MAC address (for Ethernet L2 encapsulation)
    uint8_t client_mac[6];     // Locally-administered random MAC
    // Gateway MAC address (resolved via ARP after DHCP)
    uint8_t gateway_mac[6];    // Destination MAC for outgoing IP packets
    int gateway_mac_resolved;  // 1 if gateway MAC has been resolved via ARP
    uint32_t gateway_ip;       // Gateway IP in host byte order (from DHCP)
    uint32_t assigned_ip;      // Our assigned IP in host byte order (from DHCP)
    // Receive frame queue (for multi-block messages)
    queued_frame_t recv_queue[RECV_QUEUE_SIZE];
    int recv_queue_head;       // read position
    int recv_queue_tail;       // write position
    int recv_queue_count;      // number of queued frames
    // RUDP (UDP acceleration)
    rudp_context_t* rudp;
    int rudp_enabled;
    uint32_t rudp_server_cookie;
    uint32_t rudp_client_cookie;
    uint8_t rudp_server_key[128];
    int rudp_server_key_size;
    uint8_t rudp_server_key_v2[128];
    int rudp_server_key_v2_size;
    char rudp_server_ip[64];
    uint16_t rudp_server_port;
    int rudp_version;
    // Client info for server session list
    char client_product_name[128];
    char client_product_version[32];
    int client_product_build;
    char client_os_name[128];
    char client_os_version[64];
    char client_os_product_id[128];
    char client_host_name[128];
    char client_ip_address[64];
    int client_port;
    char server_host_name[128];
    char server_ip_address[64];
    int server_port_reported;
    // IPv6 fields (dual-stack support)
    char client_ip_v6[128];   // Client IPv6 address (reported in login PACK)
    char server_ip_v6[128];   // Server IPv6 address (from resolved host)
    int is_ipv6;              // 1 if the connection is over IPv6
    // Thread safety for concurrent send/receive
    pthread_mutex_t write_mutex;  // protects SSL writes (send loop + keepalive response)
    // Multi-connection support
    softether_tcp_sock_t additional[MAX_SE_CONNECTIONS];  // additional TCP sockets (index 0 unused; primary is in socket_fd/ssl)
    int num_additional;          // number of active additional connections
    int max_connection;          // target max connections (sent in login PACK)
    int half_connection;         // 0 = bidirectional, 1 = unidirectional per socket
    int primary_direction;       // TCP_DIRECTION_* for primary socket (default BOTH)
    uint64_t next_connect_time;  // monotonic timestamp for next additional connect attempt (ms)
    int additional_failed_count; // serial failure counter for additional connects
    // Background additional connection thread
    pthread_t additional_thread; // background thread for non-blocking additional connect
    int additional_connecting;   // 1 if background thread is running
    int additional_connect_slot; // which slot the background thread is targeting
    int additional_connect_result; // result from background thread (0=success, -1=fail)
    int send_rr_idx;              // round-robin index for send socket selection
    uint64_t next_tcp_keepalive_time;  // monotonic timestamp for next periodic TCP keepalive sweep (ms)
    // Callbacks
    void (*on_connect)(struct softether_connection* conn);
    void (*on_disconnect)(struct softether_connection* conn);
    void (*on_data)(struct softether_connection* conn, const uint8_t* data, size_t len);
    void (*on_error)(struct softether_connection* conn, int error_code);
} softether_connection_t;

// Function prototypes

// Connection management
softether_connection_t* softether_create(void);
void softether_destroy(softether_connection_t* conn);
int softether_connect(softether_connection_t* conn, const char* host, int port,
                      const char* username, const char* password);
int softether_connect_with_hub(softether_connection_t* conn, const char* host, int port,
                               const char* username, const char* password, const char* hub_name,
                               int use_tcp,
                               const char* client_product_name, const char* client_product_version, int client_product_build,
                               const char* client_os_name, const char* client_os_version, const char* client_os_product_id,
                               const char* client_host_name, const char* client_ip_address, int client_port,
                               const char* server_host_name, const char* server_ip_address, int server_port);
void softether_disconnect(softether_connection_t* conn);

// State management
softether_state_t softether_get_state(softether_connection_t* conn);
const char* softether_state_string(softether_state_t state);

// Data I/O (wraps IP packets in Ethernet frames for L2 tunnel)
int softether_send(softether_connection_t* conn, const uint8_t* data, size_t len);
int softether_receive(softether_connection_t* conn, uint8_t* buffer, size_t max_len);

// Raw L2 I/O (sends/receives raw Ethernet frames — used by DHCP)
int softether_send_raw(softether_connection_t* conn, const uint8_t* frame, size_t len);
int softether_receive_raw(softether_connection_t* conn, uint8_t* frame, size_t max_len, uint32_t* frame_len);

// ARP resolution — resolves gateway MAC after DHCP
int softether_resolve_gateway(softether_connection_t* conn, uint32_t gateway_ip_host);

// Protocol operations
int softether_send_packet(softether_connection_t* conn, uint16_t command,
                          const uint8_t* payload, uint32_t payload_len);
int softether_receive_packet(softether_connection_t* conn, uint16_t* command,
                             uint8_t* payload, uint32_t* payload_len, uint32_t max_payload);

// Data tunnel operations
int softether_send_data(softether_connection_t* conn, const uint8_t* data, uint32_t data_len);
int softether_receive_data(softether_connection_t* conn, uint8_t* buffer, uint32_t max_len,
                           uint32_t* received_len, uint16_t* command);

// Keepalive and connection monitoring
int softether_send_keepalive(softether_connection_t* conn);
int softether_send_keepalive_all(softether_connection_t* conn);
int softether_check_connection(softether_connection_t* conn);
int softether_process_keepalive(softether_connection_t* conn);

// Multi-block receive queue (fills queue from one protocol message)
int softether_fill_recv_queue(softether_connection_t* conn);

// Multi-connection support
int softether_additional_connect(softether_connection_t* conn);
void softether_close_additional(softether_connection_t* conn);
int softether_select_send_socket(softether_connection_t* conn);
int softether_get_num_connections(softether_connection_t* conn);
int softether_get_active_socket_fds(softether_connection_t* conn, int* fds, int max_fds);
void softether_additional_thread_wait(softether_connection_t* conn);

// Reconnection support
void softether_set_reconnect_enabled(softether_connection_t* conn, int enabled);
int softether_reconnect(softether_connection_t* conn);

// Set authentication type explicitly (use CLIENT_AUTHTYPE_* constants; 0=auto)
void softether_set_auth_type(softether_connection_t* conn, int auth_type);

// DHCP result
typedef struct {
    uint32_t assigned_ip;
    uint32_t subnet_mask;
    uint32_t gateway;
    uint32_t dns_server;
    uint32_t dns_server2;
    uint32_t lease_time;
    int success;
} dhcp_result_t;

// DHCP over SoftEther tunnel
int softether_do_dhcp(softether_connection_t* conn, dhcp_result_t* result);

// Utility
const char* softether_error_string(int error_code);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_PROTOCOL_H
