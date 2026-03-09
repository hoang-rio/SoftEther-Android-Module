#ifndef SOFTETHER_PROTOCOL_H
#define SOFTETHER_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Real SoftEther data channel constants
#define KEEP_ALIVE_MAGIC        0xFFFFFFFF
#define SOFTETHER_MAX_BLOCK     (1600 * 1600)

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
    uint32_t server_use_fast_rc4;
    uint32_t server_timeout;
    int use_ssl_data;  // 1 = SSL for data, 0 = raw TCP
    int session_established;    // 1 if Welcome PACK was parsed successfully
    // Client MAC address (for Ethernet L2 encapsulation)
    uint8_t client_mac[6];     // Locally-administered random MAC
    // Receive frame queue (for multi-block messages)
    queued_frame_t recv_queue[RECV_QUEUE_SIZE];
    int recv_queue_head;       // read position
    int recv_queue_tail;       // write position
    int recv_queue_count;      // number of queued frames
    // Thread safety for concurrent send/receive
    pthread_mutex_t write_mutex;  // protects SSL writes (send loop + keepalive response)
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
                               const char* username, const char* password, const char* hub_name);
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
int softether_check_connection(softether_connection_t* conn);
int softether_process_keepalive(softether_connection_t* conn);

// Multi-block receive queue (fills queue from one protocol message)
int softether_fill_recv_queue(softether_connection_t* conn);

// Reconnection support
void softether_set_reconnect_enabled(softether_connection_t* conn, int enabled);
int softether_reconnect(softether_connection_t* conn);

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
