/**
 * SoftEther VPN Protocol Implementation - Header
 * 
 * This is a clean-room reimplementation of the SoftEther VPN protocol
 * for Android native connections.
 * 
 * Protocol: SoftEther SSL-VPN (based on HTTPS/TLS)
 * Version: Compatible with SoftEther VPN 4.x/5.x servers
 */

#ifndef SOFTETHER_PROTOCOL_H
#define SOFTETHER_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Protocol Constants
// ============================================================================

#define SE_VERSION_MAJOR     4
#define SE_VERSION_MINOR     0
#define SE_VERSION_BUILD     0

// Protocol magic numbers
#define SE_PROTOCOL_SIGNATURE 0x53545650  // "STVP" in hex

// Connection states
#define SE_STATE_DISCONNECTED   0
#define SE_STATE_CONNECTING     1
#define SE_STATE_CONNECTED      2
#define SE_STATE_DISCONNECTING  3
#define SE_STATE_ERROR          4

// Error codes
#define SE_ERR_SUCCESS              0
#define SE_ERR_INVALID_PARAM        1
#define SE_ERR_CONNECT_FAILED       2
#define SE_ERR_AUTH_FAILED          3
#define SE_ERR_SSL_HANDSHAKE_FAILED 4
#define SE_ERR_PROTOCOL_MISMATCH    5
#define SE_ERR_DHCP_FAILED          6
#define SE_ERR_TUN_FAILED           7
#define SE_ERR_TIMEOUT              8
#define SE_ERR_NETWORK_ERROR        9
#define SE_ERR_OUT_OF_MEMORY        10

// Buffer sizes
#define SE_MAX_HOSTNAME_LEN     256
#define SE_MAX_USERNAME_LEN     256
#define SE_MAX_PASSWORD_LEN     256
#define SE_MAX_HUBNAME_LEN      256
#define SE_MAX_PACKET_SIZE      65536
#define SE_MAX_RECV_BUFFER      65536
#define SE_MAX_SEND_BUFFER      65536

// Default ports
#define SE_DEFAULT_PORT_HTTPS   443
#define SE_DEFAULT_PORT_IPSEC   500
#define SE_DEFAULT_PORT_SSTP    443
#define SE_DEFAULT_PORT_OPENVPN 1194

// Timeouts (milliseconds)
#define SE_CONNECT_TIMEOUT_MS   30000
#define SE_HANDSHAKE_TIMEOUT_MS 10000
#define SE_DHCP_TIMEOUT_MS      30000
#define SE_KEEPALIVE_INTERVAL_MS 5000

// ============================================================================
// Data Structures
// ============================================================================

/**
 * Connection parameters
 */
typedef struct {
    char server_host[SE_MAX_HOSTNAME_LEN];
    int server_port;
    char hub_name[SE_MAX_HUBNAME_LEN];
    char username[SE_MAX_USERNAME_LEN];
    char password[SE_MAX_PASSWORD_LEN];
    bool use_encrypt;
    bool use_compress;
    int proxy_type;      // 0: None, 1: HTTP, 2: SOCKS5
    char proxy_host[SE_MAX_HOSTNAME_LEN];
    int proxy_port;
    int reconnect_retries;
    bool verify_server_cert;
    int mtu;
} se_connection_params_t;

/**
 * Network configuration (assigned by DHCP)
 */
typedef struct {
    uint32_t client_ip;      // Virtual IP assigned to client
    uint32_t subnet_mask;    // Subnet mask
    uint32_t gateway;        // Gateway IP
    uint32_t dns1;           // Primary DNS
    uint32_t dns2;           // Secondary DNS
    uint32_t dhcp_server;    // DHCP server IP
    uint32_t lease_time;     // DHCP lease time in seconds
} se_network_config_t;

/**
 * Connection statistics
 */
typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t errors;
    uint64_t start_time_ms;
} se_statistics_t;

/**
 * SSL/TLS context (opaque)
 */
typedef struct se_ssl_context se_ssl_context_t;

/**
 * Connection context
 */
typedef struct se_connection {
    // Connection state
    volatile int state;
    int last_error;
    char error_message[256];
    
    // Socket
    int socket_fd;
    se_ssl_context_t* ssl_ctx;
    
    // Parameters
    se_connection_params_t params;
    
    // Network config
    se_network_config_t net_config;
    
    // TUN interface
    int tun_fd;
    
    // Threads
    pthread_t recv_thread;
    pthread_t send_thread;
    pthread_t keepalive_thread;
    volatile bool threads_running;
    
    // Synchronization
    pthread_mutex_t lock;
    pthread_cond_t cond;
    
    // Packet queues
    struct se_packet_queue* send_queue;
    struct se_packet_queue* recv_queue;
    
    // Statistics
    se_statistics_t stats;
    
    // Session ID
    uint8_t session_id[16];
    uint32_t session_key;
    
    // Protocol version
    uint16_t server_version;
    uint16_t server_build;
    
    // Callbacks
    void (*on_connected)(struct se_connection* conn, const se_network_config_t* config);
    void (*on_disconnected)(struct se_connection* conn, int reason);
    void (*on_error)(struct se_connection* conn, int error_code, const char* message);
    void (*on_packet)(struct se_connection* conn, const uint8_t* data, size_t len);
    void* user_data;
} se_connection_t;

/**
 * Packet structure
 */
typedef struct se_packet {
    uint32_t type;
    uint32_t flags;
    uint32_t payload_len;
    uint8_t* payload;
    struct se_packet* next;
} se_packet_t;

/**
 * Packet queue
 */
typedef struct se_packet_queue {
    se_packet_t* head;
    se_packet_t* tail;
    size_t count;
    size_t max_size;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} se_packet_queue_t;

// ============================================================================
// Protocol Packet Types
// ============================================================================

#define SE_PACKET_TYPE_DATA         0x0001  // VPN data packet
#define SE_PACKET_TYPE_CONTROL      0x0002  // Control message
#define SE_PACKET_TYPE_KEEPALIVE    0x0003  // Keepalive
#define SE_PACKET_TYPE_AUTH_REQUEST 0x0010  // Authentication request
#define SE_PACKET_TYPE_AUTH_RESPONSE 0x0011 // Authentication response
#define SE_PACKET_TYPE_DHCP_REQUEST 0x0020  // DHCP request
#define SE_PACKET_TYPE_DHCP_RESPONSE 0x0021 // DHCP response
#define SE_PACKET_TYPE_DISCONNECT   0x00FF  // Disconnect

// ============================================================================
// API Functions
// ============================================================================

// Connection management
se_connection_t* se_connection_new(void);
void se_connection_free(se_connection_t* conn);
int se_connection_connect(se_connection_t* conn, const se_connection_params_t* params);
void se_connection_disconnect(se_connection_t* conn);
int se_connection_get_state(se_connection_t* conn);
int se_connection_get_last_error(se_connection_t* conn);
const char* se_connection_get_error_string(se_connection_t* conn);

// Network operations
int se_connection_set_tun_fd(se_connection_t* conn, int tun_fd);
int se_connection_send_packet(se_connection_t* conn, const uint8_t* data, size_t len);
int se_connection_recv_packet(se_connection_t* conn, uint8_t* buffer, size_t buffer_size);

// Statistics
void se_connection_get_statistics(se_connection_t* conn, se_statistics_t* stats);
void se_connection_reset_statistics(se_connection_t* conn);

// Utility functions
const char* se_error_string(int error_code);
const char* se_state_string(int state);
uint32_t se_ip_string_to_int(const char* ip_str);
void se_ip_int_to_string(uint32_t ip, char* buffer, size_t buffer_size);

// Packet queue operations
se_packet_queue_t* se_packet_queue_new(size_t max_size);
void se_packet_queue_free(se_packet_queue_t* queue);
int se_packet_queue_push(se_packet_queue_t* queue, se_packet_t* packet, bool blocking);
se_packet_t* se_packet_queue_pop(se_packet_queue_t* queue, bool blocking);
size_t se_packet_queue_size(se_packet_queue_t* queue);
void se_packet_queue_clear(se_packet_queue_t* queue);

// Packet operations
se_packet_t* se_packet_new(uint32_t type, uint32_t flags, const uint8_t* payload, size_t payload_len);
void se_packet_free(se_packet_t* packet);
int se_packet_serialize(se_packet_t* packet, uint8_t* buffer, size_t buffer_size);
se_packet_t* se_packet_deserialize(const uint8_t* data, size_t data_len);

// Internal protocol functions (exposed for testing)
int se_protocol_send_hello(se_connection_t* conn);
int se_protocol_recv_hello(se_connection_t* conn);
int se_protocol_send_auth(se_connection_t* conn);
int se_protocol_recv_auth_response(se_connection_t* conn);
int se_protocol_send_dhcp_request(se_connection_t* conn);
int se_protocol_recv_dhcp_response(se_connection_t* conn);
int se_protocol_send_keepalive(se_connection_t* conn);

// Thread functions
void* se_recv_thread(void* arg);
void* se_send_thread(void* arg);
void* se_keepalive_thread(void* arg);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_PROTOCOL_H
