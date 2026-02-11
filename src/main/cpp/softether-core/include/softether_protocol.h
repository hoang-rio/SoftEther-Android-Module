#ifndef SOFTETHER_PROTOCOL_H
#define SOFTETHER_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol constants
#define SOFTETHER_SIGNATURE     0x53455448  // 'SETH'
#define SOFTETHER_VERSION       0x0001

// Command types
#define CMD_CONNECT             0x0001
#define CMD_CONNECT_ACK         0x0002
#define CMD_AUTH                0x0003
#define CMD_AUTH_CHALLENGE      0x0004
#define CMD_AUTH_RESPONSE       0x0005
#define CMD_AUTH_SUCCESS        0x0006
#define CMD_AUTH_FAIL           0x0007
#define CMD_SESSION_REQUEST     0x0008
#define CMD_SESSION_ASSIGN      0x0009
#define CMD_CONFIG_REQUEST      0x000A
#define CMD_CONFIG_RESPONSE     0x000B
#define CMD_DATA                0x000C
#define CMD_KEEPALIVE           0x000D
#define CMD_KEEPALIVE_ACK       0x000E
#define CMD_DISCONNECT          0x000F
#define CMD_DISCONNECT_ACK      0x0010
#define CMD_ERROR               0x00FF

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

// SoftEther packet header
#pragma pack(push, 1)
typedef struct {
    uint32_t signature;          // 'SETH' = 0x53455448
    uint16_t version;            // Protocol version
    uint16_t command;            // Command type
    uint32_t payload_length;     // Length of payload
    uint32_t session_id;         // Session identifier
    uint32_t sequence_num;       // Sequence number
} softether_header_t;
#pragma pack(pop)

#define SOFTETHER_HEADER_SIZE   sizeof(softether_header_t)
#define SOFTETHER_MAX_PAYLOAD   65535

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
    int timeout_ms;
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
void softether_disconnect(softether_connection_t* conn);

// State management
softether_state_t softether_get_state(softether_connection_t* conn);
const char* softether_state_string(softether_state_t state);

// Data I/O
int softether_send(softether_connection_t* conn, const uint8_t* data, size_t len);
int softether_receive(softether_connection_t* conn, uint8_t* buffer, size_t max_len);

// Protocol operations
int softether_send_packet(softether_connection_t* conn, uint16_t command,
                          const uint8_t* payload, uint32_t payload_len);
int softether_receive_packet(softether_connection_t* conn, uint16_t* command,
                             uint8_t* payload, uint32_t* payload_len, uint32_t max_payload);

// Keepalive
int softether_send_keepalive(softether_connection_t* conn);
int softether_process_keepalive(softether_connection_t* conn);

// Utility
const char* softether_error_string(int error_code);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_PROTOCOL_H
