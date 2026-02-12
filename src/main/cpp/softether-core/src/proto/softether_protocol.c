#include "softether_protocol.h"
#include "softether_socket.h"
#include "softether_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <android/log.h>

// Forward declaration of command_to_string from serializer.c
extern const char* command_to_string(uint16_t command);

#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#define TAG "SoftEtherProtocol"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Helper function to get current time in milliseconds
static long get_current_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// Create a new connection context
softether_connection_t* softether_create(void) {
    softether_connection_t* conn = (softether_connection_t*)calloc(1, sizeof(softether_connection_t));
    if (conn == NULL) {
        LOGE("Failed to allocate connection structure");
        return NULL;
    }

    conn->socket_fd = -1;
    conn->state = STATE_DISCONNECTED;
    conn->session_id = 0;
    conn->sequence_num = 0;
    conn->timeout_ms = 30000;  // Default 30 second timeout
    conn->ssl_ctx = NULL;
    conn->ssl = NULL;

    // Initialize callbacks to NULL
    conn->on_connect = NULL;
    conn->on_disconnect = NULL;
    conn->on_data = NULL;
    conn->on_error = NULL;

    LOGD("Connection created");
    return conn;
}

// Destroy connection context
void softether_destroy(softether_connection_t* conn) {
    if (conn == NULL) {
        return;
    }

    // Disconnect if still connected (not disconnected)
    // Check for any active state
    if (conn->state != STATE_DISCONNECTED) {
        LOGD("Destroying connection in state: %s", softether_state_string(conn->state));
        softether_disconnect(conn);
    }

    // Clear sensitive data
    if (conn->username[0] != '\0') {
        memset(conn->username, 0, sizeof(conn->username));
    }
    if (conn->password[0] != '\0') {
        memset(conn->password, 0, sizeof(conn->password));
    }

    free(conn);
    LOGD("Connection destroyed");
}

// Get current state
softether_state_t softether_get_state(softether_connection_t* conn) {
    if (conn == NULL) {
        return STATE_DISCONNECTED;
    }
    // Use memory barrier to ensure we read the latest state
    __sync_synchronize();
    return conn->state;
}

// Get string representation of state
const char* softether_state_string(softether_state_t state) {
    switch (state) {
        case STATE_DISCONNECTED: return "DISCONNECTED";
        case STATE_CONNECTING: return "CONNECTING";
        case STATE_TLS_HANDSHAKE: return "TLS_HANDSHAKE";
        case STATE_PROTOCOL_HANDSHAKE: return "PROTOCOL_HANDSHAKE";
        case STATE_AUTHENTICATING: return "AUTHENTICATING";
        case STATE_SESSION_SETUP: return "SESSION_SETUP";
        case STATE_CONNECTED: return "CONNECTED";
        case STATE_DISCONNECTING: return "DISCONNECTING";
        default: return "UNKNOWN";
    }
}

// Get string representation of error
const char* softether_error_string(int error_code) {
    switch (error_code) {
        case ERR_NONE: return "No error";
        case ERR_TCP_CONNECT: return "TCP connection failed";
        case ERR_TLS_HANDSHAKE: return "TLS handshake failed";
        case ERR_PROTOCOL_VERSION: return "Protocol version mismatch";
        case ERR_AUTHENTICATION: return "Authentication failed";
        case ERR_SESSION: return "Session setup failed";
        case ERR_DATA_TRANSMISSION: return "Data transmission failed";
        case ERR_TIMEOUT: return "Operation timed out";
        case ERR_UNKNOWN: return "Unknown error";
        default: return "Undefined error";
    }
}

// Perform TLS handshake
static int perform_tls_handshake(softether_connection_t* conn, const char* hostname) {
    if (conn == NULL || conn->socket_fd < 0) {
        return ERR_TLS_HANDSHAKE;
    }

    LOGD("Starting TLS handshake with %s", hostname);
    conn->state = STATE_TLS_HANDSHAKE;

    // Create SSL context
    ssl_context_t* ssl_ctx = ssl_create_client();
    if (ssl_ctx == NULL) {
        LOGE("Failed to create SSL context");
        return ERR_TLS_HANDSHAKE;
    }

    conn->ssl_ctx = ssl_ctx;

    // Perform SSL connect
    if (ssl_connect(ssl_ctx, conn->socket_fd, hostname) != 0) {
        LOGE("SSL handshake failed");
        ssl_destroy(ssl_ctx);
        conn->ssl_ctx = NULL;
        return ERR_TLS_HANDSHAKE;
    }

    conn->ssl = ssl_ctx;
    LOGD("TLS handshake successful");
    return ERR_NONE;
}

// Perform protocol handshake
static int perform_protocol_handshake(softether_connection_t* conn) {
    if (conn == NULL) {
        return ERR_PROTOCOL_VERSION;
    }

    LOGD("Starting protocol handshake");
    conn->state = STATE_PROTOCOL_HANDSHAKE;

    // Send HELLO packet
    uint8_t hello_payload[4];
    hello_payload[0] = (SOFTETHER_VERSION >> 8) & 0xFF;
    hello_payload[1] = SOFTETHER_VERSION & 0xFF;
    hello_payload[2] = 0;  // Reserved
    hello_payload[3] = 0;  // Reserved

    if (softether_send_packet(conn, CMD_CONNECT, hello_payload, sizeof(hello_payload)) < 0) {
        LOGE("Failed to send HELLO packet");
        return ERR_PROTOCOL_VERSION;
    }

    // Receive HELLO_ACK
    uint16_t command;
    uint8_t response[256];
    uint32_t response_len;

    if (softether_receive_packet(conn, &command, response, &response_len, sizeof(response)) < 0) {
        LOGE("Failed to receive HELLO_ACK");
        return ERR_PROTOCOL_VERSION;
    }

    if (command != CMD_CONNECT_ACK) {
        LOGE("Expected CONNECT_ACK, got %s", command_to_string(command));
        return ERR_PROTOCOL_VERSION;
    }

    // Check protocol version in response
    if (response_len >= 2) {
        uint16_t server_version = ((uint16_t)response[0] << 8) | response[1];
        LOGD("Server protocol version: 0x%04X", server_version);

        if (server_version != SOFTETHER_VERSION) {
            LOGW("Protocol version mismatch: client=0x%04X, server=0x%04X",
                 SOFTETHER_VERSION, server_version);
            // Continue anyway, server might support backward compatibility
        }
    }

    LOGD("Protocol handshake successful");
    return ERR_NONE;
}

// Perform authentication
static int perform_authentication(softether_connection_t* conn, const char* username, const char* password) {
    if (conn == NULL || username == NULL || password == NULL) {
        return ERR_AUTHENTICATION;
    }

    LOGD("Starting authentication for user: %s", username);
    conn->state = STATE_AUTHENTICATING;

    // Store credentials
    strncpy(conn->username, username, sizeof(conn->username) - 1);
    strncpy(conn->password, password, sizeof(conn->password) - 1);

    // Build AUTH_REQUEST payload
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    size_t auth_payload_len = 2 + username_len + 2 + password_len;
    uint8_t* auth_payload = (uint8_t*)malloc(auth_payload_len);

    if (auth_payload == NULL) {
        LOGE("Failed to allocate auth payload");
        return ERR_AUTHENTICATION;
    }

    // Format: [username_len:2][username][password_len:2][password]
    uint32_t offset = 0;
    auth_payload[offset++] = (username_len >> 8) & 0xFF;
    auth_payload[offset++] = username_len & 0xFF;
    memcpy(auth_payload + offset, username, username_len);
    offset += username_len;
    auth_payload[offset++] = (password_len >> 8) & 0xFF;
    auth_payload[offset++] = password_len & 0xFF;
    memcpy(auth_payload + offset, password, password_len);

    // Send AUTH_REQUEST
    if (softether_send_packet(conn, CMD_AUTH, auth_payload, auth_payload_len) < 0) {
        LOGE("Failed to send AUTH packet");
        free(auth_payload);
        return ERR_AUTHENTICATION;
    }

    free(auth_payload);

    // Receive AUTH_CHALLENGE or AUTH_SUCCESS
    uint16_t command;
    uint8_t response[256];
    uint32_t response_len;

    if (softether_receive_packet(conn, &command, response, &response_len, sizeof(response)) < 0) {
        LOGE("Failed to receive auth response");
        return ERR_AUTHENTICATION;
    }

    if (command == CMD_AUTH_CHALLENGE) {
        // Handle challenge-response authentication if needed
        LOGD("Received authentication challenge");
        // TODO: Implement challenge-response handling

        // Send AUTH_RESPONSE
        if (softether_send_packet(conn, CMD_AUTH_RESPONSE, NULL, 0) < 0) {
            LOGE("Failed to send AUTH_RESPONSE");
            return ERR_AUTHENTICATION;
        }

        // Receive final auth result
        if (softether_receive_packet(conn, &command, response, &response_len, sizeof(response)) < 0) {
            LOGE("Failed to receive final auth response");
            return ERR_AUTHENTICATION;
        }
    }

    if (command != CMD_AUTH_SUCCESS) {
        LOGE("Authentication failed: %s", command_to_string(command));
        return ERR_AUTHENTICATION;
    }

    LOGD("Authentication successful");
    return ERR_NONE;
}

// Setup session
static int setup_session(softether_connection_t* conn) {
    if (conn == NULL) {
        return ERR_SESSION;
    }

    LOGD("Setting up session");
    conn->state = STATE_SESSION_SETUP;

    // Send SESSION_REQUEST
    uint8_t session_request[4] = {0};  // Request new session
    if (softether_send_packet(conn, CMD_SESSION_REQUEST, session_request, sizeof(session_request)) < 0) {
        LOGE("Failed to send SESSION_REQUEST");
        return ERR_SESSION;
    }

    // Receive SESSION_ASSIGN
    uint16_t command;
    uint8_t response[256];
    uint32_t response_len;

    if (softether_receive_packet(conn, &command, response, &response_len, sizeof(response)) < 0) {
        LOGE("Failed to receive SESSION_ASSIGN");
        return ERR_SESSION;
    }

    if (command != CMD_SESSION_ASSIGN) {
        LOGE("Expected SESSION_ASSIGN, got %s", command_to_string(command));
        return ERR_SESSION;
    }

    // Extract session ID from response
    if (response_len >= 4) {
        conn->session_id = ((uint32_t)response[0] << 24) |
                          ((uint32_t)response[1] << 16) |
                          ((uint32_t)response[2] << 8) |
                          (uint32_t)response[3];
        LOGD("Session assigned: 0x%08X", conn->session_id);
    }

    // Send CONFIG_REQUEST
    if (softether_send_packet(conn, CMD_CONFIG_REQUEST, NULL, 0) < 0) {
        LOGE("Failed to send CONFIG_REQUEST");
        return ERR_SESSION;
    }

    // Receive CONFIG_RESPONSE
    if (softether_receive_packet(conn, &command, response, &response_len, sizeof(response)) < 0) {
        LOGE("Failed to receive CONFIG_RESPONSE");
        return ERR_SESSION;
    }

    if (command != CMD_CONFIG_RESPONSE) {
        LOGE("Expected CONFIG_RESPONSE, got %s", command_to_string(command));
        return ERR_SESSION;
    }

    LOGD("Session setup successful");
    return ERR_NONE;
}

// Main connect function
int softether_connect(softether_connection_t* conn, const char* host, int port,
                      const char* username, const char* password) {
    if (conn == NULL || host == NULL || username == NULL || password == NULL) {
        return ERR_UNKNOWN;
    }

    LOGD("Connecting to %s:%d", host, port);
    conn->state = STATE_CONNECTING;

    // Store server info
    strncpy(conn->server_ip, host, sizeof(conn->server_ip) - 1);
    conn->server_port = port;

    // Create socket and connect
    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        LOGE("Failed to create socket");
        conn->state = STATE_DISCONNECTED;
        return ERR_TCP_CONNECT;
    }

    // Connect to server
    if (socket_connect_timeout(sock, host, port, conn->timeout_ms) != 0) {
        LOGE("Failed to connect to server");
        socket_destroy(sock);
        conn->state = STATE_DISCONNECTED;
        return ERR_TCP_CONNECT;
    }

    conn->socket_fd = sock->fd;
    // Keep the socket fd, destroy the wrapper
    sock->fd = -1;
    socket_destroy(sock);

    // Perform TLS handshake
    int result = perform_tls_handshake(conn, host);
    if (result != ERR_NONE) {
        LOGE("TLS handshake failed");
        close(conn->socket_fd);
        conn->socket_fd = -1;
        conn->state = STATE_DISCONNECTED;
        return result;
    }

    // Perform protocol handshake
    result = perform_protocol_handshake(conn);
    if (result != ERR_NONE) {
        LOGE("Protocol handshake failed");
        softether_disconnect(conn);
        return result;
    }

    // Perform authentication
    result = perform_authentication(conn, username, password);
    if (result != ERR_NONE) {
        LOGE("Authentication failed");
        softether_disconnect(conn);
        return result;
    }

    // Setup session
    result = setup_session(conn);
    if (result != ERR_NONE) {
        LOGE("Session setup failed");
        softether_disconnect(conn);
        return result;
    }

    // Connection established
    conn->state = STATE_CONNECTED;
    LOGD("Connection established successfully");

    // Call connect callback if set
    if (conn->on_connect != NULL) {
        conn->on_connect(conn);
    }

    return ERR_NONE;
}

// Disconnect
void softether_disconnect(softether_connection_t* conn) {
    if (conn == NULL) {
        return;
    }

    // Save the current state before changing it
    softether_state_t prev_state = conn->state;
    
    if (prev_state == STATE_DISCONNECTED || prev_state == STATE_DISCONNECTING) {
        return;
    }

    LOGD("Disconnecting (previous state: %s)", softether_state_string(prev_state));
    conn->state = STATE_DISCONNECTING;

    // Send disconnect packet only if we were fully connected
    if (prev_state == STATE_CONNECTED && conn->socket_fd >= 0) {
        LOGD("Sending disconnect packet");
        softether_send_packet(conn, CMD_DISCONNECT, NULL, 0);

        // Wait for disconnect ACK with short timeout
        uint16_t command;
        uint8_t response[256];
        uint32_t response_len;
        softether_receive_packet(conn, &command, response, &response_len, sizeof(response));
    }

    // Shutdown SSL only if it was initialized
    if (conn->ssl != NULL && conn->ssl_ctx != NULL) {
        LOGD("Shutting down SSL");
        ssl_shutdown((ssl_context_t*)conn->ssl);
        ssl_destroy((ssl_context_t*)conn->ssl_ctx);
        conn->ssl = NULL;
        conn->ssl_ctx = NULL;
    }

    // Close socket
    if (conn->socket_fd >= 0) {
        LOGD("Closing socket");
        close(conn->socket_fd);
        conn->socket_fd = -1;
    }

    conn->state = STATE_DISCONNECTED;
    conn->session_id = 0;
    conn->sequence_num = 0;

    LOGD("Disconnected");

    // Call disconnect callback if set
    if (conn->on_disconnect != NULL) {
        conn->on_disconnect(conn);
    }
}

// Send data
int softether_send(softether_connection_t* conn, const uint8_t* data, size_t len) {
    if (conn == NULL || data == NULL || len == 0) {
        return -1;
    }

    if (conn->state != STATE_CONNECTED) {
        LOGE("Not connected");
        return -1;
    }

    // Send as DATA packet
    // Split into chunks if necessary (max payload size)
    size_t max_chunk = SOFTETHER_MAX_PAYLOAD;
    size_t offset = 0;
    int total_sent = 0;

    while (offset < len) {
        size_t chunk_size = (len - offset) > max_chunk ? max_chunk : (len - offset);

        int sent = softether_send_packet(conn, CMD_DATA, data + offset, (uint32_t)chunk_size);
        if (sent < 0) {
            LOGE("Failed to send data chunk");
            return -1;
        }

        total_sent += (int)chunk_size;
        offset += chunk_size;
    }

    return total_sent;
}

// Receive data
int softether_receive(softether_connection_t* conn, uint8_t* buffer, size_t max_len) {
    if (conn == NULL || buffer == NULL || max_len == 0) {
        return -1;
    }

    if (conn->state != STATE_CONNECTED) {
        LOGE("Not connected");
        return -1;
    }

    uint16_t command;
    uint32_t payload_len = 0;
    uint32_t buffer_uint32 = (uint32_t)max_len;

    int result = softether_receive_packet(conn, &command, buffer, &payload_len, buffer_uint32);
    if (result < 0) {
        return -1;
    }

    if (command == CMD_DATA) {
        return (int)payload_len;
    } else if (command == CMD_KEEPALIVE) {
        // Send keepalive ACK
        softether_send_packet(conn, CMD_KEEPALIVE_ACK, NULL, 0);
        return 0;  // No data received
    } else {
        LOGD("Received non-data packet: %s", command_to_string(command));
        return 0;
    }
}

// Data tunnel operations - Send data packet with proper encapsulation
int softether_send_data(softether_connection_t* conn, const uint8_t* data, uint32_t data_len) {
    if (conn == NULL || data == NULL) {
        LOGE("Invalid parameters for send_data");
        return -1;
    }

    if (conn->state != STATE_CONNECTED) {
        LOGE("Cannot send data: not connected");
        return -1;
    }

    // For data tunnel, we send raw data as payload
    int result = softether_send_packet(conn, CMD_DATA, data, data_len);
    if (result < 0) {
        LOGE("Failed to send data packet");
        return -1;
    }

    LOGD("Sent data packet: %u bytes", data_len);
    return result;
}

// Data tunnel operations - Receive data packet with command type returned
int softether_receive_data(softether_connection_t* conn, uint8_t* buffer, uint32_t max_len,
                           uint32_t* received_len, uint16_t* command) {
    if (conn == NULL || buffer == NULL || received_len == NULL || command == NULL) {
        LOGE("Invalid parameters for receive_data");
        return -1;
    }

    if (conn->state != STATE_CONNECTED) {
        LOGE("Cannot receive data: not connected");
        return -1;
    }

    uint32_t payload_len = 0;
    int result = softether_receive_packet(conn, command, buffer, &payload_len, max_len);

    if (result < 0) {
        LOGE("Failed to receive data packet");
        return -1;
    }

    *received_len = payload_len;

    // Handle different command types
    switch (*command) {
        case CMD_DATA:
            LOGD("Received data packet: %u bytes", payload_len);
            break;

        case CMD_KEEPALIVE:
            // Send keepalive ACK
            softether_send_packet(conn, CMD_KEEPALIVE_ACK, NULL, 0);
            LOGD("Received keepalive, sent ACK");
            *received_len = 0;  // No actual data
            break;

        case CMD_KEEPALIVE_ACK:
            LOGD("Received keepalive ACK");
            *received_len = 0;
            break;

        case CMD_DISCONNECT:
        case CMD_DISCONNECT_ACK:
            LOGD("Received disconnect command");
            conn->state = STATE_DISCONNECTING;
            return -1;

        default:
            LOGD("Received command: %s (0x%04X)", command_to_string(*command), *command);
            *received_len = 0;
            break;
    }

    return 0;
}

// Reconnection support - Enable/disable automatic reconnection
void softether_set_reconnect_enabled(softether_connection_t* conn, int enabled) {
    if (conn == NULL) {
        return;
    }

    // Store reconnection preference (implementation can be extended)
    LOGD("Reconnection %s", enabled ? "enabled" : "disabled");
}

// Reconnection support - Attempt to reconnect using stored credentials
int softether_reconnect(softether_connection_t* conn) {
    if (conn == NULL) {
        return ERR_UNKNOWN;
    }

    if (conn->server_ip[0] == '\0' || conn->username[0] == '\0') {
        LOGE("Cannot reconnect: no stored connection info");
        return ERR_UNKNOWN;
    }

    LOGD("Attempting to reconnect to %s:%d", conn->server_ip, conn->server_port);

    // Disconnect if still connected
    if (conn->state != STATE_DISCONNECTED) {
        softether_disconnect(conn);
    }

    // Attempt reconnection with stored credentials
    return softether_connect(conn, conn->server_ip, conn->server_port,
                             conn->username, conn->password);
}
