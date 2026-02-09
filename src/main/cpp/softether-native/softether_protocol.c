/**
 * SoftEther VPN Protocol Implementation
 * 
 * Clean-room reimplementation of the SoftEther VPN client protocol.
 */

#include "softether_protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <android/log.h>

#define LOG_TAG "SoftEtherProtocol"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ============================================================================
// Internal Structures
// ============================================================================

// SSL context structure definition
struct se_ssl_context {
    void* ssl;           // SSL pointer (opaque to avoid OpenSSL header dependency issues)
    void* ctx;           // SSL_CTX pointer
    int socket_fd;
    bool is_initialized;
};

// ============================================================================
// Utility Functions
// ============================================================================

const char* se_error_string(int error_code) {
    switch (error_code) {
        case SE_ERR_SUCCESS:              return "Success";
        case SE_ERR_INVALID_PARAM:        return "Invalid parameter";
        case SE_ERR_CONNECT_FAILED:       return "Connection failed";
        case SE_ERR_AUTH_FAILED:          return "Authentication failed";
        case SE_ERR_SSL_HANDSHAKE_FAILED: return "SSL handshake failed";
        case SE_ERR_PROTOCOL_MISMATCH:    return "Protocol mismatch";
        case SE_ERR_DHCP_FAILED:          return "DHCP failed";
        case SE_ERR_TUN_FAILED:           return "TUN interface failed";
        case SE_ERR_TIMEOUT:              return "Timeout";
        case SE_ERR_NETWORK_ERROR:        return "Network error";
        case SE_ERR_OUT_OF_MEMORY:        return "Out of memory";
        default:                          return "Unknown error";
    }
}

const char* se_state_string(int state) {
    switch (state) {
        case SE_STATE_DISCONNECTED:   return "Disconnected";
        case SE_STATE_CONNECTING:     return "Connecting";
        case SE_STATE_CONNECTED:      return "Connected";
        case SE_STATE_DISCONNECTING:  return "Disconnecting";
        case SE_STATE_ERROR:          return "Error";
        default:                      return "Unknown";
    }
}

uint32_t se_ip_string_to_int(const char* ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

void se_ip_int_to_string(uint32_t ip, char* buffer, size_t buffer_size) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    strncpy(buffer, inet_ntoa(addr), buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
}

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void generate_random_bytes(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(rand() & 0xFF);
    }
}

// ============================================================================
// Packet Queue Implementation
// ============================================================================

se_packet_queue_t* se_packet_queue_new(size_t max_size) {
    se_packet_queue_t* queue = (se_packet_queue_t*)calloc(1, sizeof(se_packet_queue_t));
    if (!queue) return NULL;
    
    queue->max_size = max_size > 0 ? max_size : 100;
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    
    return queue;
}

void se_packet_queue_free(se_packet_queue_t* queue) {
    if (!queue) return;
    
    se_packet_queue_clear(queue);
    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    free(queue);
}

int se_packet_queue_push(se_packet_queue_t* queue, se_packet_t* packet, bool blocking) {
    if (!queue || !packet) return -1;
    
    pthread_mutex_lock(&queue->lock);
    
    while (queue->count >= queue->max_size) {
        if (!blocking) {
            pthread_mutex_unlock(&queue->lock);
            return -1;  // Queue full
        }
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }
    
    packet->next = NULL;
    if (queue->tail) {
        queue->tail->next = packet;
    } else {
        queue->head = packet;
    }
    queue->tail = packet;
    queue->count++;
    
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
    
    return 0;
}

se_packet_t* se_packet_queue_pop(se_packet_queue_t* queue, bool blocking) {
    if (!queue) return NULL;
    
    pthread_mutex_lock(&queue->lock);
    
    while (queue->count == 0) {
        if (!blocking) {
            pthread_mutex_unlock(&queue->lock);
            return NULL;
        }
        pthread_cond_wait(&queue->not_empty, &queue->lock);
    }
    
    se_packet_t* packet = queue->head;
    queue->head = packet->next;
    if (!queue->head) {
        queue->tail = NULL;
    }
    queue->count--;
    packet->next = NULL;
    
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    
    return packet;
}

size_t se_packet_queue_size(se_packet_queue_t* queue) {
    if (!queue) return 0;
    
    pthread_mutex_lock(&queue->lock);
    size_t count = queue->count;
    pthread_mutex_unlock(&queue->lock);
    
    return count;
}

void se_packet_queue_clear(se_packet_queue_t* queue) {
    if (!queue) return;
    
    pthread_mutex_lock(&queue->lock);
    
    se_packet_t* packet = queue->head;
    while (packet) {
        se_packet_t* next = packet->next;
        se_packet_free(packet);
        packet = next;
    }
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;
    
    pthread_mutex_unlock(&queue->lock);
}

// ============================================================================
// Packet Operations
// ============================================================================

se_packet_t* se_packet_new(uint32_t type, uint32_t flags, const uint8_t* payload, size_t payload_len) {
    se_packet_t* packet = (se_packet_t*)calloc(1, sizeof(se_packet_t));
    if (!packet) return NULL;
    
    packet->type = type;
    packet->flags = flags;
    packet->payload_len = (uint32_t)payload_len;
    
    if (payload_len > 0 && payload) {
        packet->payload = (uint8_t*)malloc(payload_len);
        if (!packet->payload) {
            free(packet);
            return NULL;
        }
        memcpy(packet->payload, payload, payload_len);
    }
    
    return packet;
}

void se_packet_free(se_packet_t* packet) {
    if (!packet) return;
    
    if (packet->payload) {
        free(packet->payload);
    }
    free(packet);
}

int se_packet_serialize(se_packet_t* packet, uint8_t* buffer, size_t buffer_size) {
    if (!packet || !buffer || buffer_size < 12 + packet->payload_len) {
        return -1;
    }
    
    // Write header: type (4) + flags (4) + payload_len (4)
    buffer[0] = (packet->type >> 24) & 0xFF;
    buffer[1] = (packet->type >> 16) & 0xFF;
    buffer[2] = (packet->type >> 8) & 0xFF;
    buffer[3] = packet->type & 0xFF;
    
    buffer[4] = (packet->flags >> 24) & 0xFF;
    buffer[5] = (packet->flags >> 16) & 0xFF;
    buffer[6] = (packet->flags >> 8) & 0xFF;
    buffer[7] = packet->flags & 0xFF;
    
    buffer[8] = (packet->payload_len >> 24) & 0xFF;
    buffer[9] = (packet->payload_len >> 16) & 0xFF;
    buffer[10] = (packet->payload_len >> 8) & 0xFF;
    buffer[11] = packet->payload_len & 0xFF;
    
    // Write payload
    if (packet->payload_len > 0 && packet->payload) {
        memcpy(buffer + 12, packet->payload, packet->payload_len);
    }
    
    return 12 + packet->payload_len;
}

se_packet_t* se_packet_deserialize(const uint8_t* data, size_t data_len) {
    if (!data || data_len < 12) return NULL;
    
    uint32_t type = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                    ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    
    uint32_t flags = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                     ((uint32_t)data[6] << 8) | (uint32_t)data[7];
    
    uint32_t payload_len = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
                           ((uint32_t)data[10] << 8) | (uint32_t)data[11];
    
    if (data_len < 12 + payload_len) {
        return NULL;  // Incomplete packet
    }
    
    return se_packet_new(type, flags, data + 12, payload_len);
}

// ============================================================================
// Connection Management
// ============================================================================

se_connection_t* se_connection_new(void) {
    se_connection_t* conn = (se_connection_t*)calloc(1, sizeof(se_connection_t));
    if (!conn) return NULL;
    
    conn->state = SE_STATE_DISCONNECTED;
    conn->socket_fd = -1;
    conn->tun_fd = -1;
    
    pthread_mutex_init(&conn->lock, NULL);
    pthread_cond_init(&conn->cond, NULL);
    
    conn->send_queue = se_packet_queue_new(100);
    conn->recv_queue = se_packet_queue_new(100);
    
    if (!conn->send_queue || !conn->recv_queue) {
        se_connection_free(conn);
        return NULL;
    }
    
    // Generate random session ID
    generate_random_bytes(conn->session_id, 16);
    conn->session_key = (uint32_t)rand();
    
    LOGD("Created new connection context");
    return conn;
}

void se_connection_free(se_connection_t* conn) {
    if (!conn) return;
    
    se_connection_disconnect(conn);
    
    se_packet_queue_free(conn->send_queue);
    se_packet_queue_free(conn->recv_queue);
    
    pthread_mutex_destroy(&conn->lock);
    pthread_cond_destroy(&conn->cond);
    
    free(conn);
    LOGD("Freed connection context");
}

// ============================================================================
// Socket and Network Operations
// ============================================================================

static int create_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOGE("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // Enable TCP keepalive
    int keepalive = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    
    // Disable Nagle's algorithm for lower latency
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    
    // Set socket buffer sizes
    int recv_buf = SE_MAX_RECV_BUFFER;
    int send_buf = SE_MAX_SEND_BUFFER;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv_buf, sizeof(recv_buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buf, sizeof(send_buf));
    
    return fd;
}

static int connect_with_timeout(int fd, const struct sockaddr* addr, socklen_t addrlen, int timeout_ms) {
    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    int result = connect(fd, addr, addrlen);
    if (result < 0 && errno != EINPROGRESS) {
        LOGE("Connect failed immediately: %s", strerror(errno));
        return -1;
    }
    
    if (result == 0) {
        // Connected immediately
        fcntl(fd, F_SETFL, flags);
        return 0;
    }
    
    // Wait for connection with timeout
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    
    result = poll(&pfd, 1, timeout_ms);
    if (result <= 0) {
        LOGE("Connection timeout or error: %s", result == 0 ? "timeout" : strerror(errno));
        return -1;
    }
    
    // Check if connection succeeded
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    
    if (so_error != 0) {
        LOGE("Connection failed: %s", strerror(so_error));
        return -1;
    }
    
    // Restore blocking mode
    fcntl(fd, F_SETFL, flags);
    
    return 0;
}

static int resolve_and_connect(const char* hostname, int port, int timeout_ms) {
    LOGD("Resolving %s:%d", hostname, port);
    
    struct hostent* host = gethostbyname(hostname);
    if (!host || !host->h_addr_list[0]) {
        LOGE("Failed to resolve hostname: %s", hostname);
        return -1;
    }
    
    int fd = create_socket();
    if (fd < 0) return -1;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, host->h_addr_list[0], sizeof(struct in_addr));
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
    LOGD("Connecting to %s:%d", ip_str, port);
    
    if (connect_with_timeout(fd, (struct sockaddr*)&addr, sizeof(addr), timeout_ms) < 0) {
        close(fd);
        return -1;
    }
    
    LOGD("Connected successfully");
    return fd;
}

// ============================================================================
// SSL/TLS Operations (simplified - actual SSL implementation needed)
// ============================================================================

// Note: Full SSL implementation would require OpenSSL
// This is a simplified version for the protocol structure

static se_ssl_context_t* ssl_context_new(int socket_fd, bool verify_cert) {
    se_ssl_context_t* ctx = (se_ssl_context_t*)calloc(1, sizeof(se_ssl_context_t));
    if (!ctx) return NULL;
    
    ctx->socket_fd = socket_fd;
    ctx->is_initialized = false;
    
    // TODO: Initialize actual SSL context here
    // For now, we just store the socket fd
    
    return ctx;
}

static void ssl_context_free(se_ssl_context_t* ctx) {
    if (!ctx) return;
    
    // TODO: Cleanup SSL context
    
    free(ctx);
}

static int ssl_handshake(se_ssl_context_t* ctx) {
    if (!ctx) return -1;
    
    // TODO: Perform actual SSL handshake
    // For testing, we'll simulate success
    
    LOGD("SSL handshake (simulated)");
    ctx->is_initialized = true;
    
    return 0;
}

static int ssl_read(se_ssl_context_t* ctx, uint8_t* buffer, size_t len) {
    if (!ctx || ctx->socket_fd < 0) return -1;
    
    // For now, just read directly from socket
    // In real implementation, this would use SSL_read
    return recv(ctx->socket_fd, buffer, len, 0);
}

static int ssl_write(se_ssl_context_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || ctx->socket_fd < 0) return -1;
    
    // For now, just write directly to socket
    // In real implementation, this would use SSL_write
    return send(ctx->socket_fd, data, len, MSG_NOSIGNAL);
}

// ============================================================================
// Protocol Functions
// ============================================================================

int se_protocol_send_hello(se_connection_t* conn) {
    if (!conn || conn->socket_fd < 0) return -1;
    
    LOGD("Sending hello packet");
    
    // Build hello packet
    uint8_t hello[64];
    memset(hello, 0, sizeof(hello));
    
    // Protocol signature
    hello[0] = 'S';
    hello[1] = 'T';
    hello[2] = 'V';
    hello[3] = 'P';
    
    // Version
    hello[4] = SE_VERSION_MAJOR;
    hello[5] = SE_VERSION_MINOR;
    hello[6] = (SE_VERSION_BUILD >> 8) & 0xFF;
    hello[7] = SE_VERSION_BUILD & 0xFF;
    
    // Client capabilities
    hello[8] = conn->params.use_encrypt ? 1 : 0;
    hello[9] = conn->params.use_compress ? 1 : 0;
    
    // Session ID
    memcpy(hello + 16, conn->session_id, 16);
    
    // Write to socket
    int result = ssl_write(conn->ssl_ctx, hello, sizeof(hello));
    if (result != sizeof(hello)) {
        LOGE("Failed to send hello: %d", result);
        return -1;
    }
    
    LOGD("Hello packet sent");
    return 0;
}

int se_protocol_recv_hello(se_connection_t* conn) {
    if (!conn || !conn->ssl_ctx) return -1;
    
    LOGD("Receiving hello response");
    
    uint8_t response[64];
    int total = 0;
    
    while (total < 64) {
        int n = ssl_read(conn->ssl_ctx, response + total, 64 - total);
        if (n <= 0) {
            LOGE("Failed to receive hello response: %d", n);
            return -1;
        }
        total += n;
    }
    
    // Verify signature
    if (response[0] != 'S' || response[1] != 'T' || 
        response[2] != 'V' || response[3] != 'P') {
        LOGE("Invalid protocol signature in hello response");
        return -1;
    }
    
    // Get server version
    conn->server_version = ((uint16_t)response[4] << 8) | response[5];
    conn->server_build = ((uint16_t)response[6] << 8) | response[7];
    
    LOGD("Server version: %d.%d (build %d)", 
         conn->server_version >> 8, conn->server_version & 0xFF, conn->server_build);
    
    return 0;
}

int se_protocol_send_auth(se_connection_t* conn) {
    if (!conn) return -1;
    
    LOGD("Sending authentication request");
    
    // Build auth packet
    size_t username_len = strlen(conn->params.username);
    size_t password_len = strlen(conn->params.password);
    size_t hubname_len = strlen(conn->params.hub_name);
    
    size_t payload_len = 4 + username_len + 4 + password_len + 4 + hubname_len;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) return -1;
    
    size_t offset = 0;
    
    // Username length + data
    payload[offset++] = (username_len >> 24) & 0xFF;
    payload[offset++] = (username_len >> 16) & 0xFF;
    payload[offset++] = (username_len >> 8) & 0xFF;
    payload[offset++] = username_len & 0xFF;
    memcpy(payload + offset, conn->params.username, username_len);
    offset += username_len;
    
    // Password length + data
    payload[offset++] = (password_len >> 24) & 0xFF;
    payload[offset++] = (password_len >> 16) & 0xFF;
    payload[offset++] = (password_len >> 8) & 0xFF;
    payload[offset++] = password_len & 0xFF;
    memcpy(payload + offset, conn->params.password, password_len);
    offset += password_len;
    
    // Hub name length + data
    payload[offset++] = (hubname_len >> 24) & 0xFF;
    payload[offset++] = (hubname_len >> 16) & 0xFF;
    payload[offset++] = (hubname_len >> 8) & 0xFF;
    payload[offset++] = hubname_len & 0xFF;
    memcpy(payload + offset, conn->params.hub_name, hubname_len);
    
    // Create and send packet
    se_packet_t* packet = se_packet_new(SE_PACKET_TYPE_AUTH_REQUEST, 0, payload, payload_len);
    free(payload);
    
    if (!packet) return -1;
    
    uint8_t buffer[SE_MAX_PACKET_SIZE];
    int len = se_packet_serialize(packet, buffer, sizeof(buffer));
    se_packet_free(packet);
    
    if (len < 0) return -1;
    
    int result = ssl_write(conn->ssl_ctx, buffer, len);
    if (result != len) {
        LOGE("Failed to send auth packet");
        return -1;
    }
    
    LOGD("Authentication request sent");
    return 0;
}

int se_protocol_recv_auth_response(se_connection_t* conn) {
    if (!conn || !conn->ssl_ctx) return -1;
    
    LOGD("Receiving authentication response");
    
    // Read packet header
    uint8_t header[12];
    int total = 0;
    
    while (total < 12) {
        int n = ssl_read(conn->ssl_ctx, header + total, 12 - total);
        if (n <= 0) {
            LOGE("Failed to receive auth response header");
            return -1;
        }
        total += n;
    }
    
    uint32_t type = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
                    ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    uint32_t payload_len = ((uint32_t)header[8] << 24) | ((uint32_t)header[9] << 16) |
                           ((uint32_t)header[10] << 8) | (uint32_t)header[11];
    
    if (type != SE_PACKET_TYPE_AUTH_RESPONSE) {
        LOGE("Unexpected packet type: %u", type);
        return -1;
    }
    
    // Read payload
    if (payload_len > 0) {
        uint8_t* payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;
        
        total = 0;
        while (total < (int)payload_len) {
            int n = ssl_read(conn->ssl_ctx, payload + total, payload_len - total);
            if (n <= 0) {
                free(payload);
                return -1;
            }
            total += n;
        }
        
        // Check auth result (first 4 bytes)
        uint32_t auth_result = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                               ((uint32_t)payload[2] << 8) | (uint32_t)payload[3];
        
        free(payload);
        
        if (auth_result != 0) {
            LOGE("Authentication failed: %u", auth_result);
            return -1;
        }
    }
    
    LOGD("Authentication successful");
    return 0;
}

int se_protocol_send_dhcp_request(se_connection_t* conn) {
    if (!conn) return -1;
    
    LOGD("Sending DHCP request");
    
    // Simple DHCP request
    uint8_t request[16];
    memset(request, 0, sizeof(request));
    memcpy(request, conn->session_id, 16);
    
    se_packet_t* packet = se_packet_new(SE_PACKET_TYPE_DHCP_REQUEST, 0, request, sizeof(request));
    if (!packet) return -1;
    
    uint8_t buffer[SE_MAX_PACKET_SIZE];
    int len = se_packet_serialize(packet, buffer, sizeof(buffer));
    se_packet_free(packet);
    
    if (len < 0) return -1;
    
    int result = ssl_write(conn->ssl_ctx, buffer, len);
    if (result != len) {
        LOGE("Failed to send DHCP request");
        return -1;
    }
    
    return 0;
}

int se_protocol_recv_dhcp_response(se_connection_t* conn) {
    if (!conn || !conn->ssl_ctx) return -1;
    
    LOGD("Receiving DHCP response");
    
    // Read packet header
    uint8_t header[12];
    int total = 0;
    
    while (total < 12) {
        int n = ssl_read(conn->ssl_ctx, header + total, 12 - total);
        if (n <= 0) {
            LOGE("Failed to receive DHCP response header");
            return -1;
        }
        total += n;
    }
    
    uint32_t type = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
                    ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    uint32_t payload_len = ((uint32_t)header[8] << 24) | ((uint32_t)header[9] << 16) |
                           ((uint32_t)header[10] << 8) | (uint32_t)header[11];
    
    if (type != SE_PACKET_TYPE_DHCP_RESPONSE) {
        LOGE("Unexpected packet type: %u", type);
        return -1;
    }
    
    // Read payload
    if (payload_len >= 24) {
        uint8_t* payload = (uint8_t*)malloc(payload_len);
        if (!payload) return -1;
        
        total = 0;
        while (total < (int)payload_len) {
            int n = ssl_read(conn->ssl_ctx, payload + total, payload_len - total);
            if (n <= 0) {
                free(payload);
                return -1;
            }
            total += n;
        }
        
        // Parse network config
        conn->net_config.client_ip = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                                     ((uint32_t)payload[2] << 8) | (uint32_t)payload[3];
        conn->net_config.subnet_mask = ((uint32_t)payload[4] << 24) | ((uint32_t)payload[5] << 16) |
                                       ((uint32_t)payload[6] << 8) | (uint32_t)payload[7];
        conn->net_config.gateway = ((uint32_t)payload[8] << 24) | ((uint32_t)payload[9] << 16) |
                                   ((uint32_t)payload[10] << 8) | (uint32_t)payload[11];
        conn->net_config.dns1 = ((uint32_t)payload[12] << 24) | ((uint32_t)payload[13] << 16) |
                                ((uint32_t)payload[14] << 8) | (uint32_t)payload[15];
        
        free(payload);
        
        char ip_str[16];
        se_ip_int_to_string(conn->net_config.client_ip, ip_str, sizeof(ip_str));
        LOGD("DHCP response received - IP: %s", ip_str);
    }
    
    return 0;
}

int se_protocol_send_keepalive(se_connection_t* conn) {
    if (!conn || !conn->ssl_ctx) return -1;
    
    se_packet_t* packet = se_packet_new(SE_PACKET_TYPE_KEEPALIVE, 0, NULL, 0);
    if (!packet) return -1;
    
    uint8_t buffer[64];
    int len = se_packet_serialize(packet, buffer, sizeof(buffer));
    se_packet_free(packet);
    
    if (len < 0) return -1;
    
    int result = ssl_write(conn->ssl_ctx, buffer, len);
    return (result == len) ? 0 : -1;
}

// ============================================================================
// Thread Functions
// ============================================================================

void* se_recv_thread(void* arg) {
    se_connection_t* conn = (se_connection_t*)arg;
    if (!conn) return NULL;
    
    LOGD("Receive thread started");
    
    uint8_t buffer[SE_MAX_PACKET_SIZE];
    
    while (conn->threads_running) {
        // Read packet header
        int total = 0;
        while (total < 12 && conn->threads_running) {
            int n = ssl_read(conn->ssl_ctx, buffer + total, 12 - total);
            if (n <= 0) {
                if (conn->threads_running) {
                    LOGE("Receive error: %d", n);
                    pthread_mutex_lock(&conn->lock);
                    conn->state = SE_STATE_ERROR;
                    conn->last_error = SE_ERR_NETWORK_ERROR;
                    pthread_mutex_unlock(&conn->lock);
                }
                goto recv_thread_exit;
            }
            total += n;
        }
        
        if (!conn->threads_running) break;
        
        uint32_t type = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                        ((uint32_t)buffer[2] << 8) | (uint32_t)buffer[3];
        uint32_t payload_len = ((uint32_t)buffer[8] << 24) | ((uint32_t)buffer[9] << 16) |
                               ((uint32_t)buffer[10] << 8) | (uint32_t)buffer[11];
        
        // Read payload
        if (payload_len > 0) {
            total = 0;
            while (total < (int)payload_len && conn->threads_running) {
                int n = ssl_read(conn->ssl_ctx, buffer + 12 + total, payload_len - total);
                if (n <= 0) {
                    LOGE("Receive payload error: %d", n);
                    goto recv_thread_exit;
                }
                total += n;
            }
        }
        
        if (!conn->threads_running) break;
        
        // Handle packet based on type
        switch (type) {
            case SE_PACKET_TYPE_DATA:
                // Queue data packet
                if (conn->tun_fd >= 0) {
                    write(conn->tun_fd, buffer + 12, payload_len);
                    pthread_mutex_lock(&conn->lock);
                    conn->stats.bytes_received += payload_len;
                    conn->stats.packets_received++;
                    pthread_mutex_unlock(&conn->lock);
                }
                break;
                
            case SE_PACKET_TYPE_KEEPALIVE:
                // Keepalive received, no action needed
                break;
                
            case SE_PACKET_TYPE_DISCONNECT:
                LOGD("Disconnect packet received");
                goto recv_thread_exit;
                
            default:
                LOGD("Unknown packet type: %u", type);
                break;
        }
    }
    
recv_thread_exit:
    LOGD("Receive thread exiting");
    return NULL;
}

void* se_send_thread(void* arg) {
    se_connection_t* conn = (se_connection_t*)arg;
    if (!conn) return NULL;
    
    LOGD("Send thread started");
    
    uint8_t buffer[SE_MAX_PACKET_SIZE];
    
    while (conn->threads_running) {
        // Read from TUN interface
        if (conn->tun_fd >= 0) {
            ssize_t len = read(conn->tun_fd, buffer + 12, SE_MAX_PACKET_SIZE - 12);
            if (len > 0) {
                // Build packet header
                buffer[0] = 0; buffer[1] = 0; buffer[2] = 0; buffer[3] = SE_PACKET_TYPE_DATA;
                buffer[4] = 0; buffer[5] = 0; buffer[6] = 0; buffer[7] = 0;
                buffer[8] = (len >> 24) & 0xFF;
                buffer[9] = (len >> 16) & 0xFF;
                buffer[10] = (len >> 8) & 0xFF;
                buffer[11] = len & 0xFF;
                
                // Send packet
                int result = ssl_write(conn->ssl_ctx, buffer, 12 + len);
                if (result == 12 + len) {
                    pthread_mutex_lock(&conn->lock);
                    conn->stats.bytes_sent += len;
                    conn->stats.packets_sent++;
                    pthread_mutex_unlock(&conn->lock);
                }
            }
        }
        
        // Small delay to prevent busy waiting
        usleep(1000);
    }
    
    LOGD("Send thread exiting");
    return NULL;
}

void* se_keepalive_thread(void* arg) {
    se_connection_t* conn = (se_connection_t*)arg;
    if (!conn) return NULL;
    
    LOGD("Keepalive thread started");
    
    while (conn->threads_running) {
        if (se_protocol_send_keepalive(conn) < 0) {
            LOGE("Failed to send keepalive");
            break;
        }
        
        // Sleep for keepalive interval
        for (int i = 0; i < SE_KEEPALIVE_INTERVAL_MS / 100 && conn->threads_running; i++) {
            usleep(100000);  // 100ms
        }
    }
    
    LOGD("Keepalive thread exiting");
    return NULL;
}

// ============================================================================
// Main Connection Functions
// ============================================================================

int se_connection_connect(se_connection_t* conn, const se_connection_params_t* params) {
    if (!conn || !params) {
        LOGE("Invalid parameters");
        return SE_ERR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->lock);
    
    if (conn->state != SE_STATE_DISCONNECTED) {
        pthread_mutex_unlock(&conn->lock);
        LOGE("Connection already in progress");
        return SE_ERR_INVALID_PARAM;
    }
    
    conn->state = SE_STATE_CONNECTING;
    memcpy(&conn->params, params, sizeof(se_connection_params_t));
    
    pthread_mutex_unlock(&conn->lock);
    
    // Step 1: Establish TCP connection
    LOGD("Connecting to %s:%d", params->server_host, params->server_port);
    
    conn->socket_fd = resolve_and_connect(params->server_host, params->server_port, SE_CONNECT_TIMEOUT_MS);
    if (conn->socket_fd < 0) {
        pthread_mutex_lock(&conn->lock);
        conn->state = SE_STATE_ERROR;
        conn->last_error = SE_ERR_CONNECT_FAILED;
        pthread_mutex_unlock(&conn->lock);
        return SE_ERR_CONNECT_FAILED;
    }
    
    // Step 2: SSL/TLS handshake
    LOGD("Starting SSL handshake");
    
    conn->ssl_ctx = ssl_context_new(conn->socket_fd, params->verify_server_cert);
    if (!conn->ssl_ctx) {
        close(conn->socket_fd);
        conn->socket_fd = -1;
        pthread_mutex_lock(&conn->lock);
        conn->state = SE_STATE_ERROR;
        conn->last_error = SE_ERR_OUT_OF_MEMORY;
        pthread_mutex_unlock(&conn->lock);
        return SE_ERR_OUT_OF_MEMORY;
    }
    
    if (ssl_handshake(conn->ssl_ctx) < 0) {
        ssl_context_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
        close(conn->socket_fd);
        conn->socket_fd = -1;
        pthread_mutex_lock(&conn->lock);
        conn->state = SE_STATE_ERROR;
        conn->last_error = SE_ERR_SSL_HANDSHAKE_FAILED;
        pthread_mutex_unlock(&conn->lock);
        return SE_ERR_SSL_HANDSHAKE_FAILED;
    }
    
    // Step 3: Protocol handshake
    LOGD("Starting protocol handshake");
    
    if (se_protocol_send_hello(conn) < 0) {
        goto connect_failed;
    }
    
    if (se_protocol_recv_hello(conn) < 0) {
        goto connect_failed;
    }
    
    // Step 4: Authentication
    LOGD("Authenticating");
    
    if (se_protocol_send_auth(conn) < 0) {
        goto connect_failed;
    }
    
    if (se_protocol_recv_auth_response(conn) < 0) {
        pthread_mutex_lock(&conn->lock);
        conn->state = SE_STATE_ERROR;
        conn->last_error = SE_ERR_AUTH_FAILED;
        pthread_mutex_unlock(&conn->lock);
        return SE_ERR_AUTH_FAILED;
    }
    
    // Step 5: DHCP request
    LOGD("Requesting DHCP configuration");
    
    if (se_protocol_send_dhcp_request(conn) < 0) {
        goto connect_failed;
    }
    
    if (se_protocol_recv_dhcp_response(conn) < 0) {
        pthread_mutex_lock(&conn->lock);
        conn->state = SE_STATE_ERROR;
        conn->last_error = SE_ERR_DHCP_FAILED;
        pthread_mutex_unlock(&conn->lock);
        return SE_ERR_DHCP_FAILED;
    }
    
    // Step 6: Start threads
    LOGD("Starting worker threads");
    
    conn->threads_running = true;
    conn->stats.start_time_ms = get_time_ms();
    
    pthread_create(&conn->recv_thread, NULL, se_recv_thread, conn);
    pthread_create(&conn->send_thread, NULL, se_send_thread, conn);
    pthread_create(&conn->keepalive_thread, NULL, se_keepalive_thread, conn);
    
    pthread_mutex_lock(&conn->lock);
    conn->state = SE_STATE_CONNECTED;
    pthread_mutex_unlock(&conn->lock);
    
    LOGD("Connection established successfully");
    
    // Call connected callback
    if (conn->on_connected) {
        conn->on_connected(conn, &conn->net_config);
    }
    
    return SE_ERR_SUCCESS;
    
connect_failed:
    ssl_context_free(conn->ssl_ctx);
    conn->ssl_ctx = NULL;
    close(conn->socket_fd);
    conn->socket_fd = -1;
    pthread_mutex_lock(&conn->lock);
    conn->state = SE_STATE_ERROR;
    conn->last_error = SE_ERR_PROTOCOL_MISMATCH;
    pthread_mutex_unlock(&conn->lock);
    return SE_ERR_PROTOCOL_MISMATCH;
}

void se_connection_disconnect(se_connection_t* conn) {
    if (!conn) return;
    
    pthread_mutex_lock(&conn->lock);
    
    if (conn->state == SE_STATE_DISCONNECTED || conn->state == SE_STATE_DISCONNECTING) {
        pthread_mutex_unlock(&conn->lock);
        return;
    }
    
    conn->state = SE_STATE_DISCONNECTING;
    conn->threads_running = false;
    
    pthread_mutex_unlock(&conn->lock);
    
    LOGD("Disconnecting...");
    
    // Send disconnect packet
    if (conn->ssl_ctx) {
        se_packet_t* packet = se_packet_new(SE_PACKET_TYPE_DISCONNECT, 0, NULL, 0);
        if (packet) {
            uint8_t buffer[64];
            int len = se_packet_serialize(packet, buffer, sizeof(buffer));
            if (len > 0) {
                ssl_write(conn->ssl_ctx, buffer, len);
            }
            se_packet_free(packet);
        }
    }
    
    // Wait for threads to finish
    if (conn->recv_thread) {
        pthread_join(conn->recv_thread, NULL);
        conn->recv_thread = 0;
    }
    if (conn->send_thread) {
        pthread_join(conn->send_thread, NULL);
        conn->send_thread = 0;
    }
    if (conn->keepalive_thread) {
        pthread_join(conn->keepalive_thread, NULL);
        conn->keepalive_thread = 0;
    }
    
    // Cleanup SSL
    if (conn->ssl_ctx) {
        ssl_context_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }
    
    // Close socket
    if (conn->socket_fd >= 0) {
        close(conn->socket_fd);
        conn->socket_fd = -1;
    }
    
    pthread_mutex_lock(&conn->lock);
    conn->state = SE_STATE_DISCONNECTED;
    pthread_mutex_unlock(&conn->lock);
    
    LOGD("Disconnected");
    
    // Call disconnected callback
    if (conn->on_disconnected) {
        conn->on_disconnected(conn, 0);
    }
}

int se_connection_get_state(se_connection_t* conn) {
    if (!conn) return SE_STATE_ERROR;
    
    pthread_mutex_lock(&conn->lock);
    int state = conn->state;
    pthread_mutex_unlock(&conn->lock);
    
    return state;
}

int se_connection_get_last_error(se_connection_t* conn) {
    if (!conn) return SE_ERR_INVALID_PARAM;
    
    pthread_mutex_lock(&conn->lock);
    int error = conn->last_error;
    pthread_mutex_unlock(&conn->lock);
    
    return error;
}

const char* se_connection_get_error_string(se_connection_t* conn) {
    if (!conn) return "Invalid connection";
    return se_error_string(conn->last_error);
}

int se_connection_set_tun_fd(se_connection_t* conn, int tun_fd) {
    if (!conn) return -1;
    
    pthread_mutex_lock(&conn->lock);
    conn->tun_fd = tun_fd;
    pthread_mutex_unlock(&conn->lock);
    
    return 0;
}

int se_connection_send_packet(se_connection_t* conn, const uint8_t* data, size_t len) {
    if (!conn || !data || len == 0) return -1;
    
    se_packet_t* packet = se_packet_new(SE_PACKET_TYPE_DATA, 0, data, len);
    if (!packet) return -1;
    
    int result = se_packet_queue_push(conn->send_queue, packet, false);
    if (result < 0) {
        se_packet_free(packet);
    }
    
    return result;
}

int se_connection_recv_packet(se_connection_t* conn, uint8_t* buffer, size_t buffer_size) {
    if (!conn || !buffer || buffer_size == 0) return -1;
    
    se_packet_t* packet = se_packet_queue_pop(conn->recv_queue, false);
    if (!packet) return 0;  // No packet available
    
    size_t copy_len = packet->payload_len < buffer_size ? packet->payload_len : buffer_size;
    memcpy(buffer, packet->payload, copy_len);
    se_packet_free(packet);
    
    return (int)copy_len;
}

void se_connection_get_statistics(se_connection_t* conn, se_statistics_t* stats) {
    if (!conn || !stats) return;
    
    pthread_mutex_lock(&conn->lock);
    memcpy(stats, &conn->stats, sizeof(se_statistics_t));
    pthread_mutex_unlock(&conn->lock);
}

void se_connection_reset_statistics(se_connection_t* conn) {
    if (!conn) return;
    
    pthread_mutex_lock(&conn->lock);
    memset(&conn->stats, 0, sizeof(se_statistics_t));
    pthread_mutex_unlock(&conn->lock);
}
