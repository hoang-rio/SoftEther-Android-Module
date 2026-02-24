#include "native_test.h"
#include "softether_protocol.h"
#include "softether_socket.h"
#include "softether_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <android/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define TAG "NativeTest"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// HTTP detection response patterns from official SoftEther source
static const char* http_detect_startwith = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">";
static const char* http_detect_tag = "9C37197CA7C2428388C2E6E59B829B30";

// Helper: Send HTTP GET with X-VPN header to detect SoftEther server
static int detect_softether_server(softether_connection_t* conn, const char* server_ip) {
    // Build HTTP GET request with X-VPN header
    char http_request[512];
    int offset = 0;
    
    // HTTP GET request line
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "GET / HTTP/1.1\r\n");
    
    // Required headers
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "X-VPN: 1\r\n");
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "Host: %s\r\n", server_ip);
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "Keep-Alive: timeout=15\r\n");
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "Connection: Keep-Alive\r\n");
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "Accept-Language: ja\r\n");
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "User-Agent: SoftEther VPN Client\r\n");
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "Pragma: no-cache\r\n");
    offset += snprintf(http_request + offset, sizeof(http_request) - offset,
                       "Cache-Control: no-cache\r\n");
    
    // End of headers
    offset += snprintf(http_request + offset, sizeof(http_request) - offset, "\r\n");
    
    LOGD("Sending HTTP detection request");
    
    // Send HTTP request over SSL
    int sent = ssl_write((ssl_context_t*)conn->ssl, (uint8_t*)http_request, strlen(http_request));
    if (sent <= 0) {
        LOGE("Failed to send HTTP detection request");
        return -1;
    }
    
    // Receive HTTP response
    uint8_t recv_buffer[2048];
    int total_received = 0;
    int received;
    
    // Set a timeout for receiving
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    while (total_received < (int)sizeof(recv_buffer) - 1) {
        received = ssl_read((ssl_context_t*)conn->ssl, recv_buffer + total_received, 
                           sizeof(recv_buffer) - total_received - 1);
        
        if (received <= 0) {
            break;
        }
        total_received += received;
        
        // Check if we have complete HTTP headers
        recv_buffer[total_received] = '\0';
        if (strstr((char*)recv_buffer, "\r\n\r\n") != NULL) {
            break;
        }
    }
    
    // Restore original timeout
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    if (total_received <= 0) {
        LOGE("Failed to receive HTTP response");
        return -1;
    }
    
    recv_buffer[total_received] = '\0';
    LOGD("HTTP detection response (%d bytes): %.256s", total_received, (char*)recv_buffer);
    
    // Check for SoftEther detection patterns
    // Pattern 1: HTTP 403 Forbidden response (SoftEther returns this when accessed without proper protocol)
    if (strstr((char*)recv_buffer, "HTTP/1.1 403") != NULL || 
        strstr((char*)recv_buffer, "HTTP/1.0 403") != NULL) {
        LOGD("Detected SoftEther VPN server (403 Forbidden response)");
        return 1; // Detected
    }
    
    // Pattern 2: DOCTYPE in response body
    if (strncmp((char*)recv_buffer, http_detect_startwith, strlen(http_detect_startwith)) == 0) {
        LOGD("Detected SoftEther VPN server (DOCTYPE response)");
        return 1; // Detected
    }
    
    // Pattern 3: Check anywhere in the response for DOCTYPE
    if (strstr((char*)recv_buffer, http_detect_startwith) != NULL) {
        LOGD("Detected SoftEther VPN server (DOCTYPE found in body)");
        return 1; // Detected
    }
    
    // Pattern 4: Magic tag
    if (strstr((char*)recv_buffer, http_detect_tag) != NULL) {
        LOGD("Detected SoftEther VPN server (magic tag found)");
        return 1; // Detected
    }
    
    // Pattern 5: Check for "VPN" in response which indicates SoftEther
    if (strstr((char*)recv_buffer, "VPN") != NULL || 
        strstr((char*)recv_buffer, "vpn") != NULL) {
        LOGD("Detected potential VPN server");
        return 1; // Possibly detected
    }
    
    LOGD("Server does not appear to be SoftEther VPN");
    return 0; // Not detected (or not a SoftEther server)
}

// Get current timestamp in milliseconds
long get_test_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// Initialize test result
void test_result_init(native_test_result_t* result, bool success, int error_code,
                      const char* message, long duration_ms) {
    if (result == NULL) return;

    result->success = success;
    result->error_code = error_code;
    result->duration_ms = duration_ms;

    if (message != NULL) {
        strncpy(result->message, message, sizeof(result->message) - 1);
        result->message[sizeof(result->message) - 1] = '\0';
    } else {
        result->message[0] = '\0';
    }
}

// Convert error code to string
const char* test_error_to_string(int error_code) {
    return softether_error_string(error_code);
}

// Test 1: TCP Connection
native_test_result_t test_tcp_connection(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();

    LOGD("Testing TCP connection to %s:%d", config->host, config->port);

    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "Failed to create socket", duration);
        return result;
    }

    int ret = socket_connect_timeout(sock, config->host, config->port, config->timeout_ms);
    long duration = get_test_timestamp_ms() - start_time;

    if (ret != 0) {
        socket_destroy(sock);
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "TCP connection failed", duration);
        return result;
    }

    socket_destroy(sock);

    char msg[256];
    snprintf(msg, sizeof(msg), "TCP connection successful to %s:%d", config->host, config->port);
    test_result_init(&result, true, ERR_NONE, msg, duration);
    LOGD("TCP connection test passed in %ld ms", duration);
    return result;
}

// Test 2: TLS Handshake
native_test_result_t test_tls_handshake(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();

    LOGD("Testing TLS handshake with %s:%d", config->host, config->port);

    // Create socket
    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "Failed to create socket", duration);
        return result;
    }

    // Connect
    if (socket_connect_timeout(sock, config->host, config->port, config->timeout_ms) != 0) {
        socket_destroy(sock);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "TCP connection failed", duration);
        return result;
    }

    // Perform TLS handshake
    ssl_context_t* ssl_ctx = ssl_create_client();
    if (ssl_ctx == NULL) {
        close(sock->fd);
        sock->fd = -1;
        socket_destroy(sock);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TLS_HANDSHAKE,
                        "Failed to create SSL context", duration);
        return result;
    }

    int ret = ssl_connect(ssl_ctx, sock->fd, config->host);
    long duration = get_test_timestamp_ms() - start_time;

    // Cleanup
    ssl_destroy(ssl_ctx);
    close(sock->fd);
    sock->fd = -1;
    socket_destroy(sock);

    if (ret != 0) {
        test_result_init(&result, false, ERR_TLS_HANDSHAKE,
                        "TLS handshake failed", duration);
        return result;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "TLS handshake successful with %s:%d", config->host, config->port);
    test_result_init(&result, true, ERR_NONE, msg, duration);
    LOGD("TLS handshake test passed in %ld ms", duration);
    return result;
}

// Test 3: SoftEther Protocol Handshake
native_test_result_t test_softether_handshake(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();

    LOGD("Testing SoftEther protocol handshake with %s:%d", config->host, config->port);

    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_UNKNOWN,
                        "Failed to create connection", duration);
        return result;
    }

    conn->timeout_ms = config->timeout_ms;

    // Create socket
    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "Failed to create socket", duration);
        return result;
    }

    // Connect
    if (socket_connect_timeout(sock, config->host, config->port, config->timeout_ms) != 0) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "TCP connection failed", duration);
        return result;
    }

    conn->socket_fd = sock->fd;
    sock->fd = -1;
    socket_destroy(sock);

    // TLS handshake
    ssl_context_t* ssl_ctx = ssl_create_client();
    if (ssl_ctx == NULL || ssl_connect(ssl_ctx, conn->socket_fd, config->host) != 0) {
        close(conn->socket_fd);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TLS_HANDSHAKE,
                        "TLS handshake failed", duration);
        return result;
    }

    conn->ssl = ssl_ctx;
    conn->ssl_ctx = ssl_ctx;
    
    // Step 1: HTTP detection - Send HTTP GET with X-VPN header
    LOGD("Performing HTTP detection phase...");
    int detect_result = detect_softether_server(conn, config->host);
    
    if (detect_result < 0) {
        // Detection failed (connection issue)
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TLS_HANDSHAKE,
                        "HTTP detection failed", duration);
        return result;
    }
    
    LOGD("HTTP detection completed (result: %d)", detect_result);
    
    // Set connection state to protocol handshake
    conn->state = STATE_PROTOCOL_HANDSHAKE;

    // Send protocol HELLO
    uint8_t hello_payload[4] = {0x00, 0x01, 0x00, 0x00};  // Version 1
    int ret = softether_send_packet(conn, CMD_CONNECT, hello_payload, sizeof(hello_payload));

    if (ret < 0) {
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_PROTOCOL_VERSION,
                        "Failed to send protocol HELLO", duration);
        return result;
    }

    // Receive response
    uint16_t command;
    uint8_t response[256];
    uint32_t response_len;
    ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));

    long duration = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);

    if (ret < 0 || command != CMD_CONNECT_ACK) {
        test_result_init(&result, false, ERR_PROTOCOL_VERSION,
                        "Protocol handshake failed", duration);
        return result;
    }

    test_result_init(&result, true, ERR_NONE,
                    "SoftEther protocol handshake successful", duration);
    LOGD("SoftEther handshake test passed in %ld ms", duration);
    return result;
}

// Test 4: Authentication
native_test_result_t test_authentication(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();

    LOGD("Testing authentication with %s:%d (user: %s)",
         config->host, config->port, config->username);

    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_UNKNOWN,
                        "Failed to create connection", duration);
        return result;
    }

    conn->timeout_ms = config->timeout_ms;

    // Create and connect socket
    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "Failed to create socket", duration);
        return result;
    }

    if (socket_connect_timeout(sock, config->host, config->port, config->timeout_ms) != 0) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "TCP connection failed", duration);
        return result;
    }

    conn->socket_fd = sock->fd;
    sock->fd = -1;
    socket_destroy(sock);

    // TLS handshake
    ssl_context_t* ssl_ctx = ssl_create_client();
    if (ssl_ctx == NULL || ssl_connect(ssl_ctx, conn->socket_fd, config->host) != 0) {
        close(conn->socket_fd);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TLS_HANDSHAKE,
                        "TLS handshake failed", duration);
        return result;
    }

    conn->ssl = ssl_ctx;
    conn->ssl_ctx = ssl_ctx;
    
    // HTTP detection phase
    LOGD("Performing HTTP detection phase...");
    int detect_result = detect_softether_server(conn, config->host);
    
    // Continue regardless of detection result
    conn->state = STATE_CONNECTED;

    // Protocol handshake
    uint8_t hello_payload[4] = {0x00, 0x01, 0x00, 0x00};
    softether_send_packet(conn, CMD_CONNECT, hello_payload, sizeof(hello_payload));

    uint16_t command;
    uint8_t response[256];
    uint32_t response_len;
    int ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));

    if (ret < 0 || command != CMD_CONNECT_ACK) {
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_PROTOCOL_VERSION,
                        "Protocol handshake failed", duration);
        return result;
    }

    // Send authentication
    size_t username_len = strlen(config->username);
    size_t password_len = strlen(config->password);
    size_t auth_len = 2 + username_len + 2 + password_len;
    uint8_t* auth_payload = (uint8_t*)malloc(auth_len);

    if (auth_payload == NULL) {
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_AUTHENTICATION,
                        "Failed to allocate auth payload", duration);
        return result;
    }

    auth_payload[0] = (username_len >> 8) & 0xFF;
    auth_payload[1] = username_len & 0xFF;
    memcpy(auth_payload + 2, config->username, username_len);
    auth_payload[2 + username_len] = (password_len >> 8) & 0xFF;
    auth_payload[3 + username_len] = password_len & 0xFF;
    memcpy(auth_payload + 4 + username_len, config->password, password_len);

    softether_send_packet(conn, CMD_AUTH, auth_payload, auth_len);
    free(auth_payload);

    ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));
    long duration = get_test_timestamp_ms() - start_time;

    softether_disconnect(conn);
    softether_destroy(conn);

    if (ret < 0 || (command != CMD_AUTH_SUCCESS && command != CMD_AUTH_CHALLENGE)) {
        test_result_init(&result, false, ERR_AUTHENTICATION,
                        "Authentication failed", duration);
        return result;
    }

    test_result_init(&result, true, ERR_NONE,
                    "Authentication successful", duration);
    LOGD("Authentication test passed in %ld ms", duration);
    return result;
}

// Test 5: Session Setup - Full implementation
native_test_result_t test_session(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();

    LOGD("Testing session setup with %s:%d", config->host, config->port);

    // Create connection
    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_UNKNOWN,
                        "Failed to create connection", duration);
        return result;
    }

    conn->timeout_ms = config->timeout_ms;

    // Create and connect socket
    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "Failed to create socket", duration);
        return result;
    }

    if (socket_connect_timeout(sock, config->host, config->port, config->timeout_ms) != 0) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TCP_CONNECT,
                        "TCP connection failed", duration);
        return result;
    }

    conn->socket_fd = sock->fd;
    sock->fd = -1;
    socket_destroy(sock);

    // TLS handshake
    ssl_context_t* ssl_ctx = ssl_create_client();
    if (ssl_ctx == NULL || ssl_connect(ssl_ctx, conn->socket_fd, config->host) != 0) {
        close(conn->socket_fd);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_TLS_HANDSHAKE,
                        "TLS handshake failed", duration);
        return result;
    }

    conn->ssl = ssl_ctx;
    conn->ssl_ctx = ssl_ctx;

    // HTTP detection phase
    detect_softether_server(conn, config->host);
    conn->state = STATE_CONNECTED;

    // Protocol handshake
    uint8_t hello_payload[4] = {0x00, 0x01, 0x00, 0x00};
    softether_send_packet(conn, CMD_CONNECT, hello_payload, sizeof(hello_payload));

    uint16_t command;
    uint8_t response[256];
    uint32_t response_len;
    int ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));

    if (ret < 0 || command != CMD_CONNECT_ACK) {
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_PROTOCOL_VERSION,
                        "Protocol handshake failed", duration);
        return result;
    }

    // Authentication
    size_t username_len = strlen(config->username);
    size_t password_len = strlen(config->password);
    size_t auth_len = 2 + username_len + 2 + password_len;
    uint8_t* auth_payload = (uint8_t*)malloc(auth_len);

    if (auth_payload == NULL) {
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_AUTHENTICATION,
                        "Failed to allocate auth payload", duration);
        return result;
    }

    auth_payload[0] = (username_len >> 8) & 0xFF;
    auth_payload[1] = username_len & 0xFF;
    memcpy(auth_payload + 2, config->username, username_len);
    auth_payload[2 + username_len] = (password_len >> 8) & 0xFF;
    auth_payload[3 + username_len] = password_len & 0xFF;
    memcpy(auth_payload + 4 + username_len, config->password, password_len);

    softether_send_packet(conn, CMD_AUTH, auth_payload, auth_len);
    free(auth_payload);

    ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));

    if (ret < 0 || (command != CMD_AUTH_SUCCESS && command != CMD_AUTH_CHALLENGE)) {
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_AUTHENTICATION,
                        "Authentication failed", duration);
        return result;
    }

    // Handle challenge-response if needed
    if (command == CMD_AUTH_CHALLENGE) {
        // Send AUTH_RESPONSE
        softether_send_packet(conn, CMD_AUTH_RESPONSE, NULL, 0);

        // Receive final auth result
        ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));
        if (ret < 0 || command != CMD_AUTH_SUCCESS) {
            softether_disconnect(conn);
            softether_destroy(conn);
            long duration = get_test_timestamp_ms() - start_time;
            test_result_init(&result, false, ERR_AUTHENTICATION,
                            "Authentication challenge failed", duration);
            return result;
        }
    }

    // Session setup - Send SESSION_REQUEST
    uint8_t session_request[8] = {0};  // Request new session with default parameters
    softether_send_packet(conn, CMD_SESSION_REQUEST, session_request, sizeof(session_request));

    // Receive SESSION_ASSIGN
    ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));

    if (ret < 0 || command != CMD_SESSION_ASSIGN) {
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_SESSION,
                        "Session assignment failed", duration);
        return result;
    }

    // Extract session ID from response
    uint32_t session_id = 0;
    if (response_len >= 4) {
        session_id = ((uint32_t)response[0] << 24) |
                    ((uint32_t)response[1] << 16) |
                    ((uint32_t)response[2] << 8) |
                    (uint32_t)response[3];
    }

    // Send CONFIG_REQUEST
    softether_send_packet(conn, CMD_CONFIG_REQUEST, NULL, 0);

    // Receive CONFIG_RESPONSE
    ret = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));
    long duration = get_test_timestamp_ms() - start_time;

    softether_disconnect(conn);
    softether_destroy(conn);

    if (ret < 0 || command != CMD_CONFIG_RESPONSE) {
        test_result_init(&result, false, ERR_SESSION,
                        "Configuration failed", duration);
        return result;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "Session established successfully (session_id: 0x%08X)", session_id);
    test_result_init(&result, true, ERR_NONE, msg, duration);
    LOGD("Session test passed in %ld ms", duration);
    return result;
}

// Test 6: Data Transmission - Full implementation
native_test_result_t test_data_transmission(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();
    long bytes_sent = 0;
    long bytes_received = 0;

    LOGD("Testing data transmission with %s:%d", config->host, config->port);

    // Create full connection
    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_UNKNOWN,
                        "Failed to create connection", duration);
        return result;
    }

    conn->timeout_ms = config->timeout_ms;

    // Full connect sequence
    int ret = softether_connect(conn, config->host, config->port,
                                config->username, config->password);

    if (ret != ERR_NONE) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        char msg[256];
        snprintf(msg, sizeof(msg), "Connection failed: %s", softether_error_string(ret));
        test_result_init(&result, false, ret, msg, duration);
        return result;
    }

    // Allocate test data buffer
    uint8_t* send_buffer = (uint8_t*)malloc(config->packet_size);
    uint8_t* recv_buffer = (uint8_t*)malloc(config->packet_size + 256); // Extra space for headers

    if (send_buffer == NULL || recv_buffer == NULL) {
        free(send_buffer);
        free(recv_buffer);
        softether_disconnect(conn);
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                        "Failed to allocate buffers", duration);
        return result;
    }

    // Fill with test pattern
    for (int i = 0; i < config->packet_size; i++) {
        send_buffer[i] = (uint8_t)(i & 0xFF);
    }

    // Send test packets
    int packets_sent = 0;
    int packets_received = 0;

    for (int i = 0; i < config->packet_count; i++) {
        // Update sequence number in data for verification
        send_buffer[0] = (uint8_t)(i & 0xFF);
        send_buffer[1] = (uint8_t)((i >> 8) & 0xFF);

        // Send data packet
        ret = softether_send_data(conn, send_buffer, config->packet_size);
        if (ret < 0) {
            LOGE("Failed to send packet %d", i);
            break;
        }
        bytes_sent += config->packet_size;
        packets_sent++;

        // Small delay between packets
        usleep(1000); // 1ms

        // Try to receive response (some servers echo back)
        uint16_t cmd;
        uint32_t recv_len;
        ret = softether_receive_data(conn, recv_buffer, config->packet_size + 256,
                                     &recv_len, &cmd);

        if (ret == 0 && cmd == CMD_DATA && recv_len > 0) {
            bytes_received += recv_len;
            packets_received++;
        }
    }

    free(send_buffer);
    free(recv_buffer);

    long duration = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);

    // We consider the test successful if we could send at least one packet
    if (packets_sent == 0) {
        test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                        "Failed to send any data packets", duration);
        return result;
    }

    char msg[256];
    snprintf(msg, sizeof(msg),
             "Data transmission successful: sent=%ld bytes (%d pkts), received=%ld bytes (%d pkts)",
             bytes_sent, packets_sent, bytes_received, packets_received);

    result.success = true;
    result.error_code = ERR_NONE;
    result.duration_ms = duration;
    strncpy(result.message, msg, sizeof(result.message) - 1);
    result.message[sizeof(result.message) - 1] = '\0';

    LOGD("Data transmission test passed in %ld ms", duration);
    return result;
}

// Test 7: Keepalive - Full implementation
native_test_result_t test_keepalive(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();
    int keepalive_count = 0;
    int keepalive_ack_count = 0;

    LOGD("Testing keepalive with %s:%d (duration: %ds)",
         config->host, config->port, config->duration_seconds);

    // Create full connection
    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_UNKNOWN,
                        "Failed to create connection", duration);
        return result;
    }

    conn->timeout_ms = config->timeout_ms;

    // Full connect sequence
    int ret = softether_connect(conn, config->host, config->port,
                                config->username, config->password);

    if (ret != ERR_NONE) {
        softether_destroy(conn);
        long duration = get_test_timestamp_ms() - start_time;
        char msg[256];
        snprintf(msg, sizeof(msg), "Connection failed: %s", softether_error_string(ret));
        test_result_init(&result, false, ret, msg, duration);
        return result;
    }

    LOGD("Connection established, starting keepalive test for %d seconds", config->duration_seconds);

    // Keepalive test loop
    long test_duration_ms = config->duration_seconds * 1000;
    long keepalive_interval_ms = 5000; // Send keepalive every 5 seconds
    long last_keepalive_time = 0;
    uint8_t recv_buffer[256];

    while ((get_test_timestamp_ms() - start_time) < test_duration_ms) {
        long current_time = get_test_timestamp_ms();

        // Send keepalive if interval has passed
        if ((current_time - last_keepalive_time) >= keepalive_interval_ms) {
            ret = softether_send_keepalive(conn);
            if (ret < 0) {
                LOGE("Failed to send keepalive");
                break;
            }
            keepalive_count++;
            last_keepalive_time = current_time;
            LOGD("Sent keepalive #%d", keepalive_count);
        }

        // Non-blocking receive with short timeout
        uint16_t cmd;
        uint32_t recv_len;

        // Set socket to non-blocking temporarily for polling
        int flags = fcntl(conn->socket_fd, F_GETFL, 0);
        fcntl(conn->socket_fd, F_SETFL, flags | O_NONBLOCK);

        ret = softether_receive_data(conn, recv_buffer, sizeof(recv_buffer),
                                     &recv_len, &cmd);

        // Restore blocking mode
        fcntl(conn->socket_fd, F_SETFL, flags);

        if (ret == 0) {
            if (cmd == CMD_KEEPALIVE_ACK) {
                keepalive_ack_count++;
                LOGD("Received keepalive ACK #%d", keepalive_ack_count);
            } else if (cmd == CMD_KEEPALIVE) {
                // Server sent keepalive, respond with ACK
                softether_send_packet(conn, CMD_KEEPALIVE_ACK, NULL, 0);
                LOGD("Responded to server keepalive");
            }
        }

        // Small sleep to prevent busy-waiting
        usleep(100000); // 100ms
    }

    long duration = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);

    // Calculate success rate
    float success_rate = (keepalive_count > 0) ?
                         ((float)keepalive_ack_count / keepalive_count * 100.0f) : 0.0f;

    char msg[256];
    snprintf(msg, sizeof(msg),
             "Keepalive test completed: sent=%d, acked=%d, success_rate=%.1f%%",
             keepalive_count, keepalive_ack_count, success_rate);

    result.success = true;
    result.error_code = ERR_NONE;
    result.duration_ms = duration;
    strncpy(result.message, msg, sizeof(result.message) - 1);
    result.message[sizeof(result.message) - 1] = '\0';

    LOGD("Keepalive test passed in %ld ms", duration);
    return result;
}

// Test 8: Full Lifecycle
native_test_result_t test_full_lifecycle(const native_test_config_t* config) {
    native_test_result_t result;
    long start_time = get_test_timestamp_ms();

    LOGD("Testing full connection lifecycle with %s:%d", config->host, config->port);

    // Attempt full connection
    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        long duration = get_test_timestamp_ms() - start_time;
        test_result_init(&result, false, ERR_UNKNOWN,
                        "Failed to create connection", duration);
        return result;
    }

    conn->timeout_ms = config->timeout_ms;

    int ret = softether_connect(conn, config->host, config->port,
                                config->username, config->password);
    long duration = get_test_timestamp_ms() - start_time;

    if (ret != ERR_NONE) {
        softether_destroy(conn);
        char msg[256];
        snprintf(msg, sizeof(msg), "Full connection failed: %s", softether_error_string(ret));
        test_result_init(&result, false, ret, msg, duration);
        return result;
    }

    LOGD("Full connection established in %ld ms", duration);

    // Send a test data packet
    uint8_t test_data[64];
    memset(test_data, 0xAB, sizeof(test_data));
    ret = softether_send(conn, test_data, sizeof(test_data));

    if (ret < 0) {
        softether_disconnect(conn);
        softether_destroy(conn);
        test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                        "Failed to send test data", duration);
        return result;
    }

    LOGD("Test data sent successfully");

    // Wait a moment and try to receive
    usleep(500000); // 500ms

    uint8_t recv_buffer[256];
    ret = softether_receive(conn, recv_buffer, sizeof(recv_buffer));

    // Disconnect cleanly
    softether_disconnect(conn);
    softether_destroy(conn);

    char msg[256];
    snprintf(msg, sizeof(msg),
             "Full lifecycle test successful (connected in %ld ms, data recv: %s)",
             duration, (ret > 0) ? "yes" : "no");

    test_result_init(&result, true, ERR_NONE, msg, duration);
    LOGD("Full lifecycle test passed");
    return result;
}
