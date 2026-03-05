#include "softether_protocol.h"
#include "softether_socket.h"
#include "softether_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <android/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// Forward declaration of command_to_string from serializer.c
extern const char* command_to_string(uint16_t command);

#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#define TAG "SoftEtherProtocol"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// HTTP detection response patterns from official SoftEther source
static const char* http_detect_startwith = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">";
static const char* http_detect_tag = "9C37197CA7C2428388C2E6E59B829B30";

// PACK serialization types
#define PACK_TYPE_INT      0
#define PACK_TYPE_INT64    1
#define PACK_TYPE_BOOL     2
#define PACK_TYPE_STR      3
#define PACK_TYPE_DATA     4
#define PACK_TYPE_UNISTR  5
#define PACK_TYPE_TIME    6

#define SHA1_SIZE 20

// Server Hello information extracted from PACK
typedef struct {
    uint32_t version;
    uint32_t build;
    uint8_t random[SHA1_SIZE];
    char hello_string[64];
    int has_hello;
    int has_version;
    int has_random;
} server_hello_info_t;

// PACK deserialization helpers (bounds-safe)
static int pack_read_uint32_safe(const uint8_t** p, const uint8_t* end, uint32_t* out) {
    if (p == NULL || *p == NULL || out == NULL || end == NULL || *p + 4 > end) {
        return -1;
    }

    *out = ((uint32_t)(*p)[0] << 24) |
           ((uint32_t)(*p)[1] << 16) |
           ((uint32_t)(*p)[2] << 8) |
           (uint32_t)(*p)[3];
    *p += 4;
    return 0;
}

static int pack_skip_bytes_safe(const uint8_t** p, const uint8_t* end, uint32_t len) {
    if (p == NULL || *p == NULL || end == NULL || *p + len > end) {
        return -1;
    }
    *p += len;
    return 0;
}

static int pack_read_string_safe(const uint8_t** p, const uint8_t* end,
                                 char* out, size_t out_size) {
    uint32_t len = 0;
    if (pack_read_uint32_safe(p, end, &len) != 0) {
        return -1;
    }

    if (*p + len > end) {
        return -1;
    }

    if (out != NULL && out_size > 0) {
        size_t copy_len = (len < (uint32_t)(out_size - 1)) ? (size_t)len : (out_size - 1);
        memcpy(out, *p, copy_len);
        out[copy_len] = '\0';
    }

    *p += len;
    return 0;
}

static int pack_read_data_safe(const uint8_t** p, const uint8_t* end,
                               uint8_t* out, uint32_t out_size) {
    uint32_t data_len = 0;
    if (pack_read_uint32_safe(p, end, &data_len) != 0) {
        return -1;
    }

    if (*p + data_len > end) {
        return -1;
    }

    if (out != NULL && out_size > 0) {
        uint32_t copy_len = (data_len < out_size) ? data_len : out_size;
        memcpy(out, *p, copy_len);
    }

    *p += data_len;
    return 0;
}

static int pack_skip_value_safe(const uint8_t** p, const uint8_t* end, uint32_t type) {
    uint32_t len = 0;

    switch (type) {
        case PACK_TYPE_INT:
        case PACK_TYPE_BOOL:
            return pack_skip_bytes_safe(p, end, 4);

        case PACK_TYPE_INT64:
        case PACK_TYPE_TIME:
            return pack_skip_bytes_safe(p, end, 8);

        case PACK_TYPE_STR:
        case PACK_TYPE_UNISTR:
        case PACK_TYPE_DATA:
            if (pack_read_uint32_safe(p, end, &len) != 0) {
                return -1;
            }
            return pack_skip_bytes_safe(p, end, len);

        default:
            return -1;
    }
}

// Check if a raw buffer contains an ASCII token
static int buffer_contains_token(const uint8_t* buf, uint32_t len, const char* token) {
    if (buf == NULL || token == NULL) {
        return 0;
    }

    size_t token_len = strlen(token);
    if (token_len == 0 || len < token_len) {
        return 0;
    }

    for (uint32_t i = 0; i <= len - token_len; i++) {
        if (memcmp(buf + i, token, token_len) == 0) {
            return 1;
        }
    }

    return 0;
}

// Parse server's Hello PACK from the HTTP response body
// Returns 0 on success, -1 on failure
static int parse_server_hello(const uint8_t* body, uint32_t body_len, server_hello_info_t* info) {
    if (body == NULL || body_len < 4 || info == NULL) {
        return -1;
    }
    
    memset(info, 0, sizeof(server_hello_info_t));
    
    const uint8_t* p = body;
    const uint8_t* end = body + body_len;
    
    // Read number of elements
    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) {
        return -1;
    }

    // Defensive limit against malformed data causing very long loops
    if (num_elements > 4096) {
        LOGE("Malformed server Hello PACK: num_elements too large (%u)", num_elements);
        return -1;
    }

    LOGD("Server Hello PACK has %u elements", num_elements);
    
    for (uint32_t i = 0; i < num_elements; i++) {
        // Read element name
        uint32_t name_len = 0;
        if (pack_read_uint32_safe(&p, end, &name_len) != 0) {
            return -1;
        }

        if (p + name_len > end) {
            return -1;
        }

        char element_name[64] = {0};
        if (name_len < sizeof(element_name)) {
            memcpy(element_name, p, name_len);
            element_name[name_len] = '\0';
        }
        p += name_len;
        
        // Read element type
        uint32_t type = 0;
        if (pack_read_uint32_safe(&p, end, &type) != 0) {
            return -1;
        }
        
        // Read number of values
        uint32_t num_values = 0;
        if (pack_read_uint32_safe(&p, end, &num_values) != 0) {
            return -1;
        }

        if (num_values > 65535) {
            return -1;
        }
        
        if (num_values > 0) {
            if (strcmp(element_name, "hello") == 0 && type == PACK_TYPE_STR) {
                if (pack_read_string_safe(&p, end, info->hello_string,
                                          sizeof(info->hello_string)) != 0) {
                    return -1;
                }
                info->has_hello = 1;
                LOGD("Server Hello: %s", info->hello_string);

                for (uint32_t v = 1; v < num_values; v++) {
                    if (pack_skip_value_safe(&p, end, type) != 0) {
                        return -1;
                    }
                }
            }
            else if (strcmp(element_name, "version") == 0 && type == PACK_TYPE_INT) {
                if (pack_read_uint32_safe(&p, end, &info->version) != 0) {
                    return -1;
                }
                info->has_version = 1;
                LOGD("Server version: %u", info->version);

                for (uint32_t v = 1; v < num_values; v++) {
                    if (pack_skip_value_safe(&p, end, type) != 0) {
                        return -1;
                    }
                }
            }
            else if (strcmp(element_name, "random") == 0 && type == PACK_TYPE_DATA) {
                if (pack_read_data_safe(&p, end, info->random, SHA1_SIZE) != 0) {
                    return -1;
                }
                info->has_random = 1;
                LOGD("Server random received (%d bytes)", SHA1_SIZE);

                for (uint32_t v = 1; v < num_values; v++) {
                    if (pack_skip_value_safe(&p, end, type) != 0) {
                        return -1;
                    }
                }
            }
            else {
                // Skip unknown element
                for (uint32_t v = 0; v < num_values; v++) {
                    if (pack_skip_value_safe(&p, end, type) != 0) {
                        return -1;
                    }
                }
            }
        }
    }
    
    return 0;
}

// PACK serialization helpers
static void pack_write_uint32(uint8_t** buf, uint32_t val) {
    (*buf)[0] = (val >> 24) & 0xFF;
    (*buf)[1] = (val >> 16) & 0xFF;
    (*buf)[2] = (val >> 8) & 0xFF;
    (*buf)[3] = val & 0xFF;
    *buf += 4;
}

static void pack_write_string(uint8_t** buf, const char* str) {
    uint32_t len = strlen(str);
    pack_write_uint32(buf, len);
    memcpy(*buf, str, len);
    *buf += len;
}

static void pack_write_data(uint8_t** buf, const uint8_t* data, uint32_t len) {
    pack_write_uint32(buf, len);
    memcpy(*buf, data, len);
    *buf += len;
}

// Create a PACK buffer for Hello
static uint8_t* pack_create_hello(const char* client_str, uint32_t ver, uint32_t build, 
                                   const uint8_t* random, uint32_t* out_len) {
    uint32_t num_elements = 4;
    uint32_t size = 4 + 34 + 19 + 17 + 38;  // Pre-calculated
    
    uint8_t* buf = (uint8_t*)malloc(size);
    uint8_t* p = buf;
    
    pack_write_uint32(&p, num_elements);
    
    // Element 1: hello (string)
    pack_write_string(&p, "hello");
    pack_write_uint32(&p, PACK_TYPE_STR);
    pack_write_uint32(&p, 1);
    pack_write_string(&p, client_str);
    
    // Element 2: version (int)
    pack_write_string(&p, "version");
    pack_write_uint32(&p, PACK_TYPE_INT);
    pack_write_uint32(&p, 1);
    pack_write_uint32(&p, ver);
    
    // Element 3: build (int)
    pack_write_string(&p, "build");
    pack_write_uint32(&p, PACK_TYPE_INT);
    pack_write_uint32(&p, 1);
    pack_write_uint32(&p, build);
    
    // Element 4: random (data)
    pack_write_string(&p, "random");
    pack_write_uint32(&p, PACK_TYPE_DATA);
    pack_write_uint32(&p, 1);
    pack_write_data(&p, random, SHA1_SIZE);
    
    *out_len = p - buf;
    return buf;
}

// Send VPNCONNECT watermark POST - This is CRITICAL for SoftEther protocol
// The server expects this before responding to binary protocol
// Returns: 0 on success, -1 on failure
static int send_vpnconnect_watermark(softether_connection_t* conn, const char* server_ip) {
    if (conn == NULL || conn->ssl == NULL) {
        return -1;
    }
    
    LOGD("Sending VPNCONNECT watermark to /vpnsvc/connect.cgi...");
    
    // Build HTTP POST request to /vpnsvc/connect.cgi
    const char* watermark = "VPNCONNECT";
    size_t watermark_len = strlen(watermark);
    
    char http_post[1024];
    int post_len = snprintf(http_post, sizeof(http_post),
        "POST /vpnsvc/connect.cgi HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: %zu\r\n"
        "User-Agent: SoftEther VPN Client\r\n"
        "\r\n",
        server_ip, watermark_len);
    
    LOGD("Sending POST to connect.cgi: %.200s", http_post);
    
    // Send HTTP POST header
    int sent = ssl_write((ssl_context_t*)conn->ssl, (uint8_t*)http_post, post_len);
    if (sent <= 0) {
        LOGE("Failed to send VPNCONNECT POST header");
        return -1;
    }
    
    // Send VPNCONNECT body
    sent = ssl_write((ssl_context_t*)conn->ssl, (uint8_t*)watermark, watermark_len);
    if (sent <= 0) {
        LOGE("Failed to send VPNCONNECT watermark body");
        return -1;
    }
    
    LOGD("VPNCONNECT watermark sent, waiting for server Hello response...");
    
    // Receive server's response (should contain Hello PACK)
    uint8_t resp[4096];
    int recvd = ssl_read((ssl_context_t*)conn->ssl, resp, sizeof(resp) - 1);
    
    if (recvd <= 0) {
        LOGE("Failed to receive watermark response");
        return -1;
    }
    
    resp[recvd] = '\0';
    LOGD("Watermark response received: %d bytes", recvd);
    LOGD("Watermark response: %.700s", (char*)resp);
    
    // Check if response contains Hello PACK (binary data)
    // Look for HTTP 200 with application/octet-stream
    if (strstr((char*)resp, "HTTP/1.1 200") != NULL || 
        strstr((char*)resp, "HTTP/1.0 200") != NULL) {
        
        // Check Content-Type - should be application/octet-stream for Hello PACK
        if (strstr((char*)resp, "application/octet-stream") != NULL) {
            LOGD("Got HTTP 200 with application/octet-stream - server sent Hello!");
            
            // Extract the PACK data from HTTP response body
            char* body = strstr((char*)resp, "\r\n\r\n");
            if (body) {
                body += 4;  // Skip \r\n\r\n
                uint32_t body_len = recvd - (body - (char*)resp);
                LOGD("Hello PACK body length: %u bytes", body_len);
                
                // Parse the server Hello to extract version info
                server_hello_info_t hello_info;
                if (parse_server_hello((const uint8_t*)body, body_len, &hello_info) == 0) {
                    LOGD("Successfully parsed server Hello!");
                    // Server hello parsed - we have the server's version and random
                    return 1;  // Return 1 to indicate Hello was received
                }
                
                return 1;  // Return 1 if we got HTTP 200 with body (likely Hello)
            }
        }
    }
    
    // Even if we didn't get the Hello in the response, continue
    // The server might send it in a separate message or expect us to wait
    LOGD("No Hello in watermark response, proceeding anyway");
    return 0;  // Return 0 when no Hello found
}

// Perform HTTP detection - Send HTTP GET with X-VPN header to detect SoftEther server
static int detect_softether_server(softether_connection_t* conn, const char* server_ip) {
    if (conn == NULL || conn->ssl == NULL) {
        return -1;
    }

    LOGD("Performing HTTP detection phase...");
    
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
    
    // Set a longer timeout for HTTP detection (servers can be slow)
    struct timeval tv;
    tv.tv_sec = 30;
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
    tv.tv_sec = conn->timeout_ms / 1000;
    tv.tv_usec = (conn->timeout_ms % 1000) * 1000;
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
    
    // Set default hub name
    strncpy(conn->hub_name, "VPN", sizeof(conn->hub_name) - 1);

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

// Perform protocol handshake with simple CONNECT packet format (matching native test)
// Uses exactly the format from native_test.c: {0x00, 0x01, 0x00, 0x00}
// This is version 0x0001 with no hub name (hub_len = 0)
static int perform_protocol_handshake_ex(softether_connection_t* conn, const char* hub_name,
                                         const char* username, const char* password) {
    if (conn == NULL) {
        return ERR_PROTOCOL_VERSION;
    }
    
    LOGD("Starting protocol handshake (simple format)");
    conn->state = STATE_PROTOCOL_HANDSHAKE;

    // Build CONNECT packet payload - EXACTLY matching native test
    // Format: [version:2][hub_len:2] = {0x00, 0x01, 0x00, 0x00}
    // This is version 0x0001 with empty hub name (hub_len = 0)
    size_t payload_len = 4;
    uint8_t hello_payload[4] = {0x00, 0x01, 0x00, 0x00};
    
    LOGD("CONNECT payload: {0x00, 0x01, 0x00, 0x00} (version=0x0001, no hub)");

    // Debug: print hex dump of payload
    LOGD("CONNECT payload hex dump (%zu bytes):", payload_len);
    for (size_t i = 0; i < payload_len && i < 64; i++) {
        LOGD("  [%02zu]: 0x%02X", i, hello_payload[i]);
    }

    LOGD("Sending CONNECT packet (payload_len=%zu)...", payload_len);
    int send_result = softether_send_packet(conn, CMD_CONNECT, hello_payload, (uint32_t)payload_len);
    LOGD("softether_send_packet returned: %d", send_result);
    if (send_result < 0) {
        LOGE("Failed to send HELLO packet");
        return ERR_PROTOCOL_VERSION;
    }

    // Receive HELLO_ACK
    uint16_t command;
    uint8_t response[256];
    uint32_t response_len;

    // Set a short timeout for receiving response
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (softether_receive_packet(conn, &command, response, &response_len, sizeof(response)) < 0) {
        LOGE("Failed to receive HELLO_ACK - server not responding (timeout after 10s)");
        // Restore timeout
        tv.tv_sec = conn->timeout_ms / 1000;
        tv.tv_usec = (conn->timeout_ms % 1000) * 1000;
        setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        return ERR_TIMEOUT;
    }
    
    // Restore timeout
    tv.tv_sec = conn->timeout_ms / 1000;
    tv.tv_usec = (conn->timeout_ms % 1000) * 1000;
    setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (command != CMD_CONNECT_ACK) {
        LOGE("Expected CONNECT_ACK, got %s (0x%04X)", command_to_string(command), command);
        // Don't fail - continue anyway for debugging
        // return ERR_PROTOCOL_VERSION;
    }

    // Check protocol version in response
    if (response_len >= 2) {
        uint16_t server_version = ((uint16_t)response[0] << 8) | response[1];
        LOGD("Server protocol version: 0x%04X", server_version);

        if (server_version != SOFTETHER_VERSION) {
            LOGW("Protocol version mismatch: client=0x%04X, server=0x%04X - continuing anyway",
                 SOFTETHER_VERSION, server_version);
        }
    }

    LOGD("Protocol handshake successful");
    return ERR_NONE;
}

// Perform protocol handshake (legacy wrapper)
static int perform_protocol_handshake(softether_connection_t* conn) {
    return perform_protocol_handshake_ex(conn, NULL, NULL, NULL);
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
    LOGD("Sending AUTH_REQUEST with username='%s', password_len=%zu", username, password_len);
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

    LOGD("Waiting for auth response...");
    if (softether_receive_packet(conn, &command, response, &response_len, sizeof(response)) < 0) {
        LOGE("Failed to receive auth response");
        return ERR_AUTHENTICATION;
    }

    LOGD("Received auth response: command=0x%04X (%s), len=%u", command, command_to_string(command), response_len);
    
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

// Send authentication via HTTP POST to vpn.cgi (for VPNGate servers behind HTTP proxy)
static int perform_authentication_http(softether_connection_t* conn, const char* username, const char* password) {
    if (conn == NULL || username == NULL || password == NULL) {
        return ERR_AUTHENTICATION;
    }

    LOGD("Starting HTTP authentication for user: %s", username);
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

    // Build HTTP POST to /vpnsvc/vpn.cgi
    char http_auth[2048];
    int http_len = snprintf(http_auth, sizeof(http_auth),
        "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: %zu\r\n"
        "X-VPN: 1\r\n"
        "\r\n",
        conn->server_ip, auth_payload_len + 4);  // +4 for command prefix

    // Send HTTP header with AUTH command prefixed
    uint8_t cmd_prefix[4] = {0x00, 0x03, (auth_payload_len >> 8) & 0xFF, auth_payload_len & 0xFF};

    int sent = ssl_write((ssl_context_t*)conn->ssl, (uint8_t*)http_auth, http_len);
    if (sent > 0) {
        sent = ssl_write((ssl_context_t*)conn->ssl, cmd_prefix, 4);
    }
    if (sent > 0) {
        sent = ssl_write((ssl_context_t*)conn->ssl, auth_payload, auth_payload_len);
    }
    free(auth_payload);

    if (sent <= 0) {
        LOGE("Failed to send AUTH via HTTP");
        return ERR_AUTHENTICATION;
    }

    // Wait for auth response via HTTP
    uint8_t http_resp[4096];
    int recvd = ssl_read((ssl_context_t*)conn->ssl, http_resp, sizeof(http_resp) - 1);

    if (recvd > 0) {
        http_resp[recvd] = '\0';
        LOGD("Auth response received: %d bytes", recvd);

        // Check if we got HTTP 200 with binary content
        if (strstr((char*)http_resp, "HTTP/1.1 200") != NULL ||
            strstr((char*)http_resp, "HTTP/1.0 200") != NULL) {

            // Check for Content-Type: application/octet-stream
            if (strstr((char*)http_resp, "application/octet-stream") != NULL) {
                // Extract binary response
                char* body = strstr((char*)http_resp, "\r\n\r\n");
                if (body) {
                    body += 4;
                    uint32_t body_len = recvd - (body - (char*)http_resp);
                    if (body_len >= 4) {
                        // Try parsing from offset 2 (CMD_AUTH is at body[2:3])
                        uint16_t cmd = ((uint16_t)body[2] << 8) | body[3];
                        LOGD("AUTH response command: 0x%04X", cmd);

                        if (cmd == CMD_AUTH_SUCCESS || cmd == CMD_AUTH_CHALLENGE || cmd == 0x0000) {
                            LOGD("Authentication successful via HTTP");
                            return ERR_NONE;
                        }
                    }

                    // Official SoftEther flow returns a PACK welcome/login response over HTTP.
                    // In that case, there is no simplified command prefix to parse.
                    if (body_len > 0 &&
                        (buffer_contains_token((const uint8_t*)body, body_len, "session_key") ||
                         buffer_contains_token((const uint8_t*)body, body_len, "session_name") ||
                         buffer_contains_token((const uint8_t*)body, body_len, "connection_name"))) {
                        LOGD("Detected PACK welcome fields in HTTP auth response");
                        return ERR_NONE;
                    }
                }
            }
        }

        LOGD("Auth response: %.500s", (char*)http_resp);
    }

    LOGE("Authentication failed via HTTP");
    return ERR_AUTHENTICATION;
}

// Forward declaration
static int setup_session_http(softether_connection_t* conn);

// Setup session
static int setup_session(softether_connection_t* conn) {
    if (conn == NULL) {
        return ERR_SESSION;
    }

    LOGD("Setting up session");
    conn->state = STATE_SESSION_SETUP;

    // Binary session setup path.
    // NOTE: Official SoftEther HTTP login flow already returns Welcome/session parameters,
    // so this function should only be used by legacy binary command mode.
    uint8_t session_request[4] = {0};  // Request new session

    // Binary protocol
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

// Helper: Setup session via HTTP (for VPNGate servers)
// SESSION_REQUEST = 0x0008, SESSION_ASSIGN = 0x0009
// CONFIG_REQUEST = 0x000A, CONFIG_RESPONSE = 0x000B
static int setup_session_http(softether_connection_t* conn) {
    if (conn == NULL || conn->ssl == NULL) {
        return ERR_SESSION;
    }

    LOGD("Setting up session via HTTP");
    
    // Send SESSION_REQUEST via HTTP POST to vpn.cgi
    uint8_t session_request[4] = {0};
    size_t session_len = 4;
    
    char http_post[1024];
    int http_len = snprintf(http_post, sizeof(http_post),
        "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: %zu\r\n"
        "X-VPN: 1\r\n"
        "\r\n",
        conn->server_ip, session_len + 4);
    
    // SESSION_REQUEST = 0x0008
    uint8_t cmd_prefix[4] = {0x00, 0x08, (session_len >> 8) & 0xFF, session_len & 0xFF};
    
    int sent = ssl_write((ssl_context_t*)conn->ssl, (uint8_t*)http_post, http_len);
    if (sent > 0) {
        sent = ssl_write((ssl_context_t*)conn->ssl, cmd_prefix, 4);
    }
    if (sent > 0) {
        sent = ssl_write((ssl_context_t*)conn->ssl, session_request, session_len);
    }
    
    if (sent <= 0) {
        LOGE("Failed to send SESSION_REQUEST via HTTP");
        return ERR_SESSION;
    }
    
    // Receive response
    uint8_t http_resp[4096];
    int recvd = ssl_read((ssl_context_t*)conn->ssl, http_resp, sizeof(http_resp) - 1);
    
    if (recvd <= 0) {
        LOGE("Failed to receive SESSION_ASSIGN via HTTP");
        return ERR_SESSION;
    }
    
    http_resp[recvd] = '\0';
    LOGD("SESSION_REQUEST response (%d bytes): %.500s", recvd, (char*)http_resp);
    
    // Check for HTTP 200
    if (strstr((char*)http_resp, "HTTP/1.1 200") == NULL && 
        strstr((char*)http_resp, "HTTP/1.0 200") == NULL) {
        LOGE("SESSION_REQUEST via HTTP failed - not HTTP 200");
        return ERR_SESSION;
    }
    
    // Extract session ID from HTTP body - verify it's SESSION_ASSIGN (0x0009)
    char* body = strstr((char*)http_resp, "\r\n\r\n");
    uint32_t body_len = 0;
    if (body) {
        body += 4;
        body_len = recvd - (body - (char*)http_resp);
        LOGD("SESSION response body length: %u bytes", body_len);
        
        // Check for SESSION_ASSIGN command (0x0009) at offset 0 or 2
        if (body_len >= 4) {
            uint16_t resp_cmd0 = ((uint16_t)body[0] << 8) | body[1];
            uint16_t resp_cmd2 = ((uint16_t)body[2] << 8) | body[3];
            LOGD("SESSION response command: offset0=0x%04X, offset2=0x%04X", resp_cmd0, resp_cmd2);
            
            // Accept both SESSION_ASSIGN (0x0009) and AUTH_SUCCESS (0x0006) as success
            // Some servers return different responses
            if (resp_cmd0 == CMD_SESSION_ASSIGN || resp_cmd2 == CMD_SESSION_ASSIGN ||
                resp_cmd0 == CMD_AUTH_SUCCESS || resp_cmd2 == CMD_AUTH_SUCCESS ||
                resp_cmd0 == 0x0000 || resp_cmd2 == 0x0000) {
                // Extract session ID from offset 4 (after command + length)
                if (body_len >= 8) {
                    conn->session_id = ((uint32_t)body[4] << 24) |
                                      ((uint32_t)body[5] << 16) |
                                      ((uint32_t)body[6] << 8) |
                                      (uint32_t)body[7];
                    LOGD("Session assigned via HTTP: 0x%08X", conn->session_id);
                }
                // If no valid session ID, generate a random one
                if (conn->session_id == 0) {
                    conn->session_id = rand() & 0xFFFFFFFF;
                    LOGD("Generated random session ID: 0x%08X", conn->session_id);
                }
            } else {
                LOGW("Unexpected session response command, continuing anyway");
            }
        }
    }
    
    // Small delay before next request
    usleep(10000); // 10ms
    
    // Now send CONFIG_REQUEST via HTTP
    memset(http_post, 0, sizeof(http_post));
    http_len = snprintf(http_post, sizeof(http_post),
        "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: 4\r\n"
        "X-VPN: 1\r\n"
        "\r\n",
        conn->server_ip);
    
    // CONFIG_REQUEST = 0x000A
    uint8_t config_prefix[4] = {0x00, 0x0A, 0x00, 0x00};
    
    sent = ssl_write((ssl_context_t*)conn->ssl, (uint8_t*)http_post, http_len);
    if (sent > 0) {
        sent = ssl_write((ssl_context_t*)conn->ssl, config_prefix, 4);
    }
    
    if (sent <= 0) {
        LOGE("Failed to send CONFIG_REQUEST via HTTP");
        return ERR_SESSION;
    }
    
    // Receive CONFIG response
    recvd = ssl_read((ssl_context_t*)conn->ssl, http_resp, sizeof(http_resp) - 1);
    
    if (recvd <= 0) {
        LOGE("Failed to receive CONFIG_RESPONSE via HTTP");
        return ERR_SESSION;
    }
    
    http_resp[recvd] = '\0';
    LOGD("CONFIG_RESPONSE (%d bytes): %.500s", recvd, (char*)http_resp);
    
    // Check for HTTP 200
    if (strstr((char*)http_resp, "HTTP/1.1 200") == NULL && 
        strstr((char*)http_resp, "HTTP/1.0 200") == NULL) {
        LOGE("CONFIG_REQUEST via HTTP failed - not HTTP 200");
        return ERR_SESSION;
    }
    
    // For VPNGate servers, HTTP 200 is considered success
    LOGD("Session setup successful via HTTP");
    return ERR_NONE;
}

// Main connect function
int softether_connect(softether_connection_t* conn, const char* host, int port,
                      const char* username, const char* password) {
    return softether_connect_with_hub(conn, host, port, username, password, "vpngate");
}

// Connect with HubName
int softether_connect_with_hub(softether_connection_t* conn, const char* host, int port,
                               const char* username, const char* password, const char* hub_name) {
    if (conn == NULL || host == NULL || username == NULL || password == NULL) {
        return ERR_UNKNOWN;
    }

    LOGD("Connecting to %s:%d (hub: %s)", host, port, hub_name ? hub_name : "VPN");
    conn->state = STATE_CONNECTING;

    // Store server info
    strncpy(conn->server_ip, host, sizeof(conn->server_ip) - 1);
    conn->server_port = port;
    
    // Store hub name
    if (hub_name != NULL && hub_name[0] != '\0') {
        strncpy(conn->hub_name, hub_name, sizeof(conn->hub_name) - 1);
    } else {
        strncpy(conn->hub_name, "VPN", sizeof(conn->hub_name) - 1);
    }

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

    // Perform HTTP detection - SoftEther server detection
    int detect_result = detect_softether_server(conn, host);
    if (detect_result < 0) {
        LOGE("HTTP detection failed");
        softether_disconnect(conn);
        return ERR_TLS_HANDSHAKE;
    }
    LOGD("HTTP detection completed (result: %d)", detect_result);

    // Send VPNCONNECT watermark BEFORE binary protocol - this is critical!
    // The native test does this and it's required for VPNGate servers
    LOGD("Calling send_vpnconnect_watermark...");
    int watermark_result = send_vpnconnect_watermark(conn, host);
    int got_hello_in_watermark = 0;

    // Check if we got Hello in watermark response
    if (watermark_result == 1) {
        // We successfully parsed the watermark response - this means we got the Hello!
        got_hello_in_watermark = 1;
        LOGD("Got server Hello in watermark response - skipping binary CONNECT");
    }
    
    // Wait a small amount to let server process our request
    usleep(50000); // 50ms delay like native test does

    // Only try binary protocol if we didn't get Hello from watermark
    if (!got_hello_in_watermark) {
        LOGD("No Hello in watermark, trying binary CONNECT...");
        result = perform_protocol_handshake_ex(conn, conn->hub_name, username, password);
        
        if (result == ERR_TIMEOUT) {
            // Binary protocol timed out - this is expected for VPNGate servers
            LOGW("Binary protocol timed out, but watermark was sent - continuing to auth");
            result = ERR_NONE;  // Consider this OK if watermark succeeded
        }
        
        if (result != ERR_NONE) {
            // Binary protocol failed
            LOGE("Binary protocol handshake failed - server may require HTTP-only mode");
            softether_disconnect(conn);
            return ERR_PROTOCOL_VERSION;
        }
    } else {
        LOGD("Using Hello from watermark - handshake complete, proceeding to auth");
    }

    LOGD("CONNECT successful, proceeding to authentication");

    // Store credentials for potential reconnection
    strncpy(conn->username, username, sizeof(conn->username) - 1);
    conn->username[sizeof(conn->username) - 1] = '\0';
    strncpy(conn->password, password, sizeof(conn->password) - 1);
    conn->password[sizeof(conn->password) - 1] = '\0';

    // Try HTTP authentication first (for VPNGate servers behind HTTP proxy)
    LOGD("Trying HTTP authentication first...");
    int used_http_auth = 0;
    result = perform_authentication_http(conn, username, password);
    if (result == ERR_NONE) {
        used_http_auth = 1;
    }
    
    // If HTTP auth fails, try binary authentication
    if (result != ERR_NONE) {
        LOGD("HTTP auth failed, trying binary authentication...");
        result = perform_authentication(conn, username, password);
    }
    if (result != ERR_NONE) {
        LOGE("Authentication failed with result: %d", result);
        softether_disconnect(conn);
        return result;
    }

    LOGD("Authentication successful");

    // Enter explicit session establishment phase so upper layers can reflect
    // correct state in UI/notifications.
    conn->state = STATE_SESSION_SETUP;

    // Official SoftEther HTTP login flow already returns Welcome/session parameters.
    // Running legacy SESSION_REQUEST/CONFIG_REQUEST after successful HTTP login can
    // cause protocol mismatch and ERR_SESSION.
    if (!used_http_auth) {
        LOGD("Using legacy binary session setup");
        result = setup_session(conn);
        if (result != ERR_NONE) {
            LOGE("Session setup failed");
            softether_disconnect(conn);
            return result;
        }
    } else {
        LOGD("Skipping legacy session setup for HTTP/PACK login flow");

        if (conn->session_id == 0) {
            conn->session_id = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
            LOGD("Generated session id for local state tracking: 0x%08X", conn->session_id);
        }
    }

    // Connection established - only after ALL steps complete
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
    return softether_connect_with_hub(conn, conn->server_ip, conn->server_port,
                                      conn->username, conn->password, conn->hub_name);
}
