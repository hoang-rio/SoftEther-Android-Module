#include "softether_protocol.h"
#include "softether_socket.h"
#include "softether_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <android/log.h>

#define TAG "SoftEtherPacket"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Send a packet through the connection
int softether_send_packet(softether_connection_t* conn, uint16_t command,
                          const uint8_t* payload, uint32_t payload_len) {
    if (conn == NULL) {
        LOGE("Connection is NULL");
        return -1;
    }
    
    if (conn->socket_fd < 0) {
        LOGE("Socket not connected");
        return -1;
    }
    
    // Create packet header
    softether_header_t header;
    create_packet_header(&header, command, payload_len, conn->session_id, conn->sequence_num++);
    
    // Calculate total packet size
    size_t packet_size = SOFTETHER_HEADER_SIZE + payload_len;
    uint8_t* packet = (uint8_t*)malloc(packet_size);
    if (packet == NULL) {
        LOGE("Failed to allocate packet buffer");
        return -1;
    }
    
    // Serialize the packet
    int serialized_size = serialize_packet(&header, payload, packet, packet_size);
    if (serialized_size < 0) {
        LOGE("Failed to serialize packet");
        free(packet);
        return -1;
    }
    
    // Send through SSL if available, otherwise through plain socket
    int bytes_sent = 0;
    if (conn->ssl != NULL) {
        bytes_sent = ssl_write((ssl_context_t*)conn->ssl, packet, serialized_size);
    } else {
        // Create a temporary socket wrapper for plain socket send
        softether_socket_t temp_sock;
        temp_sock.fd = conn->socket_fd;
        temp_sock.connected = 1;
        temp_sock.timeout_ms = conn->timeout_ms;
        bytes_sent = socket_send_all(&temp_sock, packet, serialized_size, conn->timeout_ms);
    }
    
    free(packet);
    
    if (bytes_sent < 0) {
        LOGE("Failed to send packet");
        return -1;
    }
    
    LOGD("Sent packet: cmd=%s(0x%04X), payload=%u bytes", 
         command_to_string(command), command, payload_len);
    
    return bytes_sent;
}

// Receive a packet from the connection
int softether_receive_packet(softether_connection_t* conn, uint16_t* command,
                             uint8_t* payload, uint32_t* payload_len, uint32_t max_payload) {
    if (conn == NULL || command == NULL) {
        LOGE("Invalid parameters");
        return -1;
    }
    
    if (conn->socket_fd < 0) {
        LOGE("Socket not connected");
        return -1;
    }
    
    // First, receive the header
    uint8_t header_buffer[SOFTETHER_HEADER_SIZE];
    int header_received = 0;
    
    if (conn->ssl != NULL) {
        // Receive through SSL
        while (header_received < SOFTETHER_HEADER_SIZE) {
            int ret = ssl_read((ssl_context_t*)conn->ssl, 
                              header_buffer + header_received, 
                              SOFTETHER_HEADER_SIZE - header_received);
            if (ret <= 0) {
                LOGE("SSL read failed during header receive");
                return -1;
            }
            header_received += ret;
        }
    } else {
        // Receive through plain socket
        softether_socket_t temp_sock;
        temp_sock.fd = conn->socket_fd;
        temp_sock.connected = 1;
        temp_sock.timeout_ms = conn->timeout_ms;
        header_received = socket_recv_all(&temp_sock, header_buffer, SOFTETHER_HEADER_SIZE, conn->timeout_ms);
        if (header_received < 0) {
            LOGE("Socket receive failed during header receive");
            return -1;
        }
    }
    
    // Deserialize header
    softether_header_t header;
    if (deserialize_header(header_buffer, SOFTETHER_HEADER_SIZE, &header) < 0) {
        LOGE("Failed to deserialize header");
        return -1;
    }
    
    // Validate signature
    if (header.signature != SOFTETHER_SIGNATURE) {
        LOGE("Invalid packet signature: 0x%08X", header.signature);
        return -1;
    }
    
    // Validate version
    if (header.version != SOFTETHER_VERSION) {
        LOGE("Unsupported protocol version: %u", header.version);
        return -1;
    }
    
    // Check payload size
    if (header.payload_length > max_payload) {
        LOGE("Payload too large: %u > %u", header.payload_length, max_payload);
        return -1;
    }
    
    *command = header.command;
    
    // Receive payload if present
    if (header.payload_length > 0) {
        if (payload == NULL || payload_len == NULL) {
            LOGE("Payload expected but buffer is NULL");
            return -1;
        }
        
        int payload_received = 0;
        
        if (conn->ssl != NULL) {
            // Receive payload through SSL
            while (payload_received < (int)header.payload_length) {
                int ret = ssl_read((ssl_context_t*)conn->ssl,
                                  payload + payload_received,
                                  header.payload_length - payload_received);
                if (ret <= 0) {
                    LOGE("SSL read failed during payload receive");
                    return -1;
                }
                payload_received += ret;
            }
        } else {
            // Receive payload through plain socket
            softether_socket_t temp_sock;
            temp_sock.fd = conn->socket_fd;
            temp_sock.connected = 1;
            temp_sock.timeout_ms = conn->timeout_ms;
            payload_received = socket_recv_all(&temp_sock, payload, header.payload_length, conn->timeout_ms);
            if (payload_received < 0) {
                LOGE("Socket receive failed during payload receive");
                return -1;
            }
        }
        
        *payload_len = header.payload_length;
    } else {
        if (payload_len != NULL) {
            *payload_len = 0;
        }
    }
    
    // Update session ID if provided by server
    if (header.session_id != 0 && header.session_id != conn->session_id) {
        conn->session_id = header.session_id;
        LOGD("Session ID updated to: 0x%08X", conn->session_id);
    }
    
    LOGD("Received packet: cmd=%s(0x%04X), payload=%u bytes",
         command_to_string(*command), *command, header.payload_length);
    
    return SOFTETHER_HEADER_SIZE + header.payload_length;
}

// Send keepalive packet
int softether_send_keepalive(softether_connection_t* conn) {
    if (conn == NULL) {
        return -1;
    }
    
    LOGD("Sending keepalive");
    return softether_send_packet(conn, CMD_KEEPALIVE, NULL, 0);
}

// Process keepalive response
int softether_process_keepalive(softether_connection_t* conn) {
    if (conn == NULL) {
        return -1;
    }
    
    uint16_t command;
    uint8_t buffer[256];
    uint32_t payload_len;
    
    int result = softether_receive_packet(conn, &command, buffer, &payload_len, sizeof(buffer));
    if (result < 0) {
        return -1;
    }
    
    if (command != CMD_KEEPALIVE_ACK) {
        LOGE("Expected KEEPALIVE_ACK, got %s", command_to_string(command));
        return -1;
    }
    
    LOGD("Keepalive acknowledged");
    return 0;
}
