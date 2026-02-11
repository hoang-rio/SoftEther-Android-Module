#include "softether_protocol.h"
#include <string.h>
#include <arpa/inet.h>
#include <android/log.h>

#define TAG "SoftEtherSerializer"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Serialize a packet header to network byte order
int serialize_header(const softether_header_t* header, uint8_t* buffer, size_t buffer_size) {
    if (header == NULL || buffer == NULL || buffer_size < SOFTETHER_HEADER_SIZE) {
        LOGE("Invalid parameters for serialize_header");
        return -1;
    }
    
    uint32_t offset = 0;
    
    // Signature (4 bytes) - already in host byte order, but we convert for consistency
    uint32_t signature_net = htonl(header->signature);
    memcpy(buffer + offset, &signature_net, sizeof(signature_net));
    offset += sizeof(signature_net);
    
    // Version (2 bytes)
    uint16_t version_net = htons(header->version);
    memcpy(buffer + offset, &version_net, sizeof(version_net));
    offset += sizeof(version_net);
    
    // Command (2 bytes)
    uint16_t command_net = htons(header->command);
    memcpy(buffer + offset, &command_net, sizeof(command_net));
    offset += sizeof(command_net);
    
    // Payload length (4 bytes)
    uint32_t payload_length_net = htonl(header->payload_length);
    memcpy(buffer + offset, &payload_length_net, sizeof(payload_length_net));
    offset += sizeof(payload_length_net);
    
    // Session ID (4 bytes)
    uint32_t session_id_net = htonl(header->session_id);
    memcpy(buffer + offset, &session_id_net, sizeof(session_id_net));
    offset += sizeof(session_id_net);
    
    // Sequence number (4 bytes)
    uint32_t sequence_num_net = htonl(header->sequence_num);
    memcpy(buffer + offset, &sequence_num_net, sizeof(sequence_num_net));
    offset += sizeof(sequence_num_net);
    
    return (int)offset;
}

// Deserialize a packet header from network byte order
int deserialize_header(const uint8_t* buffer, size_t buffer_size, softether_header_t* header) {
    if (header == NULL || buffer == NULL || buffer_size < SOFTETHER_HEADER_SIZE) {
        LOGE("Invalid parameters for deserialize_header");
        return -1;
    }
    
    uint32_t offset = 0;
    
    // Signature (4 bytes)
    uint32_t signature_net;
    memcpy(&signature_net, buffer + offset, sizeof(signature_net));
    header->signature = ntohl(signature_net);
    offset += sizeof(signature_net);
    
    // Version (2 bytes)
    uint16_t version_net;
    memcpy(&version_net, buffer + offset, sizeof(version_net));
    header->version = ntohs(version_net);
    offset += sizeof(version_net);
    
    // Command (2 bytes)
    uint16_t command_net;
    memcpy(&command_net, buffer + offset, sizeof(command_net));
    header->command = ntohs(command_net);
    offset += sizeof(command_net);
    
    // Payload length (4 bytes)
    uint32_t payload_length_net;
    memcpy(&payload_length_net, buffer + offset, sizeof(payload_length_net));
    header->payload_length = ntohl(payload_length_net);
    offset += sizeof(payload_length_net);
    
    // Session ID (4 bytes)
    uint32_t session_id_net;
    memcpy(&session_id_net, buffer + offset, sizeof(session_id_net));
    header->session_id = ntohl(session_id_net);
    offset += sizeof(session_id_net);
    
    // Sequence number (4 bytes)
    uint32_t sequence_num_net;
    memcpy(&sequence_num_net, buffer + offset, sizeof(sequence_num_net));
    header->sequence_num = ntohl(sequence_num_net);
    offset += sizeof(sequence_num_net);
    
    return (int)offset;
}

// Serialize a complete packet (header + payload)
int serialize_packet(const softether_header_t* header, const uint8_t* payload,
                     uint8_t* buffer, size_t buffer_size) {
    if (header == NULL || buffer == NULL || buffer_size < SOFTETHER_HEADER_SIZE) {
        LOGE("Invalid parameters for serialize_packet");
        return -1;
    }
    
    // Validate payload
    if (header->payload_length > 0 && payload == NULL) {
        LOGE("Payload length > 0 but payload is NULL");
        return -1;
    }
    
    // Check buffer size
    size_t total_size = SOFTETHER_HEADER_SIZE + header->payload_length;
    if (buffer_size < total_size) {
        LOGE("Buffer too small: need %zu, have %zu", total_size, buffer_size);
        return -1;
    }
    
    // Serialize header
    int header_size = serialize_header(header, buffer, buffer_size);
    if (header_size < 0) {
        LOGE("Failed to serialize header");
        return -1;
    }
    
    // Copy payload if present
    if (header->payload_length > 0) {
        memcpy(buffer + header_size, payload, header->payload_length);
    }
    
    return (int)(header_size + header->payload_length);
}

// Deserialize a complete packet (header + payload)
int deserialize_packet(const uint8_t* buffer, size_t buffer_size,
                       softether_header_t* header, uint8_t* payload, size_t max_payload_size) {
    if (buffer == NULL || header == NULL || buffer_size < SOFTETHER_HEADER_SIZE) {
        LOGE("Invalid parameters for deserialize_packet");
        return -1;
    }
    
    // Deserialize header
    int header_size = deserialize_header(buffer, buffer_size, header);
    if (header_size < 0) {
        LOGE("Failed to deserialize header");
        return -1;
    }
    
    // Validate signature
    if (header->signature != SOFTETHER_SIGNATURE) {
        LOGE("Invalid signature: expected 0x%08X, got 0x%08X", 
             SOFTETHER_SIGNATURE, header->signature);
        return -1;
    }
    
    // Validate payload length
    if (header->payload_length > SOFTETHER_MAX_PAYLOAD) {
        LOGE("Payload too large: %u", header->payload_length);
        return -1;
    }
    
    // Check if we have enough data
    size_t total_size = SOFTETHER_HEADER_SIZE + header->payload_length;
    if (buffer_size < total_size) {
        LOGE("Incomplete packet: need %zu, have %zu", total_size, buffer_size);
        return -1;
    }
    
    // Copy payload if requested
    if (payload != NULL && header->payload_length > 0) {
        if (max_payload_size < header->payload_length) {
            LOGE("Payload buffer too small: need %u, have %zu",
                 header->payload_length, max_payload_size);
            return -1;
        }
        memcpy(payload, buffer + header_size, header->payload_length);
    }
    
    return (int)total_size;
}

// Create a standard packet header
void create_packet_header(softether_header_t* header, uint16_t command,
                          uint32_t payload_length, uint32_t session_id,
                          uint32_t sequence_num) {
    if (header == NULL) {
        return;
    }
    
    header->signature = SOFTETHER_SIGNATURE;
    header->version = SOFTETHER_VERSION;
    header->command = command;
    header->payload_length = payload_length;
    header->session_id = session_id;
    header->sequence_num = sequence_num;
}

// Get string representation of command
const char* command_to_string(uint16_t command) {
    switch (command) {
        case CMD_CONNECT: return "CONNECT";
        case CMD_CONNECT_ACK: return "CONNECT_ACK";
        case CMD_AUTH: return "AUTH";
        case CMD_AUTH_CHALLENGE: return "AUTH_CHALLENGE";
        case CMD_AUTH_RESPONSE: return "AUTH_RESPONSE";
        case CMD_AUTH_SUCCESS: return "AUTH_SUCCESS";
        case CMD_AUTH_FAIL: return "AUTH_FAIL";
        case CMD_SESSION_REQUEST: return "SESSION_REQUEST";
        case CMD_SESSION_ASSIGN: return "SESSION_ASSIGN";
        case CMD_CONFIG_REQUEST: return "CONFIG_REQUEST";
        case CMD_CONFIG_RESPONSE: return "CONFIG_RESPONSE";
        case CMD_DATA: return "DATA";
        case CMD_KEEPALIVE: return "KEEPALIVE";
        case CMD_KEEPALIVE_ACK: return "KEEPALIVE_ACK";
        case CMD_DISCONNECT: return "DISCONNECT";
        case CMD_DISCONNECT_ACK: return "DISCONNECT_ACK";
        case CMD_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

// Calculate packet size
size_t calculate_packet_size(uint32_t payload_length) {
    return SOFTETHER_HEADER_SIZE + payload_length;
}

// Validate packet buffer
int validate_packet_buffer(const uint8_t* buffer, size_t buffer_size) {
    if (buffer == NULL || buffer_size < SOFTETHER_HEADER_SIZE) {
        return -1;
    }
    
    // Peek at signature
    uint32_t signature_net;
    memcpy(&signature_net, buffer, sizeof(signature_net));
    uint32_t signature = ntohl(signature_net);
    
    if (signature != SOFTETHER_SIGNATURE) {
        return -1;
    }
    
    return 0;
}

// Peek at payload length without full deserialization
int peek_payload_length(const uint8_t* buffer, size_t buffer_size, uint32_t* payload_length) {
    if (buffer == NULL || buffer_size < SOFTETHER_HEADER_SIZE || payload_length == NULL) {
        return -1;
    }
    
    // Payload length is at offset 8 (after signature, version, command)
    uint32_t payload_length_net;
    memcpy(&payload_length_net, buffer + 8, sizeof(payload_length_net));
    *payload_length = ntohl(payload_length_net);
    
    return 0;
}
