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
#include <netinet/tcp.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>

#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#define TAG "SoftEtherProtocol"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// PACK serialization types
// VPNGate server PACK element types (from Pack.h VALUE_* constants)
#define PACK_TYPE_INT      0    // VALUE_INT
#define PACK_TYPE_DATA     1    // VALUE_DATA
#define PACK_TYPE_STR      2    // VALUE_STR
#define PACK_TYPE_UNISTR   3    // VALUE_UNISTR
#define PACK_TYPE_INT64    4    // VALUE_INT64

#define SHA1_SIZE 20

// SoftEther NODE_INFO stores int fields in big-endian byte order via Endian32().
// On little-endian ARM, Endian32 = byte-swap. We need the same for NODE_INFO fields.
static uint32_t softether_endian32(uint32_t x) {
    return __builtin_bswap32(x);
}

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
    // STR value format: uint32(strlen) + strlen bytes (no +1, unlike WriteBufStr)
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
            return pack_skip_bytes_safe(p, end, 4);

        case PACK_TYPE_INT64:
            return pack_skip_bytes_safe(p, end, 8);

        case PACK_TYPE_STR:
        case PACK_TYPE_UNISTR:
        case PACK_TYPE_DATA:
            // All use uint32(len) + len bytes format
            if (pack_read_uint32_safe(p, end, &len) != 0) {
                return -1;
            }
            return pack_skip_bytes_safe(p, end, len);

        default:
            LOGE("pack_skip_value_safe: unknown type %u", type);
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
        // Read element name (WriteBufStr format: uint32(strlen+1) + strlen bytes)
        uint32_t name_len_plus1 = 0;
        if (pack_read_uint32_safe(&p, end, &name_len_plus1) != 0) {
            return -1;
        }
        if (name_len_plus1 == 0) {
            return -1;
        }
        uint32_t name_len = name_len_plus1 - 1;

        if (p + name_len > end) {
            return -1;
        }

        char element_name[64] = {0};
        uint32_t copy_len = (name_len < sizeof(element_name) - 1) ? name_len : (uint32_t)(sizeof(element_name) - 1);
        memcpy(element_name, p, copy_len);
        element_name[copy_len] = '\0';
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
// Verified against official SoftEther source (Pack.c, Memory.c):
//   Element names:  WriteBufStr → uint32(strlen+1) + strlen bytes (no null)
//   Element type:   WriteBufInt  → uint32 big-endian (via Endian32)
//   Num values:     WriteBufInt  → uint32 big-endian
//   INT value:      WriteBufInt  → uint32 big-endian (via Endian32)
//   STR value:      WriteBufInt(strlen) + strlen bytes (no null) — WriteValue for VALUE_STR
//   DATA value:     WriteBufInt(size) + size bytes
// IMPORTANT: WriteBufInt/ReadBufInt both use Endian32() which converts to/from
// network byte order (big-endian) regardless of host platform.

// Write big-endian uint32 (matching Endian32)
static void pack_write_uint32(uint8_t** buf, uint32_t val) {
    (*buf)[0] = (val >> 24) & 0xFF;
    (*buf)[1] = (val >> 16) & 0xFF;
    (*buf)[2] = (val >> 8) & 0xFF;
    (*buf)[3] = val & 0xFF;
    *buf += 4;
}

// Write element NAME (WriteBufStr format: uint32(strlen+1) + strlen bytes)
static void pack_write_elem_name(uint8_t** buf, const char* name) {
    uint32_t len = (uint32_t)strlen(name);
    pack_write_uint32(buf, len + 1);   // strlen+1
    memcpy(*buf, name, len);           // strlen bytes (no null)
    *buf += len;
}

// Write STR value (simple format: uint32(strlen) + strlen bytes)
static void pack_write_str_val(uint8_t** buf, const char* str) {
    uint32_t len = (uint32_t)strlen(str);
    pack_write_uint32(buf, len);  // STR value: strlen (no +1)
    memcpy(*buf, str, len);
    *buf += len;
}

// Write DATA value (uint32(size) + size bytes)
static void pack_write_data_val(uint8_t** buf, const uint8_t* data, uint32_t len) {
    pack_write_uint32(buf, len);
    if (data && len > 0) {
        memcpy(*buf, data, len);
    }
    *buf += len;
}

// Full element write helpers (name + type + num_values + 1 value)
static void pack_add_int(uint8_t** buf, const char* name, uint32_t val) {
    pack_write_elem_name(buf, name);
    pack_write_uint32(buf, PACK_TYPE_INT);
    pack_write_uint32(buf, 1);    // num_values = 1
    pack_write_uint32(buf, val);
}

static void pack_add_str(uint8_t** buf, const char* name, const char* val) {
    pack_write_elem_name(buf, name);
    pack_write_uint32(buf, PACK_TYPE_STR);
    pack_write_uint32(buf, 1);
    pack_write_str_val(buf, val);
}

static void pack_add_data(uint8_t** buf, const char* name,
                          const uint8_t* data, uint32_t dlen) {
    pack_write_elem_name(buf, name);
    pack_write_uint32(buf, PACK_TYPE_DATA);
    pack_write_uint32(buf, 1);
    pack_write_data_val(buf, data, dlen);
}

// Size calculation macros (WriteBufStr format)
// Element name occupies: 4 + strlen bytes
#define PACK_NAME_SZ(n)       (4 + (uint32_t)strlen(n))
// Element header: name + type(4) + num_values(4)
#define PACK_ELEM_HDR_SZ(n)   (PACK_NAME_SZ(n) + 8)
// Full element sizes (1 value each)
// STR value: 4-byte prefix (stores strlen+1) + strlen data bytes
#define PACK_INT_SZ(n)        (PACK_ELEM_HDR_SZ(n) + 4)
#define PACK_STR_SZ(n, v)     (PACK_ELEM_HDR_SZ(n) + 4 + (uint32_t)strlen(v))
#define PACK_DATA_SZ(n, d)    (PACK_ELEM_HDR_SZ(n) + 4 + (d))

// Parse an integer field from a PACK binary buffer.
// Returns the value via out_val; returns 0 on success, -1 if not found or error.
static int pack_get_int(const uint8_t* body, uint32_t body_len,
                        const char* field_name, uint32_t* out_val) {
    if (!body || body_len < 4 || !field_name || !out_val) return -1;

    const uint8_t* p = body;
    const uint8_t* end = body + body_len;

    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) return -1;
    if (num_elements > 4096) return -1;

    for (uint32_t i = 0; i < num_elements; i++) {
        // Element name: uint32(strlen+1) + strlen bytes
        uint32_t name_len_plus1 = 0;
        if (pack_read_uint32_safe(&p, end, &name_len_plus1) != 0) return -1;
        if (name_len_plus1 == 0) return -1;
        uint32_t name_len = name_len_plus1 - 1;
        if (p + name_len > end) return -1;

        char elem[64] = {0};
        uint32_t cp = (name_len < 63) ? name_len : 63;
        memcpy(elem, p, cp);
        p += name_len;

        uint32_t type = 0, num_values = 0;
        if (pack_read_uint32_safe(&p, end, &type) != 0) return -1;
        if (pack_read_uint32_safe(&p, end, &num_values) != 0) return -1;
        if (num_values > 65535) return -1;

        if (strcmp(elem, field_name) == 0 && type == PACK_TYPE_INT && num_values >= 1) {
            if (pack_read_uint32_safe(&p, end, out_val) != 0) return -1;
            return 0;  // found
        }
        // Skip all values for this element
        for (uint32_t v = 0; v < num_values; v++) {
            if (pack_skip_value_safe(&p, end, type) != 0) return -1;
        }
    }
    return -1;  // not found
}

// Parse a string field from a PACK binary buffer.
// Copies up to out_size-1 chars into out_str (null-terminated).
// Returns 0 on success, -1 if not found or error.
static int pack_get_str(const uint8_t* body, uint32_t body_len,
                        const char* field_name, char* out_str, uint32_t out_size) {
    if (!body || body_len < 4 || !field_name || !out_str || out_size == 0) return -1;

    const uint8_t* p = body;
    const uint8_t* end = body + body_len;

    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) return -1;
    if (num_elements > 4096) return -1;

    for (uint32_t i = 0; i < num_elements; i++) {
        uint32_t name_len_plus1 = 0;
        if (pack_read_uint32_safe(&p, end, &name_len_plus1) != 0) return -1;
        if (name_len_plus1 == 0) return -1;
        uint32_t name_len = name_len_plus1 - 1;
        if (p + name_len > end) return -1;

        char elem[64] = {0};
        uint32_t cp = (name_len < 63) ? name_len : 63;
        memcpy(elem, p, cp);
        p += name_len;

        uint32_t type = 0, num_values = 0;
        if (pack_read_uint32_safe(&p, end, &type) != 0) return -1;
        if (pack_read_uint32_safe(&p, end, &num_values) != 0) return -1;
        if (num_values > 65535) return -1;

        if (strcmp(elem, field_name) == 0 && type == PACK_TYPE_STR && num_values >= 1) {
            // Read string value: uint32(strlen) + strlen bytes
            uint32_t str_len = 0;
            if (pack_read_uint32_safe(&p, end, &str_len) != 0) return -1;
            if (p + str_len > end) return -1;
            uint32_t copy_len = (str_len < out_size - 1) ? str_len : (out_size - 1);
            memcpy(out_str, p, copy_len);
            out_str[copy_len] = '\0';
            return 0;
        }
        for (uint32_t v = 0; v < num_values; v++) {
            if (pack_skip_value_safe(&p, end, type) != 0) return -1;
        }
    }
    return -1;
}

// Parse a DATA field from a PACK binary buffer.
// Copies up to out_size bytes into out_data, sets *out_len to actual size.
// Returns 0 on success, -1 if not found or error.
static int pack_get_data(const uint8_t* body, uint32_t body_len,
                         const char* field_name, uint8_t* out_data,
                         uint32_t out_size, uint32_t* out_len) {
    if (!body || body_len < 4 || !field_name || !out_data || out_size == 0) return -1;

    const uint8_t* p = body;
    const uint8_t* end = body + body_len;

    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) return -1;
    if (num_elements > 4096) return -1;

    for (uint32_t i = 0; i < num_elements; i++) {
        uint32_t name_len_plus1 = 0;
        if (pack_read_uint32_safe(&p, end, &name_len_plus1) != 0) return -1;
        if (name_len_plus1 == 0) return -1;
        uint32_t name_len = name_len_plus1 - 1;
        if (p + name_len > end) return -1;

        char elem[64] = {0};
        uint32_t cp = (name_len < 63) ? name_len : 63;
        memcpy(elem, p, cp);
        p += name_len;

        uint32_t type = 0, num_values = 0;
        if (pack_read_uint32_safe(&p, end, &type) != 0) return -1;
        if (pack_read_uint32_safe(&p, end, &num_values) != 0) return -1;
        if (num_values > 65535) return -1;

        if (strcmp(elem, field_name) == 0 && type == PACK_TYPE_DATA && num_values >= 1) {
            uint32_t data_len = 0;
            if (pack_read_uint32_safe(&p, end, &data_len) != 0) return -1;
            if (p + data_len > end) return -1;
            uint32_t copy_len = (data_len < out_size) ? data_len : out_size;
            memcpy(out_data, p, copy_len);
            if (out_len) *out_len = copy_len;
            return 0;
        }
        for (uint32_t v = 0; v < num_values; v++) {
            if (pack_skip_value_safe(&p, end, type) != 0) return -1;
        }
    }
    return -1;
}
// auth_type: 0 = anonymous, 1 = hashed password, 2 = plain password (RADIUS)
// For password auth, secure_password must be 20 bytes:
//   secure_password = SHA1( SHA1(password + UPPER(username)) + server_random )
// For plain password auth, plain_password is the plaintext password string.
static uint8_t* build_login_pack(const char* hub_name, const char* username,
                                  int auth_type, const uint8_t* secure_password,
                                  const char* plain_password,
                                  rudp_context_t* rudp,
                                  softether_connection_t* conn,
                                  uint32_t* out_len) {
    if (!hub_name || !username || !out_len) return NULL;

    const char* client_hello = "SoftEther VPN Client"; // Must be exactly this string, server rejects unrecognized values
    const uint32_t client_ver = 420;
    const uint32_t client_build = 9699;

    // Parse product version string (e.g. "2.3.2") into int for ClientProductVer
    // Server displays as "%u.%02u" = val/100 . val%100, so "2.3.2" → 232 → displays "2.32"
    uint32_t client_product_ver_int = 0;
    if (conn->client_product_version[0]) {
        int major = 0, minor = 0, patch = 0;
        sscanf(conn->client_product_version, "%d.%d.%d", &major, &minor, &patch);
        client_product_ver_int = (uint32_t)(major * 100 + minor * 10 + patch);
    }

    // Generate a dummy "pencore" random data (matching CreateDummyValue)
    uint32_t pencore_size = (uint32_t)(rand() % 1000);  // HTTP_PACK_RAND_SIZE_MAX
    uint8_t* pencore_data = (uint8_t*)malloc(pencore_size > 0 ? pencore_size : 1);
    if (pencore_data && pencore_size > 0) {
        for (uint32_t i = 0; i < pencore_size; i++) {
            pencore_data[i] = (uint8_t)(rand() & 0xFF);
        }
    }

    // Generate unique_id (SHA1 of a machine-specific value)
    uint8_t unique_id[SHA1_SIZE];
    {
        const char* machine_str = "SoftEtherVPN_Android_Client";
        sha1_hash((const uint8_t*)machine_str, strlen(machine_str), unique_id);
    }

    // Count elements and calculate buffer size
    // Base: method, hubname, username, authtype, hello, version, build,
    //       client_str, client_ver, client_build, client_id,
    //       protocol, max_connection, use_encrypt, use_compress, half_connection,
    //       require_bridge_routing_mode, require_monitor_mode, qos,
    //       support_bulk_on_rudp, support_hmac_on_bulk_of_rudp,
    //       support_udp_recovery, unique_id, rudp_bulk_max_version,
    //       pencore
    uint32_t num_elems = 20;
    uint32_t size = 4;

    size += PACK_STR_SZ("method", "login");
    size += PACK_STR_SZ("hubname", hub_name);
    size += PACK_STR_SZ("username", username);
    size += PACK_INT_SZ("authtype");
    size += PACK_STR_SZ("hello", client_hello);
    size += PACK_INT_SZ("version");
    size += PACK_INT_SZ("build");
    size += PACK_STR_SZ("client_str", client_hello);
    size += PACK_INT_SZ("client_ver");
    size += PACK_INT_SZ("client_build");
    size += PACK_INT_SZ("client_id");
    size += PACK_INT_SZ("protocol");
    size += PACK_INT_SZ("max_connection");
    size += PACK_INT_SZ("use_encrypt");
    size += PACK_INT_SZ("use_compress");
    size += PACK_INT_SZ("half_connection");
    size += PACK_INT_SZ("require_bridge_routing_mode");
    size += PACK_INT_SZ("require_monitor_mode");
    size += PACK_INT_SZ("qos");
    size += PACK_DATA_SZ("pencore", pencore_size);

    // Client info fields (reported in server session list)
    // Server reads via InRpcNodeInfo which expects:
    //   STR fields: ClientProductName, ClientOsName, ClientOsVer, ClientOsProductId, ClientHostname, ServerHostname, HubName
    //   INT fields (Endian32'd): ClientProductVer, ClientProductBuild, ClientPort, ServerPort2
    //   IP fields (as INT via PackAddIp32): ClientIpAddress, ServerIpAddress
    num_elems += 12;
    size += PACK_STR_SZ("ClientProductName", conn->client_product_name);
    size += PACK_INT_SZ("ClientProductVer");
    size += PACK_INT_SZ("ClientProductBuild");
    size += PACK_STR_SZ("ClientOsName", conn->client_os_name);
    size += PACK_STR_SZ("ClientOsVer", conn->client_os_version);
    size += PACK_STR_SZ("ClientOsProductId", conn->client_os_product_id);
    size += PACK_STR_SZ("ClientHostName", conn->client_host_name);
    size += PACK_INT_SZ("ClientIpAddress");
    size += PACK_INT_SZ("ClientPort");
    size += PACK_STR_SZ("ServerHostName", conn->server_host_name);
    size += PACK_INT_SZ("ServerIpAddress");
    size += PACK_INT_SZ("ServerPort2");

    // RUDP-related fields (only sent when RUDP mode is active)
    if (rudp != NULL) {
        num_elems += 5;
        size += PACK_INT_SZ("support_bulk_on_rudp");
        size += PACK_INT_SZ("support_hmac_on_bulk_of_rudp");
        size += PACK_INT_SZ("support_udp_recovery");
        size += PACK_DATA_SZ("unique_id", SHA1_SIZE);
        size += PACK_INT_SZ("rudp_bulk_max_version");
    }
    if (rudp != NULL) {
        num_elems += 8;
        size += PACK_INT_SZ("use_udp_acceleration");
        size += PACK_DATA_SZ("udp_acceleration_client_key", RUDP_COMMON_KEY_SIZE_V1);
        size += PACK_DATA_SZ("udp_acceleration_client_key_v2", RUDP_COMMON_KEY_SIZE_V2);
        size += PACK_INT_SZ("udp_acceleration_client_cookie");
        size += PACK_INT_SZ("udp_acceleration_max_version");
        size += PACK_INT_SZ("support_hmac_on_udp_acceleration");
        size += PACK_INT_SZ("udp_acceleration_client_ip");
        size += PACK_INT_SZ("udp_acceleration_client_port");
    }

    if (auth_type == 1 && secure_password) {
        num_elems++;
        size += PACK_DATA_SZ("secure_password", SHA1_SIZE);
    }
    if (auth_type == 2 && plain_password) {
        num_elems++;
        size += PACK_STR_SZ("plain_password", plain_password);
    }

    uint8_t* buf = (uint8_t*)calloc(1, size + 64);  // +64 safety margin
    if (!buf) { free(pencore_data); return NULL; }
    uint8_t* p = buf;

    pack_write_uint32(&p, num_elems);

    pack_add_str(&p, "method", "login");
    pack_add_str(&p, "hubname", hub_name);
    pack_add_str(&p, "username", username);
    pack_add_int(&p, "authtype", (uint32_t)auth_type);
    pack_add_str(&p, "hello", client_hello);
    pack_add_int(&p, "version", client_ver);
    pack_add_int(&p, "build", client_build);
    pack_add_str(&p, "client_str", client_hello);
    pack_add_int(&p, "client_ver", client_ver);
    pack_add_int(&p, "client_build", client_build);
    pack_add_int(&p, "client_id", 0);
    pack_add_int(&p, "protocol", rudp ? 1 : 0);   // 0 = TCP, 1 = UDP
    pack_add_int(&p, "max_connection", 4);  // Request 4 connections for multi-connection throughput
    pack_add_int(&p, "use_encrypt", 1);
    pack_add_int(&p, "use_compress", 1);
    pack_add_int(&p, "half_connection", 1);  // Enable half-connection for better throughput with multi-TCP
    pack_add_int(&p, "require_bridge_routing_mode", 0);
    pack_add_int(&p, "require_monitor_mode", 0);
    pack_add_int(&p, "qos", 1);
    pack_add_data(&p, "pencore", pencore_data, pencore_size);

    // Client info fields (reported in server session list)
    // InRpcNodeInfo expects NODE_INFO int fields pre-Endian32'd (big-endian as native uint),
    // because the display code applies Endian32() to convert back to actual values.
    pack_add_str(&p, "ClientProductName", conn->client_product_name);
    pack_add_int(&p, "ClientProductVer", softether_endian32(client_product_ver_int));
    pack_add_int(&p, "ClientProductBuild", softether_endian32((uint32_t)conn->client_product_build));
    pack_add_str(&p, "ClientOsName", conn->client_os_name);
    pack_add_str(&p, "ClientOsVer", conn->client_os_version);
    pack_add_str(&p, "ClientOsProductId", conn->client_os_product_id);
    pack_add_str(&p, "ClientHostName", conn->client_host_name);
    // ClientIpAddress: PackGetIp32 reads INT, stores as UINT via inet_addr
    uint32_t client_ip_uint = 0;
    if (conn->client_ip_address[0]) {
        client_ip_uint = (uint32_t)inet_addr(conn->client_ip_address);
    }
    pack_add_int(&p, "ClientIpAddress", client_ip_uint);
    // Get actual local port from connected socket (like original SoftEther: c->FirstSock->LocalPort)
    uint32_t client_port = (uint32_t)conn->client_port;
    if (client_port == 0 && conn->socket_fd >= 0) {
        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        if (getsockname(conn->socket_fd, (struct sockaddr*)&local_addr, &addr_len) == 0) {
            client_port = ntohs(local_addr.sin_port);
        }
    }
    pack_add_int(&p, "ClientPort", softether_endian32(client_port));
    pack_add_str(&p, "ServerHostName", conn->server_host_name);
    // ServerIpAddress: same format as ClientIpAddress
    uint32_t server_ip_uint = 0;
    if (conn->server_ip_address[0]) {
        server_ip_uint = (uint32_t)inet_addr(conn->server_ip_address);
    }
    pack_add_int(&p, "ServerIpAddress", server_ip_uint);
    pack_add_int(&p, "ServerPort2", softether_endian32((uint32_t)conn->server_port_reported));

    // RUDP-related fields (only sent when RUDP mode is active)
    if (rudp != NULL) {
        pack_add_int(&p, "support_bulk_on_rudp", 1);
        pack_add_int(&p, "support_hmac_on_bulk_of_rudp", 1);
        pack_add_int(&p, "support_udp_recovery", 1);
        pack_add_data(&p, "unique_id", unique_id, SHA1_SIZE);
        pack_add_int(&p, "rudp_bulk_max_version", 1);
    }

    // RUDP client fields
    if (rudp != NULL) {
        pack_add_int(&p, "use_udp_acceleration", 1);
        pack_add_data(&p, "udp_acceleration_client_key", rudp->my_key, RUDP_COMMON_KEY_SIZE_V1);
        pack_add_data(&p, "udp_acceleration_client_key_v2", rudp->my_key_v2, RUDP_COMMON_KEY_SIZE_V2);
        pack_add_int(&p, "udp_acceleration_client_cookie", rudp->my_cookie);
        pack_add_int(&p, "udp_acceleration_max_version", 1);
        pack_add_int(&p, "support_hmac_on_udp_acceleration", 1);
        pack_add_int(&p, "udp_acceleration_client_ip", 0);   // all-zeros IP → server will replace with client's TCP remote IP
        pack_add_int(&p, "udp_acceleration_client_port", rudp->my_port);
    }

    if (auth_type == 1 && secure_password) {
        pack_add_data(&p, "secure_password", secure_password, SHA1_SIZE);
    }
    if (auth_type == 2 && plain_password) {
        pack_add_str(&p, "plain_password", plain_password);
    }

    free(pencore_data);
    *out_len = (uint32_t)(p - buf);
    return buf;
}

// Read an HTTP response precisely: headers byte-by-byte until \r\n\r\n,
// then exactly Content-Length bytes for the body.
// This prevents over-reading into the data channel protocol that follows.
// Returns total bytes in buf (headers + body), or -1 on error.
// Sets *body_offset to the start of body data, *body_len to body length.
static int read_http_response(softether_connection_t* conn,
                              uint8_t* buf, int buf_size,
                              int* body_offset, int* body_len) {
    // Read headers byte-by-byte until we find \r\n\r\n
    int hdr_len = 0;
    int found_end = 0;
    while (hdr_len < buf_size - 1 && !found_end) {
        int r = ssl_read((ssl_context_t*)conn->ssl, buf + hdr_len, 1);
        if (r <= 0) {
            LOGE("read_http_response: failed reading headers at byte %d", hdr_len);
            return -1;
        }
        hdr_len++;
        // Check for \r\n\r\n at the end
        if (hdr_len >= 4 &&
            buf[hdr_len-4] == '\r' && buf[hdr_len-3] == '\n' &&
            buf[hdr_len-2] == '\r' && buf[hdr_len-1] == '\n') {
            found_end = 1;
        }
    }
    if (!found_end) {
        LOGE("read_http_response: headers too large or no terminator found");
        return -1;
    }
    buf[hdr_len] = '\0';
    *body_offset = hdr_len;

    // Parse Content-Length from headers
    uint32_t content_length = 0;
    const char* cl_str = strstr((char*)buf, "Content-Length: ");
    if (!cl_str) cl_str = strstr((char*)buf, "content-length: ");
    if (cl_str) {
        content_length = (uint32_t)atoi(cl_str + 16);
    }
    LOGD("read_http_response: headers=%d bytes, Content-Length=%u", hdr_len, content_length);
    // Log HTTP status line and key headers
    {
        char* line_start = (char*)buf;
        char* line_end;
        int line_num = 0;
        while (line_start < (char*)buf + hdr_len && (line_end = strstr(line_start, "\r\n")) != NULL) {
            int line_len = (int)(line_end - line_start);
            if (line_len == 0) break; // empty line = end of headers
            if (line_num < 8) { // log first 8 header lines
                LOGD("  Header[%d]: %.*s", line_num, line_len, line_start);
            }
            line_start = line_end + 2;
            line_num++;
        }
    }

    // Read exactly content_length bytes for the body
    if (content_length > 0) {
        if (hdr_len + (int)content_length > buf_size) {
            LOGE("read_http_response: buffer too small for body (%d + %u > %d)",
                 hdr_len, content_length, buf_size);
            return -1;
        }
        // Read body using ssl_read in a loop until we have all bytes
        uint32_t body_read = 0;
        while (body_read < content_length) {
            int r = ssl_read((ssl_context_t*)conn->ssl,
                             buf + hdr_len + body_read,
                             (int)(content_length - body_read));
            if (r <= 0) {
                LOGE("read_http_response: failed reading body (%u/%u bytes)",
                     body_read, content_length);
                return -1;
            }
            body_read += (uint32_t)r;
        }
        *body_len = (int)content_length;
    } else {
        *body_len = 0;
    }

    return hdr_len + *body_len;
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
        "Content-Type: image/jpeg\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        server_ip, watermark_len);
    
    LOGD("Sending POST to connect.cgi: %.200s", http_post);
    
    // Send HTTP POST header + body as single SSL_write (matching reference PostHttp)
    size_t combined_len = post_len + watermark_len;
    uint8_t* combined = (uint8_t*)malloc(combined_len);
    if (combined == NULL) {
        LOGE("Failed to allocate combined buffer");
        return -1;
    }
    memcpy(combined, http_post, post_len);
    memcpy(combined + post_len, watermark, watermark_len);
    
    int sent = ssl_write((ssl_context_t*)conn->ssl, combined, (int)combined_len);
    free(combined);
    
    if (sent <= 0) {
        LOGE("Failed to send VPNCONNECT POST");
        return -1;
    }
    
    LOGD("VPNCONNECT watermark sent, waiting for server Hello response...");
    
    // Read HTTP response precisely — no over-reading into data channel
    uint8_t resp[4096];
    int body_offset = 0, body_len = 0;
    int total = read_http_response(conn, resp, sizeof(resp), &body_offset, &body_len);
    
    if (total <= 0) {
        LOGE("Failed to receive watermark response");
        return -1;
    }
    
    LOGD("Watermark response: %d total bytes (headers=%d, body=%d)", total, body_offset, body_len);
    
    // Check for HTTP 200
    if (strstr((char*)resp, "HTTP/1.1 200") == NULL &&
        strstr((char*)resp, "HTTP/1.0 200") == NULL) {
        LOGD("Watermark response not HTTP 200: %.200s", (char*)resp);
        return 0;
    }
    
    if (strstr((char*)resp, "application/octet-stream") == NULL) {
        LOGD("Watermark response not octet-stream");
        return 0;
    }
    
    LOGD("Got HTTP 200 with application/octet-stream - server sent Hello!");
    
    if (body_len < 4) {
        LOGD("Hello body too short: %d bytes", body_len);
        return 0;
    }
    
    // Parse the server Hello to extract version info and random
    const uint8_t* body_start = resp + body_offset;
    server_hello_info_t hello_info;
    if (parse_server_hello(body_start, (uint32_t)body_len, &hello_info) == 0) {
        LOGD("Successfully parsed server Hello!");
        if (hello_info.has_random) {
            memcpy(conn->server_random, hello_info.random, SHA1_SIZE);
            conn->has_server_random = 1;
            LOGD("Server random stored for authentication");
        }
    } else {
        LOGW("Failed to parse server Hello PACK");
    }
    
    return 1;
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
    
    // Generate random locally-administered MAC address (02:XX:XX:XX:XX:XX)
    conn->client_mac[0] = 0x5E;  // SE prefix (SoftEther), locally administered + unicast
    for (int i = 1; i < 6; i++) {
        conn->client_mac[i] = (uint8_t)(rand() & 0xFF);
    }

    // Set default hub name
    strncpy(conn->hub_name, "vpngate", sizeof(conn->hub_name) - 1);

    // Initialize callbacks to NULL
    conn->on_connect = NULL;
    conn->on_disconnect = NULL;
    conn->on_data = NULL;
    conn->on_error = NULL;

    // Initialize write mutex for thread-safe SSL writes
    pthread_mutex_init(&conn->write_mutex, NULL);

    // Initialize multi-connection fields
    conn->num_additional = 0;
    conn->max_connection = 4;  // Target: request 4 connections in login PACK
    conn->half_connection = 0;
    conn->primary_direction = TCP_DIRECTION_BOTH;
    conn->next_connect_time = 0;
    conn->additional_failed_count = 0;
    memset(conn->additional, 0, sizeof(conn->additional));
    conn->additional_connecting = 0;
    conn->additional_connect_slot = -1;
    conn->additional_connect_result = -1;

    LOGD("Connection created");
    return conn;
}

// Destroy connection context
void softether_destroy(softether_connection_t* conn) {
    if (conn == NULL) {
        return;
    }

    // Wait for any background additional connect thread to finish
    if (conn->additional_connecting) {
        LOGD("Waiting for background additional connect thread to finish");
        pthread_join(conn->additional_thread, NULL);
        conn->additional_connecting = 0;
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

    // Destroy write mutex
    pthread_mutex_destroy(&conn->write_mutex);

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

    // Perform SSL connect — pass hostname for SNI (server may require extension presence)
    if (ssl_connect(ssl_ctx, conn->socket_fd, hostname) != 0) {
        LOGE("SSL handshake failed");
        ssl_destroy(ssl_ctx);
        conn->ssl_ctx = NULL;
        return ERR_TLS_HANDSHAKE;
    }

    conn->ssl = ssl_ctx;
    
    // Set TCP_NODELAY to match reference SoftEther (disables Nagle's algorithm)
    int nodelay = 1;
    setsockopt(conn->socket_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    
    LOGD("TLS handshake successful");
    return ERR_NONE;
}

// Send authentication via HTTP POST to /vpnsvc/vpn.cgi using proper PACK format.
// This is the correct SoftEther VPN login protocol:
//   1. Build PACK with method="login", hubname, username, authtype
//   2. POST the PACK as application/octet-stream body to /vpnsvc/vpn.cgi
//   3. Server responds with HTTP 200 + PACK; check error field == 0
static int perform_authentication_http(softether_connection_t* conn,
                                        const char* username, const char* password) {
    if (conn == NULL || username == NULL || password == NULL) {
        return ERR_AUTHENTICATION;
    }

    LOGD("Starting PACK-based HTTP authentication for user: %s hub: %s",
         username, conn->hub_name);
    conn->state = STATE_AUTHENTICATING;

    strncpy(conn->username, username, sizeof(conn->username) - 1);
    strncpy(conn->password, password, sizeof(conn->password) - 1);

    // Decide auth type: use forced_auth_type if set, otherwise auto-detect
    int auth_type;
    uint8_t secure_password[SHA1_SIZE];
    memset(secure_password, 0, sizeof(secure_password));

    if (conn->forced_auth_type == CLIENT_AUTHTYPE_PLAIN_PASSWORD) {
        // Plain password auth (used for RADIUS): send password in plaintext
        auth_type = CLIENT_AUTHTYPE_PLAIN_PASSWORD;
        LOGD("Using PLAIN_PASSWORD auth (RADIUS mode)");
    } else if (conn->forced_auth_type == CLIENT_AUTHTYPE_ANONYMOUS) {
        auth_type = CLIENT_AUTHTYPE_ANONYMOUS;
        LOGD("Using ANONYMOUS auth (forced)");
    } else {
        // Auto-detect: password if non-empty, else anonymous
        auth_type = (strlen(password) > 0) ? CLIENT_AUTHTYPE_PASSWORD : CLIENT_AUTHTYPE_ANONYMOUS;
    }

    if (auth_type == CLIENT_AUTHTYPE_PASSWORD) {
        // Compute HashedPassword = SHA1(password_bytes + UPPER(username_bytes))
        uint8_t hashed_pw[SHA1_SIZE];
        size_t pw_len = strlen(password);
        size_t user_len = strlen(username);
        char* upper_user = (char*)malloc(user_len + 1);
        if (upper_user) {
            memcpy(upper_user, username, user_len + 1);
            for (size_t ci = 0; ci < user_len; ci++) {
                if (upper_user[ci] >= 'a' && upper_user[ci] <= 'z')
                    upper_user[ci] -= 32;
            }
            size_t concat_len = pw_len + user_len;
            uint8_t* concat_buf = (uint8_t*)malloc(concat_len);
            if (concat_buf) {
                memcpy(concat_buf, password, pw_len);
                memcpy(concat_buf + pw_len, upper_user, user_len);
                sha1_hash(concat_buf, concat_len, hashed_pw);
                free(concat_buf);
                LOGD("HashedPassword (SHA1(pw+UPPER_user)) computed");
                if (conn->has_server_random) {
                    uint8_t combined[SHA1_SIZE * 2];
                    memcpy(combined, hashed_pw, SHA1_SIZE);
                    memcpy(combined + SHA1_SIZE, conn->server_random, SHA1_SIZE);
                    sha1_hash(combined, SHA1_SIZE * 2, secure_password);
                    LOGD("SecurePassword (SHA1(hashed_pw+server_random)) computed");
                } else {
                    memcpy(secure_password, hashed_pw, SHA1_SIZE);
                    LOGW("No server random available; using raw hashed password");
                }
            }
            free(upper_user);
        }
    }

    // Build the login PACK
    uint32_t pack_len = 0;
    uint8_t* pack_buf = build_login_pack(conn->hub_name, username,
                                          auth_type,
                                          (auth_type == CLIENT_AUTHTYPE_PASSWORD) ? secure_password : NULL,
                                          (auth_type == CLIENT_AUTHTYPE_PLAIN_PASSWORD) ? password : NULL,
                                          conn->rudp,
                                          conn,
                                          &pack_len);
    if (pack_buf == NULL || pack_len == 0) {
        LOGE("Failed to build login PACK");
        if (pack_buf) free(pack_buf);
        return ERR_AUTHENTICATION;
    }

    LOGD("Login PACK built: %u bytes, auth_type=%d", pack_len, auth_type);

    // Send HTTP POST to /vpnsvc/vpn.cgi (matching reference HttpClientSend)
    // Include Date and Keep-Alive headers like the reference
    char date_str[64];
    {
        time_t now = time(NULL);
        struct tm* gmt = gmtime(&now);
        strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", gmt);
    }

    char http_hdr[512];
    int hdr_len = snprintf(http_hdr, sizeof(http_hdr),
        "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n"
        "Date: %s\r\n"
        "Host: %s\r\n"
        "Keep-Alive: timeout=15; max=19\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %u\r\n"
        "\r\n",
        date_str, conn->server_ip, pack_len);

    // Combine header + body into single buffer and send as one SSL_write
    // (matching reference PostHttp which does SendAll of header+body)
    size_t combined_len = (size_t)hdr_len + pack_len;
    uint8_t* combined = (uint8_t*)malloc(combined_len);
    if (combined == NULL) {
        free(pack_buf);
        LOGE("Failed to allocate combined buffer");
        return ERR_AUTHENTICATION;
    }
    memcpy(combined, http_hdr, hdr_len);
    memcpy(combined + hdr_len, pack_buf, pack_len);
    free(pack_buf);

    int sent = ssl_write((ssl_context_t*)conn->ssl, combined, (int)combined_len);
    free(combined);

    if (sent <= 0) {
        LOGE("Failed to send login PACK via HTTP");
        return ERR_AUTHENTICATION;
    }

    // Receive the Welcome / error PACK response — read precisely to avoid
    // consuming data channel bytes that follow the HTTP response
    uint8_t resp_buf[8192];
    int body_offset = 0, body_len_i = 0;
    int total = read_http_response(conn, resp_buf, sizeof(resp_buf), &body_offset, &body_len_i);

    if (total <= 0) {
        LOGE("No response received for login PACK");
        return ERR_AUTHENTICATION;
    }
    LOGD("Login response: %d total bytes (headers=%d, body=%d)", total, body_offset, body_len_i);

    // Parse HTTP response
    if (strstr((char*)resp_buf, "HTTP/1.1 200") == NULL &&
        strstr((char*)resp_buf, "HTTP/1.0 200") == NULL) {
        LOGE("Login HTTP response is not 200 OK: %.200s", (char*)resp_buf);
        return ERR_AUTHENTICATION;
    }

    const char* body = (const char*)resp_buf + body_offset;
    uint32_t body_len = (uint32_t)body_len_i;

    if (body_len < 4) {
        LOGE("Login response body too short: %u bytes", body_len);
        return ERR_AUTHENTICATION;
    }

    LOGD("Login response body: %u bytes", body_len);

    // Parse the response PACK — check the "error" field
    uint32_t err_val = 0;
    if (pack_get_int((const uint8_t*)body, body_len, "error", &err_val) == 0) {
        if (err_val != 0) {
            LOGE("Server returned error in login response: %u", err_val);
            return ERR_AUTHENTICATION;
        }
        LOGD("Login PACK response: error=0 (success)");
    } else {
        // "error" field not found — may be a Welcome PACK (no error = success)
        // Check for session fields that indicate success
        LOGD("No 'error' field in response; checking for session fields");
        if (!buffer_contains_token((const uint8_t*)body, body_len, "session_key") &&
            !buffer_contains_token((const uint8_t*)body, body_len, "session_name") &&
            !buffer_contains_token((const uint8_t*)body, body_len, "connection_name")) {
            LOGE("Login response PACK contains neither error nor session fields");
            // Hex dump first 32 bytes for diagnostics
            for (uint32_t di = 0; di < body_len && di < 32; di++) {
                LOGD("  body[%02u] = 0x%02X", di, (unsigned char)body[di]);
            }
            return ERR_AUTHENTICATION;
        }
    }

    LOGD("HTTP PACK authentication succeeded");

    // Parse Welcome PACK session fields
    if (pack_get_str((const uint8_t*)body, body_len, "session_name",
                     conn->session_name, sizeof(conn->session_name)) == 0) {
        LOGD("Session name: %s", conn->session_name);
    }
    if (pack_get_str((const uint8_t*)body, body_len, "connection_name",
                     conn->connection_name, sizeof(conn->connection_name)) == 0) {
        LOGD("Connection name: %s", conn->connection_name);
    }
    uint32_t sk_len = 0;
    if (pack_get_data((const uint8_t*)body, body_len, "session_key",
                      conn->session_key, sizeof(conn->session_key), &sk_len) == 0) {
        LOGD("Session key received (%u bytes)", sk_len);
    }
    pack_get_int((const uint8_t*)body, body_len, "session_key_32", &conn->session_key_32);
    pack_get_int((const uint8_t*)body, body_len, "max_connection", &conn->server_max_connection);
    pack_get_int((const uint8_t*)body, body_len, "use_encrypt", &conn->server_use_encrypt);
    pack_get_int((const uint8_t*)body, body_len, "use_compress", &conn->server_use_compress);
    pack_get_int((const uint8_t*)body, body_len, "use_fast_rc4", &conn->server_use_fast_rc4);
    pack_get_int((const uint8_t*)body, body_len, "timeout", &conn->server_timeout);

    // Parse half_connection from server response
    uint32_t half_conn = 0;
    if (pack_get_int((const uint8_t*)body, body_len, "half_connection", &half_conn) == 0) {
        conn->half_connection = (int)half_conn;
        LOGD("Server half_connection=%u", half_conn);
    }
    
    // Determine data channel mode (same logic as reference SoftEther)
    if (conn->server_use_encrypt && !conn->server_use_fast_rc4) {
        conn->use_ssl_data = 1;
        LOGD("Data channel: SSL encryption");
    } else {
        conn->use_ssl_data = 0;
        LOGD("Data channel: raw TCP (use_encrypt=%u, use_fast_rc4=%u)",
             conn->server_use_encrypt, conn->server_use_fast_rc4);
    }
    LOGD("Server use_compress=%u", conn->server_use_compress);
    // Parse RUDP (UDP acceleration) server response from Welcome PACK
    {
        uint32_t use_udp = 0;
        if (pack_get_int((const uint8_t*)body, body_len,
                         "use_udp_acceleration", &use_udp) == 0 && use_udp) {
            uint32_t udp_version = 1;
            pack_get_int((const uint8_t*)body, body_len,
                         "udp_acceleration_version", &udp_version);
            conn->rudp_version = (int)udp_version;

            // Server IP
            if (pack_get_str((const uint8_t*)body, body_len,
                             "udp_acceleration_server_ip",
                             conn->rudp_server_ip,
                             sizeof(conn->rudp_server_ip)) == 0) {
                LOGD("RUDP: server IP = %s", conn->rudp_server_ip);
            } else {
                // Fallback to the TCP server IP
                strncpy(conn->rudp_server_ip, conn->server_ip,
                        sizeof(conn->rudp_server_ip) - 1);
                LOGD("RUDP: using TCP server IP = %s", conn->rudp_server_ip);
            }

            // Server port
            uint32_t srv_port = 0;
            if (pack_get_int((const uint8_t*)body, body_len,
                             "udp_acceleration_server_port", &srv_port) == 0
                             && srv_port > 0 && srv_port <= 65535) {
                conn->rudp_server_port = (uint16_t)srv_port;
                LOGD("RUDP: server port = %u", conn->rudp_server_port);
            }

            // Server key (V1)
            uint32_t key_len = 0;
            if (pack_get_data((const uint8_t*)body, body_len,
                              "udp_acceleration_server_key",
                              conn->rudp_server_key,
                              sizeof(conn->rudp_server_key),
                              &key_len) == 0 && key_len > 0) {
                conn->rudp_server_key_size = (int)key_len;
                LOGD("RUDP: server key received (%u bytes)", key_len);
            } else {
                // Try V2 key
                key_len = 0;
                if (pack_get_data((const uint8_t*)body, body_len,
                                  "udp_acceleration_server_key_v2",
                                  conn->rudp_server_key,
                                  sizeof(conn->rudp_server_key),
                                  &key_len) == 0 && key_len > 0) {
                    conn->rudp_server_key_size = (int)key_len;
                    LOGD("RUDP: server key V2 received (%u bytes)", key_len);
                }
            }

            // Cookies
            pack_get_int((const uint8_t*)body, body_len,
                         "udp_acceleration_server_cookie",
                         &conn->rudp_server_cookie);
            pack_get_int((const uint8_t*)body, body_len,
                         "udp_acceleration_client_cookie",
                         &conn->rudp_client_cookie);
            LOGD("RUDP: cookies server=0x%08X client=0x%08X",
                 conn->rudp_server_cookie, conn->rudp_client_cookie);

            conn->rudp_enabled = 1;
            LOGD("RUDP: server supports UDP acceleration (v%u)", udp_version);
        } else if (conn->rudp != NULL) {
            LOGD("RUDP: server does not advertise UDP acceleration");
        }
    }

    conn->session_established = 1;

    // In half-connection mode, the primary socket direction is client-to-server (send only).
    // Server will assign directions to additional connections (alternating S2C / C2S).
    if (conn->half_connection) {
        conn->primary_direction = TCP_DIRECTION_CLIENT_TO_SERVER;
        LOGD("Half-connection enabled: primary socket set to TCP_DIRECTION_CLIENT_TO_SERVER");
    }

    return ERR_NONE;
}

// Main connect function
int softether_connect(softether_connection_t* conn, const char* host, int port,
                      const char* username, const char* password) {
    return softether_connect_with_hub(conn, host, port, username, password, "vpngate", 1,
        "", "", 0, "", "", "",
        "", "", 0,
        "", "", 0);
}

// Connect with HubName
int softether_connect_with_hub(softether_connection_t* conn, const char* host, int port,
                               const char* username, const char* password, const char* hub_name,
                               int use_tcp,
                               const char* client_product_name, const char* client_product_version, int client_product_build,
                               const char* client_os_name, const char* client_os_version, const char* client_os_product_id,
                               const char* client_host_name, const char* client_ip_address, int client_port,
                               const char* server_host_name, const char* server_ip_address, int server_port) {
    int result;
    if (conn == NULL || host == NULL || username == NULL || password == NULL) {
        return ERR_UNKNOWN;
    }

    LOGD("Connecting to %s:%d (hub: %s)", host, port, hub_name ? hub_name : "VPN");
    conn->state = STATE_CONNECTING;

    // Store client info for login PACK
    if (client_product_name && client_product_name[0]) {
        strncpy(conn->client_product_name, client_product_name, sizeof(conn->client_product_name) - 1);
    }
    if (client_product_version && client_product_version[0]) {
        strncpy(conn->client_product_version, client_product_version, sizeof(conn->client_product_version) - 1);
    }
    conn->client_product_build = client_product_build;
    if (client_os_name && client_os_name[0]) {
        strncpy(conn->client_os_name, client_os_name, sizeof(conn->client_os_name) - 1);
    }
    if (client_os_version && client_os_version[0]) {
        strncpy(conn->client_os_version, client_os_version, sizeof(conn->client_os_version) - 1);
    }
    if (client_os_product_id && client_os_product_id[0]) {
        strncpy(conn->client_os_product_id, client_os_product_id, sizeof(conn->client_os_product_id) - 1);
    }
    if (client_host_name && client_host_name[0]) {
        strncpy(conn->client_host_name, client_host_name, sizeof(conn->client_host_name) - 1);
    }
    if (client_ip_address && client_ip_address[0]) {
        strncpy(conn->client_ip_address, client_ip_address, sizeof(conn->client_ip_address) - 1);
    }
    conn->client_port = client_port;
    if (server_host_name && server_host_name[0]) {
        strncpy(conn->server_host_name, server_host_name, sizeof(conn->server_host_name) - 1);
    }
    if (server_ip_address && server_ip_address[0]) {
        strncpy(conn->server_ip_address, server_ip_address, sizeof(conn->server_ip_address) - 1);
    }
    conn->server_port_reported = server_port;

    // Store hub name
    if (hub_name != NULL && hub_name[0] != '\0') {
        strncpy(conn->hub_name, hub_name, sizeof(conn->hub_name) - 1);
    } else {
        strncpy(conn->hub_name, "vpngate", sizeof(conn->hub_name) - 1);
    }

    // Resolve hostname to IP upfront — use the IP for both TCP connect and TLS handshake.
    char resolved_ip[64];
    if (resolve_hostname(host, resolved_ip, sizeof(resolved_ip)) != 0) {
        LOGE("Failed to resolve hostname: %s", host);
        conn->state = STATE_DISCONNECTED;
        return ERR_TCP_CONNECT;
    }
    const char* connect_host = resolved_ip;

    // Store server info
    strncpy(conn->server_ip, resolved_ip, sizeof(conn->server_ip) - 1);
    conn->server_port = port;

    // Create TCP socket and connect
    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        LOGE("Failed to create socket");
        conn->state = STATE_DISCONNECTED;
        return ERR_TCP_CONNECT;
    }

    if (socket_connect_timeout(sock, connect_host, port, conn->timeout_ms) != 0) {
        LOGE("Failed to connect to server");
        socket_destroy(sock);
        conn->state = STATE_DISCONNECTED;
        return ERR_TCP_CONNECT;
    }

    conn->socket_fd = sock->fd;
    sock->fd = -1;
    socket_destroy(sock);

    // TLS handshake
    result = perform_tls_handshake(conn, connect_host);
    if (result != ERR_NONE) {
        LOGE("TLS handshake failed");
        close(conn->socket_fd);
        conn->socket_fd = -1;
        conn->state = STATE_DISCONNECTED;
        return result;
    }

    // ---- SoftEther Protocol: Step 1 ----
    // POST /vpnsvc/connect.cgi with "VPNCONNECT" watermark.
    // Server responds with Hello PACK containing version + server_random.
    LOGD("Sending VPNCONNECT watermark (connect.cgi)...");
    int watermark_result = send_vpnconnect_watermark(conn, host);

    if (watermark_result < 0) {
        LOGE("VPNCONNECT watermark failed — server may not be SoftEther");
        softether_disconnect(conn);
        return ERR_TLS_HANDSHAKE;
    }

    if (watermark_result != 1) {
        LOGW("Watermark sent but no Hello PACK received (result=%d)", watermark_result);
        // Continue anyway — auth step may still work
    } else {
        LOGD("Got server Hello in watermark response (server_random stored)");
    }

    // ---- SoftEther Protocol: Step 2 ----
    // Create RUDP context before building login PACK when UDP mode is requested,
    // so we can include client's keys/cookies in the login PACK for server negotiation.
    if (!use_tcp) {
        conn->rudp = rudp_create(1);  // 1 = client mode
        if (conn->rudp == NULL) {
            LOGW("Failed to create RUDP context (UDP acceleration disabled)");
        } else {
            LOGD("RUDP context created (my_port=%u, cookie=0x%08X)",
                 conn->rudp->my_port, conn->rudp->my_cookie);
        }
    } else {
        conn->rudp = NULL;
        LOGD("TCP mode - skipping RUDP initialization");
    }

    // POST /vpnsvc/vpn.cgi with login PACK.
    // Server responds with Welcome PACK (error=0 on success).
    LOGD("Performing PACK-based authentication...");
    result = perform_authentication_http(conn, username, password);

    if (result != ERR_NONE) {
        LOGE("Authentication failed: %d (%s)", result, softether_error_string(result));
        softether_disconnect(conn);
        return result;
    }

    LOGD("Authentication successful");

    // ---- SoftEther Protocol: Step 3 ----
    // If server supports RUDP, initialize the RUDP context
    if (!use_tcp && conn->rudp && conn->rudp_enabled) {
        if (conn->rudp_server_port == 0 || conn->rudp_server_key_size == 0) {
            LOGW("RUDP enabled by server but missing port/key - disabling");
            conn->rudp_enabled = 0;
        } else {
            // Init RUDP client with server params
            int r = rudp_init_client(conn->rudp,
                                     conn->rudp_server_key,
                                     conn->rudp_server_key_size,
                                     conn->rudp_server_ip[0] ?
                                         conn->rudp_server_ip : conn->server_ip,
                                     conn->rudp_server_port,
                                     conn->rudp_server_cookie,
                                     conn->rudp_client_cookie);
            if (r == 0) {
                LOGD("RUDP client initialized successfully");
                rudp_set_version(conn->rudp, conn->rudp_version);
                // Start RUDP poll immediately to send initial keepalive
                rudp_poll(conn->rudp);
            } else {
                LOGW("RUDP init failed - disabling");
                conn->rudp_enabled = 0;
            }
        }
    }

    // Session is established via the PACK login flow.
    conn->state = STATE_SESSION_SETUP;

    if (conn->session_established) {
        // Use session_key_32 from server as session_id
        if (conn->session_key_32 != 0) {
            conn->session_id = conn->session_key_32;
            LOGD("Using server session_key_32: 0x%08X", conn->session_id);
        }
        LOGD("Session: name=%s, connection=%s",
             conn->session_name, conn->connection_name);
    }

    if (conn->session_id == 0) {
        conn->session_id = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
        LOGD("Generated local session id: 0x%08X", conn->session_id);
    }

    // Connection established
    conn->state = STATE_CONNECTED;
    LOGD("Connection established successfully");

    // Schedule additional connections (multi-connection support)
    // Clamp max_connection to what the server accepted
    if (conn->server_max_connection > 0 && conn->server_max_connection < (uint32_t)conn->max_connection) {
        conn->max_connection = (int)conn->server_max_connection;
    }
    if (conn->max_connection > MAX_SE_CONNECTIONS) {
        conn->max_connection = MAX_SE_CONNECTIONS;
    }
    conn->next_connect_time = softether_tick_ms() + ADDITIONAL_CONNECT_INTERVAL_MS;
    LOGD("Multi-connection: max_connection=%d, server_max=%u, additional connections will open gradually",
         conn->max_connection, conn->server_max_connection);
    
    // Check for any leftover SSL data from the HTTP exchange
    {
        int pending = ssl_has_pending((ssl_context_t*)conn->ssl);
        LOGD("SSL pending bytes after auth: %d", pending);
    }
    
    // Set appropriate timeout for data operations
    int data_timeout_ms = 5000;
    struct timeval tv;
    tv.tv_sec = data_timeout_ms / 1000;
    tv.tv_usec = (data_timeout_ms % 1000) * 1000;
    setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    LOGD("Socket timeout set to %d ms for data operations", data_timeout_ms);

    // Call connect callback if set
    if (conn->on_connect != NULL) {
        conn->on_connect(conn);
    }

    return ERR_NONE;
}

// Check connection status by receiving any pending packets
// Returns: > 0 if data received, 0 if no data (timeout), < 0 on error
int softether_check_connection(softether_connection_t* conn) {
    if (conn == NULL || conn->state != STATE_CONNECTED) {
        return -1;
    }

    // Try to receive any pending packets with short timeout
    uint16_t command;
    uint8_t response[512];
    uint32_t response_len;
    
    int result = softether_receive_packet(conn, &command, response, &response_len, sizeof(response));
    
    if (result == 0) {
        // Timeout - this is normal, no data available
        return 0;
    } else if (result > 0) {
        // Data received
        LOGD("Received packet: command=0x%04X, len=%u", command, response_len);
        // Handle any server-initiated disconnects or notifications here if needed
        return 1;
    } else {
        // Error
        LOGE("Error checking connection: %d", result);
        return -1;
    }
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

    // Wait for any background additional connect thread to finish
    if (conn->additional_connecting) {
        LOGD("Waiting for background additional connect thread before disconnect");
        pthread_join(conn->additional_thread, NULL);
        conn->additional_connecting = 0;
    }

    // Close all additional connections first
    softether_close_additional(conn);

    // In real SoftEther, disconnect is simply closing the connection.
    // No special disconnect packet exists in the block protocol.

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

    // Destroy RUDP context if present
    if (conn->rudp != NULL) {
        rudp_destroy(conn->rudp);
        conn->rudp = NULL;
    }
    conn->rudp_enabled = 0;

    conn->state = STATE_DISCONNECTED;
    conn->session_id = 0;
    conn->sequence_num = 0;

    LOGD("Disconnected");

    // Call disconnect callback if set
    if (conn->on_disconnect != NULL) {
        conn->on_disconnect(conn);
    }
}

// Ethernet header constants
#define ETH_HEADER_SIZE     14
#define ETH_TYPE_IPV4       0x0800
#define ETH_TYPE_IPV6       0x86DD
#define ETH_TYPE_ARP        0x0806

// Build an Ethernet frame around an IP packet
static int build_ethernet_frame(uint8_t* frame, size_t max_frame_len,
                                const uint8_t* ip_packet, size_t ip_len,
                                const uint8_t* src_mac,
                                const uint8_t* dst_mac) {
    if (ip_len + ETH_HEADER_SIZE > max_frame_len) return -1;
    memcpy(frame, dst_mac, 6);  // dst MAC
    memcpy(frame + 6, src_mac, 6);  // src MAC
    // Determine EtherType from IP version
    uint16_t ethertype = ETH_TYPE_IPV4;
    if (ip_len > 0 && ((ip_packet[0] >> 4) & 0x0F) == 6) {
        ethertype = ETH_TYPE_IPV6;
    }
    frame[12] = (ethertype >> 8) & 0xFF;
    frame[13] = ethertype & 0xFF;
    memcpy(frame + ETH_HEADER_SIZE, ip_packet, ip_len);
    return (int)(ETH_HEADER_SIZE + ip_len);
}

// Send data — wraps IP packet in Ethernet frame for SoftEther L2 tunnel
int softether_send(softether_connection_t* conn, const uint8_t* data, size_t len) {
    if (conn == NULL || data == NULL || len == 0) {
        return -1;
    }

    if (conn->state != STATE_CONNECTED) {
        LOGE("Not connected");
        return -1;
    }

    // Use gateway MAC if resolved, otherwise broadcast
    const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t* dst_mac = conn->gateway_mac_resolved ? conn->gateway_mac : broadcast_mac;

    // Wrap IP packet in Ethernet frame
    uint8_t frame[ETH_HEADER_SIZE + 65535];
    int frame_len = build_ethernet_frame(frame, sizeof(frame), data, len, conn->client_mac, dst_mac);
    if (frame_len < 0) {
        LOGE("Failed to build Ethernet frame");
        return -1;
    }

    // Send as a single data block using real SoftEther format (with RUDP if active)
    int sent = softether_send_data(conn, frame, (uint32_t)frame_len);
    if (sent < 0) {
        LOGE("Failed to send data block");
        return -1;
    }

    return (int)len;
}

// Forward declaration for background thread routine
static void* additional_connect_thread_routine(void* arg);

// Receive data — uses queue to handle multi-block messages; strips Ethernet header
// Also handles ARP requests automatically
// Also triggers additional connection establishment (multi-connection)
int softether_receive(softether_connection_t* conn, uint8_t* buffer, size_t max_len) {
    if (conn == NULL || buffer == NULL || max_len == 0) {
        return -1;
    }

    if (conn->state != STATE_CONNECTED) {
        LOGE("Not connected");
        return -1;
    }

    // Multi-connection: launch additional connections in background thread (non-blocking)
    if (conn->num_additional < conn->max_connection - 1 &&
        conn->additional_failed_count < 16 &&
        !conn->additional_connecting) {
        uint64_t now = softether_tick_ms();
        if (conn->next_connect_time == 0 || now >= conn->next_connect_time) {
            // Find a free slot for the background thread
            int slot = -1;
            for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
                if (!conn->additional[i].active) {
                    slot = i;
                    break;
                }
            }
            if (slot >= 0) {
                conn->additional_connect_slot = slot;
                conn->additional_connecting = 1;
                conn->additional_connect_result = -1;
                if (pthread_create(&conn->additional_thread, NULL,
                                   additional_connect_thread_routine, conn) == 0) {
                    LOGD("Launched background additional connect (slot=%d)", slot);
                } else {
                    LOGE("Failed to create background additional connect thread");
                    conn->additional_connecting = 0;
                    conn->additional_connect_slot = -1;
                }
            }
            conn->next_connect_time = now + ADDITIONAL_CONNECT_INTERVAL_MS;
        }
    }

    // Multi-connection: clean up failed additional sockets
    for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
        softether_tcp_sock_t* ts = &conn->additional[i];
        if (!ts->active) continue;

        // Skip the slot being connected by background thread
        if (conn->additional_connecting && i == conn->additional_connect_slot) continue;

        // Check if socket is still connected
        struct pollfd pfd;
        pfd.fd = ts->socket_fd;
        pfd.events = 0;
        pfd.revents = 0;
        int poll_ret = poll(&pfd, 1, 0);
        if (poll_ret > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            LOGW("Additional socket [%d] fd=%d disconnected (revents=0x%x), closing",
                 i, ts->socket_fd, pfd.revents);
            if (ts->ssl != NULL) {
                ssl_shutdown((ssl_context_t*)ts->ssl);
            }
            if (ts->ssl_ctx != NULL) {
                ssl_destroy((ssl_context_t*)ts->ssl_ctx);
                ts->ssl_ctx = NULL;
                ts->ssl = NULL;
            }
            if (ts->socket_fd >= 0) {
                close(ts->socket_fd);
                ts->socket_fd = -1;
            }
            ts->active = 0;
            conn->num_additional--;
        }
    }

    // If queue is empty, read one protocol message and fill queue
    if (conn->recv_queue_count <= 0) {
        int rc = softether_fill_recv_queue(conn);
        if (rc < 0) return -1;
        if (rc == 0) return 0;  // keepalive or empty — no user data
    }

    // Dequeue one frame
    if (conn->recv_queue_count <= 0) return 0;

    queued_frame_t* entry = &conn->recv_queue[conn->recv_queue_head];
    uint32_t frame_len = entry->len;

    // Handle ARP requests automatically (respond to server's ARP for our IP)
    if (frame_len >= 42 && entry->data[12] == 0x08 && entry->data[13] == 0x06) {
        if (entry->data[20] == 0x00 && entry->data[21] == 0x01 && conn->assigned_ip != 0) {
            // ARP request — check if it's for our IP
            uint32_t target_ip = ((uint32_t)entry->data[38] << 24) |
                                 ((uint32_t)entry->data[39] << 16) |
                                 ((uint32_t)entry->data[40] << 8) | entry->data[41];
            if (target_ip == conn->assigned_ip) {
                uint8_t reply[42];
                memcpy(reply, entry->data + 6, 6);
                memcpy(reply + 6, conn->client_mac, 6);
                reply[12] = 0x08; reply[13] = 0x06;
                reply[14] = 0x00; reply[15] = 0x01;
                reply[16] = 0x08; reply[17] = 0x00;
                reply[18] = 6; reply[19] = 4;
                reply[20] = 0x00; reply[21] = 0x02;
                memcpy(reply + 22, conn->client_mac, 6);
                reply[28] = (conn->assigned_ip >> 24) & 0xFF;
                reply[29] = (conn->assigned_ip >> 16) & 0xFF;
                reply[30] = (conn->assigned_ip >> 8) & 0xFF;
                reply[31] = conn->assigned_ip & 0xFF;
                memcpy(reply + 32, entry->data + 22, 6);
                memcpy(reply + 38, entry->data + 28, 4);
                softether_send_raw(conn, reply, 42);
                LOGD("Sent ARP reply for our IP");
            }
        }
        // Skip ARP frames — not IP data for TUN
        conn->recv_queue_head = (conn->recv_queue_head + 1) % RECV_QUEUE_SIZE;
        conn->recv_queue_count--;
        return 0;
    }

    if (frame_len <= ETH_HEADER_SIZE) {
        // Too small for Ethernet — skip
        conn->recv_queue_head = (conn->recv_queue_head + 1) % RECV_QUEUE_SIZE;
        conn->recv_queue_count--;
        return 0;
    }

    // Check EtherType — only pass IPv4/IPv6 to TUN
    uint16_t ethertype = (entry->data[12] << 8) | entry->data[13];
    if (ethertype != 0x0800 && ethertype != 0x86DD) {
        // Not IP — skip (e.g., ARP already handled above)
        conn->recv_queue_head = (conn->recv_queue_head + 1) % RECV_QUEUE_SIZE;
        conn->recv_queue_count--;
        return 0;
    }

    // Strip Ethernet header — return IP packet only
    uint32_t ip_len = frame_len - ETH_HEADER_SIZE;
    if (ip_len > max_len) {
        LOGE("IP packet too large for buffer: %u > %zu", ip_len, max_len);
        conn->recv_queue_head = (conn->recv_queue_head + 1) % RECV_QUEUE_SIZE;
        conn->recv_queue_count--;
        return -1;
    }

    memcpy(buffer, entry->data + ETH_HEADER_SIZE, ip_len);
    conn->recv_queue_head = (conn->recv_queue_head + 1) % RECV_QUEUE_SIZE;
    conn->recv_queue_count--;
    return (int)ip_len;
}

// Raw L2 send — sends a raw Ethernet frame as a data block (for DHCP)
int softether_send_raw(softether_connection_t* conn, const uint8_t* frame, size_t len) {
    if (conn == NULL || frame == NULL || len == 0) return -1;
    if (conn->state != STATE_CONNECTED) return -1;
    return softether_send_data(conn, frame, (uint32_t)len);
}

// Raw L2 receive — uses queue; returns raw Ethernet frame (for DHCP)
int softether_receive_raw(softether_connection_t* conn, uint8_t* frame, size_t max_len, uint32_t* frame_len) {
    if (conn == NULL || frame == NULL) return -1;
    if (conn->state != STATE_CONNECTED) return -1;

    // If queue is empty, read one protocol message
    if (conn->recv_queue_count <= 0) {
        int rc = softether_fill_recv_queue(conn);
        if (rc < 0) return -1;
        if (rc == 0) {
            if (frame_len) *frame_len = 0;
            return 0;
        }
    }

    if (conn->recv_queue_count <= 0) {
        if (frame_len) *frame_len = 0;
        return 0;
    }

    // Dequeue one raw frame
    queued_frame_t* entry = &conn->recv_queue[conn->recv_queue_head];
    LOGD("softether_receive_raw: dequeuing frame head=%u count=%u len=%u first8: %02X %02X %02X %02X %02X %02X %02X %02X",
         conn->recv_queue_head, conn->recv_queue_count, entry->len,
         entry->len > 0 ? entry->data[0] : 0, entry->len > 1 ? entry->data[1] : 0,
         entry->len > 2 ? entry->data[2] : 0, entry->len > 3 ? entry->data[3] : 0,
         entry->len > 4 ? entry->data[4] : 0, entry->len > 5 ? entry->data[5] : 0,
         entry->len > 6 ? entry->data[6] : 0, entry->len > 7 ? entry->data[7] : 0);
    if (entry->len > (uint32_t)max_len) {
        if (frame_len) *frame_len = 0;
        conn->recv_queue_head = (conn->recv_queue_head + 1) % RECV_QUEUE_SIZE;
        conn->recv_queue_count--;
        return 0;
    }

    memcpy(frame, entry->data, entry->len);
    if (frame_len) *frame_len = entry->len;
    conn->recv_queue_head = (conn->recv_queue_head + 1) % RECV_QUEUE_SIZE;
    conn->recv_queue_count--;
    return (int)entry->len;
}

// ARP resolution — resolves gateway MAC address after DHCP
int softether_resolve_gateway(softether_connection_t* conn, uint32_t gateway_ip_host) {
    if (conn == NULL || conn->state != STATE_CONNECTED) return -1;

    conn->gateway_ip = gateway_ip_host;
    LOGD("Resolving gateway MAC for IP %d.%d.%d.%d",
         (gateway_ip_host >> 24) & 0xFF, (gateway_ip_host >> 16) & 0xFF,
         (gateway_ip_host >> 8) & 0xFF, gateway_ip_host & 0xFF);

    // Build ARP request
    uint8_t arp_req[42];
    memset(arp_req, 0xFF, 6);                    // dst: broadcast
    memcpy(arp_req + 6, conn->client_mac, 6);    // src: our MAC
    arp_req[12] = 0x08; arp_req[13] = 0x06;      // EtherType: ARP

    arp_req[14] = 0x00; arp_req[15] = 0x01;      // Hardware: Ethernet
    arp_req[16] = 0x08; arp_req[17] = 0x00;      // Protocol: IPv4
    arp_req[18] = 6; arp_req[19] = 4;
    arp_req[20] = 0x00; arp_req[21] = 0x01;      // Operation: request

    memcpy(arp_req + 22, conn->client_mac, 6);   // Sender MAC
    // Sender IP: our assigned IP
    arp_req[28] = (conn->assigned_ip >> 24) & 0xFF;
    arp_req[29] = (conn->assigned_ip >> 16) & 0xFF;
    arp_req[30] = (conn->assigned_ip >> 8) & 0xFF;
    arp_req[31] = conn->assigned_ip & 0xFF;

    memset(arp_req + 32, 0, 6);                   // Target MAC: unknown
    arp_req[38] = (gateway_ip_host >> 24) & 0xFF;
    arp_req[39] = (gateway_ip_host >> 16) & 0xFF;
    arp_req[40] = (gateway_ip_host >> 8) & 0xFF;
    arp_req[41] = gateway_ip_host & 0xFF;

    softether_send_raw(conn, arp_req, 42);

    // Wait for ARP reply (up to 3 seconds, 3 attempts)
    for (int attempt = 0; attempt < 3; attempt++) {
        for (int i = 0; i < 40; i++) {  // 40 × 50ms = 2s per attempt
            uint8_t frame[2048];
            uint32_t frame_len = 0;
            int ret = softether_receive_raw(conn, frame, sizeof(frame), &frame_len);
            if (ret > 0 && frame_len >= 42) {
                // Check for ARP reply
                if (frame[12] == 0x08 && frame[13] == 0x06 &&
                    frame[20] == 0x00 && frame[21] == 0x02) {
                    uint32_t sender_ip = ((uint32_t)frame[28] << 24) |
                                         ((uint32_t)frame[29] << 16) |
                                         ((uint32_t)frame[30] << 8) | frame[31];
                    if (sender_ip == gateway_ip_host) {
                        memcpy(conn->gateway_mac, frame + 22, 6);
                        conn->gateway_mac_resolved = 1;
                        LOGD("Gateway MAC resolved: %02X:%02X:%02X:%02X:%02X:%02X",
                             conn->gateway_mac[0], conn->gateway_mac[1],
                             conn->gateway_mac[2], conn->gateway_mac[3],
                             conn->gateway_mac[4], conn->gateway_mac[5]);
                        return 0;
                    }
                }
            } else if (ret == 0) {
                usleep(50000);  // 50ms
            }
        }
        // Resend ARP request
        softether_send_raw(conn, arp_req, 42);
        LOGD("Resending ARP request (attempt %d)", attempt + 1);
    }

    LOGE("Failed to resolve gateway MAC");
    return -1;
}
// Data tunnel operations - Send data block
int softether_send_data(softether_connection_t* conn, const uint8_t* data, uint32_t data_len) {
    if (conn == NULL || data == NULL) {
        LOGE("Invalid parameters for send_data");
        return -1;
    }

    if (conn->state != STATE_CONNECTED) {
        LOGE("Cannot send data: not connected");
        return -1;
    }

    // Try RUDP if active
    if (conn->rudp && conn->rudp_enabled) {
        rudp_poll(conn->rudp);

        // Use check_keepalive=0 for initial data (DHCP), check_keepalive=1 for VPN data
        // This allows initial packets through while waiting for server to be ready for VPN data
        int check_keepalive = conn->session_established ? 1 : 0;
        if (rudp_is_send_ready(conn->rudp, check_keepalive)) {
            int r = rudp_send(conn->rudp, data, data_len, 0);
            if (r > 0) {
                LOGD("Sent data block via RUDP: %u bytes", data_len);
                return (int)data_len;
            }
            LOGW("RUDP send failed (%d), falling back to TCP", r);
        }
    }

    // Fall back to TCP
    int result = softether_send_packet(conn, CMD_DATA, data, data_len);
    if (result < 0) {
        LOGE("Failed to send data block");
        return -1;
    }

    LOGD("Sent data block via TCP: %u bytes", data_len);
    return result;
}

// Data tunnel operations - Receive data block
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

    // Try RUDP first if active
    if (conn->rudp && conn->rudp_enabled) {
        int have_rudp_data = 0;

        rudp_poll(conn->rudp);

        uint32_t rudp_len = 0;
        int r = rudp_recv(conn->rudp, buffer, &rudp_len, max_len);
        if (r > 0) {
            have_rudp_data = 1;
        }

        if (!have_rudp_data) {
            struct pollfd fds[2];
            nfds_t nfds = 0;

            int udp_fd = rudp_get_udp_fd(conn->rudp);
            if (udp_fd >= 0) {
                fds[nfds].fd = udp_fd;
                fds[nfds].events = POLLIN;
                fds[nfds].revents = 0;
                nfds++;
            }

            fds[nfds].fd = conn->socket_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;

            int poll_ret = poll(fds, nfds, 200);
            if (poll_ret > 0) {
                for (nfds_t i = 0; i < nfds; i++) {
                    if (udp_fd >= 0 && fds[i].fd == udp_fd &&
                        (fds[i].revents & POLLIN)) {
                        rudp_poll(conn->rudp);
                        rudp_len = 0;
                        r = rudp_recv(conn->rudp, buffer, &rudp_len, max_len);
                        if (r > 0) {
                            have_rudp_data = 1;
                        }
                        break;
                    }
                }
            }
        }

        if (have_rudp_data) {
            *received_len = rudp_len;
            *command = CMD_DATA;
            return 0;
        }
    }

    // Fall back to TCP read
    {
        uint32_t payload_len = 0;
        int result = softether_receive_packet(conn, command, buffer, &payload_len, max_len);

        if (result < 0) {
            LOGD("No data available from server (timeout or error)");
            *received_len = 0;
            *command = 0;
            return 0;
        }

        *received_len = payload_len;

        if (*command == CMD_KEEPALIVE) {
            softether_send_keepalive(conn);
            LOGD("Received keepalive, sent response");
            *received_len = 0;
        }
    }

    return 0;
}

// ---- Multi-Connection Support ----

// Close all additional (non-primary) TCP connections
void softether_close_additional(softether_connection_t* conn) {
    if (conn == NULL) return;

    // Wait for any background additional connect thread to finish
    if (conn->additional_connecting) {
        LOGD("Waiting for background additional connect thread before closing");
        pthread_join(conn->additional_thread, NULL);
        conn->additional_connecting = 0;
    }

    for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
        softether_tcp_sock_t* ts = &conn->additional[i];
        if (!ts->active) continue;

        LOGD("Closing additional connection [%d] fd=%d", i, ts->socket_fd);

        if (ts->ssl != NULL) {
            ssl_shutdown((ssl_context_t*)ts->ssl);
        }
        if (ts->ssl_ctx != NULL) {
            ssl_destroy((ssl_context_t*)ts->ssl_ctx);
            ts->ssl_ctx = NULL;
            ts->ssl = NULL;
        }
        if (ts->socket_fd >= 0) {
            close(ts->socket_fd);
            ts->socket_fd = -1;
        }
        ts->active = 0;
        ts->late_count = 0;
        ts->last_recv = 0;
    }
    conn->num_additional = 0;
    conn->additional_failed_count = 0;
    LOGD("All additional connections closed");
}

// Background thread routine for non-blocking additional connection
static void* additional_connect_thread_routine(void* arg) {
    softether_connection_t* conn = (softether_connection_t*)arg;
    int slot = conn->additional_connect_slot;
    int result = softether_additional_connect(conn);
    conn->additional_connect_result = result;
    conn->additional_connecting = 0;
    LOGD("Background additional connect thread finished (slot=%d result=%d)", slot, result);
    return NULL;
}

// Wait for any in-progress background additional connect thread to finish.
// This is a non-blocking check: returns immediately if no thread is running.
void softether_additional_thread_wait(softether_connection_t* conn) {
    if (conn == NULL || !conn->additional_connecting) return;
    pthread_join(conn->additional_thread, NULL);
    conn->additional_connecting = 0;
}

// Open an additional TCP connection to the server (ClientAdditionalConnect).
// Follows the upstream SoftEther flow:
//   1. Open TCP socket + TLS handshake
//   2. Send SoftEther signature (VPNCONNECT watermark via /vpnsvc/connect.cgi)
//   3. Download Hello
//   4. Send "additional_connect" method with session_key for authentication
//   5. Parse response, add socket to additional[] array
// Returns 0 on success, -1 on failure.
int softether_additional_connect(softether_connection_t* conn) {
    if (conn == NULL) return -1;
    if (conn->state != STATE_CONNECTED) return -1;

    // Find a free slot
    int slot = -1;
    uint32_t server_direction = TCP_DIRECTION_BOTH;
    for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
        if (!conn->additional[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        LOGD("additional_connect: no free slot (num_additional=%d)", conn->num_additional);
        return -1;
    }

    LOGD("additional_connect: opening connection to %s:%d (slot %d)",
         conn->server_ip, conn->server_port, slot);

    // Step 1: Open TCP socket
    softether_socket_t* sock = socket_create(SOCKET_TYPE_TCP);
    if (sock == NULL) {
        LOGE("additional_connect: failed to create socket");
        conn->additional_failed_count++;
        return -1;
    }

    if (socket_connect_timeout(sock, conn->server_ip, conn->server_port, conn->timeout_ms) != 0) {
        LOGE("additional_connect: TCP connect failed");
        socket_destroy(sock);
        conn->additional_failed_count++;
        return -1;
    }

    int fd = sock->fd;
    sock->fd = -1;
    socket_destroy(sock);

    // Step 2: TLS handshake
    ssl_context_t* ssl_ctx = ssl_create_client();
    if (ssl_ctx == NULL) {
        LOGE("additional_connect: failed to create SSL context");
        close(fd);
        conn->additional_failed_count++;
        return -1;
    }

    if (ssl_connect(ssl_ctx, fd, conn->server_ip) != 0) {
        LOGE("additional_connect: TLS handshake failed");
        ssl_destroy(ssl_ctx);
        close(fd);
        conn->additional_failed_count++;
        return -1;
    }

    // Set TCP_NODELAY
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    // Set data timeout
    int data_timeout_ms = 5000;
    struct timeval tv;
    tv.tv_sec = data_timeout_ms / 1000;
    tv.tv_usec = (data_timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Step 3: Send SoftEther signature (VPNCONNECT watermark)
    {
        const char* watermark = "VPNCONNECT";
        size_t watermark_len = strlen(watermark);

        char http_post[1024];
        int post_len = snprintf(http_post, sizeof(http_post),
            "POST /vpnsvc/connect.cgi HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: image/jpeg\r\n"
            "Connection: Keep-Alive\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            conn->server_ip, watermark_len);

        size_t combined_len = (size_t)post_len + watermark_len;
        uint8_t* combined = (uint8_t*)malloc(combined_len);
        if (combined == NULL) {
            ssl_shutdown(ssl_ctx);
            ssl_destroy(ssl_ctx);
            close(fd);
            conn->additional_failed_count++;
            return -1;
        }
        memcpy(combined, http_post, post_len);
        memcpy(combined + post_len, watermark, watermark_len);

        int write_ret = ssl_write(ssl_ctx, combined, (int)combined_len);
        free(combined);

        if (write_ret <= 0) {
            LOGE("additional_connect: failed to send VPNCONNECT watermark");
            ssl_shutdown(ssl_ctx);
            ssl_destroy(ssl_ctx);
            close(fd);
            conn->additional_failed_count++;
            return -1;
        }
    }

    // Read HTTP response from connect.cgi
    {
        uint8_t resp[4096];
        int hdr_len = 0;
        int found_end = 0;
        while (hdr_len < (int)sizeof(resp) - 1 && !found_end) {
            int r = ssl_read(ssl_ctx, resp + hdr_len, 1);
            if (r <= 0) {
                LOGE("additional_connect: failed reading connect.cgi response");
                ssl_shutdown(ssl_ctx);
                ssl_destroy(ssl_ctx);
                close(fd);
                conn->additional_failed_count++;
                return -1;
            }
            hdr_len++;
            if (hdr_len >= 4 &&
                resp[hdr_len-4] == '\r' && resp[hdr_len-3] == '\n' &&
                resp[hdr_len-2] == '\r' && resp[hdr_len-1] == '\n') {
                found_end = 1;
            }
        }
        if (!found_end) {
            LOGE("additional_connect: connect.cgi response headers too large");
            ssl_shutdown(ssl_ctx);
            ssl_destroy(ssl_ctx);
            close(fd);
            conn->additional_failed_count++;
            return -1;
        }

        uint32_t content_length = 0;
        const char* cl_str = strstr((char*)resp, "Content-Length: ");
        if (!cl_str) cl_str = strstr((char*)resp, "content-length: ");
        if (cl_str) {
            content_length = (uint32_t)atoi(cl_str + 16);
        }

        if (content_length > 0 && hdr_len + (int)content_length < (int)sizeof(resp)) {
            uint32_t body_read = 0;
            while (body_read < content_length) {
                int r = ssl_read(ssl_ctx, resp + hdr_len + body_read,
                                 (int)(content_length - body_read));
                if (r <= 0) {
                    LOGE("additional_connect: failed reading connect.cgi body");
                    ssl_shutdown(ssl_ctx);
                    ssl_destroy(ssl_ctx);
                    close(fd);
                    conn->additional_failed_count++;
                    return -1;
                }
                body_read += (uint32_t)r;
            }
        }

        LOGD("additional_connect: connect.cgi response received");
    }

    // Step 4: Send "additional_connect" method with session_key
    {
        uint32_t pack_size = 4;  // num_elements (uint32)
        pack_size += PACK_STR_SZ("method", "additional_connect");
        pack_size += PACK_DATA_SZ("session_key", SHA1_SIZE);

        uint8_t* pack_buf = (uint8_t*)calloc(1, pack_size + 64);
        if (pack_buf == NULL) {
            ssl_shutdown(ssl_ctx);
            ssl_destroy(ssl_ctx);
            close(fd);
            conn->additional_failed_count++;
            return -1;
        }

        uint8_t* pp = pack_buf;
        pack_write_uint32(&pp, 2);  // num_elements = 2
        pack_add_str(&pp, "method", "additional_connect");
        pack_add_data(&pp, "session_key", conn->session_key, SHA1_SIZE);

        uint32_t actual_len = (uint32_t)(pp - pack_buf);

        char date_str[64];
        {
            time_t now = time(NULL);
            struct tm* gmt = gmtime(&now);
            strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", gmt);
        }

        char auth_hdr[512];
        int auth_hdr_len = snprintf(auth_hdr, sizeof(auth_hdr),
            "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n"
            "Date: %s\r\n"
            "Host: %s\r\n"
            "Keep-Alive: timeout=15; max=19\r\n"
            "Connection: Keep-Alive\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %u\r\n"
            "\r\n",
            date_str, conn->server_ip, actual_len);

        size_t auth_combined_len = (size_t)auth_hdr_len + actual_len;
        uint8_t* auth_combined = (uint8_t*)malloc(auth_combined_len);
        if (auth_combined == NULL) {
            free(pack_buf);
            ssl_shutdown(ssl_ctx);
            ssl_destroy(ssl_ctx);
            close(fd);
            conn->additional_failed_count++;
            return -1;
        }
        memcpy(auth_combined, auth_hdr, auth_hdr_len);
        memcpy(auth_combined + auth_hdr_len, pack_buf, actual_len);
        free(pack_buf);

        int write_ret = ssl_write(ssl_ctx, auth_combined, (int)auth_combined_len);
        free(auth_combined);

        if (write_ret <= 0) {
            LOGE("additional_connect: failed to send additional_connect PACK");
            ssl_shutdown(ssl_ctx);
            ssl_destroy(ssl_ctx);
            close(fd);
            conn->additional_failed_count++;
            return -1;
        }
    }

    // Read the additional_connect response
    {
        uint8_t auth_resp[4096];
        int hdr_len = 0;
        int found_end = 0;
        while (hdr_len < (int)sizeof(auth_resp) - 1 && !found_end) {
            int r = ssl_read(ssl_ctx, auth_resp + hdr_len, 1);
            if (r <= 0) {
                LOGE("additional_connect: failed reading auth response");
                ssl_shutdown(ssl_ctx);
                ssl_destroy(ssl_ctx);
                close(fd);
                conn->additional_failed_count++;
                return -1;
            }
            hdr_len++;
            if (hdr_len >= 4 &&
                auth_resp[hdr_len-4] == '\r' && auth_resp[hdr_len-3] == '\n' &&
                auth_resp[hdr_len-2] == '\r' && auth_resp[hdr_len-1] == '\n') {
                found_end = 1;
            }
        }
        if (!found_end) {
            LOGE("additional_connect: auth response headers too large");
            ssl_shutdown(ssl_ctx);
            ssl_destroy(ssl_ctx);
            close(fd);
            conn->additional_failed_count++;
            return -1;
        }
        auth_resp[hdr_len] = '\0';

        uint32_t content_length = 0;
        const char* cl_str = strstr((char*)auth_resp, "Content-Length: ");
        if (!cl_str) cl_str = strstr((char*)auth_resp, "content-length: ");
        if (cl_str) {
            content_length = (uint32_t)atoi(cl_str + 16);
        }

        int body_off = hdr_len;
        int body_ln = 0;
        if (content_length > 0 && hdr_len + (int)content_length < (int)sizeof(auth_resp)) {
            uint32_t body_read = 0;
            while (body_read < content_length) {
                int r = ssl_read(ssl_ctx, auth_resp + hdr_len + body_read,
                                 (int)(content_length - body_read));
                if (r <= 0) {
                    LOGE("additional_connect: failed reading auth body");
                    ssl_shutdown(ssl_ctx);
                    ssl_destroy(ssl_ctx);
                    close(fd);
                    conn->additional_failed_count++;
                    return -1;
                }
                body_read += (uint32_t)r;
            }
            body_ln = (int)content_length;
        }

        uint32_t err_val = 0;
        if (body_ln >= 4) {
            if (pack_get_int(auth_resp + body_off, (uint32_t)body_ln, "error", &err_val) == 0) {
                if (err_val != 0) {
                    LOGE("additional_connect: server returned error %u", err_val);
                    ssl_shutdown(ssl_ctx);
                    ssl_destroy(ssl_ctx);
                    close(fd);
                    conn->additional_failed_count++;
                    return -1;
                }
            }
            // Parse direction from server response (used in half-connection mode)
            pack_get_int(auth_resp + body_off, (uint32_t)body_ln, "direction", &server_direction);
        }

        LOGD("additional_connect: auth response parsed (error=%u, direction=%u)", err_val, server_direction);
    }

    // Step 5: Add socket to additional[] array
    {
        softether_tcp_sock_t* ts = &conn->additional[slot];
        ts->socket_fd = fd;
        ts->ssl_ctx = ssl_ctx;
        ts->ssl = ssl_ctx;
        ts->direction = (int)server_direction;
        ts->last_recv = softether_tick_ms();
        ts->late_count = 0;
        ts->active = 1;
        conn->num_additional++;
    }

    LOGD("additional_connect: SUCCESS slot=%d fd=%d direction=%u num_additional=%d",
         slot, fd, server_direction, conn->num_additional);

    conn->additional_failed_count = 0;
    return 0;
}

// Select the best TCP socket for sending (lowest late_count).
// Returns the socket index: 0 = primary, 1..N = additional.
// In half-connection mode, only selects sockets whose direction allows sending
// (client mode: TCP_DIRECTION_BOTH or TCP_DIRECTION_CLIENT_TO_SERVER).
int softether_select_send_socket(softether_connection_t* conn) {
    if (conn == NULL) return 0;

    int best_idx = -1;
    uint32_t min_late = UINT32_MAX;

    // Check primary socket (client mode: send if direction is BOTH or C2S)
    if (conn->socket_fd >= 0 && conn->ssl != NULL) {
        int pd = conn->primary_direction;
        if (pd == TCP_DIRECTION_BOTH || pd == TCP_DIRECTION_CLIENT_TO_SERVER) {
            min_late = 0;
            best_idx = 0;
        }
    }

    // Check additional sockets - only prefer over primary if strictly less late
    for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
        softether_tcp_sock_t* ts = &conn->additional[i];
        if (!ts->active) continue;

        // Client mode: can send on TCP_BOTH or TCP_CLIENT_TO_SERVER
        int d = ts->direction;
        if (d != TCP_DIRECTION_BOTH && d != TCP_DIRECTION_CLIENT_TO_SERVER) continue;

        if (ts->late_count < min_late) {
            min_late = ts->late_count;
            best_idx = i + 1;  // +1 because index 0 = primary
        }
    }

    // Fallback to primary if no send-capable socket found
    if (best_idx < 0) {
        best_idx = 0;
    }

    return best_idx;
}

// Get the total number of active connections (primary + additional)
int softether_get_num_connections(softether_connection_t* conn) {
    if (conn == NULL) return 0;
    int count = (conn->socket_fd >= 0) ? 1 : 0;
    count += conn->num_additional;
    return count;
}

// Fill an array with the file descriptors of all active TCP sockets.
// Returns the number of FDs written.
int softether_get_active_socket_fds(softether_connection_t* conn, int* fds, int max_fds) {
    if (conn == NULL || fds == NULL || max_fds <= 0) return 0;

    int count = 0;

    if (conn->socket_fd >= 0 && count < max_fds) {
        fds[count++] = conn->socket_fd;
    }

    for (int i = 0; i < MAX_SE_CONNECTIONS && count < max_fds; i++) {
        if (conn->additional[i].active && conn->additional[i].socket_fd >= 0) {
            fds[count++] = conn->additional[i].socket_fd;
        }
    }

    return count;
}

// Reconnection support - Enable/disable automatic reconnection
// Reconnection support - Enable/disable automatic reconnection
void softether_set_reconnect_enabled(softether_connection_t* conn, int enabled) {
    if (conn == NULL) {
        return;
    }

    // Store reconnection preference (implementation can be extended)
    LOGD("Reconnection %s", enabled ? "enabled" : "disabled");
}

void softether_set_auth_type(softether_connection_t* conn, int auth_type) {
    if (conn) {
        conn->forced_auth_type = auth_type;
        LOGD("Auth type set to %d", auth_type);
    }
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

    // Attempt reconnection with stored credentials (use TCP to be safe on reconnect)
    return softether_connect_with_hub(conn, conn->server_ip, conn->server_port,
                                      conn->username, conn->password, conn->hub_name, 1,
        "", "", 0, "", "", "",
        "", "", 0,
        "", "", 0);
}
