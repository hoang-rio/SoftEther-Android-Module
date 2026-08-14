#include "softether_pack.h"
#include <stdlib.h>
#include <android/log.h>

#define TAG "SoftEtherPack"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define PACK_INITIAL_CAP 256
#define PACK_MAX_ELEMENTS 4096
#define PACK_MAX_VALUES 65535

// Write big-endian uint32 (matching Endian32)
static void pack_write_uint32(uint8_t** buf, uint32_t val) {
    (*buf)[0] = (val >> 24) & 0xFF;
    (*buf)[1] = (val >> 16) & 0xFF;
    (*buf)[2] = (val >> 8) & 0xFF;
    (*buf)[3] = val & 0xFF;
    *buf += 4;
}

static void pack_write_uint64(uint8_t** buf, uint64_t val) {
    for (int i = 7; i >= 0; i--) {
        (*buf)[0] = (uint8_t)((val >> (i * 8)) & 0xFF);
        *buf += 1;
    }
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

static int pack_reserve(softether_pack_t* p, uint32_t add) {
    if (p == NULL || p->data == NULL) {
        return -1;
    }
    if (add > UINT32_MAX - p->len) {
        return -1;
    }
    uint32_t need = p->len + add;
    if (need <= p->cap) {
        return 0;
    }
    uint32_t new_cap = p->cap ? p->cap : PACK_INITIAL_CAP;
    while (new_cap < need) {
        if (new_cap > UINT32_MAX / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }
    uint8_t* nd = (uint8_t*)realloc(p->data, new_cap);
    if (nd == NULL) {
        LOGE("pack_reserve: realloc(%u) failed", new_cap);
        return -1;
    }
    p->data = nd;
    p->cap = new_cap;
    return 0;
}

// Finish an element that was written into the pack buffer, bump the element
// count and patch the num_elements field at offset 0.
static void pack_commit_element(softether_pack_t* p, uint32_t elem_size) {
    p->len += elem_size;
    p->num_elements++;
    uint8_t* buf = p->data;
    pack_write_uint32(&buf, p->num_elements);
}

softether_pack_t* pack_new(void) {
    softether_pack_t* p = (softether_pack_t*)calloc(1, sizeof(softether_pack_t));
    if (p == NULL) {
        return NULL;
    }
    p->data = (uint8_t*)malloc(PACK_INITIAL_CAP);
    if (p->data == NULL) {
        free(p);
        return NULL;
    }
    p->cap = PACK_INITIAL_CAP;
    p->len = 4;  // num_elements placeholder
    p->num_elements = 0;
    return p;
}

void pack_free(softether_pack_t* p) {
    if (p == NULL) {
        return;
    }
    free(p->data);
    free(p);
}

int pack_add_int(softether_pack_t* p, const char* name, uint32_t val) {
    if (p == NULL || name == NULL) {
        return -1;
    }
    uint32_t elem_size = PACK_INT_SZ(name);
    if (pack_reserve(p, elem_size) != 0) {
        return -1;
    }
    uint8_t* buf = p->data + p->len;
    pack_write_elem_name(&buf, name);
    pack_write_uint32(&buf, PACK_TYPE_INT);
    pack_write_uint32(&buf, 1);   // num_values = 1
    pack_write_uint32(&buf, val);
    pack_commit_element(p, elem_size);
    return 0;
}

int pack_add_int64(softether_pack_t* p, const char* name, uint64_t val) {
    if (p == NULL || name == NULL) {
        return -1;
    }
    uint32_t elem_size = PACK_INT64_SZ(name);
    if (pack_reserve(p, elem_size) != 0) {
        return -1;
    }
    uint8_t* buf = p->data + p->len;
    pack_write_elem_name(&buf, name);
    pack_write_uint32(&buf, PACK_TYPE_INT64);
    pack_write_uint32(&buf, 1);
    pack_write_uint64(&buf, val);
    pack_commit_element(p, elem_size);
    return 0;
}

int pack_add_str(softether_pack_t* p, const char* name, const char* val) {
    if (p == NULL || name == NULL || val == NULL) {
        return -1;
    }
    uint32_t elem_size = PACK_STR_SZ(name, val);
    if (pack_reserve(p, elem_size) != 0) {
        return -1;
    }
    uint8_t* buf = p->data + p->len;
    pack_write_elem_name(&buf, name);
    pack_write_uint32(&buf, PACK_TYPE_STR);
    pack_write_uint32(&buf, 1);
    pack_write_str_val(&buf, val);
    pack_commit_element(p, elem_size);
    return 0;
}

int pack_add_data(softether_pack_t* p, const char* name, const uint8_t* data, uint32_t dlen) {
    if (p == NULL || name == NULL || (dlen > 0 && data == NULL)) {
        return -1;
    }
    uint32_t elem_size = PACK_DATA_SZ(name, dlen);
    if (pack_reserve(p, elem_size) != 0) {
        return -1;
    }
    uint8_t* buf = p->data + p->len;
    pack_write_elem_name(&buf, name);
    pack_write_uint32(&buf, PACK_TYPE_DATA);
    pack_write_uint32(&buf, 1);
    pack_write_data_val(&buf, data, dlen);
    pack_commit_element(p, elem_size);
    return 0;
}

const uint8_t* pack_data(const softether_pack_t* p) {
    if (p == NULL) {
        return NULL;
    }
    return p->data;
}

uint32_t pack_length(const softether_pack_t* p) {
    if (p == NULL) {
        return 0;
    }
    return p->len;
}

// ---- Bounds-safe readers ----

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

static int pack_read_uint64_safe(const uint8_t** p, const uint8_t* end, uint64_t* out) {
    if (p == NULL || *p == NULL || out == NULL || end == NULL || *p + 8 > end) {
        return -1;
    }

    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (*p)[i];
    }
    *out = v;
    *p += 8;
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

// Read an element header, matching it against field_name/type.
// On match with num_values >= 1 returns 1 and leaves *p at the first value.
// On non-match returns 0 and leaves *p after the whole element.
// Returns -1 on malformed data.
static int pack_match_element(const uint8_t** p, const uint8_t* end,
                              const char* field_name, uint32_t type) {
    uint32_t name_len_plus1 = 0;
    if (pack_read_uint32_safe(p, end, &name_len_plus1) != 0) {
        return -1;
    }
    if (name_len_plus1 == 0) {
        return -1;
    }
    uint32_t name_len = name_len_plus1 - 1;
    if (*p + name_len > end) {
        return -1;
    }

    char elem[64] = {0};
    uint32_t cp = (name_len < 63) ? name_len : 63;
    memcpy(elem, *p, cp);
    *p += name_len;

    uint32_t elem_type = 0, num_values = 0;
    if (pack_read_uint32_safe(p, end, &elem_type) != 0) {
        return -1;
    }
    if (pack_read_uint32_safe(p, end, &num_values) != 0) {
        return -1;
    }
    if (num_values > PACK_MAX_VALUES) {
        return -1;
    }

    if (strcmp(elem, field_name) == 0 && elem_type == type && num_values >= 1) {
        return 1;  // match; *p is at first value
    }

    for (uint32_t v = 0; v < num_values; v++) {
        if (pack_skip_value_safe(p, end, elem_type) != 0) {
            return -1;
        }
    }
    return 0;  // no match
}

int pack_get_int(const uint8_t* body, uint32_t body_len,
                 const char* field_name, uint32_t* out_val) {
    if (!body || body_len < 4 || !field_name || !out_val) {
        return -1;
    }

    const uint8_t* p = body;
    const uint8_t* end = body + body_len;

    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) {
        return -1;
    }
    if (num_elements > PACK_MAX_ELEMENTS) {
        return -1;
    }

    for (uint32_t i = 0; i < num_elements; i++) {
        int m = pack_match_element(&p, end, field_name, PACK_TYPE_INT);
        if (m < 0) {
            return -1;
        }
        if (m == 1) {
            if (pack_read_uint32_safe(&p, end, out_val) != 0) {
                return -1;
            }
            return 0;  // found
        }
    }
    return -1;  // not found
}

int pack_get_int64(const uint8_t* body, uint32_t body_len,
                   const char* field_name, uint64_t* out_val) {
    if (!body || body_len < 4 || !field_name || !out_val) {
        return -1;
    }

    const uint8_t* p = body;
    const uint8_t* end = body + body_len;

    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) {
        return -1;
    }
    if (num_elements > PACK_MAX_ELEMENTS) {
        return -1;
    }

    for (uint32_t i = 0; i < num_elements; i++) {
        int m = pack_match_element(&p, end, field_name, PACK_TYPE_INT64);
        if (m < 0) {
            return -1;
        }
        if (m == 1) {
            if (pack_read_uint64_safe(&p, end, out_val) != 0) {
                return -1;
            }
            return 0;  // found
        }
    }
    return -1;  // not found
}

int pack_get_str(const uint8_t* body, uint32_t body_len,
                 const char* field_name, char* out_str, uint32_t out_size) {
    if (!body || body_len < 4 || !field_name || !out_str || out_size == 0) {
        return -1;
    }

    const uint8_t* p = body;
    const uint8_t* end = body + body_len;

    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) {
        return -1;
    }
    if (num_elements > PACK_MAX_ELEMENTS) {
        return -1;
    }

    for (uint32_t i = 0; i < num_elements; i++) {
        int m = pack_match_element(&p, end, field_name, PACK_TYPE_STR);
        if (m < 0) {
            return -1;
        }
        if (m == 1) {
            if (pack_read_string_safe(&p, end, out_str, out_size) != 0) {
                return -1;
            }
            return 0;  // found
        }
    }
    return -1;  // not found
}

int pack_get_data(const uint8_t* body, uint32_t body_len,
                  const char* field_name, uint8_t* out_data,
                  uint32_t out_size, uint32_t* out_len) {
    if (!body || body_len < 4 || !field_name || !out_data || out_size == 0) {
        return -1;
    }

    const uint8_t* p = body;
    const uint8_t* end = body + body_len;

    uint32_t num_elements = 0;
    if (pack_read_uint32_safe(&p, end, &num_elements) != 0) {
        return -1;
    }
    if (num_elements > PACK_MAX_ELEMENTS) {
        return -1;
    }

    for (uint32_t i = 0; i < num_elements; i++) {
        int m = pack_match_element(&p, end, field_name, PACK_TYPE_DATA);
        if (m < 0) {
            return -1;
        }
        if (m == 1) {
            uint32_t data_len = 0;
            if (pack_read_uint32_safe(&p, end, &data_len) != 0) {
                return -1;
            }
            if (p + data_len > end) {
                return -1;
            }
            uint32_t copy_len = (data_len < out_size) ? data_len : out_size;
            memcpy(out_data, p, copy_len);
            if (out_len) {
                *out_len = copy_len;
            }
            return 0;  // found
        }
    }
    return -1;  // not found
}
