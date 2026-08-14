#ifndef SOFTETHER_PACK_H
#define SOFTETHER_PACK_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// PACK serialization types (SoftEther Pack.h VALUE_* constants)
#define PACK_TYPE_INT      0    // VALUE_INT
#define PACK_TYPE_DATA     1    // VALUE_DATA
#define PACK_TYPE_STR      2    // VALUE_STR
#define PACK_TYPE_UNISTR   3    // VALUE_UNISTR
#define PACK_TYPE_INT64    4    // VALUE_INT64

#define PACK_SHA1_SIZE 20

// PACK element size macros (WriteBufStr format — verified against Pack.c/Memory.c):
//   Element names:  uint32(strlen+1) + strlen bytes (no null)
//   INT value:      uint32 big-endian (Endian32)
//   STR value:      uint32(strlen) + strlen bytes
//   DATA value:     uint32(size) + size bytes
// Element name occupies: 4 + strlen bytes
#define PACK_NAME_SZ(n)       (4 + (uint32_t)strlen(n))
// Element header: name + type(4) + num_values(4)
#define PACK_ELEM_HDR_SZ(n)   (PACK_NAME_SZ(n) + 8)
// Full element sizes (1 value each)
#define PACK_INT_SZ(n)        (PACK_ELEM_HDR_SZ(n) + 4)
#define PACK_INT64_SZ(n)      (PACK_ELEM_HDR_SZ(n) + 8)
#define PACK_STR_SZ(n, v)     (PACK_ELEM_HDR_SZ(n) + 4 + (uint32_t)strlen(v))
#define PACK_DATA_SZ(n, d)    (PACK_ELEM_HDR_SZ(n) + 4 + (d))

// Growable PACK writer. Buffer layout starts with uint32 num_elements,
// patched in place on every pack_add_* call.
typedef struct {
    uint8_t* data;
    uint32_t len;
    uint32_t cap;
    uint32_t num_elements;
} softether_pack_t;

// Writer
softether_pack_t* pack_new(void);
void pack_free(softether_pack_t* p);
int pack_add_int(softether_pack_t* p, const char* name, uint32_t val);
int pack_add_int64(softether_pack_t* p, const char* name, uint64_t val);
int pack_add_str(softether_pack_t* p, const char* name, const char* val);
int pack_add_data(softether_pack_t* p, const char* name, const uint8_t* data, uint32_t dlen);
const uint8_t* pack_data(const softether_pack_t* p);
uint32_t pack_length(const softether_pack_t* p);

// Reader (bounds-safe). Return 0 on success, -1 if not found or malformed.
int pack_get_int(const uint8_t* body, uint32_t body_len, const char* field, uint32_t* out);
int pack_get_int64(const uint8_t* body, uint32_t body_len, const char* field, uint64_t* out);
int pack_get_str(const uint8_t* body, uint32_t body_len, const char* field,
                 char* out, uint32_t out_size);
int pack_get_data(const uint8_t* body, uint32_t body_len, const char* field,
                  uint8_t* out, uint32_t out_size, uint32_t* out_len);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_PACK_H
