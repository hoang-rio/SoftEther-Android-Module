#include "softether_compress.h"
#include <zlib.h>

int compress_data(const uint8_t* src, uint32_t src_len,
                  uint8_t* dest, uint32_t* dest_len) {
    if (src == NULL || dest == NULL || dest_len == NULL) return -1;
    if (src_len == 0) { *dest_len = 0; return 0; }

    uLongf out_len = (uLongf)*dest_len;
    int ret = compress2(dest, &out_len, src, (uLong)src_len, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) return -2;

    *dest_len = (uint32_t)out_len;
    return 0;
}

int uncompress_data(const uint8_t* src, uint32_t src_len,
                    uint8_t* dest, uint32_t* dest_len) {
    if (src == NULL || dest == NULL || dest_len == NULL) return -1;
    if (src_len == 0) { *dest_len = 0; return 0; }

    uLongf out_len = (uLongf)*dest_len;
    int ret = uncompress(dest, &out_len, src, (uLong)src_len);
    if (ret != Z_OK) return -2;

    *dest_len = (uint32_t)out_len;
    return 0;
}

uint32_t calc_compress_bound(uint32_t src_len) {
    return (uint32_t)compressBound((uLong)src_len);
}
