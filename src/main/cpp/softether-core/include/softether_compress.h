#ifndef SOFTETHER_COMPRESS_H
#define SOFTETHER_COMPRESS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compress data using zlib deflate (RFC 1951)
// Returns 0 on success, negative on error
// *dest_len is set to the compressed size
int compress_data(const uint8_t* src, uint32_t src_len,
                  uint8_t* dest, uint32_t* dest_len);

// Decompress zlib-compressed data
// Returns 0 on success, negative on error
// *dest_len is set to the decompressed size
int uncompress_data(const uint8_t* src, uint32_t src_len,
                    uint8_t* dest, uint32_t* dest_len);

// Calculate upper bound for compressed data
uint32_t calc_compress_bound(uint32_t src_len);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_COMPRESS_H
