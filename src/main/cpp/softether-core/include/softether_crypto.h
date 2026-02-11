#ifndef SOFTETHER_CRYPTO_H
#define SOFTETHER_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// AES encryption context
typedef struct aes_context aes_context_t;

// AES key sizes
#define AES_128_KEY_SIZE    16
#define AES_256_KEY_SIZE    32
#define AES_BLOCK_SIZE      16

// AES modes
#define AES_MODE_CBC        0
#define AES_MODE_GCM        1

// Function prototypes

// AES operations
aes_context_t* aes_create(int mode, const uint8_t* key, size_t key_len, 
                          const uint8_t* iv, size_t iv_len);
void aes_destroy(aes_context_t* ctx);
int aes_encrypt(aes_context_t* ctx, const uint8_t* plaintext, size_t plaintext_len,
                uint8_t* ciphertext, size_t* ciphertext_len);
int aes_decrypt(aes_context_t* ctx, const uint8_t* ciphertext, size_t ciphertext_len,
                uint8_t* plaintext, size_t* plaintext_len);

// SHA256 hashing
void sha256_hash(const uint8_t* data, size_t data_len, uint8_t* hash);

// HMAC-SHA256
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* mac);

// Random number generation
int generate_random_bytes(uint8_t* buffer, size_t len);

// TLS/SSL operations
typedef struct ssl_context ssl_context_t;

ssl_context_t* ssl_create_client(void);
void ssl_destroy(ssl_context_t* ctx);
int ssl_connect(ssl_context_t* ctx, int socket_fd, const char* hostname);
int ssl_read(ssl_context_t* ctx, uint8_t* buffer, size_t len);
int ssl_write(ssl_context_t* ctx, const uint8_t* data, size_t len);
void ssl_shutdown(ssl_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_CRYPTO_H
