#include "softether_crypto.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "SoftEtherCrypto"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// AES context structure
struct aes_context {
    EVP_CIPHER_CTX* encrypt_ctx;
    EVP_CIPHER_CTX* decrypt_ctx;
    int mode;
    uint8_t key[32];
    size_t key_len;
    uint8_t iv[16];
};

// SSL context structure
struct ssl_context {
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* bio;
    int connected;
};

aes_context_t* aes_create(int mode, const uint8_t* key, size_t key_len, 
                          const uint8_t* iv, size_t iv_len) {
    if (key == NULL || (key_len != 16 && key_len != 24 && key_len != 32)) {
        LOGE("Invalid key parameters");
        return NULL;
    }
    
    aes_context_t* ctx = (aes_context_t*)calloc(1, sizeof(aes_context_t));
    if (ctx == NULL) {
        LOGE("Failed to allocate AES context");
        return NULL;
    }
    
    ctx->encrypt_ctx = EVP_CIPHER_CTX_new();
    ctx->decrypt_ctx = EVP_CIPHER_CTX_new();
    
    if (ctx->encrypt_ctx == NULL || ctx->decrypt_ctx == NULL) {
        LOGE("Failed to create EVP contexts");
        aes_destroy(ctx);
        return NULL;
    }
    
    ctx->mode = mode;
    ctx->key_len = key_len;
    memcpy(ctx->key, key, key_len);
    
    if (iv != NULL && iv_len > 0) {
        size_t copy_len = iv_len < 16 ? iv_len : 16;
        memcpy(ctx->iv, iv, copy_len);
    }
    
    const EVP_CIPHER* cipher;
    if (mode == AES_MODE_CBC) {
        switch (key_len) {
            case 16: cipher = EVP_aes_128_cbc(); break;
            case 24: cipher = EVP_aes_192_cbc(); break;
            case 32: cipher = EVP_aes_256_cbc(); break;
            default: cipher = EVP_aes_256_cbc(); break;
        }
    } else {
        switch (key_len) {
            case 16: cipher = EVP_aes_128_gcm(); break;
            case 24: cipher = EVP_aes_192_gcm(); break;
            case 32: cipher = EVP_aes_256_gcm(); break;
            default: cipher = EVP_aes_256_gcm(); break;
        }
    }
    
    if (EVP_EncryptInit_ex(ctx->encrypt_ctx, cipher, NULL, key, iv) != 1) {
        LOGE("Failed to initialize encryption context");
        aes_destroy(ctx);
        return NULL;
    }
    
    if (EVP_DecryptInit_ex(ctx->decrypt_ctx, cipher, NULL, key, iv) != 1) {
        LOGE("Failed to initialize decryption context");
        aes_destroy(ctx);
        return NULL;
    }
    
    LOGD("AES context created: mode=%d, key_len=%zu", mode, key_len);
    return ctx;
}

void aes_destroy(aes_context_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    
    if (ctx->encrypt_ctx) {
        EVP_CIPHER_CTX_free(ctx->encrypt_ctx);
    }
    if (ctx->decrypt_ctx) {
        EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
    }
    
    // Clear sensitive data
    memset(ctx, 0, sizeof(aes_context_t));
    free(ctx);
}

int aes_encrypt(aes_context_t* ctx, const uint8_t* plaintext, size_t plaintext_len,
                uint8_t* ciphertext, size_t* ciphertext_len) {
    if (ctx == NULL || ctx->encrypt_ctx == NULL) {
        LOGE("Invalid AES context");
        return -1;
    }
    
    int len;
    int ciphertext_len_int = 0;
    
    if (EVP_EncryptInit_ex(ctx->encrypt_ctx, NULL, NULL, NULL, NULL) != 1) {
        LOGE("Failed to reinitialize encryption");
        return -1;
    }
    
    if (EVP_EncryptUpdate(ctx->encrypt_ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        LOGE("Encryption update failed");
        return -1;
    }
    ciphertext_len_int = len;
    
    if (EVP_EncryptFinal_ex(ctx->encrypt_ctx, ciphertext + len, &len) != 1) {
        LOGE("Encryption final failed");
        return -1;
    }
    ciphertext_len_int += len;
    
    *ciphertext_len = (size_t)ciphertext_len_int;
    return 0;
}

int aes_decrypt(aes_context_t* ctx, const uint8_t* ciphertext, size_t ciphertext_len,
                uint8_t* plaintext, size_t* plaintext_len) {
    if (ctx == NULL || ctx->decrypt_ctx == NULL) {
        LOGE("Invalid AES context");
        return -1;
    }
    
    int len;
    int plaintext_len_int = 0;
    
    if (EVP_DecryptInit_ex(ctx->decrypt_ctx, NULL, NULL, NULL, NULL) != 1) {
        LOGE("Failed to reinitialize decryption");
        return -1;
    }
    
    if (EVP_DecryptUpdate(ctx->decrypt_ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        LOGE("Decryption update failed");
        return -1;
    }
    plaintext_len_int = len;
    
    if (EVP_DecryptFinal_ex(ctx->decrypt_ctx, plaintext + len, &len) != 1) {
        LOGE("Decryption final failed");
        return -1;
    }
    plaintext_len_int += len;
    
    *plaintext_len = (size_t)plaintext_len_int;
    return 0;
}

void sha256_hash(const uint8_t* data, size_t data_len, uint8_t* hash) {
    if (data == NULL || hash == NULL) {
        return;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        LOGE("Failed to create MD context");
        return;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        LOGE("Failed to initialize SHA256");
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        LOGE("SHA256 update failed");
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    unsigned int hash_len = 32;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        LOGE("SHA256 final failed");
    }
    
    EVP_MD_CTX_free(ctx);
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* mac) {
    if (key == NULL || data == NULL || mac == NULL) {
        return;
    }
    
    unsigned int mac_len = 32;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, mac, &mac_len);
}

int generate_random_bytes(uint8_t* buffer, size_t len) {
    if (buffer == NULL || len == 0) {
        return -1;
    }
    
    if (RAND_bytes(buffer, (int)len) != 1) {
        LOGE("Failed to generate random bytes");
        return -1;
    }
    
    return 0;
}

ssl_context_t* ssl_create_client(void) {
    ssl_context_t* ctx = (ssl_context_t*)calloc(1, sizeof(ssl_context_t));
    if (ctx == NULL) {
        LOGE("Failed to allocate SSL context");
        return NULL;
    }
    
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD* method = TLS_client_method();
    ctx->ctx = SSL_CTX_new(method);
    
    if (ctx->ctx == NULL) {
        LOGE("Failed to create SSL context");
        free(ctx);
        return NULL;
    }
    
    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ctx->ctx, TLS1_2_VERSION);
    
    // Set default verify paths
    SSL_CTX_set_default_verify_paths(ctx->ctx);
    
    LOGD("SSL client context created");
    return ctx;
}

void ssl_destroy(ssl_context_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    
    if (ctx->ssl) {
        SSL_free(ctx->ssl);
    }
    if (ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
    }
    
    free(ctx);
}

int ssl_connect(ssl_context_t* ctx, int socket_fd, const char* hostname) {
    if (ctx == NULL || ctx->ctx == NULL) {
        LOGE("Invalid SSL context");
        return -1;
    }
    
    ctx->ssl = SSL_new(ctx->ctx);
    if (ctx->ssl == NULL) {
        LOGE("Failed to create SSL object");
        return -1;
    }
    
    // Set SNI hostname
    if (hostname != NULL) {
        SSL_set_tlsext_host_name(ctx->ssl, hostname);
    }
    
    // Attach socket to SSL
    if (SSL_set_fd(ctx->ssl, socket_fd) != 1) {
        LOGE("Failed to set SSL fd");
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        return -1;
    }
    
    // Set connect state
    SSL_set_connect_state(ctx->ssl);
    
    // Perform handshake
    int result = SSL_do_handshake(ctx->ssl);
    if (result != 1) {
        int ssl_error = SSL_get_error(ctx->ssl, result);
        LOGE("SSL handshake failed: %d", ssl_error);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        return -1;
    }
    
    ctx->connected = 1;
    LOGD("SSL handshake successful");
    return 0;
}

int ssl_read(ssl_context_t* ctx, uint8_t* buffer, size_t len) {
    if (ctx == NULL || ctx->ssl == NULL || !ctx->connected) {
        return -1;
    }
    
    int result = SSL_read(ctx->ssl, buffer, (int)len);
    if (result < 0) {
        int ssl_error = SSL_get_error(ctx->ssl, result);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            LOGE("SSL read error: %d", ssl_error);
        }
    }
    return result;
}

int ssl_write(ssl_context_t* ctx, const uint8_t* data, size_t len) {
    if (ctx == NULL || ctx->ssl == NULL || !ctx->connected) {
        return -1;
    }
    
    int result = SSL_write(ctx->ssl, data, (int)len);
    if (result < 0) {
        int ssl_error = SSL_get_error(ctx->ssl, result);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            LOGE("SSL write error: %d", ssl_error);
        }
    }
    return result;
}

void ssl_shutdown(ssl_context_t* ctx) {
    if (ctx == NULL || ctx->ssl == NULL) {
        return;
    }
    
    SSL_shutdown(ctx->ssl);
    ctx->connected = 0;
}
