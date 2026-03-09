#include "softether_crypto.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
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
            default: cipher = EVP_aes_256_cbc();
        }
    } else {
        switch (key_len) {
            case 16: cipher = EVP_aes_128_gcm(); break;
            case 24: cipher = EVP_aes_192_gcm(); break;
            case 32: cipher = EVP_aes_256_gcm(); break;
            default: cipher = EVP_aes_256_gcm();
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
    
    // Restrict to TLS 1.2 max — VPNGate servers reject TLS 1.3 ClientHellos with RST
    SSL_CTX_set_min_proto_version(ctx->ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ctx, TLS1_2_VERSION);

    // Auto-retry for renegotiation transparency
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_AUTO_RETRY);

    // Disable verification for VPN connections (self-signed certs are common)
    SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_NONE, NULL);
    
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
    
    // Set SNI hostname — hostname is always a resolved IP address at this point
    // (domain names are resolved before TLS in softether_protocol.c).
    // OpenSSL sends SNI with the IP string; VPNGate servers accept this.
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
    
    // Perform handshake with retry loop - TLS handshake often requires multiple exchanges
    int max_attempts = 100;  // Prevent infinite loop
    int attempt = 0;
    int result;
    
    while (attempt < max_attempts) {
        result = SSL_do_handshake(ctx->ssl);
        
        if (result == 1) {
            // Handshake successful
            break;
        }
        
        int ssl_error = SSL_get_error(ctx->ssl, result);
        
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // Handshake needs more data - continue
            LOGD("SSL handshake attempt %d: need more data (error=%d)", attempt + 1, ssl_error);
            attempt++;
            // Small delay to avoid busy-waiting
            usleep(10000);  // 10ms
            continue;
        }
        
        // Other error - handshake failed
        unsigned long err_detail = ERR_get_error();
        if (ssl_error == SSL_ERROR_SYSCALL) {
            // errno==0 means unexpected EOF (server closed connection)
            LOGE("SSL handshake failed: error=%d SSL_ERROR_SYSCALL errno=%d (%s) detail=%lu (%s)",
                 ssl_error, errno, strerror(errno), err_detail,
                 err_detail ? ERR_error_string(err_detail, NULL) : "EOF/no-detail");
        } else {
            LOGE("SSL handshake failed: error=%d detail=%lu (%s)", ssl_error, err_detail,
                 err_detail ? ERR_error_string(err_detail, NULL) : "none");
        }
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        return -1;
    }
    
    if (result != 1) {
        LOGE("SSL handshake did not complete after %d attempts", max_attempts);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        return -1;
    }
    
    ctx->connected = 1;
    // Log negotiated TLS version and cipher
    int tls_ver = SSL_version(ctx->ssl);
    const char* ver_str = SSL_get_version(ctx->ssl);
    const char* cipher = SSL_get_cipher(ctx->ssl);
    LOGD("SSL handshake successful after %d attempts (version: %s / 0x%04X, cipher: %s)", 
         attempt + 1, ver_str ? ver_str : "unknown", tls_ver,
         cipher ? cipher : "unknown");
    
    // Set SSL modes matching reference SoftEther implementation
    SSL_set_mode(ctx->ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_mode(ctx->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    
    return 0;
}

int ssl_read(ssl_context_t* ctx, uint8_t* buffer, size_t len) {
    if (ctx == NULL || ctx->ssl == NULL || !ctx->connected) {
        return -1;
    }
    
    // Check if there's pending data in the SSL buffer first
    int pending = SSL_pending(ctx->ssl);
    if (pending > 0 && pending % 500 == 0) {
        LOGD("SSL has %d bytes pending in buffer", pending);
    }
    
    int result = SSL_read(ctx->ssl, buffer, (int)len);
    if (result < 0) {
        int ssl_error = SSL_get_error(ctx->ssl, result);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            unsigned long err_detail = ERR_get_error();
            LOGE("SSL read error: %d, detail: %lu (%s)", ssl_error, err_detail,
                 err_detail ? ERR_error_string(err_detail, NULL) : "none");
        }
    } else if (result == 0) {
        int ssl_error = SSL_get_error(ctx->ssl, result);
        unsigned long err_detail = ERR_get_error();
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            LOGD("SSL connection closed by peer (clean shutdown)");
        } else if (ssl_error == SSL_ERROR_SYSCALL) {
            LOGE("SSL read syscall error: errno=%d", errno);
        } else {
            LOGE("SSL read returned 0, ssl_error=%d, detail=%lu (%s)", ssl_error,
                 err_detail, err_detail ? ERR_error_string(err_detail, NULL) : "none");
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

int ssl_has_pending(ssl_context_t* ctx) {
    if (ctx == NULL || ctx->ssl == NULL) return 0;
    return SSL_pending(ctx->ssl) > 0 ? 1 : 0;
}

// MD5 hashing
void md5_hash(const uint8_t* data, size_t data_len, uint8_t* hash) {
    if (data == NULL || hash == NULL) {
        LOGE("md5_hash: Invalid parameters");
        return;
    }

    unsigned int hash_len = 0;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    if (mdctx == NULL) {
        LOGE("md5_hash: Failed to create EVP_MD_CTX");
        return;
    }
    
    if (!EVP_DigestInit_ex(mdctx, EVP_md5(), NULL)) {
        LOGE("md5_hash: EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    if (!EVP_DigestUpdate(mdctx, data, data_len)) {
        LOGE("md5_hash: EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    if (!EVP_DigestFinal_ex(mdctx, md_buf, &hash_len)) {
        LOGE("md5_hash: EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    EVP_MD_CTX_free(mdctx);
    
    if (hash_len != MD5_HASH_SIZE) {
        LOGE("md5_hash: Unexpected hash length %u (expected %d)", hash_len, MD5_HASH_SIZE);
        return;
    }
    
    memcpy(hash, md_buf, MD5_HASH_SIZE);
    LOGD("md5_hash: Successfully hashed %zu bytes", data_len);
}

// SHA1 hashing
void sha1_hash(const uint8_t* data, size_t data_len, uint8_t* hash) {
    if (data == NULL || hash == NULL) {
        LOGE("sha1_hash: Invalid parameters");
        return;
    }

    unsigned int hash_len = 0;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    if (mdctx == NULL) {
        LOGE("sha1_hash: Failed to create EVP_MD_CTX");
        return;
    }
    
    if (!EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) {
        LOGE("sha1_hash: EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    if (!EVP_DigestUpdate(mdctx, data, data_len)) {
        LOGE("sha1_hash: EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    if (!EVP_DigestFinal_ex(mdctx, md_buf, &hash_len)) {
        LOGE("sha1_hash: EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    EVP_MD_CTX_free(mdctx);
    
    if (hash_len != SHA1_HASH_SIZE) {
        LOGE("sha1_hash: Unexpected hash length %u (expected %d)", hash_len, SHA1_HASH_SIZE);
        return;
    }
    
    memcpy(hash, md_buf, SHA1_HASH_SIZE);
    LOGD("sha1_hash: Successfully hashed %zu bytes", data_len);
}
