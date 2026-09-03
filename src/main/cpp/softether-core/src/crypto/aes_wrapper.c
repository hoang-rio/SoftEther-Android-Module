#include "softether_crypto.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <android/log.h>

#define TAG "SoftEtherCrypto"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Per-packet trace logging (Phase 13A) — compiled out unless SE_TRACE_PACKETS.
#ifdef SE_TRACE_PACKETS
#define LOGT(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#else
#define LOGT(...) ((void)0)
#endif

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

// TLS object lifetime guard. OpenSSL 3.5.8's multiblock record-write path
// frees a shared provider-cached EVP_SIGNATURE; concurrent SSL_write from two
// connections double-frees it — so writers stay fully serialized (wrlock is
// exclusive). Readers take the shared rdlock so parallel SSL_read keeps its
// idle latency, while ssl_destroy/shutdown take wrlock and therefore can
// never free an SSL object that a reader is still inside of (UAF crash in
// ossl_tls_handle_rlayer_return / ssl3_read_bytes during DHCP or receive).
static pthread_rwlock_t g_tls_use_lock = PTHREAD_RWLOCK_INITIALIZER;

// Serialize ALL OpenSSL provider-touching API calls (digests, RAND, etc.).
// OpenSSL 3.5.x's provider/namemap initialization is not thread-safe:
// concurrent first-time fetches (EVP_DigestInit_ex, RAND_bytes, etc.) race
// in ossl_namemap_stored / OPENSSL_sk_push, corrupting the namemap stack
// (scudo aborts) or triggering provider refcount bugs (#32008).  Wrapping
// every entry point into OpenSSL crypto with this single mutex makes all
// provider access single-threaded, preventing the race.
static pthread_mutex_t g_openssl_lock = PTHREAD_MUTEX_INITIALIZER;

// Per-connection SSL_CTX (Phase 16): sharing one CTX across connections with
// concurrent I/O corrupted TLS digest state (scudo aborts in EVP_MD_CTX_free).
// Library init stays global/once; each connection creates its own CTX under a
// creation-only mutex (serializes OpenSSL init without serializing I/O).
static pthread_mutex_t g_ssl_ctx_create_lock = PTHREAD_MUTEX_INITIALIZER;

// Phase 17: OpenSSL 3.x needs explicit provider pre-loading.
// Use pthread_once so ssl_init_library() is safe to call from ANY context
// (not just ssl_create_client under g_ssl_ctx_create_lock).  This prevents
// the lazy-load race when NAT-T/R-UDP transport threads call sha1_hash()
// before any ssl_create_client() has run, while a TCP transport thread
// simultaneously triggers provider loading via EVP_DigestInit_ex.
static pthread_once_t g_ssl_init_once = PTHREAD_ONCE_INIT;

static void ssl_init_library_do(void) {
    OPENSSL_init_ssl(OPENSSL_INIT_ADD_ALL_CIPHERS |
                     OPENSSL_INIT_ADD_ALL_DIGESTS |
                     OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    OSSL_PROVIDER *prov_default = OSSL_PROVIDER_load(NULL, "default");
    if (prov_default == NULL) {
        LOGE("Failed to load OpenSSL default provider");
    }
    OSSL_PROVIDER *prov_legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (prov_legacy == NULL) {
        LOGD("Legacy provider not available (non-fatal)");
    }

    LOGD("OpenSSL library initialized (providers: default=%s, legacy=%s)",
         prov_default ? "loaded" : "FAILED",
         prov_legacy ? "loaded" : "unavailable");
}

static void ssl_init_library(void) {
    pthread_once(&g_ssl_init_once, ssl_init_library_do);
}

// Apply the connection options every client CTX needs.
static void ssl_configure_client_ctx(SSL_CTX* c) {
    // Restrict to TLS 1.2 max — VPNGate servers reject TLS 1.3 ClientHellos with RST
    SSL_CTX_set_min_proto_version(c, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);

    // Auto-retry for renegotiation transparency
    SSL_CTX_set_mode(c, SSL_MODE_AUTO_RETRY);

    // Disable verification for VPN connections (self-signed certs are common)
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
}

aes_context_t* aes_create(int mode, const uint8_t* key, size_t key_len, 
                          const uint8_t* iv, size_t iv_len) {
    ssl_init_library();

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
    ssl_init_library();
    
    pthread_mutex_lock(&g_openssl_lock);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        LOGE("Failed to create MD context");
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        LOGE("Failed to initialize SHA256");
        EVP_MD_CTX_free(ctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        LOGE("SHA256 update failed");
        EVP_MD_CTX_free(ctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    unsigned int hash_len = 32;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        LOGE("SHA256 final failed");
    }
    
    EVP_MD_CTX_free(ctx);
    pthread_mutex_unlock(&g_openssl_lock);
}

void rc4_crypt(const uint8_t* key, size_t key_len, uint8_t* data, size_t data_len) {
    if (key == NULL || key_len == 0 || data == NULL) {
        return;
    }

    uint8_t sbox[256];
    unsigned int i, j = 0;
    for (i = 0; i < 256; i++) {
        sbox[i] = (uint8_t)i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + sbox[i] + key[i % key_len]) & 0xFF;
        uint8_t tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }

    i = 0;
    j = 0;
    for (size_t n = 0; n < data_len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + sbox[i]) & 0xFF;
        uint8_t tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
        data[n] ^= sbox[(sbox[i] + sbox[j]) & 0xFF];
    }
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* mac) {
    if (key == NULL || data == NULL || mac == NULL) {
        return;
    }
    ssl_init_library();
    
    unsigned int mac_len = 32;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, mac, &mac_len);
}

int generate_random_bytes(uint8_t* buffer, size_t len) {
    if (buffer == NULL || len == 0) {
        return -1;
    }
    ssl_init_library();

    pthread_mutex_lock(&g_openssl_lock);
    int rc = RAND_bytes(buffer, (int)len);
    pthread_mutex_unlock(&g_openssl_lock);

    if (rc != 1) {
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

    // Library init once (thread-safe)
    pthread_mutex_lock(&g_ssl_ctx_create_lock);
    ssl_init_library();

    // Phase 16: per-connection SSL_CTX, created under the create-lock so
    // concurrent OpenSSL context init cannot race (the original RAND_DRBG
    // crash motivation), while I/O on separate CTXs stays fully parallel.
    SSL_CTX* c = SSL_CTX_new(TLS_client_method());
    if (c == NULL) {
        LOGE("Failed to create SSL context");
        pthread_mutex_unlock(&g_ssl_ctx_create_lock);
        free(ctx);
        return NULL;
    }
    ssl_configure_client_ctx(c);
    pthread_mutex_unlock(&g_ssl_ctx_create_lock);

    ctx->ctx = c;

    LOGD("SSL client context created (per-connection)");
    return ctx;
}

void ssl_destroy(ssl_context_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    
    pthread_rwlock_wrlock(&g_tls_use_lock);
    if (ctx->ssl) {
        SSL_free(ctx->ssl);
    }
    if (ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
    }
    pthread_rwlock_unlock(&g_tls_use_lock);
    
    free(ctx);
}

int ssl_connect(ssl_context_t* ctx, int socket_fd, const char* hostname) {
    if (ctx == NULL || ctx->ctx == NULL) {
        LOGE("Invalid SSL context");
        return -1;
    }

    pthread_rwlock_wrlock(&g_tls_use_lock);
    ctx->ssl = SSL_new(ctx->ctx);
    if (ctx->ssl == NULL) {
        LOGE("Failed to create SSL object");
        pthread_rwlock_unlock(&g_tls_use_lock);
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
        pthread_rwlock_unlock(&g_tls_use_lock);
        return -1;
    }

    // Set connect state
    SSL_set_connect_state(ctx->ssl);
    pthread_rwlock_unlock(&g_tls_use_lock);

    // Handshake runs under the SHARED lock: it can block on network I/O for
    // seconds, but ssl_destroy must wait for it instead of freeing the SSL
    // object mid-handshake. Teardown paths force-close the fd first, so the
    // handshake exits promptly on socket error and releases the lock.
    pthread_rwlock_rdlock(&g_tls_use_lock);

    // Perform handshake with retry loop - TLS handshake often requires multiple exchanges
    int max_attempts = 100;  // Prevent infinite loop
    int attempt = 0;
    int result;
    
    while (attempt < max_attempts) {
        // The TLS handshake parses the server certificate / public key through
        // OpenSSL's ASN.1 decoder + provider/namemap machinery (OSSL_DECODER,
        // DER2KEY, ERR_pop_to_mark). These mutate GLOBAL OpenSSL provider and
        // decoder registries shared by every thread. The per-SSL g_tls_use_lock
        // above only protects this SSL object, NOT those globals, so run the
        // handshake under g_openssl_lock to make it mutually exclusive with the
        // data path's digest/RAND/SHA calls and with other concurrent
        // handshakes. A concurrent unmarshalled provider fetch here corrupts
        // the shared decoder registry (scudo header corruption in
        // ERR_pop_to_mark / der2key_decode) — see the production crash whose
        // backtrace is OSSL_DECODER_from_data -> der2key_decode.
        pthread_mutex_lock(&g_openssl_lock);
        result = SSL_do_handshake(ctx->ssl);
        pthread_mutex_unlock(&g_openssl_lock);

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
        pthread_rwlock_unlock(&g_tls_use_lock);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        return -1;
    }
    
    if (result != 1) {
        LOGE("SSL handshake did not complete after %d attempts", max_attempts);
        pthread_rwlock_unlock(&g_tls_use_lock);
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

    pthread_rwlock_unlock(&g_tls_use_lock);
    return 0;
}

int ssl_read(ssl_context_t* ctx, uint8_t* buffer, size_t len) {
    if (ctx == NULL || ctx->ssl == NULL || !ctx->connected) {
        return -1;
    }

    // Shared lock: keeps the SSL object alive against concurrent
    // ssl_destroy/shutdown without serializing parallel readers.
    pthread_rwlock_rdlock(&g_tls_use_lock);

    // Check if there's pending data in the SSL buffer first
    int pending = SSL_pending(ctx->ssl);
    if (pending > 0 && pending % 500 == 0) {
        LOGT("SSL has %d bytes pending in buffer", pending);
    }

    int result;
    int retries = 0;
    const int max_retries = 5;

    do {
        if (!ctx->connected) {
            LOGE("SSL read: connection lost");
            pthread_rwlock_unlock(&g_tls_use_lock);
            return -1;
        }
        // The TLS record layer computes the record HMAC through OpenSSL's
        // provider-fetched EVP_MAC (tls1_mac -> EVP_MD_CTX_free ->
        // EVP_PKEY_CTX_free -> EVP_MAC_free). This touches the same GLOBAL
        // provider/namemap registry shared by every thread. The per-SSL
        // g_tls_use_lock above only protects THIS SSL object; without
        // g_openssl_lock a concurrent handshake/digest/RAND on another thread
        // can corrupt the shared EVP_MAC, which surfaces as scudo header
        // corruption in EVP_MAC_free deep inside SSL_read. Serialize the read
        // (and write, below) under g_openssl_lock to close the last uncovered
        // provider-touching path. Lock order stays g_tls_use_lock ->
        // g_openssl_lock, matching the handshake.
        pthread_mutex_lock(&g_openssl_lock);
        result = SSL_read(ctx->ssl, buffer, (int)len);
        pthread_mutex_unlock(&g_openssl_lock);
        if (result > 0 || result == 0) {
            break;
        }
        int ssl_error = SSL_get_error(ctx->ssl, result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            retries++;
            LOGD("SSL read retry %d/%d (ssl_error=%d)", retries, max_retries, ssl_error);
            continue;
        }
        if (ssl_error == SSL_ERROR_SYSCALL && (errno == EINTR || errno == EAGAIN)) {
            retries++;
            LOGD("SSL read retry %d/%d (syscall errno=%d)", retries, max_retries, errno);
            continue;
        }
        unsigned long err_detail = ERR_get_error();
        LOGE("SSL read error: %d, detail: %lu (%s)", ssl_error, err_detail,
             err_detail ? ERR_error_string(err_detail, NULL) : "none");
        break;
    } while (retries < max_retries);

    if (result == 0) {
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
    pthread_rwlock_unlock(&g_tls_use_lock);
    return result;
}

int ssl_write(ssl_context_t* ctx, const uint8_t* data, size_t len) {
    if (ctx == NULL || ctx->ssl == NULL || !ctx->connected) {
        return -1;
    }

    pthread_rwlock_wrlock(&g_tls_use_lock);
    // Same provider-registry serialization as the read path: SSL_write's TLS
    // record MAC computation fetches a provider-side EVP_MAC (global namemap),
    // so it must be made mutually exclusive with every other OpenSSL
    // provider-touching op (handshake, digests, RAND, reads) under
    // g_openssl_lock. Held only around the SSL_write call itself.
    pthread_mutex_lock(&g_openssl_lock);
    int result = SSL_write(ctx->ssl, data, (int)len);
    pthread_mutex_unlock(&g_openssl_lock);
    if (result < 0) {
        int ssl_error = SSL_get_error(ctx->ssl, result);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            LOGE("SSL write error: %d", ssl_error);
        }
    }
    pthread_rwlock_unlock(&g_tls_use_lock);
    return result;
}

void ssl_shutdown(ssl_context_t* ctx) {
    if (ctx == NULL || ctx->ssl == NULL) {
        return;
    }

    pthread_rwlock_wrlock(&g_tls_use_lock);
    SSL_shutdown(ctx->ssl);
    ctx->connected = 0;
    pthread_rwlock_unlock(&g_tls_use_lock);
}

int ssl_has_pending(ssl_context_t* ctx) {
    if (ctx == NULL || ctx->ssl == NULL) return 0;
    pthread_rwlock_rdlock(&g_tls_use_lock);
    int pending = SSL_pending(ctx->ssl) > 0 ? 1 : 0;
    pthread_rwlock_unlock(&g_tls_use_lock);
    return pending;
}

// MD5 hashing
void md5_hash(const uint8_t* data, size_t data_len, uint8_t* hash) {
    if (data == NULL || hash == NULL) {
        LOGE("md5_hash: Invalid parameters");
        return;
    }
    ssl_init_library();

    pthread_mutex_lock(&g_openssl_lock);

    unsigned int hash_len = 0;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    if (mdctx == NULL) {
        LOGE("md5_hash: Failed to create EVP_MD_CTX");
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (!EVP_DigestInit_ex(mdctx, EVP_md5(), NULL)) {
        LOGE("md5_hash: EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (!EVP_DigestUpdate(mdctx, data, data_len)) {
        LOGE("md5_hash: EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (!EVP_DigestFinal_ex(mdctx, md_buf, &hash_len)) {
        LOGE("md5_hash: EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    EVP_MD_CTX_free(mdctx);
    pthread_mutex_unlock(&g_openssl_lock);
    
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
    ssl_init_library();

    pthread_mutex_lock(&g_openssl_lock);

    unsigned int hash_len = 0;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    if (mdctx == NULL) {
        LOGE("sha1_hash: Failed to create EVP_MD_CTX");
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (!EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) {
        LOGE("sha1_hash: EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (!EVP_DigestUpdate(mdctx, data, data_len)) {
        LOGE("sha1_hash: EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    if (!EVP_DigestFinal_ex(mdctx, md_buf, &hash_len)) {
        LOGE("sha1_hash: EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        pthread_mutex_unlock(&g_openssl_lock);
        return;
    }
    
    EVP_MD_CTX_free(mdctx);
    pthread_mutex_unlock(&g_openssl_lock);
    
    if (hash_len != SHA1_HASH_SIZE) {
        LOGE("sha1_hash: Unexpected hash length %u (expected %d)", hash_len, SHA1_HASH_SIZE);
        return;
    }
    
    memcpy(hash, md_buf, SHA1_HASH_SIZE);
}

// SHA-0 (the original SHA-1 with no message-schedule rotation). SoftEther's
// Hash() maps sha=true to Internal_SHA0, so the password authentication chain
// (HashPassword / SecurePassword) MUST use SHA-0, not SHA-1.
void sha0_hash(const uint8_t* data, size_t data_len, uint8_t* hash) {
    if (data == NULL || hash == NULL) {
        LOGE("sha0_hash: Invalid parameters");
        return;
    }

    static const uint32_t k0 = 0x5A827999, k1 = 0x6ED9EBA1;
    static const uint32_t k2 = 0x8F1BBCDC, k3 = 0xCA62C1D6;
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    size_t mlen = data_len;
    size_t padded = ((mlen + 8) / 64 + 1) * 64;
    uint8_t* buf = (uint8_t*)calloc(1, padded);
    if (buf == NULL) {
        LOGE("sha0_hash: calloc failed");
        return;
    }
    memcpy(buf, data, mlen);
    buf[mlen] = 0x80;
    uint64_t bits = (uint64_t)mlen * 8;
    for (int i = 0; i < 8; i++) {
        buf[padded - 1 - i] = (uint8_t)(bits >> (8 * i));
    }

    uint32_t w[80];
    for (size_t off = 0; off < padded; off += 64) {
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[off + i * 4] << 24) |
                   ((uint32_t)buf[off + i * 4 + 1] << 16) |
                   ((uint32_t)buf[off + i * 4 + 2] << 8) |
                   ((uint32_t)buf[off + i * 4 + 3]);
        }
        for (int i = 16; i < 80; i++) {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = k0;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = k1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = k2;
            } else {
                f = b ^ c ^ d;
                k = k3;
            }
            uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    for (int i = 0; i < 5; i++) {
        hash[i * 4] = (uint8_t)(h[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(h[i]);
    }
    free(buf);
}
