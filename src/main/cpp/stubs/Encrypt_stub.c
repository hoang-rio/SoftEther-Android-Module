/**
 * Encrypt stub for Android - Minimal implementation
 * This provides stub functions for encryption operations that may conflict with OpenSSL
 */

#include "stubs.h"
#include <Mayaqua/Mayaqua.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// cpu_features stub - return basic support
int GetCpuId()
{
    return 0;
}

UINT GetCpuIdEx(UINT32 *buf, UINT32 eax, UINT32 ecx)
{
    (void)eax;
    (void)ecx;
    if (buf != NULL)
    {
        buf[0] = buf[1] = buf[2] = buf[3] = 0;
    }
    return 0;
}

bool IsX64()
{
    #if defined(__x86_64__) || defined(__aarch64__)
        return true;
    #else
        return false;
    #endif
}

bool IsX86()
{
    #if defined(__i386__) || defined(__x86_64__)
        return true;
    #else
        return false;
    #endif
}

bool IsArm()
{
    #if defined(__arm__) || defined(__aarch64__)
        return true;
    #else
        return false;
    #endif
}

// AESNI support check
bool IsAesNiSupported()
{
    return false;
}

// SHA256 hardware support check
bool IsSha256Supported()
{
    return false;
}

// AVX support check
bool IsAvxSupported()
{
    return false;
}

// SSE2 support check
bool IsSse2Supported()
{
    return false;
}

// SSE4.1 support check
bool IsSse41Supported()
{
    return false;
}

// InitCPU - stub
void InitCpu()
{
    // No-op on Android
}

// GetCPUInfo - stub
void GetCpuInfo(CPUINFO *info)
{
    if (info != NULL)
    {
        Zero(info, sizeof(CPUINFO));
        info->Vendor = CPU_VENDOR_UNKNOWN;
        info->Family = 0;
        info->Model = 0;
        info->Stepping = 0;
        info->Features = 0;
        info->NumberOfCores = 1;
    }
}

// CheckAESNI - stub
bool CheckAesNi()
{
    return false;
}

// CheckSSE2 - stub
bool CheckSse2()
{
    return false;
}

// CheckAVX - stub
bool CheckAvx()
{
    return false;
}

// SHA hardware support
bool CheckSha()
{
    return false;
}

// GetNumberOfCpu - return 1 on Android
UINT GetNumberOfCpu()
{
    return 1;
}

// InitCryptLibrary - initialize OpenSSL
void InitCryptLibrary()
{
    static bool initialized = false;
    if (!initialized)
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        initialized = true;
    }
}

// FreeCryptLibrary - cleanup OpenSSL
void FreeCryptLibrary()
{
    // No-op on Android - keep OpenSSL initialized
}

// MD5 implementation using OpenSSL
void MD5_Init_ForSoftEther(void *ctx)
{
    MD5_Init((MD5_CTX *)ctx);
}

void MD5_Update_ForSoftEther(void *ctx, const void *data, size_t len)
{
    MD5_Update((MD5_CTX *)ctx, data, len);
}

void MD5_Final_ForSoftEther(unsigned char *md, void *ctx)
{
    MD5_Final(md, (MD5_CTX *)ctx);
}

// SHA1 implementation using OpenSSL
void SHA1_Init_ForSoftEther(void *ctx)
{
    SHA1_Init((SHA_CTX *)ctx);
}

void SHA1_Update_ForSoftEther(void *ctx, const void *data, size_t len)
{
    SHA1_Update((SHA_CTX *)ctx, data, len);
}

void SHA1_Final_ForSoftEther(unsigned char *md, void *ctx)
{
    SHA1_Final(md, (SHA_CTX *)ctx);
}

// SHA256 implementation using OpenSSL
void SHA256_Init_ForSoftEther(void *ctx)
{
    SHA256_Init((SHA256_CTX *)ctx);
}

void SHA256_Update_ForSoftEther(void *ctx, const void *data, size_t len)
{
    SHA256_Update((SHA256_CTX *)ctx, data, len);
}

void SHA256_Final_ForSoftEther(unsigned char *md, void *ctx)
{
    SHA256_Final(md, (SHA256_CTX *)ctx);
}

// DES implementation stub
void DES_Init(DES_KEY *key, UCHAR *key_value)
{
    (void)key;
    (void)key_value;
}

void DES_Encrypt(DES_KEY *key, UCHAR *data, UINT size)
{
    (void)key;
    (void)data;
    (void)size;
}

void DES_Decrypt(DES_KEY *key, UCHAR *data, UINT size)
{
    (void)key;
    (void)data;
    (void)size;
}

// AES implementation using OpenSSL EVP
void AES_Init(AES_KEY *key, UCHAR *key_value, UINT key_size)
{
    (void)key;
    (void)key_value;
    (void)key_size;
}

void AES_Encrypt(AES_KEY *key, UCHAR *data, UINT size)
{
    (void)key;
    (void)data;
    (void)size;
}

void AES_Decrypt(AES_KEY *key, UCHAR *data, UINT size)
{
    (void)key;
    (void)data;
    (void)size;
}

// RC4 implementation
void RC4_Init(RC4_KEY *key, UCHAR *key_value, UINT key_size)
{
    (void)key;
    (void)key_value;
    (void)key_size;
}

void RC4_Encrypt(RC4_KEY *key, UCHAR *data, UINT size)
{
    (void)key;
    (void)data;
    (void)size;
}

// ChaCha20 implementation
void ChaCha20_Init(void *ctx, UCHAR *key, UCHAR *nonce, UINT64 counter)
{
    (void)ctx;
    (void)key;
    (void)nonce;
    (void)counter;
}

void ChaCha20_Encrypt(void *ctx, UCHAR *data, UINT size)
{
    (void)ctx;
    (void)data;
    (void)size;
}

// Poly1305 implementation
void Poly1305_Init(void *ctx, UCHAR *key)
{
    (void)ctx;
    (void)key;
}

void Poly1305_Update(void *ctx, UCHAR *data, UINT size)
{
    (void)ctx;
    (void)data;
    (void)size;
}

void Poly1305_Final(void *ctx, UCHAR *mac)
{
    (void)ctx;
    (void)mac;
}

// Random number generation
void Rand(void *buf, UINT size)
{
    if (buf != NULL && size > 0)
    {
        RAND_bytes((unsigned char *)buf, (int)size);
    }
}

UINT Rand32()
{
    UINT ret;
    Rand(&ret, sizeof(ret));
    return ret;
}

UINT64 Rand64()
{
    UINT64 ret;
    Rand(&ret, sizeof(ret));
    return ret;
}

void Rand128(void *buf)
{
    Rand(buf, 16);
}

// Seed random
void SRand(UINT seed)
{
    (void)seed;
    // OpenSSL uses its own entropy source, no seeding needed
}

// Generate random bytes
void GenRandom(void *buf, UINT size)
{
    Rand(buf, size);
}

// Generate random number between min and max
UINT GenRandInterval(UINT min, UINT max)
{
    if (min >= max)
    {
        return min;
    }
    UINT range = max - min + 1;
    UINT rand_val = Rand32();
    return min + (rand_val % range);
}

// Generate MAC address
void GenMacAddress(UCHAR *mac)
{
    if (mac != NULL)
    {
        Rand(mac, 6);
        // Set locally administered bit
        mac[0] |= 0x02;
        // Clear multicast bit
        mac[0] &= ~0x01;
    }
}

// Generate random GUID
void GenRandomGuid(GUID *guid)
{
    if (guid != NULL)
    {
        Rand(guid, sizeof(GUID));
        // Set GUID version (4 - random)
        guid->Data3 = (guid->Data3 & 0x0FFF) | 0x4000;
        // Set GUID variant (RFC 4122)
        guid->Data4[0] = (guid->Data4[0] & 0x3F) | 0x80;
    }
}

// Hash password
void HashPassword(void *dst, char *username, char *password)
{
    if (dst == NULL || username == NULL || password == NULL)
    {
        return;
    }

    UCHAR tmp[SHA1_SIZE];
    char upper_username[MAX_SIZE];
    char upper_password[MAX_SIZE];

    // Convert to uppercase
    StrCpy(upper_username, sizeof(upper_username), username);
    StrCpy(upper_password, sizeof(upper_password), password);
    StrUpper(upper_username);
    StrUpper(upper_password);

    // Create hash
    BUF *b = NewBuf();
    WriteBuf(b, upper_password, StrLen(upper_password));
    WriteBuf(b, upper_username, StrLen(upper_username));

    Sha0(tmp, b->Buf, b->Size);
    Copy(dst, tmp, SHA1_SIZE);

    FreeBuf(b);
}

// Generate NTLM password hash
void GenerateNtPasswordHash(void *dst, char *password)
{
    if (dst == NULL || password == NULL)
    {
        return;
    }

    // NTLM hash is MD4 of UTF-16LE encoded password
    // Simplified implementation
    UINT len = StrLen(password);
    UCHAR *unicode = ZeroMalloc(len * 2);
    for (UINT i = 0; i < len; i++)
    {
        unicode[i * 2] = password[i];
        unicode[i * 2 + 1] = 0;
    }

    MD4_CTX ctx;
    MD4_Init(&ctx);
    MD4_Update(&ctx, unicode, len * 2);
    MD4_Final((unsigned char *)dst, &ctx);

    Free(unicode);
}

// Generate NTLMv2 response
void GenerateNtPasswordHashHash(void *dst, void *nt_hash)
{
    if (dst == NULL || nt_hash == NULL)
    {
        return;
    }

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, nt_hash, MD5_SIZE);
    MD5_Final((unsigned char *)dst, &ctx);
}
