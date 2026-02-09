/**
 * Stubs header for Android build
 * Include this first in all source files
 */

#ifndef STUBS_H
#define STUBS_H

// Essential system headers that must come first
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

// Socket headers - needed for Network.c, DNS.c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// OS type for Android
#ifndef OSTYPE_ANDROID
#define OSTYPE_ANDROID 0x8000
#endif

// HAMCORE types
struct HAMCORE;
struct HAMCORE_FILE;
typedef struct HAMCORE HAMCORE;
typedef struct HAMCORE_FILE HAMCORE_FILE;

// CPU Features for Encrypt.c
typedef struct
{
    int aes;
    int sse2;
    int avx;
    int sha;
} X86Features;

typedef struct
{
    int aes;
    int pmull;
    int sha1;
    int sha2;
} ArmFeatures;

typedef struct
{
    int aes;
    int pmull;
    int sha1;
    int sha2;
} Aarch64Features;

// CPU info structs
typedef struct
{
    X86Features features;
} X86Info;

typedef struct
{
    ArmFeatures features;
} ArmInfo;

typedef struct
{
    Aarch64Features features;
} Aarch64Info;

// Stub functions for cpu_features
static inline X86Info GetX86Info(void)
{
    X86Info info = {{0}};
    return info;
}

static inline ArmInfo GetArmInfo(void)
{
    ArmInfo info = {{0}};
    return info;
}

static inline Aarch64Info GetAarch64Info(void)
{
    Aarch64Info info = {{0}};
    return info;
}

// ETH - Ethernet adapter forward declaration
typedef struct ETH ETH;

// PACKET_ADAPTER - forward declaration
typedef struct PACKET_ADAPTER PACKET_ADAPTER;

// Include Bridge.h for BRIDGE and LOCALBRIDGE types
// This is needed even with NO_BRIDGE because Connection.c uses these types
#include <Cedar/Bridge.h>

// Include BridgeUnix.h for ETH struct
#include <Cedar/BridgeUnix.h>

#endif // STUBS_H
