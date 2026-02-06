/**
 * Android Compatibility Patch Header for Mayaqua (SoftEther VPN v4)
 */

#ifndef ANDROID_MAYAQUA_PATCH_H
#define ANDROID_MAYAQUA_PATCH_H

#include <Mayaqua/Mayaqua.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Android Thread Pool Fixes
// ============================================================================

void AndroidMayaquaInit(void);
void AndroidMayaquaCleanup(void);
int AndroidIsShutdown(void);
void AndroidThreadStart(void);
void AndroidThreadEnd(void);

// ============================================================================
// Safe Mutex Operations for Android
// ============================================================================

int AndroidSafeMutexLock(pthread_mutex_t *mutex);
int AndroidSafeMutexUnlock(pthread_mutex_t *mutex);

// ============================================================================
// Memory Allocation Fixes for Android
// ============================================================================

void *AndroidMalloc(UINT size);
void *AndroidRealloc(void *addr, UINT size);
void AndroidFree(void *addr);
void *AndroidZeroMalloc(UINT size);

// ============================================================================
// Android File System Patches
// ============================================================================

void AndroidCheckUnixTempDir(void);

#ifdef __cplusplus
}
#endif

#endif // ANDROID_MAYAQUA_PATCH_H
