/**
 * Android Compatibility Patch for Mayaqua (SoftEther VPN v4)
 * 
 * This file provides Android-specific fixes for threading and memory issues.
 * Include this file in the build to override problematic Mayaqua functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <android/log.h>

// Define basic types used by Mayaqua
#ifndef UINT_DEFINED
#define UINT_DEFINED
typedef unsigned int UINT;
#endif

#ifndef BOOL_DEFINED
#define BOOL_DEFINED
typedef int BOOL;
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#endif

#define LOG_TAG "MayaquaPatch"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================================================
// Android Thread Pool Fixes
// ============================================================================

// Thread-local storage for Android thread tracking
static __thread int g_android_thread_id = 0;
static pthread_mutex_t g_android_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_android_thread_count = 0;
static volatile int g_android_shutdown = 0;

/**
 * Initialize Android-specific threading
 * Call this before InitMayaqua()
 */
void AndroidMayaquaInit(void)
{
    pthread_mutex_lock(&g_android_thread_mutex);
    g_android_shutdown = 0;
    g_android_thread_count = 0;
    pthread_mutex_unlock(&g_android_thread_mutex);
    LOGD("AndroidMayaquaInit completed");
}

/**
 * Cleanup Android-specific threading
 * Call this after FreeMayaqua()
 */
void AndroidMayaquaCleanup(void)
{
    pthread_mutex_lock(&g_android_thread_mutex);
    g_android_shutdown = 1;
    int count = g_android_thread_count;
    pthread_mutex_unlock(&g_android_thread_mutex);
    
    // Wait for all threads to finish (with timeout)
    int retries = 100; // 5 seconds max
    while (count > 0 && retries > 0) {
        usleep(50000); // 50ms
        pthread_mutex_lock(&g_android_thread_mutex);
        count = g_android_thread_count;
        pthread_mutex_unlock(&g_android_thread_mutex);
        retries--;
    }
    
    if (count > 0) {
        LOGE("Warning: %d threads still running after cleanup", count);
    }
    
    LOGD("AndroidMayaquaCleanup completed");
}

/**
 * Check if shutdown is in progress
 */
int AndroidIsShutdown(void)
{
    return g_android_shutdown;
}

/**
 * Register thread start
 */
void AndroidThreadStart(void)
{
    pthread_mutex_lock(&g_android_thread_mutex);
    g_android_thread_count++;
    g_android_thread_id = g_android_thread_count;
    pthread_mutex_unlock(&g_android_thread_mutex);
}

/**
 * Register thread end
 */
void AndroidThreadEnd(void)
{
    pthread_mutex_lock(&g_android_thread_mutex);
    g_android_thread_count--;
    pthread_mutex_unlock(&g_android_thread_mutex);
}

// ============================================================================
// Safe Mutex Operations for Android
// ============================================================================

/**
 * Safe mutex lock that checks if mutex is valid
 */
int AndroidSafeMutexLock(pthread_mutex_t *mutex)
{
    if (mutex == NULL) {
        return EINVAL;
    }
    
    // Check if shutdown is in progress
    if (g_android_shutdown) {
        return EBUSY;
    }
    
    return pthread_mutex_lock(mutex);
}

/**
 * Safe mutex unlock that checks if mutex is valid
 */
int AndroidSafeMutexUnlock(pthread_mutex_t *mutex)
{
    if (mutex == NULL) {
        return EINVAL;
    }
    
    return pthread_mutex_unlock(mutex);
}

// ============================================================================
// Memory Allocation Fixes for Android
// ============================================================================

/**
 * Android-safe memory allocation
 * Uses standard malloc to avoid Mayaqua's tracking issues on Android
 */
void *AndroidMalloc(UINT size)
{
    if (size == 0) {
        size = 1;
    }
    
    void *p = malloc(size);
    if (p == NULL) {
        // Retry once after short sleep
        usleep(1000);
        p = malloc(size);
    }
    
    return p;
}

/**
 * Android-safe memory reallocation
 */
void *AndroidRealloc(void *addr, UINT size)
{
    if (size == 0) {
        size = 1;
    }
    
    if (addr == NULL) {
        return AndroidMalloc(size);
    }
    
    void *p = realloc(addr, size);
    if (p == NULL) {
        // Retry once after short sleep
        usleep(1000);
        p = realloc(addr, size);
    }
    
    return p;
}

/**
 * Android-safe memory free
 */
void AndroidFree(void *addr)
{
    if (addr != NULL) {
        free(addr);
    }
}

/**
 * Android-safe zero-clearing malloc
 */
void *AndroidZeroMalloc(UINT size)
{
    void *p = AndroidMalloc(size);
    if (p != NULL) {
        memset(p, 0, size);
    }
    return p;
}

// ============================================================================
// Android File System Patches
// ============================================================================

/**
 * Android-compatible temp directory check
 * Replaces CheckUnixTempDir() which tries to write to /tmp and calls exit() on failure
 * On Android, we use the app's private cache directory instead
 */
void AndroidCheckUnixTempDir(void)
{
    // On Android, we don't need to check /tmp
    // The app uses its own private directories
    // This prevents the original CheckUnixTempDir from calling exit(0)
    LOGD("AndroidCheckUnixTempDir: Skipping /tmp check for Android");
}
