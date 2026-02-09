/**
 * Kernel stub for Android - Minimal implementation
 * This provides stub functions for kernel/thread operations
 */

#include "stubs.h"
#include <Mayaqua/Mayaqua.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <android/log.h>

#define LOG_TAG "SoftEtherKernel"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Get current thread ID
UINT GetCurrentThreadId()
{
    return (UINT)syscall(SYS_gettid);
}

// Get current process ID
UINT GetCurrentProcessId()
{
    return (UINT)getpid();
}

// Set thread priority
void SetThreadPriority(UINT priority)
{
    // Android doesn't support explicit priority setting
    (void)priority;
}

// Get thread priority
UINT GetThreadPriority()
{
    return 0;
}

// Set process priority
void SetProcessPriority(UINT priority)
{
    (void)priority;
}

// Yield CPU
void YieldCpu()
{
    sched_yield();
}

// Sleep thread
void SleepThread(UINT milliseconds)
{
    usleep(milliseconds * 1000);
}

// Sleep thread accurately
void SleepThreadAccurate(UINT milliseconds)
{
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

// Get high resolution time
UINT64 GetHighResTime()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (UINT64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Get tick count (64-bit)
UINT64 Tick64()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (UINT64)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
}

// Get tick count (32-bit)
UINT Tick()
{
    return (UINT)Tick64();
}

// Convert tick to time
UINT64 TickToTime(UINT64 tick)
{
    // tick is milliseconds since boot, convert to Unix time
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    UINT64 now = (UINT64)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
    UINT64 tick_now = Tick64();
    return now - (tick_now - tick);
}

// Convert time to tick
UINT64 TimeToTick(UINT64 time)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    UINT64 now = (UINT64)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000;
    UINT64 tick_now = Tick64();
    return tick_now + (time - now);
}

// Get system time
void GetSystemTime(SYSTEMTIME *st)
{
    if (st == NULL) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    st->wYear = tm.tm_year + 1900;
    st->wMonth = tm.tm_mon + 1;
    st->wDay = tm.tm_mday;
    st->wHour = tm.tm_hour;
    st->wMinute = tm.tm_min;
    st->wSecond = tm.tm_sec;
    st->wMilliseconds = ts.tv_nsec / 1000000;
}

// Get local time
void LocalTime(SYSTEMTIME *st)
{
    GetSystemTime(st);
}

// Get system time 64
UINT64 SystemTime64()
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    return SystemToUINT64(&st);
}

// System time to UINT64
UINT64 SystemToUINT64(SYSTEMTIME *st)
{
    if (st == NULL) return 0;

    struct tm tm;
    tm.tm_year = st->wYear - 1900;
    tm.tm_mon = st->wMonth - 1;
    tm.tm_mday = st->wDay;
    tm.tm_hour = st->wHour;
    tm.tm_min = st->wMinute;
    tm.tm_sec = st->wSecond;
    tm.tm_isdst = -1;

    time_t t = mktime(&tm);
    return (UINT64)t * 1000ULL + st->wMilliseconds;
}

// UINT64 to system time
void UINT64ToSystem(SYSTEMTIME *st, UINT64 t)
{
    if (st == NULL) return;

    time_t sec = (time_t)(t / 1000);
    UINT ms = t % 1000;

    struct tm tm;
    localtime_r(&sec, &tm);

    st->wYear = tm.tm_year + 1900;
    st->wMonth = tm.tm_mon + 1;
    st->wDay = tm.tm_mday;
    st->wHour = tm.tm_hour;
    st->wMinute = tm.tm_min;
    st->wSecond = tm.tm_sec;
    st->wMilliseconds = ms;
}

// Get OS info
OS_INFO *GetOsInfo()
{
    static OS_INFO info;
    static bool initialized = false;

    if (!initialized)
    {
        Zero(&info, sizeof(info));
        info.OsType = OSTYPE_ANDROID;
        info.OsServicePack = 0;
        StrCpy(info.OsSystemName, sizeof(info.OsSystemName), "Android");
        StrCpy(info.OsProductName, sizeof(info.OsProductName), "Android");
        StrCpy(info.OsVendorName, sizeof(info.OsVendorName), "Google");
        StrCpy(info.OsVersion, sizeof(info.OsVersion), "Unknown");
        initialized = true;
    }

    return &info;
}

// OS type check functions - these are macros in MayaType.h, not functions
// OS_IS_WINDOWS, OS_IS_WINDOWS_NT, OS_IS_UNIX are defined as macros

// Get machine name
void GetMachineName(char *name, UINT size)
{
    if (name == NULL || size == 0) return;

    int ret = gethostname(name, size);
    if (ret != 0)
    {
        StrCpy(name, size, "android");
    }
}

// Set high priority
void OSSetHighPriority()
{
    // Android doesn't allow changing process priority
}

// Set low priority
void OSSetLowPriority()
{
    // Android doesn't allow changing process priority
}

// Init kernel
void InitKernel()
{
    // No-op on Android
}

// Free kernel
void FreeKernel()
{
    // No-op on Android
}

// Notice thread init
void NoticeThreadInit(THREAD *t)
{
    (void)t;
}

// Wait for thread initialization
void WaitThreadInit(THREAD *t)
{
    (void)t;
}

// Disable priority boost
void DisablePriorityBoost()
{
}

