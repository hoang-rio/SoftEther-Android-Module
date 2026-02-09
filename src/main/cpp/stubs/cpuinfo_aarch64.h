/**
 * AArch64 CPU info header for Android
 * Stub implementation - no CPU-specific optimizations
 */

#ifndef CPUINFO_AARCH64_H
#define CPUINFO_AARCH64_H

// AArch64 CPU features stub
static inline int GetAArch64CpuFeatures(void)
{
    return 0;  // No special features detected
}

static inline int GetAArch64CpuCount(void)
{
    return 1;
}

#endif // CPUINFO_AARCH64_H
