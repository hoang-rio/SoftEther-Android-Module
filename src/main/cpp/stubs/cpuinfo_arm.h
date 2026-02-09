/**
 * ARM CPU info header for Android
 * Stub implementation - no CPU-specific optimizations
 */

#ifndef CPUINFO_ARM_H
#define CPUINFO_ARM_H

// ARM CPU features stub
static inline int GetArmCpuFeatures(void)
{
    return 0;  // No special features detected
}

static inline int GetArmCpuCount(void)
{
    return 1;
}

#endif // CPUINFO_ARM_H
