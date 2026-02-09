/**
 * CPU features stub for Android build
 * Minimal implementation to satisfy Encrypt.c
 */

#ifndef CPU_FEATURES_MACROS_H
#define CPU_FEATURES_MACROS_H

// Stub definitions for CPU feature detection
// On Android/ARM, we assume basic features are available

#define CPU_FEATURES_COMPILED_ANY_ARM 1
#define CPU_FEATURES_COMPILED_ARM_NEON 1

// Stub architecture detection
#if defined(__aarch64__) || defined(_M_ARM64)
    #define CPU_FEATURES_ARCH_AARCH64 1
#elif defined(__arm__) || defined(_M_ARM)
    #define CPU_FEATURES_ARCH_ARM 1
#elif defined(__x86_64__) || defined(_M_X64)
    #define CPU_FEATURES_ARCH_X86_64 1
#elif defined(__i386__) || defined(_M_IX86)
    #define CPU_FEATURES_ARCH_X86 1
#endif

#endif // CPU_FEATURES_MACROS_H
