/**
 * Hamcore stub for Android build
 * Hamcore is SoftEther's resource embedding system
 */

#ifndef HAMCORE_H
#define HAMCORE_H

#include "../SoftEtherVPN/src/Mayaqua/Mayaqua.h"

// Stub definitions for Hamcore functions
#ifdef HAMCORE

// If Hamcore is enabled, provide stubs
void *HamcoreLoadFile(char *filename, UINT *size);
void *HamcoreLoadFileEx(char *filename, UINT *size, bool no_decrypt);
bool HamcoreLoadFileIntoBuffer(char *filename, BUF *buf);
void HamcoreLoadInit(void);
void HamcoreLoadFree(void);

#else

// If Hamcore is disabled, provide dummy macros
#define HamcoreLoadFile(filename, size) NULL
#define HamcoreLoadFileEx(filename, size, no_decrypt) NULL
#define HamcoreLoadFileIntoBuffer(filename, buf) false
#define HamcoreLoadInit()
#define HamcoreLoadFree()

#endif // HAMCORE

#endif // HAMCORE_H
