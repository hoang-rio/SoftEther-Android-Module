/*
 * Android iconv shim header
 * Android Bionic libc doesn't include iconv, so we provide minimal implementation
 * using Android's native UTF-8/UTF-16 conversion support
 */

#ifndef ANDROID_ICONV_SHIM_H
#define ANDROID_ICONV_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* iconv type - opaque handle */
typedef void* iconv_t;

/* iconv_open - create conversion descriptor */
iconv_t iconv_open(const char *tocode, const char *fromcode);

/* iconv - perform character set conversion */
size_t iconv(iconv_t cd, char **inbuf, size_t *inbytesleft,
             char **outbuf, size_t *outbytesleft);

/* iconv_close - deallocate conversion descriptor */
int iconv_close(iconv_t cd);

#ifdef __cplusplus
}
#endif

#endif /* ANDROID_ICONV_SHIM_H */
