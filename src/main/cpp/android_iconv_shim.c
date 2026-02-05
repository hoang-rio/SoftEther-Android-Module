/*
 * Android iconv shim implementation
 * Provides UTF-8 <-> UTF-16LE/BE conversion for Android Bionic libc
 */

#include "android_iconv_shim.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Conversion types we support */
typedef enum {
    CONV_UNKNOWN,
    CONV_UTF8_TO_UTF16LE,
    CONV_UTF8_TO_UTF16BE,
    CONV_UTF16LE_TO_UTF8,
    CONV_UTF16BE_TO_UTF8,
    CONV_UTF16LE_TO_UTF16LE,  /* identity */
    CONV_UTF16BE_TO_UTF16BE,  /* identity */
    CONV_UTF8_TO_UTF8         /* identity */
} conv_type_t;

/* Internal state */
struct iconv_state {
    conv_type_t type;
};

/* Case-insensitive string compare (internal use only) */
static int iconv_strcasecmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        char c1 = *s1;
        char c2 = *s2;
        /* Convert to lowercase */
        if (c1 >= 'A' && c1 <= 'Z') c1 += 'a' - 'A';
        if (c2 >= 'A' && c2 <= 'Z') c2 += 'a' - 'A';
        if (c1 != c2) return c1 - c2;
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

/* Check if encoding is UTF-8 */
static int is_utf8(const char *name) {
    return iconv_strcasecmp(name, "UTF-8") == 0 ||
           iconv_strcasecmp(name, "UTF8") == 0;
}

/* Check if encoding is UTF-16LE */
static int is_utf16le(const char *name) {
    return iconv_strcasecmp(name, "UTF-16LE") == 0 ||
           iconv_strcasecmp(name, "UTF16LE") == 0;
}

/* Check if encoding is UTF-16BE */
static int is_utf16be(const char *name) {
    return iconv_strcasecmp(name, "UTF-16BE") == 0 ||
           iconv_strcasecmp(name, "UTF16BE") == 0;
}

iconv_t iconv_open(const char *tocode, const char *fromcode) {
    struct iconv_state *state = malloc(sizeof(struct iconv_state));
    if (!state) return (iconv_t)-1;

    /* Determine conversion type */
    if (is_utf8(fromcode) && is_utf16le(tocode)) {
        state->type = CONV_UTF8_TO_UTF16LE;
    } else if (is_utf8(fromcode) && is_utf16be(tocode)) {
        state->type = CONV_UTF8_TO_UTF16BE;
    } else if (is_utf16le(fromcode) && is_utf8(tocode)) {
        state->type = CONV_UTF16LE_TO_UTF8;
    } else if (is_utf16be(fromcode) && is_utf8(tocode)) {
        state->type = CONV_UTF16BE_TO_UTF8;
    } else if ((is_utf16le(fromcode) && is_utf16le(tocode)) ||
               (is_utf16be(fromcode) && is_utf16be(tocode)) ||
               (is_utf8(fromcode) && is_utf8(tocode))) {
        /* Identity conversion */
        state->type = is_utf16le(fromcode) ? CONV_UTF16LE_TO_UTF16LE :
                      is_utf16be(fromcode) ? CONV_UTF16BE_TO_UTF16BE :
                      CONV_UTF8_TO_UTF8;
    } else {
        /* Unsupported conversion */
        free(state);
        return (iconv_t)-1;
    }

    return (iconv_t)state;
}

/* Decode UTF-8 sequence, returns bytes consumed and outputs code point */
static int decode_utf8(const uint8_t *in, size_t inlen, uint32_t *codepoint) {
    if (inlen == 0) return 0;

    uint8_t c = in[0];

    /* 1-byte sequence (ASCII) */
    if ((c & 0x80) == 0) {
        *codepoint = c;
        return 1;
    }

    /* 2-byte sequence */
    if ((c & 0xE0) == 0xC0) {
        if (inlen < 2) return 0;
        *codepoint = ((c & 0x1F) << 6) | (in[1] & 0x3F);
        return 2;
    }

    /* 3-byte sequence */
    if ((c & 0xF0) == 0xE0) {
        if (inlen < 3) return 0;
        *codepoint = ((c & 0x0F) << 12) | ((in[1] & 0x3F) << 6) | (in[2] & 0x3F);
        return 3;
    }

    /* 4-byte sequence */
    if ((c & 0xF8) == 0xF0) {
        if (inlen < 4) return 0;
        *codepoint = ((c & 0x07) << 18) | ((in[1] & 0x3F) << 12) |
                     ((in[2] & 0x3F) << 6) | (in[3] & 0x3F);
        return 4;
    }

    /* Invalid sequence */
    return -1;
}

/* Encode code point as UTF-8, returns bytes written */
static int encode_utf8(uint32_t codepoint, uint8_t *out, size_t outlen) {
    if (codepoint <= 0x7F) {
        if (outlen < 1) return 0;
        out[0] = (uint8_t)codepoint;
        return 1;
    }
    if (codepoint <= 0x7FF) {
        if (outlen < 2) return 0;
        out[0] = 0xC0 | (codepoint >> 6);
        out[1] = 0x80 | (codepoint & 0x3F);
        return 2;
    }
    if (codepoint <= 0xFFFF) {
        if (outlen < 3) return 0;
        out[0] = 0xE0 | (codepoint >> 12);
        out[1] = 0x80 | ((codepoint >> 6) & 0x3F);
        out[2] = 0x80 | (codepoint & 0x3F);
        return 3;
    }
    if (codepoint <= 0x10FFFF) {
        if (outlen < 4) return 0;
        out[0] = 0xF0 | (codepoint >> 18);
        out[1] = 0x80 | ((codepoint >> 12) & 0x3F);
        out[2] = 0x80 | ((codepoint >> 6) & 0x3F);
        out[3] = 0x80 | (codepoint & 0x3F);
        return 4;
    }
    return -1;
}

size_t iconv(iconv_t cd, char **inbuf, size_t *inbytesleft,
             char **outbuf, size_t *outbytesleft) {
    struct iconv_state *state = (struct iconv_state *)cd;
    size_t converted = 0;

    if (cd == (iconv_t)-1 || !state) {
        return (size_t)-1;
    }

    /* Handle NULL inbuf - reset state (no state to reset for us) */
    if (!inbuf || !*inbuf) {
        return 0;
    }

    const uint8_t *in = (const uint8_t *)*inbuf;
    uint8_t *out = (uint8_t *)*outbuf;
    size_t inleft = *inbytesleft;
    size_t outleft = *outbytesleft;

    while (inleft > 0) {
        uint32_t codepoint;
        int consumed, written;

        switch (state->type) {
            case CONV_UTF8_TO_UTF16LE:
            case CONV_UTF8_TO_UTF16BE: {
                consumed = decode_utf8(in, inleft, &codepoint);
                if (consumed <= 0) goto done;

                /* Encode as UTF-16 */
                if (codepoint <= 0xFFFF) {
                    if (outleft < 2) goto done;
                    uint16_t utf16 = (uint16_t)codepoint;
                    if (state->type == CONV_UTF8_TO_UTF16LE) {
                        out[0] = utf16 & 0xFF;
                        out[1] = (utf16 >> 8) & 0xFF;
                    } else {
                        out[0] = (utf16 >> 8) & 0xFF;
                        out[1] = utf16 & 0xFF;
                    }
                    out += 2;
                    outleft -= 2;
                } else {
                    /* Surrogate pair for codepoints > 0xFFFF */
                    if (outleft < 4) goto done;
                    codepoint -= 0x10000;
                    uint16_t high = 0xD800 + (codepoint >> 10);
                    uint16_t low = 0xDC00 + (codepoint & 0x3FF);

                    if (state->type == CONV_UTF8_TO_UTF16LE) {
                        out[0] = high & 0xFF;
                        out[1] = (high >> 8) & 0xFF;
                        out[2] = low & 0xFF;
                        out[3] = (low >> 8) & 0xFF;
                    } else {
                        out[0] = (high >> 8) & 0xFF;
                        out[1] = high & 0xFF;
                        out[2] = (low >> 8) & 0xFF;
                        out[3] = low & 0xFF;
                    }
                    out += 4;
                    outleft -= 4;
                }
                in += consumed;
                inleft -= consumed;
                converted++;
                break;
            }

            case CONV_UTF16LE_TO_UTF8:
            case CONV_UTF16BE_TO_UTF8: {
                if (inleft < 2) goto done;

                /* Read UTF-16 code unit */
                uint16_t utf16;
                if (state->type == CONV_UTF16LE_TO_UTF8) {
                    utf16 = in[0] | (in[1] << 8);
                } else {
                    utf16 = (in[0] << 8) | in[1];
                }
                in += 2;
                inleft -= 2;

                /* Check for surrogate pair */
                if (utf16 >= 0xD800 && utf16 <= 0xDBFF) {
                    /* High surrogate, need low surrogate */
                    if (inleft < 2) {
                        /* Incomplete sequence, put bytes back */
                        in -= 2;
                        inleft += 2;
                        goto done;
                    }
                    uint16_t low;
                    if (state->type == CONV_UTF16LE_TO_UTF8) {
                        low = in[0] | (in[1] << 8);
                    } else {
                        low = (in[0] << 8) | in[1];
                    }
                    if (low < 0xDC00 || low > 0xDFFF) {
                        /* Invalid sequence */
                        return (size_t)-1;
                    }
                    in += 2;
                    inleft -= 2;
                    codepoint = 0x10000 + ((utf16 - 0xD800) << 10) + (low - 0xDC00);
                } else {
                    codepoint = utf16;
                }

                written = encode_utf8(codepoint, out, outleft);
                if (written <= 0) {
                    /* Put bytes back */
                    in -= (utf16 >= 0xD800 && utf16 <= 0xDBFF) ? 4 : 2;
                    inleft += (utf16 >= 0xD800 && utf16 <= 0xDBFF) ? 4 : 2;
                    goto done;
                }
                out += written;
                outleft -= written;
                converted++;
                break;
            }

            case CONV_UTF16LE_TO_UTF16LE:
            case CONV_UTF16BE_TO_UTF16BE:
            case CONV_UTF8_TO_UTF8:
                /* Identity conversion - just copy */
                if (outleft < 1) goto done;
                *out++ = *in++;
                outleft--;
                inleft--;
                converted++;
                break;

            default:
                return (size_t)-1;
        }
    }

done:
    *inbuf = (char *)in;
    *inbytesleft = inleft;
    *outbuf = (char *)out;
    *outbytesleft = outleft;

    return converted;
}

int iconv_close(iconv_t cd) {
    if (cd != (iconv_t)-1) {
        free(cd);
    }
    return 0;
}
