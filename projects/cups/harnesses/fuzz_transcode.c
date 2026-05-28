/*
 * Fuzztest for charset conversion functions in transcode.c.
 *
 * Copyright © 2024 by OpenPrinting.
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "language-private.h"
#include "transcode.h"

#define kMinInputLength 2
#define kMaxInputLength 4096

static const cups_encoding_t kEncodings[] =
{
    CUPS_US_ASCII,
    CUPS_ISO8859_1,
    CUPS_ISO8859_2,
    CUPS_ISO8859_5,
    CUPS_ISO8859_7,
    CUPS_ISO8859_15,
    CUPS_UTF8,
    CUPS_WINDOWS_1250,
    CUPS_WINDOWS_1251,
    CUPS_WINDOWS_1252,
    CUPS_WINDOWS_932,
    CUPS_WINDOWS_936,
    CUPS_WINDOWS_949,
    CUPS_WINDOWS_950,
    CUPS_EUC_CN,
    CUPS_EUC_JP,
    CUPS_EUC_KR,
    CUPS_EUC_TW,
    CUPS_JIS_X0213,
};
#define NUM_ENCODINGS (sizeof(kEncodings) / sizeof(kEncodings[0]))

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    // First byte selects the encoding so libFuzzer can drive coverage across
    // every branch in the conversion tables.
    cups_encoding_t enc = kEncodings[data[0] % NUM_ENCODINGS];
    const uint8_t  *payload = data + 1;
    size_t          plen    = size - 1;

    // Treat payload as a NUL-terminated string for the *charset-to-UTF8 path.
    char *src = malloc(plen + 1);
    if (!src)
        return 0;
    memcpy(src, payload, plen);
    src[plen] = '\0';

    cups_utf8_t  utf8_out[2048];
    cups_utf32_t utf32_out[2048];
    char         charset_out[2048];

    int n = cupsCharsetToUTF8(utf8_out, src, sizeof(utf8_out), enc);

    if (n > 0)
    {
        // Roundtrip back through cupsUTF8ToCharset.
        cupsUTF8ToCharset(charset_out, utf8_out, sizeof(charset_out), enc);

        // UTF8 <-> UTF32 conversions exercise the multibyte decoder.
        int m = cupsUTF8ToUTF32(utf32_out, utf8_out, sizeof(utf32_out) / sizeof(utf32_out[0]));
        if (m > 0)
            cupsUTF32ToUTF8(utf8_out, utf32_out, sizeof(utf8_out));
    }

    // Treat the raw payload as UTF-8 input for the inverse path too.
    char *utf8_src = malloc(plen + 1);
    if (utf8_src)
    {
        memcpy(utf8_src, payload, plen);
        utf8_src[plen] = '\0';
        cupsUTF8ToCharset(charset_out, (cups_utf8_t *)utf8_src, sizeof(charset_out), enc);
        int m = cupsUTF8ToUTF32(utf32_out, (cups_utf8_t *)utf8_src,
                                sizeof(utf32_out) / sizeof(utf32_out[0]));
        if (m > 0)
            cupsUTF32ToUTF8(utf8_out, utf32_out, sizeof(utf8_out));
        free(utf8_src);
    }

    free(src);
    return 0;
}
