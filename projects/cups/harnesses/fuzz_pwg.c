/*
 * Fuzztest for pwgMedia* lookup helpers (cups/pwg-media.c).
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

#include "cups.h"
#include "pwg.h"

#define kMinInputLength 1
#define kMaxInputLength 4096

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    // Treat input as NUL-terminated text for the string-keyed lookups.
    char *buf = malloc(size + 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    (void) pwgMediaForLegacy(buf);
    (void) pwgMediaForPPD(buf);
    (void) pwgMediaForPWG(buf);

    // Integer-keyed lookup: first 4 bytes = width, next 4 = length (cups
    // uses hundredths of mm).
    if (size >= 8)
    {
        int width  = (int)(((unsigned)data[0] << 24) | ((unsigned)data[1] << 16)
                           | ((unsigned)data[2] << 8) | data[3]);
        int length = (int)(((unsigned)data[4] << 24) | ((unsigned)data[5] << 16)
                           | ((unsigned)data[6] << 8) | data[7]);
        (void) pwgMediaForSize(width, length);
    }

    // pwgFormatSizeName uses sprintf-like formatting; exercise it with the
    // input as the prefix/name.
    char keyword[256];
    int width  = (size >= 2) ? data[0] * 100 : 21000;
    int length = (size >= 2) ? data[1] * 100 : 29700;
    pwgFormatSizeName(keyword, sizeof(keyword), "custom", buf,
                      width, length, "mm");
    pwgFormatSizeName(keyword, sizeof(keyword), NULL, NULL,
                      width, length, "in");

    free(buf);
    return 0;
}
