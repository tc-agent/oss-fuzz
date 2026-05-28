/*
 * Fuzztest for cupsFormDecode/cupsFormEncode (form.c).
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
#include "form.h"

#define kMinInputLength 1
#define kMaxInputLength 4096

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    char *buf = malloc(size + 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    cups_option_t *vars = NULL;
    int num_vars = cupsFormDecode(buf, &vars);

    if (num_vars > 0)
    {
        // Round-trip through cupsFormEncode.
        char *encoded = cupsFormEncode("http://example.test/path?seed=1", num_vars, vars);
        free(encoded);

        char *encoded_no_url = cupsFormEncode(NULL, num_vars, vars);
        free(encoded_no_url);
    }

    cupsFreeOptions(num_vars, vars);
    free(buf);
    return 0;
}
