/*
 * Fuzztest for the ipptool data-file parser in ipp-file.c.
 *
 * Reads a text-format IPP test file (e.g. ipptool's `.test` files) and walks
 * every token via ippFileRead/ippFileReadToken, which exercises the bulk of
 * cups/ipp-file.c plus the helpers it calls in ipp.c.
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
#include <unistd.h>

#include "cups.h"
#include "ipp.h"
#include "file.h"

#define kMinInputLength 2
#define kMaxInputLength 65536

static bool
attr_cb(ipp_file_t *file, void *cb_data, const char *attr)
{
    (void) file;
    (void) cb_data;
    (void) attr;
    return true;
}

static bool
error_cb(ipp_file_t *file, void *cb_data, const char *error)
{
    (void) file;
    (void) cb_data;
    (void) error;
    return true;
}

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char        path[256];
    FILE        *fp;
    ipp_file_t  *file;

    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    snprintf(path, sizeof(path), "/tmp/fuzz_ipp_file.%d", getpid());
    fp = fopen(path, "wb");
    if (!fp)
        return 0;
    fwrite(data, 1, size, fp);
    fclose(fp);

    file = ippFileNew(NULL, attr_cb, error_cb, NULL);
    if (!file)
    {
        unlink(path);
        return 0;
    }

    if (ippFileOpen(file, path, "r"))
    {
        // Walk the whole file with the high-level reader (covers all token
        // dispatch in ipp-file.c plus value parsers in ipp.c).
        ippFileRead(file, /* token_cb */ NULL, /* with_groups */ true);

        // Force file->fp = NULL so ippFileDelete won't bail out (and leak the
        // file struct) if cupsFileClose returns an error.
        ippFileClose(file);
    }

    ippFileDelete(file);
    unlink(path);

    return 0;
}
