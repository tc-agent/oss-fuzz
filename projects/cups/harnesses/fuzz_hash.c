/*
 * Fuzztest for cupsHashData / cupsHashString (cups/hash.c, cups/md5.c).
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

#define kMinInputLength 2
#define kMaxInputLength 8192

static const char *const kAlgorithms[] =
{
    "md5",
    "sha",
    "sha-256",
    "sha-384",
    "sha-512",
    "sha-512-224",
    "sha-512-256",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "",
    "not-a-real-algorithm",
};
#define NUM_ALGS (sizeof(kAlgorithms) / sizeof(kAlgorithms[0]))

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    unsigned char hash[64];
    char          hex[129];

    // First byte picks the algorithm so libFuzzer can drive coverage across
    // every branch of the lookup table.
    const char *algorithm = kAlgorithms[data[0] % NUM_ALGS];
    const uint8_t *payload = data + 1;
    size_t plen = size - 1;

    ssize_t n = cupsHashData(algorithm, payload, plen, hash, sizeof(hash));
    if (n > 0)
        cupsHashString(hash, (size_t)n, hex, sizeof(hex));

    return 0;
}
