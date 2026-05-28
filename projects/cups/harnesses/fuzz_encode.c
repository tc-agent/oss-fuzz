/*
 * Fuzztest for option-to-IPP encoding helpers in encode.c.
 *
 * Copyright © 2024 by OpenPrinting.
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

#undef _CUPS_NO_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cups.h"
#include "ipp-private.h"

#define kMinInputLength 4
#define kMaxInputLength 4096

// Attribute names that are present in the option-encoder's _ipp_options table.
// Looking these up exercises _ippFindOption's binary search and forces every
// branch of cupsEncodeOption (one per data type: integer, boolean, enum,
// keyword, name, range, resolution, …).
static const char *const kKnownAttrs[] =
{
    "copies",
    "finishings",
    "job-priority",
    "media",
    "media-col",
    "number-up",
    "orientation-requested",
    "page-ranges",
    "print-quality",
    "printer-resolution",
    "sides",
    "fit-to-page",
    "job-hold-until",
    "job-sheets",
    "multiple-document-handling",
    "output-bin",
    "page-border",
    "presentation-direction-number-up",
    "print-color-mode",
    "print-scaling",
    "raw",
    "cupsDestType",
};
#define NUM_ATTRS (sizeof(kKnownAttrs) / sizeof(kKnownAttrs[0]))

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    // _ippFindOption returns a const _ipp_option_t * — calling it for every
    // known name forces the binary-search comparator over each entry, plus a
    // handful of misses to cover the not-found path.
    for (size_t i = 0; i < NUM_ATTRS; i++)
        (void) _ippFindOption(kKnownAttrs[i]);
    (void) _ippFindOption("not-a-real-attribute");
    (void) _ippFindOption("");

    // Treat the fuzz buffer as a space- and comma- and newline-separated
    // options string. cupsParseOptions handles quoting, escapes, comma-lists,
    // and integer vs string distinction.
    char *opt_str = malloc(size + 1);
    if (!opt_str)
        return 0;
    memcpy(opt_str, data, size);
    opt_str[size] = '\0';

    cups_option_t *options = NULL;
    int num_options = cupsParseOptions(opt_str, 0, &options);

    // Force values for the known attribute names so cupsEncodeOptions2 hits
    // every IPP value-type branch.
    static const struct
    {
        const char *name;
        const char *value;
    } extras[] =
    {
        { "copies",                  "5"                       },
        { "finishings",              "3,4"                     },
        { "media",                   "iso_a4_210x297mm"        },
        { "page-ranges",             "1-5,7,10-12"             },
        { "print-quality",           "5"                       },
        { "printer-resolution",      "600dpi"                  },
        { "orientation-requested",   "4"                       },
        { "sides",                   "two-sided-long-edge"     },
        { "job-hold-until",          "no-hold"                 },
        { "number-up",               "4"                       },
        { "multiple-document-handling", "separate-documents-collated-copies" },
        { "fit-to-page",             "true"                    },
        { "raw",                     ""                        },
    };
    for (size_t i = 0; i < sizeof(extras) / sizeof(extras[0]); i++)
        num_options = cupsAddOption(extras[i].name, extras[i].value, num_options, &options);

    ipp_t *request = ippNew();
    if (request)
    {
        cupsEncodeOptions(request, num_options, options);
        cupsEncodeOptions2(request, num_options, options, IPP_TAG_OPERATION);
        cupsEncodeOptions2(request, num_options, options, IPP_TAG_PRINTER);
        cupsEncodeOptions2(request, num_options, options, IPP_TAG_JOB);
        ippDelete(request);
    }

    cupsFreeOptions(num_options, options);
    free(opt_str);
    return 0;
}
