/*
 * Fuzztest for PPD option-marking and code emission (ppd-emit.c / ppd-mark.c).
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
#include <unistd.h>
#include <fcntl.h>

#include "cups.h"
#include "ppd.h"
#include "ppd-private.h"

// ASan/LSan hooks. Weak so they link to no-ops if LSan isn't present.
__attribute__((weak)) extern void __lsan_disable(void);
__attribute__((weak)) extern void __lsan_enable(void);

#define kMinInputLength 16
#define kMaxInputLength 65536

static const ppd_section_t kSections[] =
{
    PPD_ORDER_ANY,
    PPD_ORDER_DOCUMENT,
    PPD_ORDER_EXIT,
    PPD_ORDER_JCL,
    PPD_ORDER_PAGE,
    PPD_ORDER_PROLOG,
};
#define NUM_SECTIONS (sizeof(kSections) / sizeof(kSections[0]))

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE        *fp;
    char        ppd_path[256];
    ppd_file_t  *ppd;
    int         devnull;
    size_t      i;

    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    snprintf(ppd_path, sizeof(ppd_path), "/tmp/fuzz_ppd_emit.%d.ppd", getpid());

    fp = fopen(ppd_path, "wb");
    if (!fp)
        return 0;
    fwrite(data, 1, size, fp);
    fclose(fp);

    // ppdOpenFile leaks ppd->nickname (and similar fields) when the PPD
    // declares the same keyword twice — an upstream cups bug. Hide those
    // allocations from LSan so libFuzzer can keep exploring.
    if (__lsan_disable) __lsan_disable();
    ppd = ppdOpenFile(ppd_path);
    if (__lsan_enable) __lsan_enable();

    if (!ppd)
    {
        unlink(ppd_path);
        return 0;
    }

    // Set the option defaults so emit has something to write.
    ppdMarkDefaults(ppd);

    // Mark a handful of well-known options directly via ppdMarkOption.
    // (Not cupsMarkOptions: that lazily builds ppd->cache via the private
    // _ppdCacheCreateWithPPD helper, whose preset table is never freed by
    // ppdClose — so every iteration would leak.)
    static const struct
    {
        const char *option;
        const char *choice;
    } marks[] =
    {
        { "PageSize",   "Letter"             },
        { "PageSize",   "A4"                 },
        { "PageRegion", "Letter"             },
        { "Resolution", "300dpi"             },
        { "Duplex",     "DuplexNoTumble"     },
        { "Duplex",     "None"               },
        { "Collate",    "True"               },
        { "InputSlot",  "Upper"              },
        { "MediaType",  "Plain"              },
    };
    for (size_t k = 0; k < sizeof(marks) / sizeof(marks[0]); k++)
        ppdMarkOption(ppd, marks[k].option, marks[k].choice);

    // Walk every section to exercise all branches in ppdEmitString /
    // ppdCollect2 / ppdEmit / ppdEmitAfterOrder.
    devnull = open("/dev/null", O_WRONLY);

    for (i = 0; i < NUM_SECTIONS; i++)
    {
        char *out = ppdEmitString(ppd, kSections[i], 0.0f);
        free(out);

        if (devnull >= 0)
        {
            FILE *df = fdopen(dup(devnull), "w");
            if (df)
            {
                ppdEmit(ppd, df, kSections[i]);
                ppdEmitAfterOrder(ppd, df, kSections[i], 1, 10.0f);
                fclose(df);
            }

            ppdEmitFd(ppd, devnull, kSections[i]);
        }

        ppd_choice_t **choices = NULL;
        int n = ppdCollect2(ppd, kSections[i], 0.0f, &choices);
        if (choices)
            free(choices);
        (void) n;
    }

    if (devnull >= 0)
    {
        FILE *df = fdopen(devnull, "w");
        if (df)
        {
            ppdEmitJCL(ppd, df, 42, "fuzzuser", "fuzz job");
            ppdEmitJCLEnd(ppd, df);
            fclose(df);
        }
        else
        {
            close(devnull);
        }
    }

    ppdConflicts(ppd);

    ppdClose(ppd);
    unlink(ppd_path);

    return 0;
}
