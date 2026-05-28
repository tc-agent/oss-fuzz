/*
 * Fuzztest for IPP string-conversion helpers in ipp-support.c.
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

#include "file.h"
#include "string-private.h"
#include "ipp-private.h"

#define kMinInputLength 4
#define kMaxInputLength 8192

// Attribute names commonly used with ippEnumString/ippEnumValue.
static const char *const enum_attr_names[] =
{
    "document-format",
    "finishings",
    "finishings-default",
    "finishings-supported",
    "operations-supported",
    "orientation-requested",
    "orientation-requested-default",
    "orientation-requested-supported",
    "print-quality",
    "print-quality-default",
    "print-quality-supported",
    "printer-state",
    "printer-state-reasons",
    "job-state",
    "job-state-reasons",
    "job-collation-type",
};
#define NUM_ENUM_NAMES (sizeof(enum_attr_names) / sizeof(enum_attr_names[0]))

static void
exercise_lookup_tables(uint32_t seed)
{
    int             i;
    const char      *s;
    ipp_op_t        op;
    ipp_status_t    err;
    ipp_tag_t       tag;
    ipp_state_t     state;

    // Iterate the IPP operation table (covers ippOpString).
    for (op = IPP_OP_CUPS_INVALID; op <= IPP_OP_CUPS_GET_PPDS; op++)
    {
        s = ippOpString(op);
        if (s)
            (void) ippOpValue(s);
    }

    // Run a couple of unknown ops to hit the default branch.
    (void) ippOpString((ipp_op_t)(0x7fff & seed));
    (void) ippOpValue("not-a-real-operation");
    (void) ippOpValue("");

    // Status codes (covers ippErrorString). Walk every value across the four
    // numeric ranges used by IPP: 0x0000.., 0x0200.., 0x0400.., 0x0500..
    for (i = 0; i < 0x0600; i++)
    {
        s = ippErrorString((ipp_status_t)i);
        if (s)
            (void) ippErrorValue(s);
    }
    (void) ippErrorString((ipp_status_t)(0x7fff & seed));
    (void) ippErrorValue("client-error-not-a-real-error");

    // Tag table (covers ippTagString). Values 0x00..0x7f cover the public tag
    // range, including IPP_TAG_EXTENSION.
    for (tag = IPP_TAG_ZERO; tag <= IPP_TAG_EXTENSION; tag++)
    {
        s = ippTagString(tag);
        if (s)
            (void) ippTagValue(s);
    }
    (void) ippTagString((ipp_tag_t)(0xff & seed));
    (void) ippTagValue("nosuchtag");

    // State table (covers ippStateString).
    for (state = IPP_STATE_ERROR; state <= IPP_STATE_DATA; state++)
        (void) ippStateString(state);

    // Enum names (covers ippEnumString/ippEnumValue switch ladders).
    for (i = 0; i < (int)NUM_ENUM_NAMES; i++)
    {
        // Sample several values to walk the enum tables.
        int v;
        for (v = 3; v < 80; v += 7)
        {
            s = ippEnumString(enum_attr_names[i], v);
            if (s)
                (void) ippEnumValue(enum_attr_names[i], s);
        }
        // Reverse-only paths.
        (void) ippEnumValue(enum_attr_names[i], "none");
        (void) ippEnumValue(enum_attr_names[i], "0");
        (void) ippEnumValue(enum_attr_names[i], "");
    }

    // Misc helpers.
    (void) ippGetPort();
}

static void
load_request(const char *file)
{
    cups_file_t     *fp;
    ipp_t           *request;
    ipp_attribute_t *attr;
    char            buffer[2048];

    fp = cupsFileOpen(file, "r");
    if (!fp)
        return;

    request = ippNew();
    if (!request)
    {
        cupsFileClose(fp);
        return;
    }

    if (ippReadIO(fp, (ipp_iocb_t)cupsFileRead, 1, NULL, request) != IPP_STATE_ERROR)
    {
        // Walk every attribute and ask ippAttributeString to format it. This
        // exercises every branch of the value-formatting switch in
        // ipp-support.c, plus the size-query (NULL buffer) path.
        for (attr = ippGetFirstAttribute(request); attr != NULL; attr = ippGetNextAttribute(request))
        {
            (void) ippAttributeString(attr, NULL, 0);
            (void) ippAttributeString(attr, buffer, sizeof(buffer));
        }

        // ippCreateRequestedArray reads requested-attributes and expands group
        // shortcuts (e.g. "all", "job-template", "printer-description").
        cups_array_t *requested = ippCreateRequestedArray(request);
        if (requested)
            cupsArrayDelete(requested);
    }

    ippDelete(request);
    cupsFileClose(fp);
}

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE  *fp;
    char  file_name[256];
    uint32_t seed;

    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    // First 4 bytes seed the lookup-table exercise; the rest is IPP wire data.
    memcpy(&seed, data, sizeof(seed));

    exercise_lookup_tables(seed);

    snprintf(file_name, sizeof(file_name), "/tmp/fuzz_ipp_support.%d", getpid());
    fp = fopen(file_name, "wb");
    if (!fp)
        return 0;
    fwrite(data + 4, 1, size - 4, fp);
    fclose(fp);

    load_request(file_name);
    unlink(file_name);

    return 0;
}
