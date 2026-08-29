/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <sys_defs.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <vstring.h>
#include <stringops.h>
#include <mymalloc.h>
#include <mac_parse.h>
#include <mac_expand.h>
#include <name_mask.h>

#include "is_header.h"
#include "header_opts.h"
#include "header_token.h"
#include "ascii_header_text.h"
#include "mail_params.h"
#include "lex_822.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    /* header_opts_find -> header_drop_init reads var_drop_hdrs, which is
       normally populated by mail_conf_read(). Seed it with the default so the
       lookup doesn't dereference NULL. */
    if (var_drop_hdrs == NULL)
        var_drop_hdrs = mystrdup(DEF_DROP_HDRS);
    return 0;
}

static int mac_action(int type, VSTRING *buf, void *context) {
    (void) type; (void) buf; (void) context;
    return 0;
}

/* mac_expand callback: return a constant value for any name so the parser
   exercises substitution paths instead of bailing on the first lookup. */
static const char *mac_lookup(const char *name, int mode, void *context) {
    (void) name; (void) mode; (void) context;
    return "x";
}

/* A small name<->mask table so we can exercise name_mask_opt parsing. */
static const NAME_MASK fuzz_mask_table[] = {
    { "alpha",  1 << 0 },
    { "beta",   1 << 1 },
    { "gamma",  1 << 2 },
    { "delta",  1 << 3 },
    { "epsilon",1 << 4 },
    { 0, 0 },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 8192)
        return 0;
    char *buf = (char *) malloc(size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    /* is_header: tells whether a buffer looks like a mail header line. */
    (void) is_header_buf(buf, (ssize_t) size);

    /* header_opts_find scans buf as a C string and panics if no ':' appears
       before NUL. Use strchr (respects embedded nuls) to gate the call. */
    if (strchr(buf, ':') != NULL)
        (void) header_opts_find(buf);

    /* header_token: parse RFC 822 tokens from a header value. */
    {
        HEADER_TOKEN tokens[16];
        VSTRING *tok_buffer = vstring_alloc(64);
        const char *ptr = buf;
        (void) header_token(tokens, 16, tok_buffer, &ptr, LEX_822_SPECIALS, ',');
        vstring_free(tok_buffer);
    }

    /* mac_parse: locate $name, ${name}, $(name) macro references. */
    (void) mac_parse(buf, mac_action, NULL);

    /* make_ascii_header_text: encode for Comment or Phrase context. */
    {
        VSTRING *out = vstring_alloc(64);
        (void) make_ascii_header_text(out, HDR_TEXT_FLAG_COMMENT, buf);
        (void) make_ascii_header_text(out, HDR_TEXT_FLAG_PHRASE, buf);
        (void) make_ascii_header_text(out, HDR_TEXT_FLAG_COMMENT | HDR_TEXT_FLAG_FOLD, buf);
        vstring_free(out);
    }

    /* extpar: extract parenthesised text. Returned err string is owned by us. */
    {
        char *dup = mystrdup(buf);
        char *p = dup;
        char *err = extpar(&p, "()", EXTPAR_FLAG_NONE);
        if (err)
            myfree(err);
        myfree(dup);
    }

    /* mac_expand: real substitution with operators ($name, ${name?x:y}, ...). */
    {
        VSTRING *out = vstring_alloc(64);
        (void) mac_expand(out, buf, MAC_EXP_FLAG_NONE, NULL,
                          mac_lookup, (void *) 0);
        (void) mac_expand(out, buf, MAC_EXP_FLAG_RECURSE | MAC_EXP_FLAG_APPEND,
                          NULL, mac_lookup, (void *) 0);
        (void) mac_expand(out, buf, MAC_EXP_FLAG_SCAN, NULL,
                          mac_lookup, (void *) 0);
        vstring_free(out);
    }

    /* name_mask_opt: parse comma/space-separated names into a bitmask. */
    (void) name_mask_opt("fuzz_header", fuzz_mask_table, buf,
                        NAME_MASK_ANY_CASE | NAME_MASK_RETURN);
    /* str_name_mask_opt: format a bitmask back into a comma-separated string. */
    {
        VSTRING *fmt = vstring_alloc(32);
        (void) str_name_mask_opt(fmt, "fuzz_header", fuzz_mask_table,
                                 0xff, NAME_MASK_RETURN | NAME_MASK_NUMBER);
        vstring_free(fmt);
    }

    free(buf);
    return 0;
}
