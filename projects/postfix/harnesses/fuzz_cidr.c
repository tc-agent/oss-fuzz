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
#include <limits.h>
#include <msg.h>

#include <vstring.h>
#include <mymalloc.h>
#include <cidr_match.h>
#include <ip_match.h>
#include <argv.h>
#include <dict.h>
#include <dict_inline.h>
#include <fcntl.h>
#include <unistd.h>

extern int dict_allow_surrogate;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    /* Return a surrogate DICT on syntax errors instead of msg_fatal()-ing. */
    dict_allow_surrogate = 1;
    /* dict_open emits msg_error on syntax problems and the default error
       limit (13) terminates the fuzzer; raise it. */
    msg_error_limit(INT_MAX);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 4096)
        return 0;

    /* Per-input reset so accumulated msg_error counts can't trip the bound. */
    msg_error_clear();
    char *buf = (char *) malloc(size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    VSTRING *why = vstring_alloc(64);

    /* cidr_match_parse: parses host[/prefix] CIDR patterns. */
    {
        CIDR_MATCH info;
        memset(&info, 0, sizeof(info));
        char *dup = mystrdup(buf);
        (void) cidr_match_parse(&info, dup, CIDR_MATCH_TRUE, why);
        myfree(dup);
    }
    /* cidr_match_parse_if: parses if/endif blocks. */
    {
        CIDR_MATCH info;
        memset(&info, 0, sizeof(info));
        char *dup = mystrdup(buf);
        (void) cidr_match_parse_if(&info, dup, CIDR_MATCH_TRUE, why);
        myfree(dup);
    }

    /* ip_match_parse: pattern with simple wildcards/octets. */
    {
        VSTRING *byte_codes = vstring_alloc(16);
        char *dup = mystrdup(buf);
        char *err = ip_match_parse(byte_codes, dup);
        if (err == 0) {
            /* On successful parse, try a 4-byte match. */
            (void) ip_match_execute(vstring_str(byte_codes), "\x7f\x00\x00\x01");
        }
        myfree(dup);
        vstring_free(byte_codes);
    }

    /* argv_split / argv_splitq: tokenise input by whitespace. */
    {
        ARGV *a = argv_split(buf, " \t\n");
        argv_free(a);

        a = argv_splitq(buf, " \t\n", "\"\"");
        argv_free(a);
    }

    /* dict_inline_open: parses {key1=value1, ...} inline maps. */
    {
        DICT *d = dict_inline_open(buf, O_RDONLY, 0);
        if (d != NULL)
            dict_close(d);
    }

    /* dict_open with type prefixes whose parsers don't recurse into
       dict_open (so a surrogate inner DICT can't crash the outer one) and
       don't touch the filesystem. */
    {
        VSTRING *spec = vstring_alloc(128);
        const char *types[] = { "static", "inline", "fail" };
        for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
            vstring_sprintf(spec, "%s:%s", types[i], buf);
            DICT *d = dict_open(vstring_str(spec), O_RDONLY, 0);
            if (d != NULL)
                dict_close(d);
        }
        vstring_free(spec);
    }

    /* dict_regexp_open / dict_cidr_open read the patterns from a file. Drop
       the input into a tempfile and open via the dict_open dispatch. */
    {
        char tmpl[] = "/tmp/fuzz_cidr_XXXXXX";
        int fd = mkstemp(tmpl);
        if (fd >= 0) {
            if (write(fd, buf, size) != (ssize_t) size) {
                /* short write: ignore */
            }
            close(fd);

            VSTRING *spec = vstring_alloc(128);
            const char *file_types[] = { "regexp", "cidr", "texthash" };
            for (size_t i = 0; i < sizeof(file_types) / sizeof(file_types[0]); i++) {
                vstring_sprintf(spec, "%s:%s", file_types[i], tmpl);
                DICT *d = dict_open(vstring_str(spec), O_RDONLY, 0);
                if (d != NULL)
                    dict_close(d);
            }
            vstring_free(spec);
            unlink(tmpl);
        }
    }

    vstring_free(why);
    free(buf);
    return 0;
}
