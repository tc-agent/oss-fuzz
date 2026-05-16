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
#include <vstream.h>
#include <attr.h>
#include <htable.h>
#include <nvtable.h>
#include <mymalloc.h>
#include <stringops.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    msg_error_limit(INT_MAX);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 8192)
        return 0;

    msg_error_clear();

    VSTRING *vs = vstring_alloc(size + 1);
    vstring_memcpy(vs, (const char *) data, size);
    VSTREAM *stream = vstream_memopen(vs, O_RDONLY);
    if (stream == NULL) {
        vstring_free(vs);
        return 0;
    }

    /* attr_scan0: postfix internal (length-prefixed) attribute scanner. */
    {
        int int_val = 0;
        long long_val = 0;
        VSTRING *str_val = vstring_alloc(32);
        HTABLE *hash = htable_create(8);

        (void) attr_scan0(stream, ATTR_FLAG_NONE,
                          RECV_ATTR_INT("count", &int_val),
                          RECV_ATTR_LONG("size", &long_val),
                          RECV_ATTR_STR("name", str_val),
                          ATTR_TYPE_END);
        (void) attr_scan0(stream, ATTR_FLAG_MORE,
                          RECV_ATTR_HASH(hash),
                          ATTR_TYPE_END);

        /* attr_vscan0 mystrdup()s the values into the hashtable; free them. */
        htable_free(hash, myfree);
        vstring_free(str_val);
    }

    vstream_fclose(stream);

    /* attr_scan_plain: human-readable form ("name=value\n"). */
    {
        VSTRING *vs2 = vstring_alloc(size + 1);
        vstring_memcpy(vs2, (const char *) data, size);
        VSTREAM *s = vstream_memopen(vs2, O_RDONLY);
        if (s != NULL) {
            int int_val = 0;
            VSTRING *str_val = vstring_alloc(32);
            (void) attr_scan_plain(s, ATTR_FLAG_NONE,
                                   RECV_ATTR_INT("x", &int_val),
                                   RECV_ATTR_STR("y", str_val),
                                   ATTR_TYPE_END);
            vstream_fclose(s);
            vstring_free(str_val);
        }
        vstring_free(vs2);
    }

    /* attr_scan64: base-64-encoded attribute scanner. */
    {
        VSTRING *vs3 = vstring_alloc(size + 1);
        vstring_memcpy(vs3, (const char *) data, size);
        VSTREAM *s = vstream_memopen(vs3, O_RDONLY);
        if (s != NULL) {
            int int_val = 0;
            VSTRING *str_val = vstring_alloc(32);
            (void) attr_scan64(s, ATTR_FLAG_NONE,
                               RECV_ATTR_INT("a", &int_val),
                               RECV_ATTR_STR("b", str_val),
                               ATTR_TYPE_END);
            vstream_fclose(s);
            vstring_free(str_val);
        }
        vstring_free(vs3);
    }

    /* unescape: reverse C-style escapes. */
    {
        VSTRING *out = vstring_alloc(size + 1);
        char *src = (char *) malloc(size + 1);
        if (src) {
            memcpy(src, data, size);
            src[size] = '\0';
            (void) unescape(out, src);
            free(src);
        }
        vstring_free(out);
    }

    vstring_free(vs);
    return 0;
}
