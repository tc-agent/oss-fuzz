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
#include <hex_quote.h>
#include <hex_code.h>
#include <base64_code.h>
#include <base32_code.h>
#include "xtext.h"
#include "uxtext.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 8192)
        return 0;
    char *buf = (char *) malloc(size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    VSTRING *r1 = vstring_alloc(32);
    VSTRING *r2 = vstring_alloc(32);

    /* xtext quote/unquote roundtrip. */
    xtext_quote(r1, buf, "+=");
    xtext_unquote(r2, vstring_str(r1));
    xtext_unquote(r1, buf);

    /* uxtext quote/unquote roundtrip. */
    uxtext_quote(r1, buf, "\\");
    uxtext_unquote(r2, vstring_str(r1));
    uxtext_unquote(r1, buf);

    /* hex_quote / hex_unquote. */
    hex_quote(r1, buf);
    hex_unquote(r2, vstring_str(r1));
    hex_unquote(r1, buf);

    /* hex_encode / hex_decode over the raw bytes. */
    hex_encode(r1, (const char *) data, (ssize_t) size);
    hex_decode(r2, vstring_str(r1), VSTRING_LEN(r1));
    hex_decode(r2, buf, (ssize_t) size);

    /* base64 encode/decode. */
    base64_encode(r1, (const char *) data, (ssize_t) size);
    base64_decode(r2, vstring_str(r1), VSTRING_LEN(r1));
    base64_decode(r2, buf, (ssize_t) size);

    /* base32 encode/decode. */
    base32_encode(r1, (const char *) data, (ssize_t) size);
    base32_decode(r2, vstring_str(r1), VSTRING_LEN(r1));
    base32_decode(r2, buf, (ssize_t) size);

    vstring_free(r1);
    vstring_free(r2);
    free(buf);
    return 0;
}
