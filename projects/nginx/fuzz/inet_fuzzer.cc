// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
//
// Direct-call fuzzer for nginx's address/URL/string parsing helpers in
// src/core/ngx_inet.c and src/core/ngx_string.c. Each input begins with
// a one-byte selector that picks which parser is exercised.
//
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_inet.h>
}
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static ngx_log_t       g_log;
static ngx_open_file_t g_log_file;
static int             g_init_done;

static void init_once(void) {
    if (g_init_done) return;
    g_init_done = 1;
    ngx_pagesize = getpagesize();
    for (ngx_uint_t n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) {}
    ngx_cacheline_size = 64;
    ngx_time_init();
    ngx_debug_init();
    ngx_strerror_init();

    g_log.file = &g_log_file;
    g_log.log_level = NGX_LOG_EMERG;
    g_log_file.fd = ngx_stderr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();
    if (size < 2 || size > 4096) return 0;

    uint8_t selector = data[0];
    const uint8_t *p = data + 1;
    size_t          n = size - 1;

    // NUL-terminated, writable copy for parsers that expect a C string.
    ngx_pool_t *pool = ngx_create_pool(2048, &g_log);
    if (pool == NULL) return 0;

    u_char *buf = (u_char *) ngx_palloc(pool, n + 1);
    if (buf == NULL) { ngx_destroy_pool(pool); return 0; }
    memcpy(buf, p, n);
    buf[n] = 0;

    switch (selector % 11) {
    case 0:
        (void) ngx_inet_addr(buf, n);
        break;
    case 1: {
        u_char out[16];
        (void) ngx_inet6_addr(buf, n, out);
        break;
    }
    case 2: {
        ngx_str_t text = { n, buf };
        ngx_cidr_t cidr;
        memset(&cidr, 0, sizeof(cidr));
        (void) ngx_ptocidr(&text, &cidr);
        break;
    }
    case 3: {
        ngx_addr_t addr;
        memset(&addr, 0, sizeof(addr));
        (void) ngx_parse_addr(pool, &addr, buf, n);
        break;
    }
    case 4: {
        ngx_addr_t addr;
        memset(&addr, 0, sizeof(addr));
        (void) ngx_parse_addr_port(pool, &addr, buf, n);
        break;
    }
    case 5: {
        ngx_url_t u;
        memset(&u, 0, sizeof(u));
        u.url.data = buf;
        u.url.len  = n;
        u.default_port = 80;
        u.no_resolve = 1;
        (void) ngx_parse_url(pool, &u);
        break;
    }
    case 6: {
        ngx_url_t u;
        memset(&u, 0, sizeof(u));
        u.url.data = buf;
        u.url.len  = n;
        u.default_port = 443;
        u.no_resolve = 1;
        u.listen = 1;
        (void) ngx_parse_url(pool, &u);
        break;
    }
    case 7: {
        (void) ngx_atoi(buf, n);
        (void) ngx_atosz(buf, n);
        (void) ngx_atoof(buf, n);
        (void) ngx_atotm(buf, n);
        (void) ngx_hextoi(buf, n);
        break;
    }
    case 8: {
        u_char *dst = (u_char *) ngx_palloc(pool, n + 1);
        if (dst != NULL) {
            u_char *src = buf;
            ngx_unescape_uri(&dst, &src, n, 0);
        }
        break;
    }
    case 9: {
        uintptr_t need = ngx_escape_uri(NULL, buf, n, NGX_ESCAPE_URI);
        u_char *dst = (u_char *) ngx_palloc(pool, n + 2 * need + 1);
        if (dst) (void) ngx_escape_uri(dst, buf, n, NGX_ESCAPE_URI);
        break;
    }
    case 10: {
        ngx_str_t dst = { 0, NULL };
        ngx_str_t src = { n, buf };
        dst.data = (u_char *) ngx_palloc(pool, ngx_base64_decoded_length(n) + 1);
        if (dst.data) (void) ngx_decode_base64(&dst, &src);
        break;
    }
    }

    ngx_destroy_pool(pool);
    return 0;
}
