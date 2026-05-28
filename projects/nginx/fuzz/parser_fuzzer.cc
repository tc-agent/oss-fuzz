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
// Direct-call fuzzer for the HTTP/1 parser primitives in
// src/http/ngx_http_parse.c. The first input byte selects which parser
// to drive; the rest is the parser input. This bypasses the full nginx
// listening / cycle machinery so we can exercise byte-level state
// transitions cheaply.
//
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
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

// Iteratively feed bytes to a parser that returns NGX_AGAIN until either
// it terminates or we run out of data, so a single fuzz input can drive
// state transitions across the whole input rather than aborting on first
// byte boundary.
static void drive_request_line(ngx_http_request_t *r, u_char *buf, size_t n) {
    ngx_buf_t b;
    memset(&b, 0, sizeof(b));
    b.start = buf;
    b.pos   = buf;
    b.last  = buf + n;
    b.end   = buf + n;
    (void) ngx_http_parse_request_line(r, &b);
}

static void drive_header_line(ngx_http_request_t *r, u_char *buf, size_t n,
                              ngx_uint_t allow_underscores) {
    ngx_buf_t b;
    memset(&b, 0, sizeof(b));
    b.start = buf;
    b.pos   = buf;
    b.last  = buf + n;
    b.end   = buf + n;

    while (b.pos < b.last) {
        u_char *prev = b.pos;
        ngx_int_t rc = ngx_http_parse_header_line(r, &b, allow_underscores);
        if (rc == NGX_HTTP_PARSE_HEADER_DONE || rc == NGX_ERROR
            || rc == NGX_HTTP_PARSE_INVALID_HEADER) break;
        if (rc == NGX_OK) continue;
        if (rc == NGX_AGAIN && b.pos == prev) break;
    }
}

static void drive_status_line(ngx_http_request_t *r, u_char *buf, size_t n) {
    ngx_buf_t b;
    ngx_http_status_t st;
    memset(&st, 0, sizeof(st));
    memset(&b, 0, sizeof(b));
    b.start = buf; b.pos = buf; b.last = buf + n; b.end = buf + n;

    (void) ngx_http_parse_status_line(r, &b, &st);
}

static void drive_chunked(ngx_http_request_t *r, u_char *buf, size_t n,
                          ngx_uint_t keep_trailers) {
    ngx_buf_t b;
    ngx_http_chunked_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    memset(&b, 0, sizeof(b));
    b.start = buf; b.pos = buf; b.last = buf + n; b.end = buf + n;

    // Loop until the parser stops making progress so trailers, multiple
    // chunks, etc., all get exercised within one input.
    for (;;) {
        u_char *prev = b.pos;
        ngx_int_t rc = ngx_http_parse_chunked(r, &b, &ctx, keep_trailers);
        if (rc == NGX_DONE || rc == NGX_ERROR) break;
        if (b.pos == prev) break;
    }
}

static void drive_complex_uri(ngx_http_request_t *r, u_char *buf, size_t n,
                              ngx_uint_t merge_slashes) {
    u_char *dst = (u_char *) ngx_palloc(r->pool, n + 1);
    if (dst == NULL) return;
    r->uri.data  = dst;
    r->uri_start = buf;
    r->uri_end   = buf + n;
    (void) ngx_http_parse_complex_uri(r, merge_slashes);
}

static void drive_unsafe_uri(ngx_http_request_t *r, u_char *buf, size_t n) {
    ngx_str_t uri = { n, buf };
    ngx_str_t args = { 0, NULL };
    ngx_uint_t flags = 0;
    (void) ngx_http_parse_unsafe_uri(r, &uri, &args, &flags);
}

// ngx_http_parse_uri walks r->uri_start..r->uri_end validating URI chars,
// setting r->complex_uri / quoted_uri / plus_in_uri / empty_path_in_uri.
static void drive_parse_uri(ngx_http_request_t *r, u_char *buf, size_t n) {
    r->uri_start = buf;
    r->uri_end   = buf + n;
    (void) ngx_http_parse_uri(r);
}

// ngx_http_arg(r, name, len, value) finds an arg in r->args. Split input as
// "name\0args" — name has byte count up to first NUL, args is the rest.
static void drive_arg(ngx_http_request_t *r, u_char *buf, size_t n) {
    size_t name_len = 0;
    while (name_len < n && buf[name_len] != 0) name_len++;
    if (name_len == 0 || name_len == n) return;
    r->args.data = buf + name_len + 1;
    r->args.len  = n - name_len - 1;
    ngx_str_t value;
    (void) ngx_http_arg(r, buf, name_len, &value);
}

// ngx_http_split_args operates on r and a uri ngx_str_t; it splits at '?'
// into r->args and shrinks the uri.
static void drive_split_args(ngx_http_request_t *r, u_char *buf, size_t n) {
    ngx_str_t uri = { n, buf };
    ngx_str_t args = { 0, NULL };
    ngx_http_split_args(r, &uri, &args);
}

// Build a small linked list of ngx_table_elt_t from input bytes, with the
// first token used as the lookup `name`. Drives one of the multi-header
// scanners. Input layout: "<name>\0<hdr1-key>:<hdr1-val>\n<hdr2-key>:<hdr2-val>\n..."
static ngx_table_elt_t *build_header_chain(ngx_pool_t *pool, u_char *buf,
                                           size_t n, ngx_str_t *name_out) {
    size_t name_len = 0;
    while (name_len < n && buf[name_len] != 0) name_len++;
    if (name_len == 0 || name_len == n) return NULL;
    name_out->len  = name_len;
    name_out->data = buf;

    u_char *p   = buf + name_len + 1;
    u_char *end = buf + n;
    ngx_table_elt_t *head = NULL, *tail = NULL;
    while (p < end) {
        u_char *colon = (u_char *) memchr(p, ':', end - p);
        if (colon == NULL) break;
        u_char *nl = (u_char *) memchr(colon, '\n', end - colon);
        if (nl == NULL) nl = end;
        ngx_table_elt_t *h = (ngx_table_elt_t *) ngx_pcalloc(pool, sizeof(*h));
        if (h == NULL) break;
        h->key.data   = p;
        h->key.len    = colon - p;
        h->value.data = colon + 1;
        h->value.len  = nl - colon - 1;
        h->hash       = 1;
        if (head == NULL) head = h;
        if (tail) tail->next = h;
        tail = h;
        if (nl >= end) break;
        p = nl + 1;
    }
    return head;
}

static void drive_multi_header(ngx_http_request_t *r, u_char *buf, size_t n) {
    ngx_str_t name;
    ngx_table_elt_t *head = build_header_chain(r->pool, buf, n, &name);
    if (head == NULL) return;
    ngx_str_t value;
    (void) ngx_http_parse_multi_header_lines(r, head, &name, &value);
}

static void drive_cookie(ngx_http_request_t *r, u_char *buf, size_t n) {
    ngx_str_t name;
    ngx_table_elt_t *head = build_header_chain(r->pool, buf, n, &name);
    if (head == NULL) return;
    ngx_str_t value;
    (void) ngx_http_parse_cookie_lines(r, head, &name, &value);
}

static void drive_set_cookie(ngx_http_request_t *r, u_char *buf, size_t n) {
    ngx_str_t name;
    ngx_table_elt_t *head = build_header_chain(r->pool, buf, n, &name);
    if (head == NULL) return;
    ngx_str_t value;
    (void) ngx_http_parse_set_cookie_lines(r, head, &name, &value);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();
    if (size < 2 || size > 16384) return 0;

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    ngx_pool_t *pool = ngx_create_pool(4096, &g_log);
    if (pool == NULL) return 0;

    // Make a writable copy (parsers may write through r->lowcase_header, etc.,
    // but the input buffer itself is only read; still, copy to avoid lifetime
    // surprises and to be consistent across selectors).
    u_char *buf = (u_char *) ngx_palloc(pool, payload_len + 1);
    if (buf == NULL) { ngx_destroy_pool(pool); return 0; }
    memcpy(buf, payload, payload_len);

    ngx_http_request_t *r =
        (ngx_http_request_t *) ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    ngx_connection_t *c =
        (ngx_connection_t *) ngx_pcalloc(pool, sizeof(ngx_connection_t));
    if (r == NULL || c == NULL) { ngx_destroy_pool(pool); return 0; }
    r->pool       = pool;
    r->connection = c;
    c->log        = &g_log;
    c->pool       = pool;

    switch (selector % 13) {
    case 0:
        drive_request_line(r, buf, payload_len);
        break;
    case 1:
        drive_header_line(r, buf, payload_len, /*allow_underscores=*/0);
        break;
    case 2:
        drive_header_line(r, buf, payload_len, /*allow_underscores=*/1);
        break;
    case 3:
        drive_status_line(r, buf, payload_len);
        break;
    case 4:
        drive_chunked(r, buf, payload_len, /*keep_trailers=*/0);
        break;
    case 5:
        drive_complex_uri(r, buf, payload_len, /*merge_slashes=*/1);
        break;
    case 6:
        drive_unsafe_uri(r, buf, payload_len);
        break;
    case 7:
        drive_parse_uri(r, buf, payload_len);
        break;
    case 8:
        drive_arg(r, buf, payload_len);
        break;
    case 9:
        drive_split_args(r, buf, payload_len);
        break;
    case 10:
        drive_multi_header(r, buf, payload_len);
        break;
    case 11:
        drive_cookie(r, buf, payload_len);
        break;
    case 12:
        drive_set_cookie(r, buf, payload_len);
        break;
    }

    ngx_destroy_pool(pool);
    return 0;
}
