// Copyright 2025 Google LLC
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
// Standalone fuzzer for the HTTP parser functions in ngx_http_parse.c.
// Uses first byte as a selector to exercise:
//   0: ngx_http_parse_request_line
//   1: ngx_http_parse_header_line
//   2: ngx_http_parse_status_line
//   3: ngx_http_parse_chunked
//
// Coverage target: src/http/ngx_http_parse.c (1,768 lines, ~42% baseline).
// These parsers are pure state-machine code requiring only a pool + buffer.
//
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
}
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

static ngx_log_t ngx_fuzz_log;
static ngx_open_file_t ngx_fuzz_log_file;

static int init_once(void) {
    ngx_fuzz_log.file = &ngx_fuzz_log_file;
    ngx_fuzz_log.log_level = NGX_LOG_EMERG;
    ngx_fuzz_log_file.fd = ngx_stderr;

    ngx_debug_init();
    ngx_strerror_init();
    ngx_time_init();
    ngx_pagesize = getpagesize();
    ngx_cacheline_size = 64;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = init_once();
    (void)initialized;

    if (size < 2) {
        return 0;
    }

    uint8_t selector      = data[0] & 0x03;
    uint8_t keep_trailers = (data[0] >> 2) & 0x01;
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    ngx_pool_t *pool = ngx_create_pool(4096, &ngx_fuzz_log);
    if (pool == NULL) {
        return 0;
    }

    // Allocate a mutable copy of the fuzz data since parsers may modify
    // the buffer indirectly (lowercasing etc.)
    u_char *buf = reinterpret_cast<u_char *>(ngx_palloc(pool, payload_size + 1));
    if (buf == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }
    ngx_memcpy(buf, payload, payload_size);
    buf[payload_size] = '\0';

    ngx_buf_t b;
    ngx_memzero(&b, sizeof(b));
    b.pos = buf;
    b.last = buf + payload_size;

    ngx_http_request_t r;
    ngx_memzero(&r, sizeof(r));
    r.pool = pool;
    r.header_in = &b;

    switch (selector) {
    case 0:
        // Request line parser: "GET /path HTTP/1.1\r\n"
        ngx_http_parse_request_line(&r, &b);
        break;

    case 1: {
        // Header line parser: "Host: example.com\r\n"
        // Needs r.lowcase_header[] buffer in the request
        ngx_http_parse_header_line(&r, &b, 1);
        break;
    }

    case 2: {
        // Status line parser: "HTTP/1.1 200 OK\r\n"
        ngx_http_status_t status;
        ngx_memzero(&status, sizeof(status));
        ngx_http_parse_status_line(&r, &b, &status);
        break;
    }

    case 3: {
        // Chunked body parser
        ngx_http_chunked_t ctx;
        ngx_memzero(&ctx, sizeof(ctx));
        ngx_http_parse_chunked(&r, &b, &ctx, keep_trailers);
        break;
    }
    }

    ngx_destroy_pool(pool);
    return 0;
}
