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
// Fuzzes ngx_proxy_protocol_read() — the PROXY protocol v1/v2 parser.
// Coverage target: src/core/ngx_proxy_protocol.c (359 lines, 0% baseline).
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
    // ngx_pagesize is needed by ngx_create_pool via NGX_MAX_ALLOC_FROM_POOL
    ngx_pagesize = getpagesize();
    ngx_cacheline_size = 64;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = init_once();
    (void)initialized;

    ngx_pool_t *pool = ngx_create_pool(4096, &ngx_fuzz_log);
    if (pool == NULL) {
        return 0;
    }

    struct sockaddr_storage ss;
    ngx_memzero(&ss, sizeof(ss));

    ngx_connection_t c;
    ngx_memzero(&c, sizeof(c));
    c.pool = pool;
    c.log = &ngx_fuzz_log;
    c.sockaddr = reinterpret_cast<struct sockaddr *>(&ss);
    c.socklen = sizeof(ss);

    u_char *buf = reinterpret_cast<u_char *>(ngx_palloc(pool, size + 1));
    if (buf == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }
    ngx_memcpy(buf, data, size);
    buf[size] = '\0';
    ngx_proxy_protocol_read(&c, buf, buf + size);

    ngx_destroy_pool(pool);
    return 0;
}
