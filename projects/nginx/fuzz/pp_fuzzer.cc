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
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_proxy_protocol.h>
}
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static ngx_log_t       g_log;
static ngx_open_file_t g_log_file;
static int             g_init_done;

static const char *tlv_names[] = {
    "alpn", "authority", "unique_id", "ssl_version", "ssl_cn", "ssl_cipher",
    "ssl_sig_alg", "ssl_key_alg", "netns", "0xea",
};

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
    if (size == 0 || size > 4096) return 0;

    ngx_pool_t *pool = ngx_create_pool(2048, &g_log);
    if (pool == NULL) return 0;

    ngx_connection_t c;
    memset(&c, 0, sizeof(c));
    c.log  = &g_log;
    c.pool = pool;

    // Make a writable copy of the input for ngx_proxy_protocol_read,
    // which may overwrite bytes (e.g. NUL-terminating the v1 header line).
    u_char *buf = (u_char *) ngx_palloc(pool, size);
    if (buf == NULL) { ngx_destroy_pool(pool); return 0; }
    memcpy(buf, data, size);

    u_char *last = buf + size;
    u_char *p = ngx_proxy_protocol_read(&c, buf, last);

    if (p != NULL && c.proxy_protocol != NULL) {
        // Probe TLV lookup; this also exercises get_tlv parsing for v2.
        for (size_t i = 0; i < sizeof(tlv_names)/sizeof(tlv_names[0]); i++) {
            ngx_str_t name = { strlen(tlv_names[i]), (u_char *) tlv_names[i] };
            ngx_str_t value;
            ngx_proxy_protocol_get_tlv(&c, &name, &value);
        }
    }

    ngx_destroy_pool(pool);
    return 0;
}
