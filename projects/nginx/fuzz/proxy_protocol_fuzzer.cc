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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static ngx_log_t      pp_log;
static ngx_open_file_t pp_log_file;

static int
pp_init(void)
{
    ngx_debug_init();
    ngx_time_init();

    pp_log_file.fd = ngx_stderr;
    pp_log.file = &pp_log_file;
    pp_log.log_level = NGX_LOG_EMERG;

    ngx_pagesize = getpagesize();
    ngx_pagesize_shift = 0;
    for (size_t n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }
    ngx_cacheline_size = 64;

    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int init = pp_init();
    (void) init;

    if (size > NGX_PROXY_PROTOCOL_MAX_HEADER) {
        return 0;
    }

    ngx_pool_t *pool = ngx_create_pool(1024, &pp_log);
    if (pool == NULL) {
        return 0;
    }

    ngx_connection_t c;
    ngx_memzero(&c, sizeof(ngx_connection_t));
    c.pool = pool;
    c.log = &pp_log;

    /* Copy input into a heap buffer so ASan catches OOB reads. */
    u_char *buf = (u_char *) ngx_pnalloc(pool, size ? size : 1);
    if (buf == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }
    if (size) {
        ngx_memcpy(buf, data, size);
    }

    u_char *end = ngx_proxy_protocol_read(&c, buf, buf + size);

    if (end != NULL && c.proxy_protocol != NULL
        && c.proxy_protocol->tlvs.len > 0)
    {
        /* Exercise TLV lookup paths for known type names. */
        static const char *names[] = {
            "alpn", "authority", "unique_id", "netns",
            "ssl_version", "ssl_cn", "ssl_cipher",
            "ssl_sig_alg", "ssl_key_alg", "0xe0",
        };
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            ngx_str_t name;
            name.data = (u_char *) names[i];
            name.len = strlen(names[i]);
            ngx_str_t value = ngx_null_string;
            ngx_proxy_protocol_get_tlv(&c, &name, &value);
        }
    }

    ngx_destroy_pool(pool);
    return 0;
}
