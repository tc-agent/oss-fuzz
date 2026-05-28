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
// DNS-response fuzzer for src/core/ngx_resolver.c. Drives
// ngx_resolver_process_response() directly with a fuzz-controlled DNS packet
// against a minimally-mocked ngx_resolver_t. build.sh patches `static` off
// ngx_resolver_process_response so it's reachable externally.
//
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_resolver.h>

// Exposed by the build.sh sed patch (was static).
void ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf,
    size_t n, ngx_uint_t tcp);
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

static void noop_rbtree_insert(ngx_rbtree_node_t *temp,
                               ngx_rbtree_node_t *node,
                               ngx_rbtree_node_t *sentinel) {
    // The resolver inserts via specific insert_value callbacks; for fuzzing
    // we never insert nodes, so this is unused. Stub keeps init happy.
    (void) temp; (void) node; (void) sentinel;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();
    if (size < 2 || size > 65536) return 0;

    uint8_t tcp_flag = data[0] & 1;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    ngx_pool_t *pool = ngx_create_pool(8192, &g_log);
    if (pool == NULL) return 0;

    ngx_resolver_t *r = (ngx_resolver_t *) ngx_pcalloc(pool, sizeof(*r));
    if (r == NULL) { ngx_destroy_pool(pool); return 0; }
    r->log = &g_log;
    r->log_level = NGX_LOG_EMERG;
    r->ipv4 = 1;
#if (NGX_HAVE_INET6)
    r->ipv6 = 1;
#endif

    ngx_rbtree_init(&r->name_rbtree,  &r->name_sentinel,  noop_rbtree_insert);
    ngx_rbtree_init(&r->srv_rbtree,   &r->srv_sentinel,   noop_rbtree_insert);
    ngx_rbtree_init(&r->addr_rbtree,  &r->addr_sentinel,  noop_rbtree_insert);
#if (NGX_HAVE_INET6)
    ngx_rbtree_init(&r->addr6_rbtree, &r->addr6_sentinel, noop_rbtree_insert);
#endif

    ngx_queue_init(&r->name_resend_queue);
    ngx_queue_init(&r->srv_resend_queue);
    ngx_queue_init(&r->addr_resend_queue);
    ngx_queue_init(&r->name_expire_queue);
    ngx_queue_init(&r->srv_expire_queue);
    ngx_queue_init(&r->addr_expire_queue);
#if (NGX_HAVE_INET6)
    ngx_queue_init(&r->addr6_resend_queue);
    ngx_queue_init(&r->addr6_expire_queue);
#endif

    // ngx_resolver_process_response writes to the buffer in some paths
    // (e.g. unescaping during name parsing), so feed a writable copy.
    u_char *buf = (u_char *) ngx_palloc(pool, payload_len);
    if (buf == NULL) { ngx_destroy_pool(pool); return 0; }
    memcpy(buf, payload, payload_len);

    ngx_resolver_process_response(r, buf, payload_len, tcp_flag);

    ngx_destroy_pool(pool);
    return 0;
}
