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
// Fuzzes the HTTP/2 frame parser and HPACK decoder in nginx.
// Coverage targets (0% baseline):
//   src/http/v2/ngx_http_v2.c         (~3,250 lines)
//   src/http/v2/ngx_http_v2_table.c   (~363 lines, HPACK dynamic table)
//   src/http/v2/ngx_http_v2_encode.c  (~62 lines)
//
// Strategy: initialize nginx with "http2 on;" in the config, then inject
// fuzz data prepended with the H2 connection preface so every iteration
// goes through the H2 state machine (ngx_http_v2_init → read_handler).
//
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// H2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN (sizeof(H2_PREFACE) - 1)  // 24 bytes

static const char h2_configuration[] =
"error_log stderr emerg;\n"
"worker_rlimit_nofile 8192;\n"
"events {\n"
"    use epoll;\n"
"    worker_connections 2;\n"
"    multi_accept off;\n"
"    accept_mutex off;\n"
"}\n"
"http {\n"
"    server_tokens off;\n"
"    error_log stderr emerg;\n"
"    access_log off;\n"
"    client_body_temp_path /tmp/;\n"
"    server {\n"
"      listen unix:nginx_h2.sock;\n"
"      http2 on;\n"
"      location / {\n"
"        return 200;\n"
"      }\n"
"    }\n"
"}\n";

static ngx_cycle_t *h2_cycle;
static ngx_log_t ngx_h2_log;
static ngx_open_file_t ngx_h2_log_file;
static char *my_argv[2];
static char arg1[] = {0, 0xA, 0};

extern char **environ;

static const char *h2_config_file = "/tmp/http_h2_config.conf";

// Pre-allocated connection pool for H2 stream allocations.
// ngx_http_v2 creates one fake ngx_connection_t per stream.  With only 1 free
// connection in the pool, the first ngx_get_connection() call succeeds (giving
// us the client connection) but every subsequent stream allocation fails, so
// the fuzzer never exercises stream-level H2 code.  32 slots is enough for all
// realistic frame sequences the fuzzer will generate.
#define H2_CONN_POOL_SIZE 32
static ngx_connection_t h2_conn_pool[H2_CONN_POOL_SIZE];
static ngx_event_t      h2_rev_pool[H2_CONN_POOL_SIZE];
static ngx_event_t      h2_wev_pool[H2_CONN_POOL_SIZE];

// Fuzz data buffer: H2 preface + caller's data
static u_char *fuzz_buf = NULL;
static size_t  fuzz_pos = 0;
static size_t  fuzz_len = 0;

static ssize_t h2_recv_handler(ngx_connection_t *c, u_char *buf, size_t size) {
    size_t avail = fuzz_len - fuzz_pos;
    if (avail == 0) {
        // Signal EOF to trigger ngx_http_v2_finalize_connection
        return 0;
    }
    if (size > avail) {
        size = avail;
    }
    ngx_memcpy(buf, fuzz_buf + fuzz_pos, size);
    fuzz_pos += size;
    return (ssize_t)size;
}

static ngx_chain_t *h2_send_chain(ngx_connection_t *c, ngx_chain_t *in,
                                   off_t limit) {
    // Discard all outgoing data; signal write-ready so the state machine
    // can proceed past any SETTINGS ACK or WINDOW_UPDATE it wants to send.
    c->read->ready = 1;
    return NULL;
}

// No-op send for c->send (byte-by-byte interface, not used by H2)
static ssize_t h2_noop_send(ngx_connection_t *c, u_char *buf, size_t size) {
    return (ssize_t)size;
}

// No-op recv_chain (not used by H2, which uses c->recv directly)
static ssize_t h2_noop_recv_chain(ngx_connection_t *c, ngx_chain_t *in,
                                   off_t limit) {
    return NGX_AGAIN;
}

static ngx_int_t h2_noop_event(ngx_event_t *ev, ngx_int_t event,
                               ngx_uint_t flags) {
    return NGX_OK;
}

static ngx_int_t h2_init_event(ngx_cycle_t *cycle, ngx_msec_t timer) {
    return NGX_OK;
}

extern "C" int InitializeNginxH2(void) {
    ngx_log_t    *log;
    ngx_cycle_t   init_cycle;

    if (access("nginx_h2.sock", F_OK) != -1) {
        remove("nginx_h2.sock");
    }

    ngx_debug_init();
    ngx_strerror_init();
    ngx_time_init();
    ngx_regex_init();

    ngx_h2_log.file = &ngx_h2_log_file;
    ngx_h2_log.log_level = NGX_LOG_EMERG;
    ngx_h2_log_file.fd = ngx_stderr;
    log = &ngx_h2_log;

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    init_cycle.pool = ngx_create_pool(1024, log);

    my_argv[0] = arg1;
    my_argv[1] = NULL;
    ngx_argv = ngx_os_argv = my_argv;
    ngx_argc = 0;

    char *env_before = environ[0];
    environ[0] = my_argv[0] + 1;
    ngx_os_init(log);
    free(environ[0]);
    environ[0] = env_before;

    ngx_crc32_table_init();
    ngx_preinit_modules();

    FILE *fptr = fopen(h2_config_file, "w");
    fprintf(fptr, "%s", h2_configuration);
    fclose(fptr);
    init_cycle.conf_file.len = strlen(h2_config_file);
    init_cycle.conf_file.data = reinterpret_cast<unsigned char *>(
        const_cast<char *>(h2_config_file));

    h2_cycle = ngx_init_cycle(&init_cycle);

    ngx_os_status(h2_cycle->log);
    ngx_cycle = h2_cycle;

    ngx_event_actions.add  = h2_noop_event;
    ngx_event_actions.del  = h2_noop_event;  // no-op; NULL would crash when H2 calls ngx_del_event
    ngx_event_actions.init = h2_init_event;
    ngx_io.send_chain      = h2_send_chain;
    ngx_event_flags = 1;
    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_events);
    ngx_event_timer_init(h2_cycle->log);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int init = InitializeNginxH2();
    if (init != 0) {
        return 0;
    }

    // Build the combined buffer: H2 preface + fuzz data
    size_t total = H2_PREFACE_LEN + size;
    fuzz_buf = reinterpret_cast<u_char *>(malloc(total));
    if (fuzz_buf == NULL) {
        return 0;
    }
    memcpy(fuzz_buf, H2_PREFACE, H2_PREFACE_LEN);
    if (size > 0) {
        memcpy(fuzz_buf + H2_PREFACE_LEN, data, size);
    }
    fuzz_pos = 0;
    fuzz_len = total;

    // Rebuild the free connection pool each iteration so H2 stream allocations
    // don't exhaust the pool across fuzz iterations.
    ngx_memzero(h2_conn_pool, sizeof(h2_conn_pool));
    ngx_memzero(h2_rev_pool,  sizeof(h2_rev_pool));
    ngx_memzero(h2_wev_pool,  sizeof(h2_wev_pool));
    for (int i = 0; i < H2_CONN_POOL_SIZE; i++) {
        h2_conn_pool[i].read  = &h2_rev_pool[i];
        h2_conn_pool[i].write = &h2_wev_pool[i];
        if (i < H2_CONN_POOL_SIZE - 1) {
            h2_conn_pool[i].data = &h2_conn_pool[i + 1];
        }
    }
    h2_cycle->free_connections  = h2_conn_pool;
    h2_cycle->free_connection_n = H2_CONN_POOL_SIZE;

    // Use the unix-socket listening entry created by ngx_init_cycle
    ngx_listening_t *ls =
        reinterpret_cast<ngx_listening_t *>(h2_cycle->listening.elts);

    // ngx_get_connection returns h2_conn_pool[0] and removes it from the list.
    // Remaining pool slots (1..31) are available for H2 stream allocations.
    ngx_connection_t *c = ngx_get_connection(255, &ngx_h2_log);
    if (c == NULL) {
        free(fuzz_buf);
        fuzz_buf = NULL;
        return 0;
    }

    c->shared          = 1;
    c->destroyed       = 0;
    c->type            = SOCK_STREAM;
    c->pool            = ngx_create_pool(256, h2_cycle->log);
    c->sockaddr        = ls->sockaddr;
    c->listening       = ls;
    c->recv            = h2_recv_handler;
    c->send_chain      = h2_send_chain;
    c->send            = h2_noop_send;
    c->recv_chain      = h2_noop_recv_chain;
    c->log             = &ngx_h2_log;
    c->pool->log       = &ngx_h2_log;
    c->read->log       = &ngx_h2_log;
    c->write->log      = &ngx_h2_log;
    c->socklen         = ls->socklen;
    c->local_sockaddr  = ls->sockaddr;
    c->local_socklen   = ls->socklen;
    c->data            = NULL;

    // c->read and c->write point into h2_rev_pool[0] / h2_wev_pool[0]
    c->read->ready  = 1;
    c->write->ready = c->write->delayed = 1;

    // This detects the H2 preface and calls ngx_http_v2_init()
    ngx_http_init_connection(c);

    // If the state machine didn't self-destruct (e.g., stalled waiting for
    // events), force cleanup to avoid pool leaks between iterations.
    if (c->destroyed != 1) {
        ngx_http_close_connection(c);
    }

    free(fuzz_buf);
    fuzz_buf = NULL;
    return 0;
}
