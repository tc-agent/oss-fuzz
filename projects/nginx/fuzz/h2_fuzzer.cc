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
// HTTP/2 connection fuzzer. Brings up an in-process nginx cycle with an
// `http2`-enabled unix listener and feeds each fuzz input prefixed with
// the HTTP/2 connection preface so that ngx_http_v2_init() is reached and
// the H2 frame parser in src/http/v2/ngx_http_v2.c (including HPACK
// decoding in ngx_http_v2_table.c) is driven.
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

static const char configuration[] =
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
"    default_type application/octet-stream;\n"
"    error_log stderr emerg;\n"
"    access_log off;\n"
"    client_max_body_size 256M;\n"
"    client_body_temp_path /tmp/;\n"
"    gzip on;\n"
"    gzip_types *;\n"
"    gzip_min_length 1;\n"
"    charset_types *;\n"
"    source_charset utf-8;\n"
"    charset utf-8;\n"
"    keepalive_timeout 1;\n"
"    add_header X-Test value;\n"
"    server {\n"
"        listen unix:nginx_h2.sock http2;\n"
"        server_name localhost;\n"
"        userid on;\n"
"        location / {\n"
"            return 200 'hello world';\n"
"        }\n"
"        location /redir {\n"
"            return 302 /target;\n"
"        }\n"
"        location /addsuf {\n"
"            return 200 'hello hello hello hello';\n"
"        }\n"
"    }\n"
"}\n";

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN (sizeof(H2_PREFACE) - 1)

static ngx_cycle_t      *cycle;
static ngx_log_t         ngx_log;
static ngx_open_file_t   ngx_log_file;
static char             *my_argv[2];
static char              arg1[] = {0, 0xA, 0};
extern char **environ;
static const char *config_file = "/tmp/h2_config.conf";

struct fuzz_buf {
    const uint8_t *data;
    size_t         len;
};
static struct fuzz_buf g_request;

static size_t g_preface_offset;

// First serve the H2 preface, then the fuzz bytes. preface_offset is reset
// at the top of every LLVMFuzzerTestOneInput so partial-preface deliveries
// from one iteration cannot bleed into the next.
static ssize_t h2_recv(ngx_connection_t *c, u_char *buf, size_t size) {
    size_t n = 0;
    if (g_preface_offset < H2_PREFACE_LEN) {
        size_t avail = H2_PREFACE_LEN - g_preface_offset;
        size_t take  = size < avail ? size : avail;
        memcpy(buf, H2_PREFACE + g_preface_offset, take);
        g_preface_offset += take;
        buf  += take;
        size -= take;
        n    += take;
        if (size == 0) return (ssize_t) n;
    }
    if (g_request.len == 0) {
        if (n) return (ssize_t) n;
        c->read->ready = 0;
        return 0;
    }
    size_t take = size < g_request.len ? size : g_request.len;
    memcpy(buf, g_request.data, take);
    g_request.data += take;
    g_request.len  -= take;
    n              += take;
    return (ssize_t) n;
}

static ngx_int_t add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
    return NGX_OK;
}
static ngx_int_t init_event(ngx_cycle_t *cycle, ngx_msec_t timer) {
    return NGX_OK;
}
static ngx_chain_t *send_chain(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit) {
    // Pretend the entire chain was written.
    while (in && in->next) in = in->next;
    return NULL;
}
static ssize_t send_void(ngx_connection_t *c, u_char *buf, size_t size) {
    return (ssize_t) size;
}
static ssize_t recv_chain_void(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit) {
    return 0;
}

static int initialize_nginx(void) {
    ngx_cycle_t init_cycle;

    if (access("nginx_h2.sock", F_OK) != -1) {
        remove("nginx_h2.sock");
    }

    ngx_debug_init();
    ngx_strerror_init();
    ngx_time_init();
    ngx_regex_init();

    ngx_log.file = &ngx_log_file;
    ngx_log.log_level = NGX_LOG_EMERG;
    ngx_log_file.fd = ngx_stderr;

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = &ngx_log;
    ngx_cycle = &init_cycle;
    init_cycle.pool = ngx_create_pool(1024, &ngx_log);

    my_argv[0] = arg1;
    my_argv[1] = NULL;
    ngx_argv = ngx_os_argv = my_argv;
    ngx_argc = 0;

    char *env_before = environ[0];
    environ[0] = my_argv[0] + 1;
    ngx_os_init(&ngx_log);
    free(environ[0]);
    environ[0] = env_before;

    ngx_crc32_table_init();
    ngx_preinit_modules();

    FILE *fptr = fopen(config_file, "w");
    fprintf(fptr, "%s", configuration);
    fclose(fptr);
    init_cycle.conf_file.len = strlen(config_file);
    init_cycle.conf_file.data = (unsigned char *) config_file;

    cycle = ngx_init_cycle(&init_cycle);
    if (cycle == NULL) return 1;

    ngx_os_status(cycle->log);
    ngx_cycle = cycle;

    ngx_event_actions.add = add_event;
    ngx_event_actions.init = init_event;
    ngx_io.send_chain = send_chain;
    ngx_event_flags = 1;
    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_events);
    ngx_event_timer_init(cycle->log);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int init = initialize_nginx();
    if (init != 0) return 0;
    if (size > 16384) return 0;

    g_request.data    = data;
    g_request.len     = size;
    g_preface_offset  = 0;

    // Provide a small pool of free connections so H2 streams (each needing
    // a fresh ngx_connection_t) can be allocated. The H2 server caps streams
    // at SETTINGS_MAX_CONCURRENT_STREAMS (default 128), so a few extra
    // connections meaningfully widen handler/filter coverage.
    enum { N_FREE = 8 };
    ngx_event_t read_events[N_FREE] = {};
    ngx_event_t write_events[N_FREE] = {};
    ngx_connection_t pool[N_FREE] = {};
    for (int i = 0; i < N_FREE; i++) {
        pool[i].read  = &read_events[i];
        pool[i].write = &write_events[i];
        pool[i].data  = (i + 1 < N_FREE) ? &pool[i + 1] : NULL;
    }
    ngx_listening_t *ls = (ngx_listening_t *) ngx_cycle->listening.elts;
    ngx_cycle->free_connections = &pool[0];
    ngx_cycle->free_connection_n = N_FREE;

    ngx_connection_t *c = ngx_get_connection(254, &ngx_log);
    c->shared = 1;
    c->destroyed = 0;
    c->type = SOCK_STREAM;
    c->pool = ngx_create_pool(256, ngx_cycle->log);
    c->sockaddr = ls->sockaddr;
    c->listening = ls;
    c->recv = h2_recv;
    c->send = send_void;
    c->send_chain = send_chain;
    c->recv_chain = recv_chain_void;
    c->log = &ngx_log;
    c->pool->log = &ngx_log;
    c->read->log = &ngx_log;
    c->write->log = &ngx_log;
    c->socklen = ls->socklen;
    c->local_sockaddr = ls->sockaddr;
    c->local_socklen = ls->socklen;
    c->data = NULL;

    c->read->ready = 1;
    c->write->ready = c->write->delayed = 1;

    ngx_http_init_connection(c);

    if (c->destroyed != 1) {
        ngx_close_connection(c);
    }
    return 0;
}
