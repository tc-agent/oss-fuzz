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
// Upstream-side HTTP/1 response fuzzer. Brings up an in-process nginx cycle
// that proxies every request to an upstream group, then for each iteration:
//   1. Feeds a *fixed* valid HTTP/1.1 request from the "client" side so the
//      request reliably reaches the upstream pipeline.
//   2. Feeds the fuzz bytes verbatim as the "upstream" HTTP/1 response.
//
// This concentrates fuzzing on ngx_http_upstream.c + ngx_http_proxy_module.c
// (and the response filter chain) rather than the inbound HTTP parser.
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
"    worker_connections 4;\n"
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
"    proxy_temp_path /tmp/;\n"
"    proxy_buffer_size 24K;\n"
"    proxy_max_temp_file_size 0;\n"
"    proxy_buffers 8 4K;\n"
"    proxy_busy_buffers_size 28K;\n"
"    proxy_buffering off;\n"
"    gzip on;\n"
"    gzip_types *;\n"
"    upstream up { server 127.0.0.1:1010 max_fails=0; }\n"
"    server {\n"
"      listen unix:nginx_up.sock;\n"
"      proxy_next_upstream off;\n"
"      proxy_read_timeout 5m;\n"
"      proxy_http_version 1.1;\n"
"      location / {\n"
"        proxy_pass http://up;\n"
"        proxy_set_header Host upstream.local;\n"
"        proxy_set_header Connection '';\n"
"        chunked_transfer_encoding off;\n"
"        proxy_buffering off;\n"
"        proxy_cache off;\n"
"      }\n"
"    }\n"
"}\n";

// A valid HTTP/1.1 request that reliably routes to the upstream location.
static const char kClientRequest[] =
"GET /resource?x=1 HTTP/1.1\r\n"
"Host: front.local\r\n"
"User-Agent: ufuzz\r\n"
"Accept: */*\r\n"
"X-Forwarded-For: 1.2.3.4\r\n"
"Cookie: session=abc\r\n"
"\r\n";

static ngx_cycle_t      *cycle;
static ngx_log_t         ngx_log;
static ngx_open_file_t   ngx_log_file;
static char             *my_argv[2];
static char              arg1[] = {0, 0xA, 0};
extern char **environ;
static const char *config_file = "/tmp/upstream_config.conf";

struct fuzz_buf {
    const uint8_t *data;
    size_t         len;
};
static struct fuzz_buf g_client;   // fixed request bytes (re-served each iter)
static size_t          g_client_off;
static struct fuzz_buf g_reply;    // fuzzed upstream response

static ngx_http_upstream_t *upstream_ctx;
static ngx_http_request_t  *req_for_reply;
static ngx_http_cleanup_t   cln_new;
static int                  cln_added;

static void cleanup_reply(void *data) {
    req_for_reply = NULL;
}

// Client → nginx (replays kClientRequest verbatim per iteration).
static ssize_t client_recv(ngx_connection_t *c, u_char *buf, size_t size) {
    if (g_client_off >= g_client.len) {
        c->read->ready = 0;
        return 0;
    }
    size_t take = g_client.len - g_client_off;
    if (take > size) take = size;
    memcpy(buf, g_client.data + g_client_off, take);
    g_client_off += take;
    return (ssize_t) take;
}

// Upstream → nginx (fuzz input).
static ssize_t reply_recv(ngx_connection_t *c, u_char *buf, size_t size) {
    req_for_reply = (ngx_http_request_t *) c->data;
    if (!cln_added && req_for_reply) {
        cln_added = 1;
        cln_new.handler = cleanup_reply;
        cln_new.data = NULL;
        cln_new.next = req_for_reply->cleanup;
        req_for_reply->cleanup = &cln_new;
    }
    if (req_for_reply) upstream_ctx = req_for_reply->upstream;
    if (g_reply.len == 0) {
        c->read->ready = 0;
        return 0;
    }
    size_t take = g_reply.len;
    if (take > size) take = size;
    memcpy(buf, g_reply.data, take);
    g_reply.data += take;
    g_reply.len  -= take;
    return (ssize_t) take;
}

static ngx_int_t add_event(ngx_event_t *ev, ngx_int_t e, ngx_uint_t f) {
    return NGX_OK;
}
static ngx_int_t init_event(ngx_cycle_t *cycle, ngx_msec_t t) {
    return NGX_OK;
}

// When nginx writes (request to upstream OR response to client), we don't
// actually send. For the upstream side, mark its read as ready and swap in
// reply_recv so the next read consumes our fuzz bytes.
static ngx_chain_t *send_chain(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit) {
    c->read->ready = 1;
    c->recv = reply_recv;
    while (in && in->next) in = in->next;
    return NULL;
}

extern "C" long int invalid_call(ngx_connection_s *a, ngx_chain_s *b,
                                 long int cc) {
    return 0;
}

static int initialize_nginx(void) {
    ngx_cycle_t init_cycle;

    if (access("nginx_up.sock", F_OK) != -1) {
        remove("nginx_up.sock");
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
    if (size > 65536) return 0;

    g_client.data    = (const uint8_t *) kClientRequest;
    g_client.len     = sizeof(kClientRequest) - 1;
    g_client_off     = 0;
    g_reply.data     = data;
    g_reply.len      = size;
    req_for_reply    = NULL;
    upstream_ctx     = NULL;
    cln_added        = 0;

    ngx_event_t read_event1 = {};
    ngx_event_t write_event1 = {};
    ngx_connection_t local1 = {};
    ngx_event_t read_event2 = {};
    ngx_event_t write_event2 = {};
    ngx_connection_t local2 = {};

    ngx_listening_t *ls = (ngx_listening_t *) ngx_cycle->listening.elts;

    local1.read = &read_event1;
    local1.write = &write_event1;
    local2.read = &read_event2;
    local2.write = &write_event2;
    local2.send_chain = send_chain;

    ngx_cycle->free_connections = &local1;
    local1.data = &local2;
    ngx_cycle->free_connection_n = 2;

    ngx_connection_t *c = ngx_get_connection(253, &ngx_log);
    c->shared = 1;
    c->destroyed = 0;
    c->type = SOCK_STREAM;
    c->pool = ngx_create_pool(256, ngx_cycle->log);
    c->sockaddr = ls->sockaddr;
    c->listening = ls;
    c->recv = client_recv;
    c->send_chain = send_chain;
    c->send = (ngx_send_pt) invalid_call;
    c->recv_chain = (ngx_recv_chain_pt) invalid_call;
    c->log = &ngx_log;
    c->pool->log = &ngx_log;
    c->read->log = &ngx_log;
    c->write->log = &ngx_log;
    c->socklen = ls->socklen;
    c->local_sockaddr = ls->sockaddr;
    c->local_socklen = ls->socklen;
    c->data = NULL;

    read_event1.ready = 1;
    write_event1.ready = write_event1.delayed = 1;

    ngx_http_init_connection(c);

    if (c->destroyed != 1) {
        if (c->read->data != NULL) {
            ngx_connection_t *c2 = (ngx_connection_t *) c->read->data;
            ngx_http_request_t *r = (ngx_http_request_t *) c2->data;
            if (r) {
                r->cleanup = NULL;
                ngx_http_finalize_request(r, NGX_DONE);
            }
        }
        ngx_close_connection(c);
    }
    return 0;
}
