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
// Fuzzer for the HTTP/2 frame parser in nginx.  Feeds raw bytes through an
// nginx connection that has http2 enabled, covering the H2 frame state
// machine, HPACK table, stream management, and flow control.
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

// Configuration that enables HTTP/2
static char configuration[] =
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
"    server {\n"
"      listen unix:nginx_h2.sock;\n"
"      http2 on;\n"
"      server_name localhost;\n"
"      location / {\n"
"        return 200 'ok';\n"
"      }\n"
"    }\n"
"}\n"
"\n";

static const char *config_file = "/tmp/http_v2_config.conf";

static ngx_cycle_t *cycle;
static ngx_log_t ngx_log;
static ngx_open_file_t ngx_log_file;
static char *my_argv[2];
static char arg1[] = {0, 0xA, 0};

extern char **environ;

// H2 connection preface (24 bytes)
static const uint8_t h2_preface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN 24

struct fuzzing_data {
  const uint8_t *data;
  size_t data_len;
};

static struct fuzzing_data request;

// Called by the http parser to read the buffer
static ssize_t request_recv_handler(ngx_connection_t *c, u_char *buf,
                                    size_t size) {
  if (request.data_len < size)
    size = request.data_len;
  memcpy(buf, request.data, size);
  request.data += size;
  request.data_len -= size;
  return size;
}

static ngx_int_t add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
  return NGX_OK;
}

static ngx_int_t del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
  return NGX_OK;
}

static ngx_int_t init_event(ngx_cycle_t *cycle, ngx_msec_t timer) {
  return NGX_OK;
}

// Used when sending data, do nothing
static ngx_chain_t *send_chain(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit) {
  c->read->ready = 1;
  c->recv = request_recv_handler;
  return in->next;
}

static ssize_t send_stub(ngx_connection_t *c, u_char *buf, size_t size) {
  return size;
}

// Create a base state for Nginx with HTTP/2 enabled
extern "C" int InitializeNginxH2(void) {
  ngx_log_t *log;
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
  log = &ngx_log;

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

  FILE *fptr = fopen(config_file, "w");
  fprintf(fptr, "%s", configuration);
  fclose(fptr);
  init_cycle.conf_file.len = strlen(config_file);
  init_cycle.conf_file.data = (unsigned char *)config_file;

  cycle = ngx_init_cycle(&init_cycle);

  ngx_os_status(cycle->log);
  ngx_cycle = cycle;

  ngx_event_actions.add = add_event;
  ngx_event_actions.del = del_event;
  ngx_event_actions.init = init_event;
  ngx_io.send_chain = send_chain;
  ngx_event_flags = 1;
  ngx_queue_init(&ngx_posted_accept_events);
  ngx_queue_init(&ngx_posted_next_events);
  ngx_queue_init(&ngx_posted_events);
  ngx_event_timer_init(cycle->log);
  return 0;
}

extern "C" long int invalid_call(ngx_connection_s *a, ngx_chain_s *b,
                                 long int c) {
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int init = InitializeNginxH2();
  (void)init;

  if (size == 0)
    return 0;

  // Build input: H2 preface + fuzzed frame data
  size_t total = H2_PREFACE_LEN + size;
  uint8_t *buf = (uint8_t *)malloc(total);
  if (!buf)
    return 0;
  memcpy(buf, h2_preface, H2_PREFACE_LEN);
  memcpy(buf + H2_PREFACE_LEN, data, size);

  request.data = buf;
  request.data_len = total;

  // Set up two free connections
  ngx_event_t read_event1 = {};
  ngx_event_t write_event1 = {};
  ngx_connection_t local1 = {};
  ngx_event_t read_event2 = {};
  ngx_event_t write_event2 = {};
  ngx_connection_t local2 = {};
  ngx_connection_t *c;
  ngx_listening_t *ls;

  ls = (ngx_listening_t *)ngx_cycle->listening.elts;

  local1.read = &read_event1;
  local1.write = &write_event1;
  local2.read = &read_event2;
  local2.write = &write_event2;
  local2.send_chain = send_chain;

  ngx_cycle->free_connections = &local1;
  local1.data = &local2;
  ngx_cycle->free_connection_n = 2;

  c = ngx_get_connection(254, &ngx_log);

  c->shared = 1;
  c->destroyed = 0;
  c->type = SOCK_STREAM;
  c->pool = ngx_create_pool(256, ngx_cycle->log);
  c->sockaddr = ls->sockaddr;
  c->listening = ls;
  c->recv = request_recv_handler;
  c->send_chain = send_chain;
  c->send = send_stub;
  c->recv_chain = (ngx_recv_chain_pt)invalid_call;
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

  // Will detect H2 preface and route to ngx_http_v2_init
  ngx_http_init_connection(c);

  // The H2 code path calls ngx_http_close_connection (via finalize)
  // when recv returns 0 (all data consumed). But in case it didn't
  // clean up (e.g., partial frame in buffer), force-close.
  if (c->destroyed != 1) {
    ngx_http_close_connection(c);
  }

  free(buf);
  return 0;
}
