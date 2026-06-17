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
// Standalone fuzzer for nginx HTTP parsing functions.  Exercises the request
// line, header, status line, and chunked transfer-encoding parsers without
// booting the full nginx cycle.
//
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
}
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static ngx_log_t fuzz_log;
static ngx_open_file_t fuzz_log_file;
static int runtime_init;

static void init_runtime(void) {
  if (runtime_init)
    return;
  runtime_init = 1;

  fuzz_log.file = &fuzz_log_file;
  fuzz_log.log_level = NGX_LOG_EMERG;
  fuzz_log_file.fd = ngx_stderr;

  ngx_debug_init();
  ngx_strerror_init();
  ngx_time_init();
  ngx_pagesize = getpagesize();
  ngx_cacheline_size = 64;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  init_runtime();

  if (size < 2)
    return 0;

  // Use first byte to select parser sub-target
  uint8_t selector = data[0];
  data++;
  size--;

  // Make a mutable copy (parsers write into the buffer for complex URI)
  u_char *buf = (u_char *)malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  ngx_buf_t b;
  ngx_memzero(&b, sizeof(b));
  b.pos = buf;
  b.last = buf + size;
  b.start = buf;
  b.end = buf + size;
  b.temporary = 1;

  switch (selector & 0x03) {
  case 0: {
    // Parse HTTP request line
    ngx_http_request_t r;
    ngx_memzero(&r, sizeof(r));
    ngx_http_parse_request_line(&r, &b);
    break;
  }
  case 1: {
    // Parse HTTP header line (allow underscores in header names)
    ngx_http_request_t r;
    ngx_memzero(&r, sizeof(r));
    ngx_http_parse_header_line(&r, &b, 1);
    break;
  }
  case 2: {
    // Parse HTTP status line (response from upstream)
    ngx_http_request_t r;
    ngx_http_status_t status;
    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&status, sizeof(status));
    ngx_http_parse_status_line(&r, &b, &status);
    break;
  }
  case 3: {
    // Parse chunked transfer-encoding
    ngx_http_request_t r;
    ngx_http_chunked_t ctx;
    ngx_connection_t conn;
    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&ctx, sizeof(ctx));
    ngx_memzero(&conn, sizeof(conn));
    conn.log = &fuzz_log;
    r.connection = &conn;
    ngx_http_parse_chunked(&r, &b, &ctx, 0);
    break;
  }
  }

  free(buf);
  return 0;
}
