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
// Fuzzer for the PROXY protocol v1/v2 parser (ngx_proxy_protocol_read).
// Exercises address parsing, TLV decoding, and protocol switching.
//
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
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

  if (size == 0)
    return 0;

  // Create a pool for the proxy protocol parser
  ngx_pool_t *pool = ngx_create_pool(4096, &fuzz_log);
  if (pool == NULL)
    return 0;

  ngx_connection_t c;
  ngx_memzero(&c, sizeof(c));
  c.pool = pool;
  c.log = &fuzz_log;

  // Make a copy to ensure writable buffer with room for null terminator
  u_char *buf = (u_char *)ngx_pnalloc(pool, size + 1);
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
