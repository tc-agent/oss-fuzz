/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>

/*
 * Fuzzing entry point. Exercises the HSTS cache parser (hsts.c) by writing
 * fuzzer input to a temp file and loading it via CURLOPT_HSTS.
 *
 * HSTS cache file format (one entry per line):
 *   example.com "20391231 10:00:00"
 *   .example.net "20391231 10:00:00"    (dot prefix = includeSubDomains)
 *
 * Also exercises the HSTSREADFUNCTION callback path, which calls
 * hsts_push() to add entries from memory.
 *
 * The first byte of input selects the code path:
 *   bit 0: use CURLOPT_HSTS (file path), else use HSTSREADFUNCTION
 */

struct fuzz_hsts_ctx {
  const uint8_t *data;
  size_t size;
  int called;
};

static CURLSTScode hsts_read_cb(CURL *easy, struct curl_hstsentry *e,
                                void *userp)
{
  struct fuzz_hsts_ctx *ctx = (struct fuzz_hsts_ctx *)userp;
  (void)easy;

  /* Provide one entry on the first call, then signal done */
  if(ctx->called)
    return CURLSTS_DONE;

  ctx->called = 1;

  if(ctx->size < 2)
    return CURLSTS_DONE;

  /* Use fuzzer data as the hostname (fill caller-allocated buffer) */
  size_t namelen = ctx->size - 1;
  if(namelen >= e->namelen)
    namelen = e->namelen - 1;
  memcpy(e->name, ctx->data + 1, namelen);
  e->name[namelen] = '\0';

  e->includeSubDomains = (ctx->data[0] >> 1) & 1;
  /* Set a far-future expiry */
  strncpy(e->expire, "20391231 10:00:00", sizeof(e->expire) - 1);
  e->expire[sizeof(e->expire) - 1] = '\0';

  return CURLSTS_OK;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  CURL *curl;
  char tmpfile[] = "/tmp/fuzz_hsts_XXXXXX";
  int fd;

  if(!size)
    return 0;

  curl = curl_easy_init();
  if(!curl)
    return 0;

  /* Always enable HSTS */
  curl_easy_setopt(curl, CURLOPT_HSTS_CTRL, (long)CURLHSTS_ENABLE);

  if(data[0] & 1) {
    /* Path 1: load HSTS entries from a temp file */
    FILE *fp;
    fd = mkstemp(tmpfile);
    if(fd < 0) {
      curl_easy_cleanup(curl);
      return 0;
    }
    fp = fdopen(fd, "wb");
    if(!fp) {
      close(fd);
      unlink(tmpfile);
      curl_easy_cleanup(curl);
      return 0;
    }
    fwrite(data + 1, 1, size - 1, fp);
    fclose(fp);

    curl_easy_setopt(curl, CURLOPT_HSTS, tmpfile);
    /* A dummy request triggers HSTS cache load during setup */
    curl_easy_setopt(curl, CURLOPT_URL, "https://localhost:0/");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_perform(curl);

    unlink(tmpfile);
  }
  else {
    /* Path 2: inject HSTS entries via HSTSREADFUNCTION callback */
    struct fuzz_hsts_ctx ctx;
    ctx.data = data;
    ctx.size = size;
    ctx.called = 0;

    curl_easy_setopt(curl, CURLOPT_HSTSREADFUNCTION, hsts_read_cb);
    curl_easy_setopt(curl, CURLOPT_HSTSREADDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_URL, "https://localhost:0/");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_perform(curl);
  }

  curl_easy_cleanup(curl);
  return 0;
}
