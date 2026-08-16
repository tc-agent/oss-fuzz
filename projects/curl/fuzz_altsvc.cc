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
 * Fuzzing entry point. Exercises the Alt-Svc cache parser (altsvc.c) by
 * writing fuzzer input to a temp file and loading it via CURLOPT_ALTSVC.
 *
 * Alt-Svc cache file format (one entry per line):
 *   h2 src.example.com 443 h3 dst.example.com 8443 "20391231 10:00:00" 1 0
 *   Fields: src-alpn src-host src-port dst-alpn dst-host dst-port expiry persist prio
 *
 * CURLOPT_ALTSVC_CTRL must be set to enable the Alt-Svc engine; the
 * CURLALTSVC_H1/H2/H3 bits control which protocols are accepted.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  CURL *curl;
  char tmpfile[] = "/tmp/fuzz_altsvc_XXXXXX";
  int fd;
  FILE *fp;
  long ctrl_flags;

  if(!size)
    return 0;

  curl = curl_easy_init();
  if(!curl)
    return 0;

  /* Enable Alt-Svc; vary accepted ALPNs based on fuzzer input */
  ctrl_flags = CURLALTSVC_H1;
  if(data[0] & 0x01)
    ctrl_flags |= CURLALTSVC_H2;
  if(data[0] & 0x02)
    ctrl_flags |= CURLALTSVC_H3;

  curl_easy_setopt(curl, CURLOPT_ALTSVC_CTRL, ctrl_flags);

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
  fwrite(data + 1, 1, size > 1 ? size - 1 : 0, fp);
  fclose(fp);

  curl_easy_setopt(curl, CURLOPT_ALTSVC, tmpfile);
  /* CURLALTSVC_READONLYFILE so it doesn't try to write back on cleanup */
  curl_easy_setopt(curl, CURLOPT_ALTSVC_CTRL,
                   ctrl_flags | CURLALTSVC_READONLYFILE);

  /* A request triggers Alt-Svc cache load during connection setup */
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:0/");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1L);
  curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
  curl_easy_perform(curl);

  curl_easy_cleanup(curl);
  unlink(tmpfile);
  return 0;
}
