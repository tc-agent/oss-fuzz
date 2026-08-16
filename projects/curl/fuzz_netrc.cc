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

/**
 * Fuzzing entry point. Exercises the .netrc parser (netrc.c) by writing
 * fuzzer input to a temp file, pointing curl at it, and performing a
 * request to localhost (which will fail, but netrc parsing happens before
 * the connection attempt).
 *
 * The netrc file format looks like:
 *   machine hostname login user password pass
 *   default login user password pass
 *   macdef scriptname ...
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  CURL *curl;
  char tmpfile[] = "/tmp/fuzz_netrc_XXXXXX";
  int fd;
  FILE *fp;

  if(!size)
    return 0;

  /* Write fuzzer input to a temp file as the netrc content */
  fd = mkstemp(tmpfile);
  if(fd < 0)
    return 0;

  fp = fdopen(fd, "wb");
  if(!fp) {
    close(fd);
    unlink(tmpfile);
    return 0;
  }
  fwrite(data, 1, size, fp);
  fclose(fp);

  curl = curl_easy_init();
  if(!curl) {
    unlink(tmpfile);
    return 0;
  }

  /* Tell curl to use the temp file as the netrc file */
  curl_easy_setopt(curl, CURLOPT_NETRC, (long)CURL_NETRC_OPTIONAL);
  curl_easy_setopt(curl, CURLOPT_NETRC_FILE, tmpfile);
  /* Use a URL without embedded credentials so netrc lookup is triggered */
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:0/");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1L);
  /* Suppress output */
  curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

  /* Perform request — will fail (no server), but netrc.c is exercised
   * during connection setup before any network I/O. */
  curl_easy_perform(curl);

  curl_easy_cleanup(curl);
  unlink(tmpfile);
  return 0;
}
