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
#include <curl/curl.h>

/**
 * Fuzzing entry point. Exercises the URL percent-encoding functions
 * (escape.c) via curl_easy_escape() and curl_easy_unescape().
 *
 * Input layout: [1 byte selector] [data...]
 *   selector bit 0: 0 = escape, 1 = unescape
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  CURL *curl;
  char *result;

  if(size < 1)
    return 0;

  curl = curl_easy_init();
  if(!curl)
    return 0;

  if(data[0] & 1) {
    int outlen;
    result = curl_easy_unescape(curl,
                                (const char *)(data + 1),
                                (int)(size - 1),
                                &outlen);
  }
  else {
    result = curl_easy_escape(curl,
                              (const char *)(data + 1),
                              (int)(size - 1));
  }

  if(result)
    curl_free(result);

  curl_easy_cleanup(curl);
  return 0;
}
