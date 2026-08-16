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
 * Fuzzing entry point. Exercises the cookie parser (cookie.c) via
 * CURLOPT_COOKIELIST which accepts:
 *   - HTTP Set-Cookie header format: "name=value; domain=...; path=/; secure"
 *   - Netscape format: "domain\tFALSE\tpath\tFALSE\texpiry\tname\tvalue"
 *   - Commands: "ALL", "SESS", "FLUSH", "RELOAD"
 *
 * No network activity occurs — the cookie engine parses the input in-process.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  CURL *curl;
  char *str;

  if(!size)
    return 0;

  curl = curl_easy_init();
  if(!curl)
    return 0;

  /* Enable the cookie engine without reading from any file */
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

  str = (char *)malloc(size + 1);
  if(str) {
    memcpy(str, data, size);
    str[size] = '\0';
    curl_easy_setopt(curl, CURLOPT_COOKIELIST, str);
    free(str);
  }

  /* Exercise the cookie retrieval path (Curl_cookie_list) */
  {
    struct curl_slist *cookies = NULL;
    if(curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies) == CURLE_OK)
      curl_slist_free_all(cookies);
  }

  curl_easy_cleanup(curl);
  return 0;
}
