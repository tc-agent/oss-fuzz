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

static const char *encodings[] = {
  NULL, "base64", "quoted-printable", "8bit", "7bit", "binary"
};
static const char *mimetypes[] = {
  NULL, "text/plain", "application/octet-stream", "image/png",
  "multipart/mixed", "application/json"
};

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

/**
 * Fuzzing entry point. Exercises the MIME multipart construction API
 * (mime.c) including curl_mime_init(), curl_mime_addpart(), and the
 * various part-configuration functions.
 *
 * Input layout: [1 byte flags] [data...] where flags encodes options.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  CURL *curl;
  curl_mime *mime;
  curl_mimepart *part;
  char *str;
  int use_subparts;

  if(size < 2)
    return 0;

  curl = curl_easy_init();
  if(!curl)
    return 0;

  use_subparts = data[0] & 1;

  /* Null-terminate the payload for use as strings */
  str = (char *)malloc(size);
  if(!str) {
    curl_easy_cleanup(curl);
    return 0;
  }
  memcpy(str, data + 1, size - 1);
  str[size - 1] = '\0';

  mime = curl_mime_init(curl);
  if(!mime) {
    free(str);
    curl_easy_cleanup(curl);
    return 0;
  }

  /* Add a primary part with data from fuzzer input */
  part = curl_mime_addpart(mime);
  if(part) {
    curl_mime_name(part, "field1");
    curl_mime_data(part, str, size - 1);
    curl_mime_type(part, mimetypes[(data[0] >> 1) % 6]);
    curl_mime_encoder(part, encodings[(data[0] >> 3) % 6]);
    if(size > 2)
      curl_mime_filename(part, str);
  }

  /* Add a second part with custom headers */
  part = curl_mime_addpart(mime);
  if(part) {
    struct curl_slist *hdrs = NULL;
    curl_mime_name(part, "field2");
    curl_mime_data(part, (const char *)(data + 1), size - 1);
    hdrs = curl_slist_append(hdrs, "Content-Disposition: form-data");
    if(hdrs) {
      curl_mime_headers(part, hdrs, 1);
    }
  }

  /* Optionally add a nested multipart subpart */
  if(use_subparts && size > 4) {
    curl_mime *sub = curl_mime_init(curl);
    if(sub) {
      curl_mimepart *subpart = curl_mime_addpart(sub);
      if(subpart) {
        curl_mime_name(subpart, "subfield");
        curl_mime_data(subpart, str, size > 10 ? 10 : size - 1);
      }
      part = curl_mime_addpart(mime);
      if(part)
        curl_mime_subparts(part, sub);
      else
        curl_mime_free(sub);
    }
  }

  /* Attach mime to easy handle. The perform() fails (no server at localhost:0)
   * but exercises MIME attachment setup and content-length calculation. */
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:0/");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_perform(curl);

  /* Per libcurl docs, do not free the mime handle until after cleanup. */
  curl_easy_cleanup(curl);
  curl_mime_free(mime);
  free(str);
  return 0;
}
