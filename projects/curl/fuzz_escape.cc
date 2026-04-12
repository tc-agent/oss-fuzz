/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Anthropic, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * Fuzz curl_easy_escape() and curl_easy_unescape() - URL percent-encoding
 * and decoding.  Also exercises the round-trip: encode then decode.
 */

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);
  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  std::string input = fdp.ConsumeRemainingBytesAsString();
  int inlen = (int)input.size();

  /* Test escaping */
  char *escaped = curl_easy_escape(easy, input.c_str(), inlen);
  if(escaped) {
    /* Test unescaping the escaped string (round-trip) */
    int outlen = 0;
    char *unescaped = curl_easy_unescape(easy, escaped, 0, &outlen);
    curl_free(unescaped);
    curl_free(escaped);
  }

  /* Test unescaping raw fuzz input (may contain arbitrary %XX sequences) */
  {
    int outlen = 0;
    char *unescaped = curl_easy_unescape(easy, input.c_str(), inlen, &outlen);
    curl_free(unescaped);
  }

  curl_easy_cleanup(easy);
  return 0;
}
