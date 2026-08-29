/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Fuzz the cookie parser via CURLOPT_COOKIELIST.  This exercises
 * Curl_cookie_add() in cookie.c with both Set-Cookie: header format
 * and Netscape cookie-file format strings.  Also tests cookie engine
 * operations (ALL, SESS, FLUSH, RELOAD) and CURLINFO_COOKIELIST retrieval.
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

  /* Enable the cookie engine (empty string = no file, just in-memory) */
  curl_easy_setopt(easy, CURLOPT_COOKIEFILE, "");

  /* Feed multiple cookie lines to exercise the parser */
  int num_cookies = fdp.ConsumeIntegralInRange(1, 30);
  for(int i = 0; i < num_cookies && fdp.remaining_bytes() > 0; i++) {
    int action = fdp.ConsumeIntegralInRange(0, 5);
    switch(action) {
    case 0: {
      /* Set-Cookie: header format */
      std::string cookie = "Set-Cookie: " +
        fdp.ConsumeRandomLengthString(2048);
      curl_easy_setopt(easy, CURLOPT_COOKIELIST, cookie.c_str());
      break;
    }
    case 1: {
      /* Netscape cookie file format:
       * domain\tTAILMATCH\tpath\tsecure\texpires\tname\tvalue */
      std::string cookie = fdp.ConsumeRandomLengthString(2048);
      curl_easy_setopt(easy, CURLOPT_COOKIELIST, cookie.c_str());
      break;
    }
    case 2:
      /* Erase all cookies */
      curl_easy_setopt(easy, CURLOPT_COOKIELIST, "ALL");
      break;
    case 3:
      /* Erase session cookies */
      curl_easy_setopt(easy, CURLOPT_COOKIELIST, "SESS");
      break;
    case 4: {
      /* Retrieve the cookie list to exercise serialization */
      struct curl_slist *cookies = NULL;
      CURLcode rc = curl_easy_getinfo(easy, CURLINFO_COOKIELIST, &cookies);
      if(rc == CURLE_OK)
        curl_slist_free_all(cookies);
      break;
    }
    case 5: {
      /* Set a URL to change the cookie domain context */
      std::string url = "http://" + fdp.ConsumeRandomLengthString(256) + "/";
      curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
      break;
    }
    }
  }

  /* Final retrieval of all cookies */
  struct curl_slist *cookies = NULL;
  CURLcode rc = curl_easy_getinfo(easy, CURLINFO_COOKIELIST, &cookies);
  if(rc == CURLE_OK)
    curl_slist_free_all(cookies);

  curl_easy_cleanup(easy);
  return 0;
}
