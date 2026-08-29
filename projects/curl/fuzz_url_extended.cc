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
 * Fuzz the CURLU URL API with all operations: set full URL with various
 * flags, get individual parts, set individual parts, and round-trip.
 * The existing fuzz_url.cc only calls curl_url_set(CURLUPART_URL) with
 * CURLU_GUESS_SCHEME.  This exercises the much larger surface:
 *   - Multiple flag combinations for curl_url_set
 *   - curl_url_get for every part
 *   - Setting individual URL parts (scheme, host, path, query, etc.)
 *   - curl_url_dup
 */

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

/* All CURLUPart values we can set/get */
static const CURLUPart url_parts[] = {
  CURLUPART_URL,
  CURLUPART_SCHEME,
  CURLUPART_USER,
  CURLUPART_PASSWORD,
  CURLUPART_OPTIONS,
  CURLUPART_HOST,
  CURLUPART_PORT,
  CURLUPART_PATH,
  CURLUPART_QUERY,
  CURLUPART_FRAGMENT,
  CURLUPART_ZONEID,
};

/* Flag bits for curl_url_set */
static const unsigned int set_flags[] = {
  0,
  CURLU_DEFAULT_PORT,
  CURLU_NO_DEFAULT_PORT,
  CURLU_DEFAULT_SCHEME,
  CURLU_NON_SUPPORT_SCHEME,
  CURLU_PATH_AS_IS,
  CURLU_DISALLOW_USER,
  CURLU_URLDECODE,
  CURLU_URLENCODE,
  CURLU_APPENDQUERY,
  CURLU_GUESS_SCHEME,
  CURLU_NO_AUTHORITY,
  CURLU_PUNYCODE,
  CURLU_PUNY2IDN,
};

/* Flag bits for curl_url_get */
static const unsigned int get_flags[] = {
  0,
  CURLU_DEFAULT_PORT,
  CURLU_NO_DEFAULT_PORT,
  CURLU_DEFAULT_SCHEME,
  CURLU_URLDECODE,
  CURLU_URLENCODE,
  CURLU_PUNYCODE,
  CURLU_PUNY2IDN,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);
  CURLU *uh = curl_url();
  if(!uh)
    return 0;

  /* First, set a full URL with fuzzed flags */
  {
    std::string url = fdp.ConsumeRandomLengthString(4096);
    unsigned int flags = 0;
    int num_flags = fdp.ConsumeIntegralInRange(0, 4);
    for(int i = 0; i < num_flags; i++) {
      flags |= fdp.PickValueInArray(set_flags);
    }
    curl_url_set(uh, CURLUPART_URL, url.c_str(), flags);
  }

  /* Now perform a series of get/set/dup operations driven by fuzz data */
  int ops = fdp.ConsumeIntegralInRange(0, 20);
  for(int i = 0; i < ops && fdp.remaining_bytes() > 0; i++) {
    int op = fdp.ConsumeIntegralInRange(0, 3);
    switch(op) {
    case 0: {
      /* curl_url_get */
      CURLUPart part = fdp.PickValueInArray(url_parts);
      unsigned int flags = 0;
      int nf = fdp.ConsumeIntegralInRange(0, 3);
      for(int j = 0; j < nf; j++)
        flags |= fdp.PickValueInArray(get_flags);
      char *out = NULL;
      CURLUcode rc = curl_url_get(uh, part, &out, flags);
      if(rc == CURLUE_OK)
        curl_free(out);
      break;
    }
    case 1: {
      /* curl_url_set with individual part */
      CURLUPart part = fdp.PickValueInArray(url_parts);
      std::string val = fdp.ConsumeRandomLengthString(1024);
      unsigned int flags = 0;
      int nf = fdp.ConsumeIntegralInRange(0, 3);
      for(int j = 0; j < nf; j++)
        flags |= fdp.PickValueInArray(set_flags);
      curl_url_set(uh, part, val.c_str(), flags);
      break;
    }
    case 2: {
      /* curl_url_dup */
      CURLU *dup = curl_url_dup(uh);
      if(dup) {
        /* Get full URL from the dup to exercise serialization */
        char *out = NULL;
        curl_url_get(dup, CURLUPART_URL, &out, 0);
        curl_free(out);
        curl_url_cleanup(dup);
      }
      break;
    }
    case 3: {
      /* Set part to NULL (clear) */
      CURLUPart part = fdp.PickValueInArray(url_parts);
      curl_url_set(uh, part, NULL, 0);
      break;
    }
    }
  }

  /* Final round-trip: get the full URL back */
  {
    char *out = NULL;
    curl_url_get(uh, CURLUPART_URL, &out, 0);
    curl_free(out);
  }

  curl_url_cleanup(uh);
  return 0;
}
