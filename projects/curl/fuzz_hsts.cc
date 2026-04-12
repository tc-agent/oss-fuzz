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
 * Fuzz the HSTS cache parser via CURLOPT_HSTSREADFUNCTION.
 * This exercises hsts.c: parsing of HSTS entries including
 * hostnames, max-age, includeSubDomains, and expiry timestamps.
 * Also tests the HSTS write callback for round-trip coverage.
 */

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

struct fuzz_hsts_state {
  FuzzedDataProvider *fdp;
  int entries_remaining;
};

/* Callback that feeds HSTS entries from fuzz data */
static CURLSTScode hsts_read_cb(CURL *easy, struct curl_hstsentry *e,
                                void *userp)
{
  (void)easy;
  struct fuzz_hsts_state *state = (struct fuzz_hsts_state *)userp;

  if(state->entries_remaining <= 0 || state->fdp->remaining_bytes() < 4)
    return CURLSTS_DONE;

  state->entries_remaining--;

  /* Generate a hostname */
  std::string host = state->fdp->ConsumeRandomLengthString(255);
  if(host.empty())
    return CURLSTS_DONE;

  size_t copy_len = host.size();
  if(copy_len >= sizeof(e->name))
    copy_len = sizeof(e->name) - 1;
  memcpy(e->name, host.c_str(), copy_len);
  e->name[copy_len] = '\0';
  e->namelen = copy_len;

  e->includeSubDomains = state->fdp->ConsumeBool();

  /* Generate expiry date string: "YYYYMMDD HH:MM:SS" */
  std::string expire = state->fdp->ConsumeRandomLengthString(18);
  size_t exp_len = expire.size();
  if(exp_len >= sizeof(e->expire))
    exp_len = sizeof(e->expire) - 1;
  memcpy(e->expire, expire.c_str(), exp_len);
  e->expire[exp_len] = '\0';

  return CURLSTS_OK;
}

/* Write callback to exercise serialization path */
static CURLSTScode hsts_write_cb(CURL *easy, struct curl_hstsentry *e,
                                 struct curl_index *i, void *userp)
{
  (void)easy;
  (void)e;
  (void)i;
  (void)userp;
  return CURLSTS_OK;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);
  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  struct fuzz_hsts_state state;
  state.fdp = &fdp;
  state.entries_remaining = fdp.ConsumeIntegralInRange(1, 50);

  /* Enable HSTS */
  curl_easy_setopt(easy, CURLOPT_HSTS_CTRL, (long)CURLHSTS_ENABLE);

  /* Set the read callback to feed HSTS entries */
  curl_easy_setopt(easy, CURLOPT_HSTSREADFUNCTION, hsts_read_cb);
  curl_easy_setopt(easy, CURLOPT_HSTSREADDATA, &state);

  /* Set the write callback to exercise serialization */
  curl_easy_setopt(easy, CURLOPT_HSTSWRITEFUNCTION, hsts_write_cb);
  curl_easy_setopt(easy, CURLOPT_HSTSWRITEDATA, &state);

  /* Set a URL - this triggers HSTS loading via the read callback */
  std::string url = "https://" + fdp.ConsumeRandomLengthString(256) + "/";
  curl_easy_setopt(easy, CURLOPT_URL, url.c_str());

  /* The HSTS cache is loaded when we set a URL or do a transfer.
   * Force loading by setting HSTS file to empty and performing setopt. */
  curl_easy_setopt(easy, CURLOPT_HSTS, "");

  curl_easy_cleanup(easy);
  return 0;
}
