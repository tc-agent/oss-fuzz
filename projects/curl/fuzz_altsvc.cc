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
 * Fuzz the Alt-Svc cache parser via CURLOPT_ALTSVC.  This exercises
 * altsvc.c: parsing of alt-svc cache files with entries like
 * "h2 host port h3 host port YYYYMMDD HH:MM:SS".
 * Also tests the CURLOPT_ALTSVC_CTRL control flags.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);

  /* Write fuzz data to a temporary alt-svc cache file */
  char tmpfile[] = "/tmp/fuzz_altsvc_XXXXXX";
  int fd = mkstemp(tmpfile);
  if(fd < 0)
    return 0;

  std::string content = fdp.ConsumeRandomLengthString(8192);
  ssize_t written = write(fd, content.c_str(), content.size());
  close(fd);
  if(written < 0) {
    unlink(tmpfile);
    return 0;
  }

  CURL *easy = curl_easy_init();
  if(!easy) {
    unlink(tmpfile);
    return 0;
  }

  /* Enable alt-svc with various flag combinations */
  long ctrl = CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3;
  if(fdp.remaining_bytes() > 0) {
    int flags = fdp.ConsumeIntegralInRange(0, 7);
    ctrl = 0;
    if(flags & 1) ctrl |= CURLALTSVC_H1;
    if(flags & 2) ctrl |= CURLALTSVC_H2;
    if(flags & 4) ctrl |= CURLALTSVC_H3;
  }
  curl_easy_setopt(easy, CURLOPT_ALTSVC_CTRL, ctrl);

  /* Load the alt-svc cache file - this exercises the parser */
  curl_easy_setopt(easy, CURLOPT_ALTSVC, tmpfile);

  /* Set a URL to test alt-svc lookup */
  if(fdp.remaining_bytes() > 0) {
    std::string url = "https://" + fdp.ConsumeRandomLengthString(256) + "/";
    curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
  }

  curl_easy_cleanup(easy);
  unlink(tmpfile);
  return 0;
}
