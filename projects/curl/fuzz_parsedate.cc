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
 * Fuzz curl_getdate() - the date string parser used by HTTP cookies,
 * If-Modified-Since, and other date headers.  This is a standalone
 * parser that takes a C string and returns a time_t.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* curl_getdate needs a null-terminated string */
  char *str = (char *)malloc(size + 1);
  if(!str)
    return 0;

  memcpy(str, data, size);
  str[size] = '\0';

  /* Exercise the date parser */
  curl_getdate(str, NULL);

  free(str);
  return 0;
}
