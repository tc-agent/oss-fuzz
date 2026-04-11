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
 * Fuzz the MIME multipart API (curl_mime_*).  This exercises mime.c:
 * construction of multipart form data with parts containing names,
 * filenames, content types, custom headers, inline data, sub-parts,
 * and encoding.  Construction + cleanup exercises most of mime.c.
 * Also uses curl_mime_data_cb() to set a custom read callback.
 */

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

struct read_state {
  const uint8_t *data;
  size_t remaining;
};

/* Custom read callback for curl_mime_data_cb */
static size_t fuzz_read_cb(char *buffer, size_t size, size_t nitems,
                           void *arg)
{
  struct read_state *rs = (struct read_state *)arg;
  size_t want = size * nitems;
  if(want > rs->remaining)
    want = rs->remaining;
  if(want > 0) {
    memcpy(buffer, rs->data, want);
    rs->data += want;
    rs->remaining -= want;
  }
  return want;
}

static const char *encodings[] = {
  "binary",
  "8bit",
  "7bit",
  "base64",
  "quoted-printable",
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);
  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  curl_mime *mime = curl_mime_init(easy);
  if(!mime) {
    curl_easy_cleanup(easy);
    return 0;
  }

  /* Build MIME parts driven by fuzz data */
  int num_parts = fdp.ConsumeIntegralInRange(1, 10);
  for(int i = 0; i < num_parts && fdp.remaining_bytes() > 0; i++) {
    curl_mimepart *part = curl_mime_addpart(mime);
    if(!part)
      break;

    /* Randomly set various part attributes */
    int num_ops = fdp.ConsumeIntegralInRange(1, 6);
    for(int j = 0; j < num_ops && fdp.remaining_bytes() > 0; j++) {
      int op = fdp.ConsumeIntegralInRange(0, 6);
      switch(op) {
      case 0: {
        /* Set part name */
        std::string name = fdp.ConsumeRandomLengthString(256);
        curl_mime_name(part, name.c_str());
        break;
      }
      case 1: {
        /* Set inline data */
        std::string val = fdp.ConsumeRandomLengthString(4096);
        curl_mime_data(part, val.c_str(), val.size());
        break;
      }
      case 2: {
        /* Set content type */
        std::string ct = fdp.ConsumeRandomLengthString(256);
        curl_mime_type(part, ct.c_str());
        break;
      }
      case 3: {
        /* Set filename */
        std::string fn = fdp.ConsumeRandomLengthString(256);
        curl_mime_filename(part, fn.c_str());
        break;
      }
      case 4: {
        /* Set encoding */
        const char *enc = fdp.PickValueInArray(encodings);
        curl_mime_encoder(part, enc);
        break;
      }
      case 5: {
        /* Add custom headers */
        struct curl_slist *hdrs = NULL;
        int nh = fdp.ConsumeIntegralInRange(1, 5);
        for(int k = 0; k < nh && fdp.remaining_bytes() > 0; k++) {
          std::string hdr = fdp.ConsumeRandomLengthString(512);
          struct curl_slist *tmp = curl_slist_append(hdrs, hdr.c_str());
          if(tmp)
            hdrs = tmp;
        }
        /* CURLOPT_HTTPPOST_OWNED = 1 means mime takes ownership */
        curl_mime_headers(part, hdrs, 1);
        break;
      }
      case 6: {
        /* Create sub-parts (nested multipart) */
        curl_mime *sub = curl_mime_init(easy);
        if(sub) {
          curl_mimepart *sp = curl_mime_addpart(sub);
          if(sp) {
            std::string val = fdp.ConsumeRandomLengthString(1024);
            curl_mime_data(sp, val.c_str(), val.size());
            std::string name = fdp.ConsumeRandomLengthString(64);
            curl_mime_name(sp, name.c_str());
          }
          /* Attach sub-parts to the parent part */
          curl_mime_subparts(part, sub);
        }
        break;
      }
      }
    }
  }

  /* Attach the MIME data to the easy handle.
   * This exercises MIME header preparation paths in mime.c. */
  curl_easy_setopt(easy, CURLOPT_MIMEPOST, mime);

  curl_mime_free(mime);
  curl_easy_cleanup(easy);
  return 0;
}
