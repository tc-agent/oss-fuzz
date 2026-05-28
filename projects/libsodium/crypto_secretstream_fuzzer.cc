// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

// Drives the secretstream API end-to-end: init_push, push (multiple
// messages with mixed tags including REKEY), then init_pull and pull,
// confirming round-trip and exercising the pull tag-decode/MAC paths.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }

  if (size < crypto_secretstream_xchacha20poly1305_KEYBYTES + 4) {
    return 0;
  }

  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  memcpy(key, data, sizeof(key));
  const uint8_t *cursor = data + sizeof(key);
  size_t remaining = size - sizeof(key);

  crypto_secretstream_xchacha20poly1305_state push_state;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  if (crypto_secretstream_xchacha20poly1305_init_push(&push_state, header,
                                                      key) != 0) {
    return 0;
  }

  // Encrypt up to 8 chunks.
  unsigned char *cts[8] = {nullptr};
  size_t cts_len[8] = {0};
  const uint8_t *pts[8] = {nullptr};
  size_t pts_len[8] = {0};
  unsigned char ad_buf[8][16];
  size_t ad_len[8] = {0};
  unsigned char tags_used[8] = {0};
  int nchunks = 0;

  while (nchunks < 8 && remaining >= 2) {
    uint8_t hdr0 = cursor[0];
    uint8_t hdr1 = cursor[1];
    cursor += 2;
    remaining -= 2;

    size_t msglen = hdr0;  // 0..255
    if (msglen > remaining) msglen = remaining;
    size_t ad = hdr1 & 0x0F;  // 0..15
    if (ad > remaining - msglen) ad = remaining - msglen;

    unsigned char tag;
    switch ((hdr1 >> 4) & 0x3) {
      case 0: tag = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE; break;
      case 1: tag = crypto_secretstream_xchacha20poly1305_TAG_PUSH; break;
      case 2: tag = crypto_secretstream_xchacha20poly1305_TAG_REKEY; break;
      default: tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL; break;
    }
    if (ad > 0) memcpy(ad_buf[nchunks], cursor, ad);
    const uint8_t *pt = cursor + ad;
    cursor += ad + msglen;
    remaining -= ad + msglen;

    unsigned char *ct = (unsigned char *)malloc(
        msglen + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long ctlen = 0;
    int err = crypto_secretstream_xchacha20poly1305_push(
        &push_state, ct, &ctlen, pt, msglen,
        ad > 0 ? ad_buf[nchunks] : nullptr, ad, tag);
    if (err != 0) {
      free(ct);
      break;
    }
    cts[nchunks] = ct;
    cts_len[nchunks] = (size_t)ctlen;
    pts[nchunks] = pt;
    pts_len[nchunks] = msglen;
    ad_len[nchunks] = ad;
    tags_used[nchunks] = tag;
    nchunks++;
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
  }

  // Decrypt.
  crypto_secretstream_xchacha20poly1305_state pull_state;
  if (crypto_secretstream_xchacha20poly1305_init_pull(&pull_state, header,
                                                      key) == 0) {
    for (int i = 0; i < nchunks; i++) {
      unsigned char *pt = (unsigned char *)malloc(pts_len[i] + 1);
      unsigned long long ptlen = 0;
      unsigned char got_tag = 0;
      int err = crypto_secretstream_xchacha20poly1305_pull(
          &pull_state, pt, &ptlen, &got_tag, cts[i], cts_len[i],
          ad_len[i] > 0 ? ad_buf[i] : nullptr, ad_len[i]);
      if (err == 0) {
        assert(ptlen == pts_len[i]);
        assert(got_tag == tags_used[i]);
        assert(memcmp(pt, pts[i], pts_len[i]) == 0);
      }
      free(pt);
    }
  }

  for (int i = 0; i < nchunks; i++) free(cts[i]);
  return 0;
}
