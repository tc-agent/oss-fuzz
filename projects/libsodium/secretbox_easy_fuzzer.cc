// Copyright 2018 Google Inc.
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
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  int initialized = sodium_init();
  assert(initialized >= 0);

  setup_fake_random(data, size);

  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  // these use a deterministic generator
  crypto_secretbox_keygen(key);
  randombytes_buf(nonce, sizeof nonce);

  // _easy round-trip
  {
    size_t ciphertext_len = crypto_secretbox_MACBYTES + size;
    unsigned char *ciphertext = (unsigned char *) malloc(ciphertext_len);
    crypto_secretbox_easy(ciphertext, data, size, nonce, key);
    unsigned char *decrypted = (unsigned char *) malloc(size);
    int err = crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len,
                                         nonce, key);
    assert(err == 0);
    free(ciphertext);
    free(decrypted);
  }

  // _detached round-trip exercises crypto_secretbox_detached / _open_detached
  {
    unsigned char *ct = (unsigned char *) malloc(size ? size : 1);
    unsigned char mac[crypto_secretbox_MACBYTES];
    crypto_secretbox_detached(ct, mac, data, size, nonce, key);
    unsigned char *pt = (unsigned char *) malloc(size ? size : 1);
    int err = crypto_secretbox_open_detached(pt, ct, mac, size, nonce, key);
    assert(err == 0);
    if (size > 0) assert(memcmp(pt, data, size) == 0);
    free(ct);
    free(pt);
  }

  // Original zero-prepad API: routes through crypto_secretbox.c and
  // secretbox_xsalsa20poly1305.c, paths the _easy variants don't cover.
  {
    size_t mlen = size + crypto_secretbox_ZEROBYTES;
    unsigned char *m = (unsigned char *) malloc(mlen);
    memset(m, 0, crypto_secretbox_ZEROBYTES);
    memcpy(m + crypto_secretbox_ZEROBYTES, data, size);
    unsigned char *c = (unsigned char *) malloc(mlen);
    crypto_secretbox(c, m, mlen, nonce, key);
    unsigned char *m_back = (unsigned char *) malloc(mlen);
    int err = crypto_secretbox_open(m_back, c, mlen, nonce, key);
    assert(err == 0);
    assert(memcmp(m_back, m, mlen) == 0);
    free(m);
    free(c);
    free(m_back);
  }

  return 0;
}
