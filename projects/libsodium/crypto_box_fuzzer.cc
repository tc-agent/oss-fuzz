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
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  int initialized = sodium_init();
  assert(initialized >= 0);

  if (size < crypto_box_SEEDBYTES + crypto_box_NONCEBYTES) {
    return 0;
  }

  setup_fake_random(data, size);

  unsigned char pk1[crypto_box_PUBLICKEYBYTES];
  unsigned char sk1[crypto_box_SECRETKEYBYTES];
  unsigned char pk2[crypto_box_PUBLICKEYBYTES];
  unsigned char sk2[crypto_box_SECRETKEYBYTES];

  const unsigned char *seed1 = data;
  const unsigned char *nonce = data + crypto_box_SEEDBYTES;
  const unsigned char *msg = nonce + crypto_box_NONCEBYTES;
  size_t msg_len = size - (crypto_box_SEEDBYTES + crypto_box_NONCEBYTES);

  // Generate keypairs. Using seed for the first one to be more deterministic from input.
  crypto_box_seed_keypair(pk1, sk1, seed1);
  // Second keypair can be generated normally, but randombytes is hooked so it's also deterministic.
  crypto_box_keypair(pk2, sk2);

  unsigned char *ciphertext = (unsigned char *) malloc(msg_len + crypto_box_MACBYTES);
  int err = crypto_box_easy(ciphertext, msg, msg_len, nonce, pk2, sk1);
  assert(err == 0);

  unsigned char *decrypted = (unsigned char *) malloc(msg_len);
  err = crypto_box_open_easy(decrypted, ciphertext, msg_len + crypto_box_MACBYTES, nonce, pk1, sk2);
  assert(err == 0);
  assert(memcmp(decrypted, msg, msg_len) == 0);

  free(ciphertext);
  free(decrypted);

  // Original zero-prepad API routes through box_curve25519xsalsa20poly1305.c,
  // which the _easy variants delegate around.
  {
    size_t mlen = msg_len + crypto_box_ZEROBYTES;
    unsigned char *m = (unsigned char *) malloc(mlen);
    memset(m, 0, crypto_box_ZEROBYTES);
    memcpy(m + crypto_box_ZEROBYTES, msg, msg_len);
    unsigned char *c = (unsigned char *) malloc(mlen);
    int e = crypto_box(c, m, mlen, nonce, pk2, sk1);
    assert(e == 0);
    unsigned char *m_back = (unsigned char *) malloc(mlen);
    e = crypto_box_open(m_back, c, mlen, nonce, pk1, sk2);
    assert(e == 0);
    assert(memcmp(m_back, m, mlen) == 0);
    free(m);
    free(c);
    free(m_back);
  }

  // Precomputed (afternm) API hits crypto_box_beforenm + the _afternm paths.
  {
    unsigned char k[crypto_box_BEFORENMBYTES];
    int e = crypto_box_beforenm(k, pk2, sk1);
    assert(e == 0);
    unsigned char *ct = (unsigned char *) malloc(msg_len + crypto_box_MACBYTES);
    e = crypto_box_easy_afternm(ct, msg, msg_len, nonce, k);
    assert(e == 0);
    unsigned char k2[crypto_box_BEFORENMBYTES];
    e = crypto_box_beforenm(k2, pk1, sk2);
    assert(e == 0);
    unsigned char *pt = (unsigned char *) malloc(msg_len ? msg_len : 1);
    e = crypto_box_open_easy_afternm(pt, ct, msg_len + crypto_box_MACBYTES,
                                     nonce, k2);
    assert(e == 0);
    free(ct);
    free(pt);
  }

  return 0;
}
