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

// Exercises crypto_box_curve25519xchacha20poly1305 and
// crypto_secretbox_xchacha20poly1305 — variants of the box/secretbox APIs
// that wrap the chacha20-poly1305 AEAD instead of the salsa20 default.

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  if (sodium_init() == -1) return 0;
  if (size < crypto_box_curve25519xchacha20poly1305_SEEDBYTES +
                 crypto_box_curve25519xchacha20poly1305_NONCEBYTES + 1) {
    return 0;
  }

  setup_fake_random(data, size);

  const unsigned char *seed = data;
  const unsigned char *nonce =
      data + crypto_box_curve25519xchacha20poly1305_SEEDBYTES;
  const unsigned char *msg =
      nonce + crypto_box_curve25519xchacha20poly1305_NONCEBYTES;
  size_t msglen =
      size - crypto_box_curve25519xchacha20poly1305_SEEDBYTES -
      crypto_box_curve25519xchacha20poly1305_NONCEBYTES;

  // crypto_box xchacha20poly1305 round-trip
  unsigned char pk1[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
  unsigned char sk1[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
  unsigned char pk2[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
  unsigned char sk2[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
  crypto_box_curve25519xchacha20poly1305_seed_keypair(pk1, sk1, seed);
  crypto_box_curve25519xchacha20poly1305_keypair(pk2, sk2);

  unsigned char *ct = (unsigned char *)malloc(
      msglen + crypto_box_curve25519xchacha20poly1305_MACBYTES);
  int e = crypto_box_curve25519xchacha20poly1305_easy(ct, msg, msglen, nonce,
                                                      pk2, sk1);
  assert(e == 0);
  unsigned char *pt = (unsigned char *)malloc(msglen ? msglen : 1);
  e = crypto_box_curve25519xchacha20poly1305_open_easy(
      pt, ct, msglen + crypto_box_curve25519xchacha20poly1305_MACBYTES, nonce,
      pk1, sk2);
  assert(e == 0);
  free(ct);
  free(pt);

  // sealed box variant
  unsigned char *sct = (unsigned char *)malloc(
      msglen + crypto_box_curve25519xchacha20poly1305_SEALBYTES);
  e = crypto_box_curve25519xchacha20poly1305_seal(sct, msg, msglen, pk1);
  assert(e == 0);
  unsigned char *spt = (unsigned char *)malloc(msglen ? msglen : 1);
  crypto_box_curve25519xchacha20poly1305_seal_open(
      spt, sct, msglen + crypto_box_curve25519xchacha20poly1305_SEALBYTES,
      pk1, sk1);
  free(sct);
  free(spt);

  // crypto_secretbox_xchacha20poly1305 round-trip
  unsigned char skey[crypto_secretbox_xchacha20poly1305_KEYBYTES];
  unsigned char snonce[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
  randombytes_buf(skey, sizeof skey);
  randombytes_buf(snonce, sizeof snonce);
  size_t sct_len = msglen + crypto_secretbox_xchacha20poly1305_MACBYTES;
  unsigned char *sct2 = (unsigned char *)malloc(sct_len);
  crypto_secretbox_xchacha20poly1305_easy(sct2, msg, msglen, snonce, skey);
  unsigned char *spt2 = (unsigned char *)malloc(msglen ? msglen : 1);
  e = crypto_secretbox_xchacha20poly1305_open_easy(spt2, sct2, sct_len,
                                                   snonce, skey);
  assert(e == 0);
  free(sct2);
  free(spt2);

  return 0;
}
