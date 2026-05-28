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

#include "fake_random.h"

// Sealed box (anonymous public-key encryption) round-trip, plus a pass that
// feeds attacker-controlled bytes into crypto_box_seal_open to exercise the
// deserialization / MAC paths on malformed inputs.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  if (size < crypto_box_SEEDBYTES + 1) {
    return 0;
  }

  setup_fake_random(data, size);

  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  crypto_box_seed_keypair(pk, sk, data);

  const uint8_t *msg = data + crypto_box_SEEDBYTES;
  size_t msglen = size - crypto_box_SEEDBYTES;
  if (msglen > 4096) msglen = 4096;

  // Round-trip
  unsigned char *ct = (unsigned char *)malloc(msglen + crypto_box_SEALBYTES);
  int err = crypto_box_seal(ct, msg, msglen, pk);
  if (err == 0) {
    unsigned char *pt = (unsigned char *)malloc(msglen + 1);
    err = crypto_box_seal_open(pt, ct, msglen + crypto_box_SEALBYTES, pk, sk);
    if (err == 0) {
      assert(memcmp(pt, msg, msglen) == 0);
    }
    free(pt);
  }
  free(ct);

  // Negative path: treat the input itself as a sealed ciphertext.
  if (size > crypto_box_SEALBYTES) {
    size_t cap = size > 4096 + crypto_box_SEALBYTES
                     ? 4096 + crypto_box_SEALBYTES
                     : size;
    unsigned char *pt = (unsigned char *)malloc(cap);
    crypto_box_seal_open(pt, data, cap, pk, sk);
    free(pt);
  }

  return 0;
}
