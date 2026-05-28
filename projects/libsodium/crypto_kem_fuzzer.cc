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
#include <string.h>

#include <sodium.h>

#include "fake_random.h"

// Fuzzes the KEM primitives shipped in libsodium: ML-KEM-768 and X-Wing.
// Two modes per primitive:
//   - happy path: derive keypair from fuzzer seed, encapsulate, decapsulate,
//     verify shared secret matches;
//   - mauled-ciphertext path: keep a valid keypair, feed attacker-controlled
//     bytes as the ciphertext to dec() to exercise decoding and the
//     implicit-rejection branch.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  if (size < 1 + crypto_kem_mlkem768_SEEDBYTES) {
    return 0;
  }

  setup_fake_random(data, size);

  uint8_t selector = data[0];
  const uint8_t *seed = data + 1;
  const uint8_t *rest = data + 1 + crypto_kem_mlkem768_SEEDBYTES;
  size_t restlen = size - 1 - crypto_kem_mlkem768_SEEDBYTES;

  if ((selector >> 1) & 1) {
    // ML-KEM-768
    unsigned char pk[crypto_kem_mlkem768_PUBLICKEYBYTES];
    unsigned char sk[crypto_kem_mlkem768_SECRETKEYBYTES];
    if (crypto_kem_mlkem768_seed_keypair(pk, sk, seed) != 0) return 0;

    unsigned char ct[crypto_kem_mlkem768_CIPHERTEXTBYTES];
    unsigned char ss[crypto_kem_mlkem768_SHAREDSECRETBYTES];
    // mlkem768 enc_deterministic takes a 32-byte randomness; constant isn't
    // exposed so reference the literal from the header.
    if ((selector & 1) == 0 && restlen >= 32) {
      crypto_kem_mlkem768_enc_deterministic(ct, ss, pk, rest);
    } else {
      crypto_kem_mlkem768_enc(ct, ss, pk);
    }

    unsigned char ss2[crypto_kem_mlkem768_SHAREDSECRETBYTES];
    int rc = crypto_kem_mlkem768_dec(ss2, ct, sk);
    assert(rc == 0);
    assert(memcmp(ss, ss2, sizeof(ss)) == 0);

    // Mauled-ct path: build a ciphertext from the fuzzer body so the
    // decapsulator runs on attacker-controlled bytes.
    if (restlen >= crypto_kem_mlkem768_CIPHERTEXTBYTES) {
      unsigned char ctm[crypto_kem_mlkem768_CIPHERTEXTBYTES];
      memcpy(ctm, rest, sizeof(ctm));
      crypto_kem_mlkem768_dec(ss2, ctm, sk);
    }
  } else {
    // X-Wing
    if (size < 1 + crypto_kem_xwing_SEEDBYTES) return 0;
    unsigned char pk[crypto_kem_xwing_PUBLICKEYBYTES];
    unsigned char sk[crypto_kem_xwing_SECRETKEYBYTES];
    if (crypto_kem_xwing_seed_keypair(pk, sk, seed) != 0) return 0;

    unsigned char ct[crypto_kem_xwing_CIPHERTEXTBYTES];
    unsigned char ss[crypto_kem_xwing_SHAREDSECRETBYTES];
    // xwing enc_deterministic takes a 64-byte seed (32 mlkem + 32 x25519);
    // not exposed as a constant, so reference the literal from the header.
    if ((selector & 1) == 0 && restlen >= 64) {
      crypto_kem_xwing_enc_deterministic(ct, ss, pk, rest);
    } else {
      crypto_kem_xwing_enc(ct, ss, pk);
    }

    unsigned char ss2[crypto_kem_xwing_SHAREDSECRETBYTES];
    int rc = crypto_kem_xwing_dec(ss2, ct, sk);
    assert(rc == 0);
    assert(memcmp(ss, ss2, sizeof(ss)) == 0);

    if (restlen >= crypto_kem_xwing_CIPHERTEXTBYTES) {
      unsigned char ctm[crypto_kem_xwing_CIPHERTEXTBYTES];
      memcpy(ctm, rest, sizeof(ctm));
      crypto_kem_xwing_dec(ss2, ctm, sk);
    }
  }

  return 0;
}
