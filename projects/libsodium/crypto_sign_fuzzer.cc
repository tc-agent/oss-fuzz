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

  if (size < crypto_sign_SEEDBYTES) {
    return 0;
  }

  setup_fake_random(data, size);

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  const unsigned char *seed = data;
  const unsigned char *msg = data + crypto_sign_SEEDBYTES;
  size_t msg_len = size - crypto_sign_SEEDBYTES;

  crypto_sign_seed_keypair(pk, sk, seed);

  unsigned char *sig = (unsigned char *) malloc(crypto_sign_BYTES);
  unsigned long long sig_len;
  int err = crypto_sign_detached(sig, &sig_len, msg, msg_len, sk);
  assert(err == 0);
  assert(sig_len == crypto_sign_BYTES);

  err = crypto_sign_verify_detached(sig, msg, msg_len, pk);
  assert(err == 0);

  // Test multi-part signature
  crypto_sign_state state;
  crypto_sign_init(&state);
  crypto_sign_update(&state, msg, msg_len / 2);
  crypto_sign_update(&state, msg + msg_len / 2, msg_len - msg_len / 2);
  unsigned char sig2[crypto_sign_BYTES];
  err = crypto_sign_final_create(&state, sig2, &sig_len, sk);
  assert(err == 0);

  // For verification, we need a new state or re-initialized state
  crypto_sign_init(&state);
  crypto_sign_update(&state, msg, msg_len / 2);
  crypto_sign_update(&state, msg + msg_len / 2, msg_len - msg_len / 2);
  err = crypto_sign_final_verify(&state, sig2, pk);
  assert(err == 0);

  free(sig);

  // Ed25519ph (pre-hash): streaming sign + verify
  crypto_sign_ed25519ph_state ph_state;
  crypto_sign_ed25519ph_init(&ph_state);
  if (msg_len > 0) {
    crypto_sign_ed25519ph_update(&ph_state, msg, msg_len / 2);
    crypto_sign_ed25519ph_update(&ph_state, msg + msg_len / 2,
                                 msg_len - msg_len / 2);
  }
  unsigned char sig3[crypto_sign_BYTES];
  unsigned long long sig3_len;
  err = crypto_sign_ed25519ph_final_create(&ph_state, sig3, &sig3_len, sk);
  assert(err == 0);
  crypto_sign_ed25519ph_init(&ph_state);
  if (msg_len > 0) {
    crypto_sign_ed25519ph_update(&ph_state, msg, msg_len / 2);
    crypto_sign_ed25519ph_update(&ph_state, msg + msg_len / 2,
                                 msg_len - msg_len / 2);
  }
  err = crypto_sign_ed25519ph_final_verify(&ph_state, sig3, pk);
  assert(err == 0);

  // Combined sign/open (signature prepended to message)
  unsigned char *sm = (unsigned char *)malloc(crypto_sign_BYTES + msg_len);
  unsigned long long sm_len;
  err = crypto_sign(sm, &sm_len, msg, msg_len, sk);
  assert(err == 0);
  unsigned char *m_out = (unsigned char *)malloc(sm_len);
  unsigned long long m_out_len;
  err = crypto_sign_open(m_out, &m_out_len, sm, sm_len, pk);
  assert(err == 0);
  assert(m_out_len == msg_len);
  free(sm);
  free(m_out);

  // Curve25519 derivations from Ed25519 keys + sk->seed/pk recovery
  unsigned char c25519_pk[crypto_scalarmult_curve25519_BYTES];
  unsigned char c25519_sk[crypto_scalarmult_curve25519_BYTES];
  crypto_sign_ed25519_pk_to_curve25519(c25519_pk, pk);
  crypto_sign_ed25519_sk_to_curve25519(c25519_sk, sk);

  unsigned char seed_back[crypto_sign_ed25519_SEEDBYTES];
  crypto_sign_ed25519_sk_to_seed(seed_back, sk);
  assert(memcmp(seed_back, seed, crypto_sign_ed25519_SEEDBYTES) == 0);

  unsigned char pk_back[crypto_sign_ed25519_PUBLICKEYBYTES];
  crypto_sign_ed25519_sk_to_pk(pk_back, sk);
  assert(memcmp(pk_back, pk, crypto_sign_ed25519_PUBLICKEYBYTES) == 0);

  return 0;
}
