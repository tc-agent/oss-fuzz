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

// SHA-3 (256/512), SHAKE-128/256, TurboSHAKE-128/256: one-shot and the
// init/update/squeeze streaming form (broken into chunks driven by the input
// to exercise the absorb/squeeze state machine).

namespace {

void run_sha3_256(const uint8_t *in, size_t inlen) {
  unsigned char out[crypto_hash_sha3256_BYTES];
  crypto_hash_sha3256(out, in, inlen);

  crypto_hash_sha3256_state st;
  crypto_hash_sha3256_init(&st);
  size_t consumed = 0;
  while (consumed < inlen) {
    size_t chunk = (in[consumed] & 0x3F) + 1;
    if (chunk > inlen - consumed) chunk = inlen - consumed;
    crypto_hash_sha3256_update(&st, in + consumed, chunk);
    consumed += chunk;
  }
  unsigned char out2[crypto_hash_sha3256_BYTES];
  crypto_hash_sha3256_final(&st, out2);
  assert(memcmp(out, out2, sizeof(out)) == 0);
}

void run_sha3_512(const uint8_t *in, size_t inlen) {
  unsigned char out[crypto_hash_sha3512_BYTES];
  crypto_hash_sha3512(out, in, inlen);

  crypto_hash_sha3512_state st;
  crypto_hash_sha3512_init(&st);
  size_t consumed = 0;
  while (consumed < inlen) {
    size_t chunk = (in[consumed] & 0x7F) + 1;
    if (chunk > inlen - consumed) chunk = inlen - consumed;
    crypto_hash_sha3512_update(&st, in + consumed, chunk);
    consumed += chunk;
  }
  unsigned char out2[crypto_hash_sha3512_BYTES];
  crypto_hash_sha3512_final(&st, out2);
  assert(memcmp(out, out2, sizeof(out)) == 0);
}

void run_shake128(const uint8_t *in, size_t inlen, size_t outlen) {
  unsigned char *out = (unsigned char *)malloc(outlen);
  crypto_xof_shake128(out, outlen, in, inlen);
  free(out);

  crypto_xof_shake128_state st;
  crypto_xof_shake128_init(&st);
  if (inlen > 0) crypto_xof_shake128_update(&st, in, inlen / 2);
  if (inlen > 0) crypto_xof_shake128_update(&st, in + inlen / 2, inlen - inlen / 2);
  unsigned char *o2 = (unsigned char *)malloc(outlen);
  crypto_xof_shake128_squeeze(&st, o2, outlen / 2);
  crypto_xof_shake128_squeeze(&st, o2 + outlen / 2, outlen - outlen / 2);
  free(o2);
}

void run_shake256(const uint8_t *in, size_t inlen, size_t outlen) {
  unsigned char *out = (unsigned char *)malloc(outlen);
  crypto_xof_shake256(out, outlen, in, inlen);
  free(out);

  crypto_xof_shake256_state st;
  crypto_xof_shake256_init(&st);
  if (inlen > 0) crypto_xof_shake256_update(&st, in, inlen / 2);
  if (inlen > 0) crypto_xof_shake256_update(&st, in + inlen / 2, inlen - inlen / 2);
  unsigned char *o2 = (unsigned char *)malloc(outlen);
  crypto_xof_shake256_squeeze(&st, o2, outlen / 2);
  crypto_xof_shake256_squeeze(&st, o2 + outlen / 2, outlen - outlen / 2);
  free(o2);
}

void run_turboshake128(const uint8_t *in, size_t inlen, size_t outlen,
                       uint8_t domain) {
  unsigned char *out = (unsigned char *)malloc(outlen);
  crypto_xof_turboshake128(out, outlen, in, inlen);
  free(out);

  crypto_xof_turboshake128_state st;
  crypto_xof_turboshake128_init_with_domain(&st, domain);
  if (inlen > 0) crypto_xof_turboshake128_update(&st, in, inlen);
  unsigned char *o2 = (unsigned char *)malloc(outlen);
  crypto_xof_turboshake128_squeeze(&st, o2, outlen);
  free(o2);
}

void run_turboshake256(const uint8_t *in, size_t inlen, size_t outlen,
                       uint8_t domain) {
  unsigned char *out = (unsigned char *)malloc(outlen);
  crypto_xof_turboshake256(out, outlen, in, inlen);
  free(out);

  crypto_xof_turboshake256_state st;
  crypto_xof_turboshake256_init_with_domain(&st, domain);
  if (inlen > 0) crypto_xof_turboshake256_update(&st, in, inlen);
  unsigned char *o2 = (unsigned char *)malloc(outlen);
  crypto_xof_turboshake256_squeeze(&st, o2, outlen);
  free(o2);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  if (size < 3) {
    return 0;
  }
  uint8_t selector = data[0];
  size_t outlen = (data[1] | (data[2] << 8)) % 4097;  // 0..4096
  if (outlen == 0) outlen = 1;
  const uint8_t *body = data + 3;
  size_t bodylen = size - 3;

  switch (selector % 6) {
    case 0: run_sha3_256(body, bodylen); break;
    case 1: run_sha3_512(body, bodylen); break;
    case 2: run_shake128(body, bodylen, outlen); break;
    case 3: run_shake256(body, bodylen, outlen); break;
    case 4: run_turboshake128(body, bodylen, outlen, 0x1F); break;
    case 5: run_turboshake256(body, bodylen, outlen, 0x1F); break;
  }
  return 0;
}
