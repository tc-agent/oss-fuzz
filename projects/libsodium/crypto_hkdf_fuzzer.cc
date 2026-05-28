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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

// HKDF-SHA256 and HKDF-SHA512 (extract + expand), both one-shot and streaming
// extract. Also exercises the HMAC-SHA256/SHA512 paths underneath.

namespace {

void hkdf_sha256(const uint8_t *salt, size_t saltlen, const uint8_t *ikm,
                 size_t ikmlen, const uint8_t *info, size_t infolen,
                 size_t outlen) {
  unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
  if (crypto_kdf_hkdf_sha256_extract(prk, salt, saltlen, ikm, ikmlen) != 0)
    return;
  unsigned char *out = (unsigned char *)malloc(outlen);
  crypto_kdf_hkdf_sha256_expand(out, outlen, (const char *)info, infolen, prk);
  free(out);

  // Streaming extract (split IKM at every quarter).
  crypto_kdf_hkdf_sha256_state st;
  if (crypto_kdf_hkdf_sha256_extract_init(&st, salt, saltlen) == 0) {
    size_t q = ikmlen / 4;
    if (q) crypto_kdf_hkdf_sha256_extract_update(&st, ikm, q);
    if (q) crypto_kdf_hkdf_sha256_extract_update(&st, ikm + q, q);
    if (q) crypto_kdf_hkdf_sha256_extract_update(&st, ikm + 2 * q, q);
    if (ikmlen > 3 * q)
      crypto_kdf_hkdf_sha256_extract_update(&st, ikm + 3 * q, ikmlen - 3 * q);
    unsigned char prk2[crypto_kdf_hkdf_sha256_KEYBYTES];
    crypto_kdf_hkdf_sha256_extract_final(&st, prk2);
  }
}

void hkdf_sha512(const uint8_t *salt, size_t saltlen, const uint8_t *ikm,
                 size_t ikmlen, const uint8_t *info, size_t infolen,
                 size_t outlen) {
  unsigned char prk[crypto_kdf_hkdf_sha512_KEYBYTES];
  if (crypto_kdf_hkdf_sha512_extract(prk, salt, saltlen, ikm, ikmlen) != 0)
    return;
  unsigned char *out = (unsigned char *)malloc(outlen);
  crypto_kdf_hkdf_sha512_expand(out, outlen, (const char *)info, infolen, prk);
  free(out);

  crypto_kdf_hkdf_sha512_state st;
  if (crypto_kdf_hkdf_sha512_extract_init(&st, salt, saltlen) == 0) {
    size_t q = ikmlen / 4;
    if (q) crypto_kdf_hkdf_sha512_extract_update(&st, ikm, q);
    if (q) crypto_kdf_hkdf_sha512_extract_update(&st, ikm + q, q);
    if (q) crypto_kdf_hkdf_sha512_extract_update(&st, ikm + 2 * q, q);
    if (ikmlen > 3 * q)
      crypto_kdf_hkdf_sha512_extract_update(&st, ikm + 3 * q, ikmlen - 3 * q);
    unsigned char prk2[crypto_kdf_hkdf_sha512_KEYBYTES];
    crypto_kdf_hkdf_sha512_extract_final(&st, prk2);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  if (size < 4) {
    return 0;
  }

  uint8_t selector = data[0];
  uint8_t saltlen_u = data[1];
  uint8_t infolen_u = data[2];
  uint8_t outlen_u = data[3];
  const uint8_t *body = data + 4;
  size_t bodylen = size - 4;

  size_t saltlen = saltlen_u % 65;
  if (saltlen > bodylen) saltlen = bodylen;
  const uint8_t *salt = body;
  body += saltlen;
  bodylen -= saltlen;

  size_t infolen = infolen_u % 65;
  if (infolen > bodylen) infolen = bodylen;
  const uint8_t *info = body;
  body += infolen;
  bodylen -= infolen;

  size_t outlen = 1 + outlen_u;
  if (outlen > 8192) outlen = 8192;

  const uint8_t *ikm = body;
  size_t ikmlen = bodylen;

  if (selector & 1) {
    hkdf_sha256(salt, saltlen, ikm, ikmlen, info, infolen, outlen);
  } else {
    hkdf_sha512(salt, saltlen, ikm, ikmlen, info, infolen, outlen);
  }

  return 0;
}
