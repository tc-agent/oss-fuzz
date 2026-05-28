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

// HMAC-SHA256 / HMAC-SHA512 / HMAC-SHA512-256: one-shot and streaming
// (init/update/final) with mutation-driven chunking, plus negative verify on
// a flipped tag.

namespace {

void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg,
                 size_t msglen) {
  unsigned char tag[crypto_auth_hmacsha256_BYTES];
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, key, keylen);
  size_t mid = msglen / 2;
  crypto_auth_hmacsha256_update(&st, msg, mid);
  crypto_auth_hmacsha256_update(&st, msg + mid, msglen - mid);
  crypto_auth_hmacsha256_final(&st, tag);

  // One-shot uses a fixed key length, so only call it when key is the right
  // size — otherwise just verify the streaming tag.
  if (keylen == crypto_auth_hmacsha256_KEYBYTES) {
    unsigned char tag2[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256(tag2, msg, msglen, key);
    assert(memcmp(tag, tag2, sizeof(tag)) == 0);
    int v = crypto_auth_hmacsha256_verify(tag, msg, msglen, key);
    assert(v == 0);
    tag2[0] ^= 1;
    v = crypto_auth_hmacsha256_verify(tag2, msg, msglen, key);
    assert(v != 0);
  }
}

void hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *msg,
                 size_t msglen) {
  unsigned char tag[crypto_auth_hmacsha512_BYTES];
  crypto_auth_hmacsha512_state st;
  crypto_auth_hmacsha512_init(&st, key, keylen);
  size_t mid = msglen / 2;
  crypto_auth_hmacsha512_update(&st, msg, mid);
  crypto_auth_hmacsha512_update(&st, msg + mid, msglen - mid);
  crypto_auth_hmacsha512_final(&st, tag);

  if (keylen == crypto_auth_hmacsha512_KEYBYTES) {
    unsigned char tag2[crypto_auth_hmacsha512_BYTES];
    crypto_auth_hmacsha512(tag2, msg, msglen, key);
    assert(memcmp(tag, tag2, sizeof(tag)) == 0);
    int v = crypto_auth_hmacsha512_verify(tag, msg, msglen, key);
    assert(v == 0);
    tag2[0] ^= 1;
    v = crypto_auth_hmacsha512_verify(tag2, msg, msglen, key);
    assert(v != 0);
  }
}

void hmac_sha512256(const uint8_t *key, size_t keylen, const uint8_t *msg,
                    size_t msglen) {
  // Truncated HMAC-SHA512 (32-byte output).
  unsigned char tag[crypto_auth_hmacsha512256_BYTES];
  crypto_auth_hmacsha512256_state st;
  crypto_auth_hmacsha512256_init(&st, key, keylen);
  size_t mid = msglen / 2;
  crypto_auth_hmacsha512256_update(&st, msg, mid);
  crypto_auth_hmacsha512256_update(&st, msg + mid, msglen - mid);
  crypto_auth_hmacsha512256_final(&st, tag);

  if (keylen == crypto_auth_hmacsha512256_KEYBYTES) {
    unsigned char tag2[crypto_auth_hmacsha512256_BYTES];
    crypto_auth_hmacsha512256(tag2, msg, msglen, key);
    assert(memcmp(tag, tag2, sizeof(tag)) == 0);
    crypto_auth_hmacsha512256_verify(tag, msg, msglen, key);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  if (size < 2) {
    return 0;
  }

  uint8_t selector = data[0];
  uint8_t keylen_u = data[1];
  const uint8_t *body = data + 2;
  size_t bodylen = size - 2;

  // Key length distribution: small, exact, large (HMAC handles all).
  size_t keylen;
  switch (keylen_u % 4) {
    case 0: keylen = 32; break;
    case 1: keylen = 64; break;
    case 2: keylen = 8; break;
    default: keylen = 129; break;  // > block to exercise the long-key path
  }
  if (keylen > bodylen) keylen = bodylen;
  const uint8_t *key = body;
  const uint8_t *msg = body + keylen;
  size_t msglen = bodylen - keylen;

  switch (selector % 3) {
    case 0: hmac_sha256(key, keylen, msg, msglen); break;
    case 1: hmac_sha512(key, keylen, msg, msglen); break;
    case 2: hmac_sha512256(key, keylen, msg, msglen); break;
  }
  return 0;
}
