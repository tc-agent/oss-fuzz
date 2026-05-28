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

// Fuzzes the raw stream ciphers (no AEAD wrapping): XSalsa20, Salsa20,
// Salsa20/12, Salsa20/8, ChaCha20, ChaCha20-IETF, XChaCha20.

namespace {

constexpr size_t kMaxOut = 4096;

void run_xsalsa20(const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *msg, size_t msglen) {
  unsigned char *out = (unsigned char *)malloc(msglen);
  unsigned char *back = (unsigned char *)malloc(msglen);
  crypto_stream_xor(out, msg, msglen, nonce, key);
  crypto_stream_xor(back, out, msglen, nonce, key);
  assert(memcmp(back, msg, msglen) == 0);
  free(out);
  free(back);
}

void run_salsa20(const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *msg, size_t msglen) {
  unsigned char *out = (unsigned char *)malloc(msglen);
  crypto_stream_salsa20_xor(out, msg, msglen, nonce, key);
  crypto_stream_salsa20_xor_ic(out, out, msglen, nonce, 0, key);
  assert(memcmp(out, msg, msglen) == 0);
  free(out);
}

void run_salsa2012(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *msg, size_t msglen) {
  unsigned char *out = (unsigned char *)malloc(msglen);
  crypto_stream_salsa2012_xor(out, msg, msglen, nonce, key);
  crypto_stream_salsa2012(out, msglen, nonce, key);
  free(out);
}

void run_salsa208(const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *msg, size_t msglen) {
  unsigned char *out = (unsigned char *)malloc(msglen);
  crypto_stream_salsa208_xor(out, msg, msglen, nonce, key);
  free(out);
}

void run_chacha20(const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *msg, size_t msglen) {
  unsigned char *out = (unsigned char *)malloc(msglen);
  unsigned char *back = (unsigned char *)malloc(msglen);
  crypto_stream_chacha20_xor(out, msg, msglen, nonce, key);
  crypto_stream_chacha20_xor_ic(back, out, msglen, nonce, 0, key);
  assert(memcmp(back, msg, msglen) == 0);
  free(out);
  free(back);
}

void run_chacha20_ietf(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *msg, size_t msglen) {
  unsigned char *out = (unsigned char *)malloc(msglen);
  crypto_stream_chacha20_ietf_xor(out, msg, msglen, nonce, key);
  crypto_stream_chacha20_ietf_xor_ic(out, out, msglen, nonce, 0, key);
  assert(memcmp(out, msg, msglen) == 0);
  free(out);
}

void run_xchacha20(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *msg, size_t msglen) {
  unsigned char *out = (unsigned char *)malloc(msglen);
  crypto_stream_xchacha20_xor(out, msg, msglen, nonce, key);
  crypto_stream_xchacha20_xor_ic(out, out, msglen, nonce, 0, key);
  assert(memcmp(out, msg, msglen) == 0);
  free(out);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }

  // Each cipher needs a 32-byte key. Largest nonce is XChaCha20 = 24 bytes.
  const size_t hdr = 1 + 32 + 24;
  if (size < hdr) {
    return 0;
  }

  uint8_t selector = data[0] % 7;
  const uint8_t *key = data + 1;
  const uint8_t *nonce = data + 33;
  const uint8_t *msg = data + hdr;
  size_t msglen = size - hdr;
  if (msglen > kMaxOut) msglen = kMaxOut;

  switch (selector) {
    case 0: run_xsalsa20(key, nonce, msg, msglen); break;
    case 1: run_salsa20(key, nonce, msg, msglen); break;
    case 2: run_salsa2012(key, nonce, msg, msglen); break;
    case 3: run_salsa208(key, nonce, msg, msglen); break;
    case 4: run_chacha20(key, nonce, msg, msglen); break;
    case 5: run_chacha20_ietf(key, nonce, msg, msglen); break;
    case 6: run_xchacha20(key, nonce, msg, msglen); break;
  }

  return 0;
}
