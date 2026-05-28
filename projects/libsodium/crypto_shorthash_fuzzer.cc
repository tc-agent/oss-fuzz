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

#include <sodium.h>

// SipHash-2-4 (16-byte key, 8-byte output) and SipHashx-2-4 (16-byte key,
// 16-byte output).

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }

  if (size < crypto_shorthash_KEYBYTES + 1) {
    return 0;
  }

  const uint8_t *key = data;
  const uint8_t *in = data + crypto_shorthash_KEYBYTES;
  size_t inlen = size - crypto_shorthash_KEYBYTES;

  unsigned char out[crypto_shorthash_BYTES];
  crypto_shorthash(out, in, inlen, key);

  if (size >= crypto_shorthash_siphashx24_KEYBYTES) {
    unsigned char outx[crypto_shorthash_siphashx24_BYTES];
    crypto_shorthash_siphashx24(outx, in, inlen, key);
  }

  return 0;
}
