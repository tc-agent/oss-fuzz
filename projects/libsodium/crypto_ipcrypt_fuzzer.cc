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

// Fuzzes ipcrypt-deterministic, ipcrypt-nd, ipcrypt-ndx, ipcrypt-pfx.
// Each mode is a format-preserving AES-based IP encryption; the harness
// rotates through them and verifies round-trip.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  // Need at least: 1 selector + max(NDX_KEYBYTES=32) + tweak (16) + input (16)
  if (size < 1 + 32 + 16 + 16) {
    return 0;
  }

  uint8_t selector = data[0] % 4;
  const uint8_t *body = data + 1;

  switch (selector) {
    case 0: {
      // ipcrypt deterministic
      unsigned char out[crypto_ipcrypt_BYTES];
      unsigned char back[crypto_ipcrypt_BYTES];
      const unsigned char *key = body;
      const unsigned char *input = body + crypto_ipcrypt_KEYBYTES;
      crypto_ipcrypt_encrypt(out, input, key);
      crypto_ipcrypt_decrypt(back, out, key);
      assert(memcmp(back, input, crypto_ipcrypt_BYTES) == 0);
      break;
    }
    case 1: {
      // ipcrypt ND (non-deterministic with random tweak)
      unsigned char out[crypto_ipcrypt_ND_OUTPUTBYTES];
      unsigned char back[crypto_ipcrypt_ND_INPUTBYTES];
      const unsigned char *key = body;
      const unsigned char *tweak = body + crypto_ipcrypt_ND_KEYBYTES;
      const unsigned char *input =
          tweak + crypto_ipcrypt_ND_TWEAKBYTES;
      crypto_ipcrypt_nd_encrypt(out, input, tweak, key);
      crypto_ipcrypt_nd_decrypt(back, out, key);
      assert(memcmp(back, input, crypto_ipcrypt_ND_INPUTBYTES) == 0);
      break;
    }
    case 2: {
      // ipcrypt NDX (32-byte key, 16-byte tweak)
      unsigned char out[crypto_ipcrypt_NDX_OUTPUTBYTES];
      unsigned char back[crypto_ipcrypt_NDX_INPUTBYTES];
      const unsigned char *key = body;
      const unsigned char *tweak = body + crypto_ipcrypt_NDX_KEYBYTES;
      const unsigned char *input =
          tweak + crypto_ipcrypt_NDX_TWEAKBYTES;
      crypto_ipcrypt_ndx_encrypt(out, input, tweak, key);
      crypto_ipcrypt_ndx_decrypt(back, out, key);
      assert(memcmp(back, input, crypto_ipcrypt_NDX_INPUTBYTES) == 0);
      break;
    }
    case 3: {
      // ipcrypt PFX (prefix-preserving)
      unsigned char out[crypto_ipcrypt_PFX_BYTES];
      unsigned char back[crypto_ipcrypt_PFX_BYTES];
      const unsigned char *key = body;
      const unsigned char *input = body + crypto_ipcrypt_PFX_KEYBYTES;
      crypto_ipcrypt_pfx_encrypt(out, input, key);
      crypto_ipcrypt_pfx_decrypt(back, out, key);
      assert(memcmp(back, input, crypto_ipcrypt_PFX_BYTES) == 0);
      break;
    }
  }

  return 0;
}
