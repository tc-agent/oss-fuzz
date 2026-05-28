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

// Poly1305 one-shot, multi-part, and (auth, then mutate) verify.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  if (size < crypto_onetimeauth_KEYBYTES) {
    return 0;
  }

  const uint8_t *key = data;
  const uint8_t *msg = data + crypto_onetimeauth_KEYBYTES;
  size_t msglen = size - crypto_onetimeauth_KEYBYTES;

  unsigned char tag[crypto_onetimeauth_BYTES];
  crypto_onetimeauth(tag, msg, msglen, key);
  int v = crypto_onetimeauth_verify(tag, msg, msglen, key);
  assert(v == 0);

  // Multi-part: split message at every byte boundary determined by the key.
  crypto_onetimeauth_state state;
  crypto_onetimeauth_init(&state, key);
  size_t consumed = 0;
  // Walk chunks of 1..16 bytes derived from the message.
  while (consumed < msglen) {
    size_t chunk = (msg[consumed] & 0x0F) + 1;
    if (chunk > msglen - consumed) chunk = msglen - consumed;
    crypto_onetimeauth_update(&state, msg + consumed, chunk);
    consumed += chunk;
  }
  unsigned char tag2[crypto_onetimeauth_BYTES];
  crypto_onetimeauth_final(&state, tag2);
  assert(memcmp(tag, tag2, sizeof(tag)) == 0);

  // Verify rejection: flip a tag bit and confirm verify fails.
  unsigned char bad[crypto_onetimeauth_BYTES];
  memcpy(bad, tag, sizeof(bad));
  bad[0] ^= 1;
  v = crypto_onetimeauth_verify(bad, msg, msglen, key);
  assert(v != 0);

  return 0;
}
