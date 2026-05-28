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
#include <string.h>

#include <sodium.h>

// Exercises curve25519 / ed25519 / ristretto255 scalar multiplication and
// helpers (point validation, decoding, scalar reduction). These all parse
// attacker-controlled bytes as group elements / scalars, which is the
// interesting surface from a fuzzing perspective.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }

  if (size < 1 + 64) {
    return 0;
  }

  uint8_t selector = data[0];
  const uint8_t *p = data + 1;

  switch (selector % 10) {
    case 0: {
      // X25519 base scalar mult
      unsigned char q[crypto_scalarmult_BYTES];
      crypto_scalarmult_base(q, p);
      break;
    }
    case 1: {
      // X25519 scalar mult with attacker-controlled point
      unsigned char q[crypto_scalarmult_BYTES];
      crypto_scalarmult(q, p, p + 32);
      break;
    }
    case 2: {
      // Ed25519 base scalar mult (cofactor-clamped)
      unsigned char q[crypto_scalarmult_ed25519_BYTES];
      crypto_scalarmult_ed25519_base(q, p);
      break;
    }
    case 3: {
      // Ed25519 scalar mult, non-clamped variant exercises validation
      unsigned char q[crypto_scalarmult_ed25519_BYTES];
      crypto_scalarmult_ed25519_noclamp(q, p, p + 32);
      break;
    }
    case 4: {
      // Ed25519 point validation
      crypto_core_ed25519_is_valid_point(p);
      break;
    }
    case 5: {
      // Ristretto255 from_hash + base scalar mult
      if (size < 1 + crypto_core_ristretto255_HASHBYTES) break;
      unsigned char r[crypto_core_ristretto255_BYTES];
      if (crypto_core_ristretto255_from_hash(r, p) == 0) {
        unsigned char q[crypto_scalarmult_ristretto255_BYTES];
        crypto_scalarmult_ristretto255_base(q, p);
        unsigned char q2[crypto_scalarmult_ristretto255_BYTES];
        crypto_scalarmult_ristretto255(q2, p, r);
      }
      break;
    }
    case 6: {
      // Ristretto255 point validation on attacker-controlled bytes
      crypto_core_ristretto255_is_valid_point(p);
      break;
    }
    case 7: {
      // Ed25519 add / sub on attacker-controlled points
      unsigned char r[crypto_core_ed25519_BYTES];
      crypto_core_ed25519_add(r, p, p + 32);
      crypto_core_ed25519_sub(r, p, p + 32);
      break;
    }
    case 8: {
      // Scalar reduction + negate + complement
      if (size < 1 + crypto_core_ed25519_NONREDUCEDSCALARBYTES) break;
      unsigned char s[crypto_core_ed25519_SCALARBYTES];
      crypto_core_ed25519_scalar_reduce(s, p);
      unsigned char neg[crypto_core_ed25519_SCALARBYTES];
      crypto_core_ed25519_scalar_negate(neg, s);
      unsigned char inv[crypto_core_ed25519_SCALARBYTES];
      crypto_core_ed25519_scalar_invert(inv, s);
      break;
    }
    case 9: {
      // Ed25519 from_uniform
      if (size < 1 + crypto_core_ed25519_UNIFORMBYTES) break;
      unsigned char r[crypto_core_ed25519_BYTES];
      crypto_core_ed25519_from_uniform(r, p);
      break;
    }
  }

  return 0;
}
