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

// Fuzzes the password hashing primitives: Argon2id, Argon2i and scrypt.
// Uses minimum ops/mem so each iteration is fast enough for libFuzzer.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }

  // scrypt uses a 32-byte salt (largest across the algorithms); Argon2 uses
  // 16. Reserve 32 unconditionally so a single layout works for all branches.
  const size_t kSaltReserve = crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
  if (size < 1 + kSaltReserve + 1) {
    return 0;
  }

  uint8_t selector = data[0];
  const uint8_t *salt = data + 1;
  const char *passwd = reinterpret_cast<const char *>(data + 1 + kSaltReserve);
  size_t passwdlen = size - (1 + kSaltReserve);
  if (passwdlen > 256) passwdlen = 256;

  uint8_t out[64];
  size_t outlen = 16 + (selector & 0x0F);  // 16..31 bytes (>= BYTES_MIN=16)

  switch (selector >> 4) {
    case 0: {
      // Argon2id default (also exercises crypto_pwhash dispatch)
      crypto_pwhash(out, outlen, passwd, passwdlen, salt,
                    crypto_pwhash_OPSLIMIT_MIN,
                    crypto_pwhash_MEMLIMIT_MIN,
                    crypto_pwhash_ALG_DEFAULT);
      break;
    }
    case 1: {
      // Argon2id explicit
      crypto_pwhash(out, outlen, passwd, passwdlen, salt,
                    crypto_pwhash_argon2id_OPSLIMIT_MIN,
                    crypto_pwhash_argon2id_MEMLIMIT_MIN,
                    crypto_pwhash_ALG_ARGON2ID13);
      break;
    }
    case 2: {
      // Argon2i
      crypto_pwhash(out, outlen, passwd, passwdlen, salt,
                    crypto_pwhash_argon2i_OPSLIMIT_MIN,
                    crypto_pwhash_argon2i_MEMLIMIT_MIN,
                    crypto_pwhash_ALG_ARGON2I13);
      break;
    }
    case 3: {
      // pwhash_str + verify + needs_rehash round-trip (Argon2id)
      char str[crypto_pwhash_STRBYTES];
      if (crypto_pwhash_str(str, passwd, passwdlen,
                            crypto_pwhash_argon2id_OPSLIMIT_MIN,
                            crypto_pwhash_argon2id_MEMLIMIT_MIN) == 0) {
        crypto_pwhash_str_verify(str, passwd, passwdlen);
        crypto_pwhash_str_needs_rehash(str,
                                       crypto_pwhash_argon2id_OPSLIMIT_MIN,
                                       crypto_pwhash_argon2id_MEMLIMIT_MIN);
      }
      break;
    }
    case 4: {
      // pwhash_str_alg with Argon2i
      char str[crypto_pwhash_STRBYTES];
      if (crypto_pwhash_str_alg(str, passwd, passwdlen,
                                crypto_pwhash_argon2i_OPSLIMIT_MIN,
                                crypto_pwhash_argon2i_MEMLIMIT_MIN,
                                crypto_pwhash_ALG_ARGON2I13) == 0) {
        crypto_pwhash_str_verify(str, passwd, passwdlen);
      }
      break;
    }
    case 5: {
      // Treat input as a candidate encoded string and try verify on it.
      // Exercises the argon2 string parser on attacker-controlled bytes.
      char str[crypto_pwhash_STRBYTES];
      size_t copy = passwdlen < sizeof(str) - 1 ? passwdlen : sizeof(str) - 1;
      memcpy(str, passwd, copy);
      str[copy] = '\0';
      crypto_pwhash_str_verify(str, "test-password", 13);
      break;
    }
    case 6: {
      // scrypt low-cost
      crypto_pwhash_scryptsalsa208sha256(
          out, outlen, passwd, passwdlen, salt,
          crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
          crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
      break;
    }
    case 7: {
      // scrypt str + verify
      char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
      if (crypto_pwhash_scryptsalsa208sha256_str(
              str, passwd, passwdlen,
              crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
              crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN) == 0) {
        crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwdlen);
      }
      break;
    }
    case 8: {
      // scrypt-style verify of attacker-controlled string
      char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
      size_t copy = passwdlen < sizeof(str) - 1 ? passwdlen : sizeof(str) - 1;
      memcpy(str, passwd, copy);
      str[copy] = '\0';
      crypto_pwhash_scryptsalsa208sha256_str_verify(str, "test-password", 13);
      break;
    }
    default:
      break;
  }

  return 0;
}
