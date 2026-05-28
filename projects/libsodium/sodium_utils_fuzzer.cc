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

// sodium_pad/unpad, sodium_bin2hex/hex2bin, sodium_bin2base64/base642bin
// (all 4 variants), sodium_compare, sodium_increment, sodium_add, sodium_sub,
// sodium_ip2bin. These parse attacker-controlled bytes / strings.

namespace {

void try_pad(const uint8_t *data, size_t size) {
  if (size < 2) return;
  size_t blocksize = (data[0] % 64) + 1;
  size_t unpadded = size - 1;
  size_t padded_max = unpadded + blocksize;
  unsigned char *buf = (unsigned char *)malloc(padded_max);
  memcpy(buf, data + 1, unpadded);
  size_t padded_len = 0;
  if (sodium_pad(&padded_len, buf, unpadded, blocksize, padded_max) == 0) {
    size_t unpadded_back = 0;
    if (sodium_unpad(&unpadded_back, buf, padded_len, blocksize) == 0) {
      assert(unpadded_back == unpadded);
    }
  }
  free(buf);
}

void try_hex(const uint8_t *data, size_t size) {
  // bin -> hex -> bin round trip.
  char *hex = (char *)malloc(size * 2 + 1);
  sodium_bin2hex(hex, size * 2 + 1, data, size);
  unsigned char *back = (unsigned char *)malloc(size + 1);
  size_t back_len = 0;
  sodium_hex2bin(back, size, hex, size * 2, nullptr, &back_len, nullptr);
  assert(back_len == size);
  assert(memcmp(back, data, size) == 0);
  free(hex);
  free(back);

  // Negative: feed raw bytes through hex2bin with ignore chars.
  const char *str = reinterpret_cast<const char *>(data);
  unsigned char *out = (unsigned char *)malloc(size + 1);
  size_t out_len = 0;
  const char *end = nullptr;
  sodium_hex2bin(out, size, str, size, ": \n", &out_len, &end);
  free(out);
}

void try_base64(const uint8_t *data, size_t size) {
  static const int variants[4] = {
      sodium_base64_VARIANT_ORIGINAL,
      sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
      sodium_base64_VARIANT_URLSAFE,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING,
  };
  int variant = variants[data[0] & 3];

  size_t b64_max = sodium_base64_encoded_len(size, variant);
  char *b64 = (char *)malloc(b64_max);
  sodium_bin2base64(b64, b64_max, data, size, variant);
  unsigned char *back = (unsigned char *)malloc(size + 1);
  size_t back_len = 0;
  sodium_base642bin(back, size, b64, b64_max - 1, nullptr, &back_len, nullptr,
                    variant);
  free(b64);
  free(back);

  // Negative: feed raw bytes as base64.
  const char *str = reinterpret_cast<const char *>(data);
  unsigned char *out = (unsigned char *)malloc(size + 1);
  size_t out_len = 0;
  sodium_base642bin(out, size, str, size, " \r\n", &out_len, nullptr, variant);
  free(out);
}

void try_intops(const uint8_t *data, size_t size) {
  if (size < 2) return;
  size_t n = size / 2;
  unsigned char *a = (unsigned char *)malloc(n);
  unsigned char *b = (unsigned char *)malloc(n);
  memcpy(a, data, n);
  memcpy(b, data + n, n);
  sodium_compare(a, b, n);
  sodium_is_zero(a, n);
  sodium_increment(a, n);
  sodium_add(a, b, n);
  sodium_sub(a, b, n);
  free(a);
  free(b);
}

void try_ip2bin(const uint8_t *data, size_t size) {
  char buf[128];
  size_t n = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
  memcpy(buf, data, n);
  buf[n] = '\0';
  unsigned char ip[16];
  sodium_ip2bin(ip, buf, n);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }
  if (size < 2) {
    return 0;
  }

  uint8_t selector = data[0] % 5;
  const uint8_t *body = data + 1;
  size_t bodylen = size - 1;

  switch (selector) {
    case 0: try_pad(body, bodylen); break;
    case 1: try_hex(body, bodylen); break;
    case 2: try_base64(body, bodylen); break;
    case 3: try_intops(body, bodylen); break;
    case 4: try_ip2bin(body, bodylen); break;
  }

  return 0;
}
