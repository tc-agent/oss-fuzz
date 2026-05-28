// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <kj/encoding.h>
#include <kj/string.h>
#include <cstdint>

// Fuzzes the kj text/binary codec routines in kj/encoding.c++. These decoders
// run directly on attacker-controlled bytes in real deployments (Base64 / hex
// payloads, percent-encoded URI components, www-form bodies, C-escaped strings,
// and the UTF-8/16/32 transcoders), so each is a genuine parsing boundary. The
// decoded output is round-tripped back through the matching encoder to also
// exercise the encode paths and surface asymmetries.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  kj::ArrayPtr<const char> chars(reinterpret_cast<const char*>(Data), Size);
  kj::ArrayPtr<const kj::byte> bytes(Data, Size);

  {
    auto decoded = kj::decodeBase64(chars);
    kj::String reenc = kj::encodeBase64(decoded.asPtr());
    (void)kj::decodeBase64(reenc);
    (void)kj::encodeBase64Url(decoded.asPtr());
  }
  {
    auto decoded = kj::decodeHex(chars);
    (void)kj::encodeHex(decoded.asPtr());
  }
  {
    auto decoded = kj::decodeUriComponent(chars);
    (void)kj::encodeUriComponent(bytes);
    (void)kj::decodeBinaryUriComponent(chars);
  }
  {
    auto decoded = kj::decodeWwwForm(chars);
    (void)kj::encodeWwwForm(bytes);
  }
  {
    auto decoded = kj::decodeCEscape(chars);
    (void)kj::decodeBinaryCEscape(chars);
    (void)kj::encodeCEscape(bytes);
  }

  // UTF transcoders: treat the input as UTF-8 and walk the round trip through
  // UTF-16 and UTF-32 and back. The encoders substitute REPLACEMENT_CHARACTER
  // for malformed sequences, so this exercises both well-formed paths and the
  // replacement-character emission paths in encoding.c++.
  {
    auto utf16 = kj::encodeUtf16(chars);
    kj::String back16 = kj::decodeUtf16(utf16.asPtr());
    (void)back16;
    auto utf32 = kj::encodeUtf32(chars);
    kj::String back32 = kj::decodeUtf32(utf32.asPtr());
    (void)back32;
  }

  return 0;
}
