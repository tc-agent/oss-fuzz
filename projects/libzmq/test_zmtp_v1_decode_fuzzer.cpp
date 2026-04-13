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

// In-process fuzzer for the ZMTP/1.0 frame decoder (v1_decoder_t).
// ZMTP/1.0 framing differs from v2: the size byte encodes (flags+body) length
// directly, and 0xFF triggers an 8-byte extended-length path.

#include "precompiled.hpp"
#include "v1_decoder.hpp"

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    // 64 MiB max message size to avoid OOM while still covering large-frame paths.
    zmq::v1_decoder_t decoder (4096, 64 * 1024 * 1024);

    const uint8_t *cur = data;
    size_t remaining = size;

    while (remaining > 0) {
        size_t bytes_used = 0;
        int rc = decoder.decode (cur, remaining, bytes_used);
        if (bytes_used == 0)
            break;
        cur += bytes_used;
        remaining -= bytes_used;
        if (rc == -1)
            break;
    }

    return 0;
}
