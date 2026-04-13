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

// In-process fuzzer for the WebSocket frame decoder (ws_decoder_t), unmasked variant.
// Tests server-side decoding of frames that must NOT carry a masking key
// (i.e. frames sent by another server/peer, not a browser client).

#include "precompiled.hpp"
#include "ws_decoder.hpp"

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    // must_mask=false: frames are not masked (server-to-server direction).
    zmq::ws_decoder_t decoder (4096, 64 * 1024 * 1024, false, false);

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
