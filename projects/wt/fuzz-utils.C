/*
 * Copyright (C) 2026 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

#include <stdint.h>
#include <stddef.h>
#include <string>

#include <Wt/Utils.h>

#define kMinInputLength 1
#define kMaxInputLength 65536

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < kMinInputLength || Size > kMaxInputLength) {
        return -1;
    }

    std::string input(Data, Data + Size);

    std::string urlEncoded = Wt::Utils::urlEncode(input);
    Wt::Utils::urlDecode(urlEncoded);
    Wt::Utils::urlDecode(input);

    std::string b64 = Wt::Utils::base64Encode(input, false);
    Wt::Utils::base64Decode(b64);
    Wt::Utils::base64Decode(input);

    std::string hex = Wt::Utils::hexEncode(input);
    Wt::Utils::hexDecode(hex);
    Wt::Utils::hexDecode(input);

    Wt::Utils::htmlEncode(input);

    return 0;
}
