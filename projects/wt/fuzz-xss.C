/*
 * Copyright (C) 2026 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

#include <stdint.h>
#include <stddef.h>
#include <string>

#include <Wt/WString.h>

#include "web/XSSFilter.h"

#define kMinInputLength 1
#define kMaxInputLength 65536

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < kMinInputLength || Size > kMaxInputLength) {
        return -1;
    }

    std::string input(Data, Data + Size);
    Wt::WString text = Wt::WString::fromUTF8(input);
    Wt::XSSFilterRemoveScript(text);

    return 0;
}
