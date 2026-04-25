/*
 * Copyright (C) 2026 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

#include <stdint.h>
#include <stddef.h>
#include <string>

#include <Wt/WDate.h>
#include <Wt/WDateTime.h>
#include <Wt/WString.h>
#include <Wt/WTime.h>

#define kMinInputLength 2
#define kMaxInputLength 5120

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < kMinInputLength || Size > kMaxInputLength) {
        return -1;
    }

    // Bit 0 of Data[0] selects between the two call paths:
    //   0 → fromString(value)         (default-format overloads)
    //   1 → fromString(value, format) (explicit-format overloads)
    // Data[1] is the split offset between value and format strings.
    bool useFormat = Data[0] & 1;
    size_t remaining = Size - 2;
    const uint8_t *buf = Data + 2;

    try {
        if (!useFormat) {
            Wt::WString value = Wt::WString::fromUTF8(std::string(buf, buf + remaining));
            Wt::WDate::fromString(value);
            Wt::WTime::fromString(value);
            Wt::WDateTime::fromString(value);
        } else {
            size_t split = (remaining == 0) ? 0 : (Data[1] % remaining);
            Wt::WString value = Wt::WString::fromUTF8(std::string(buf, buf + split));
            Wt::WString format = Wt::WString::fromUTF8(std::string(buf + split, buf + remaining));
            Wt::WDate::fromString(value, format);
            Wt::WTime::fromString(value, format);
            Wt::WDateTime::fromString(value, format);
        }
    } catch (...) { }

    return 0;
}
