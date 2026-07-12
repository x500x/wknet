#include "rtl/Text.h"

namespace wknet::rtl
{
namespace
{
    bool IsUpperAscii(char value) noexcept
    {
        return value >= 'A' && value <= 'Z';
    }

    char ToLowerAscii(char value) noexcept
    {
        return IsUpperAscii(value) ? static_cast<char>(value + ('a' - 'A')) : value;
    }
}

Text MakeText(const char* value) noexcept
{
    Text text = {};
    if (value == nullptr) {
        return text;
    }

    text.Data = value;
    while (value[text.Length] != '\0') {
        ++text.Length;
    }
    return text;
}

bool TextEqualsIgnoreCase(Text left, Text right) noexcept
{
    if (left.Length != right.Length || left.Data == nullptr || right.Data == nullptr) {
        return false;
    }

    for (SIZE_T index = 0; index < left.Length; ++index) {
        if (ToLowerAscii(left.Data[index]) != ToLowerAscii(right.Data[index])) {
            return false;
        }
    }
    return true;
}
}
