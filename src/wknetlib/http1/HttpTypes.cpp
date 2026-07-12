#include <wknet/http1/HttpTypes.h>

namespace wknet
{
namespace http1
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

        bool IsTokenBoundary(char value) noexcept
        {
            return value == ',' || value == ' ' || value == '\t';
        }

        HttpText TrimOptionalWhitespace(HttpText text) noexcept
        {
            while (text.Length > 0 && (text.Data[0] == ' ' || text.Data[0] == '\t')) {
                ++text.Data;
                --text.Length;
            }

            while (text.Length > 0 &&
                (text.Data[text.Length - 1] == ' ' || text.Data[text.Length - 1] == '\t')) {
                --text.Length;
            }

            return text;
        }
    }

    HttpText MakeText(const char* value) noexcept
    {
        HttpText text = {};

        if (value == nullptr) {
            return text;
        }

        text.Data = value;
        while (value[text.Length] != '\0') {
            ++text.Length;
        }

        return text;
    }

    bool TextEqualsIgnoreCase(HttpText left, HttpText right) noexcept
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

    bool HeaderValueHasToken(HttpText value, HttpText token) noexcept
    {
        value = TrimOptionalWhitespace(value);

        if (value.Data == nullptr || token.Data == nullptr || token.Length == 0) {
            return false;
        }

        SIZE_T index = 0;
        while (index < value.Length) {
            while (index < value.Length && IsTokenBoundary(value.Data[index])) {
                ++index;
            }

            const SIZE_T tokenStart = index;
            while (index < value.Length && value.Data[index] != ',') {
                ++index;
            }

            HttpText candidate = { value.Data + tokenStart, index - tokenStart };
            candidate = TrimOptionalWhitespace(candidate);
            if (TextEqualsIgnoreCase(candidate, token)) {
                return true;
            }
        }

        return false;
    }
}
}
