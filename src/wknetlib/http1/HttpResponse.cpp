#include "http1/HttpResponse.h"

namespace wknet
{
namespace http1
{
    bool HttpResponse::FindHeader(HttpText name, const HttpHeader** header) const noexcept
    {
        if (header != nullptr) {
            *header = nullptr;
        }

        if (name.Data == nullptr || name.Length == 0 || Headers == nullptr) {
            return false;
        }

        for (SIZE_T index = 0; index < HeaderCount; ++index) {
            if (TextEqualsIgnoreCase(Headers[index].Name, name)) {
                if (header != nullptr) {
                    *header = &Headers[index];
                }

                return true;
            }
        }

        return false;
    }

    bool HttpResponse::HasHeaderValueToken(HttpText name, HttpText token) const noexcept
    {
        if (Headers == nullptr || token.Data == nullptr || token.Length == 0) {
            return false;
        }

        for (SIZE_T index = 0; index < HeaderCount; ++index) {
            if (TextEqualsIgnoreCase(Headers[index].Name, name) &&
                HeaderValueHasToken(Headers[index].Value, token)) {
                return true;
            }
        }

        return false;
    }

    bool HttpResponse::HasConnectionClose() const noexcept
    {
        return HasHeaderValueToken(MakeText("Connection"), MakeText("close"));
    }

    bool HttpResponse::HasConnectionKeepAlive() const noexcept
    {
        return HasHeaderValueToken(MakeText("Connection"), MakeText("keep-alive"));
    }

    bool HttpResponse::HasChunkedTransferEncoding() const noexcept
    {
        return HasHeaderValueToken(MakeText("Transfer-Encoding"), MakeText("chunked"));
    }

    bool HttpResponse::IsPartialContent() const noexcept
    {
        return StatusCode == 206;
    }

    namespace
    {
        bool IsSpace(char c) noexcept
        {
            return c == ' ' || c == '\t';
        }

        // Parses an unsigned decimal run starting at *index, advancing past it.
        // Requires at least one digit and guards against ULONGLONG overflow.
        bool ParseUnsigned(HttpText text, SIZE_T* index, ULONGLONG* value) noexcept
        {
            const SIZE_T start = *index;
            ULONGLONG result = 0;
            while (*index < text.Length) {
                const char c = text.Data[*index];
                if (c < '0' || c > '9') {
                    break;
                }

                const ULONGLONG digit = static_cast<ULONGLONG>(c - '0');
                if (result > (~static_cast<ULONGLONG>(0) - digit) / 10) {
                    return false;
                }

                result = result * 10 + digit;
                ++(*index);
            }

            if (*index == start) {
                return false;
            }

            *value = result;
            return true;
        }
    }

    bool HttpResponse::GetContentRange(HttpContentRange* range) const noexcept
    {
        if (range == nullptr) {
            return false;
        }

        *range = {};

        const HttpHeader* header = nullptr;
        if (!FindHeader(MakeText("Content-Range"), &header) || header == nullptr) {
            return false;
        }

        const HttpText value = header->Value;
        if (value.Data == nullptr) {
            return false;
        }

        SIZE_T index = 0;
        while (index < value.Length && IsSpace(value.Data[index])) {
            ++index;
        }

        // units: only "bytes" is recognized.
        const char unitsPrefix[] = "bytes";
        const SIZE_T unitsLength = sizeof(unitsPrefix) - 1;
        if (value.Length - index < unitsLength) {
            return false;
        }

        for (SIZE_T i = 0; i < unitsLength; ++i) {
            if (value.Data[index + i] != unitsPrefix[i]) {
                return false;
            }
        }

        index += unitsLength;
        if (index >= value.Length || !IsSpace(value.Data[index])) {
            return false;
        }

        while (index < value.Length && IsSpace(value.Data[index])) {
            ++index;
        }

        if (index >= value.Length) {
            return false;
        }

        if (value.Data[index] == '*') {
            // Unsatisfied range: "*" "/" complete-length
            ++index;
            if (index >= value.Length || value.Data[index] != '/') {
                return false;
            }

            ++index;
            ULONGLONG complete = 0;
            if (!ParseUnsigned(value, &index, &complete)) {
                return false;
            }

            range->CompleteLength = complete;
            range->HasCompleteLength = true;
            range->HasRange = false;
        }
        else {
            // first-byte-pos "-" last-byte-pos "/" ( complete-length | "*" )
            ULONGLONG first = 0;
            if (!ParseUnsigned(value, &index, &first)) {
                return false;
            }

            if (index >= value.Length || value.Data[index] != '-') {
                return false;
            }

            ++index;
            ULONGLONG last = 0;
            if (!ParseUnsigned(value, &index, &last)) {
                return false;
            }

            if (last < first) {
                return false;
            }

            if (index >= value.Length || value.Data[index] != '/') {
                return false;
            }

            ++index;
            range->FirstBytePos = first;
            range->LastBytePos = last;
            range->HasRange = true;

            if (index < value.Length && value.Data[index] == '*') {
                ++index;
            }
            else {
                ULONGLONG complete = 0;
                if (!ParseUnsigned(value, &index, &complete)) {
                    return false;
                }

                if (last >= complete) {
                    return false;
                }

                range->CompleteLength = complete;
                range->HasCompleteLength = true;
            }
        }

        // Allow trailing whitespace only.
        while (index < value.Length && IsSpace(value.Data[index])) {
            ++index;
        }

        return index == value.Length;
    }
}
}
