#include <wknet/http/Headers.h>
#include "session/detail/HttpHandles.h"

namespace wknet::http {
namespace
{
    SIZE_T StringLength(const char* text) noexcept
    {
        if (text == nullptr) {
            return 0;
        }
        SIZE_T length = 0;
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    char LowerAscii(char ch) noexcept
    {
        return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch;
    }

    bool TextEqualsIgnoreCase(const char* left, SIZE_T leftLength, const char* right, SIZE_T rightLength) noexcept
    {
        if (leftLength != rightLength || left == nullptr || right == nullptr) {
            return false;
        }
        for (SIZE_T index = 0; index < leftLength; ++index) {
            if (LowerAscii(left[index]) != LowerAscii(right[index])) {
                return false;
            }
        }
        return true;
    }

    bool TextEqualsLiteralIgnoreCase(const char* left, SIZE_T leftLength, const char* literal) noexcept
    {
        return TextEqualsIgnoreCase(left, leftLength, literal, StringLength(literal));
    }

    bool IsValidHeaderName(const char* name, SIZE_T nameLength) noexcept
    {
        if (name == nullptr || nameLength == 0 || nameLength > ::wknet::session::MaxHeaderNameLength) {
            return false;
        }
        for (SIZE_T index = 0; index < nameLength; ++index) {
            const unsigned char value = static_cast<unsigned char>(name[index]);
            const bool alpha = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
            const bool digit = value >= '0' && value <= '9';
            const bool token = alpha || digit || value == '!' || value == '#' || value == '$' ||
                value == '%' || value == '&' || value == '\'' || value == '*' || value == '+' ||
                value == '-' || value == '.' || value == '^' || value == '_' || value == '`' ||
                value == '|' || value == '~';
            if (!token) {
                return false;
            }
        }
        return true;
    }

    bool IsValidHeaderValue(const char* value, SIZE_T valueLength) noexcept
    {
        if (value == nullptr && valueLength != 0) {
            return false;
        }
        if (valueLength > ::wknet::session::MaxHeaderValueLength) {
            return false;
        }
        for (SIZE_T index = 0; index < valueLength; ++index) {
            const unsigned char ch = static_cast<unsigned char>(value[index]);
            if (value[index] != '\t' && (ch < 0x20 || ch == 0x7f)) {
                return false;
            }
        }
        return true;
    }

    bool IsControlledHeader(const char* name, SIZE_T nameLength) noexcept
    {
        return TextEqualsLiteralIgnoreCase(name, nameLength, "Host") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Content-Length") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Connection") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Transfer-Encoding") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "TE");
    }

    char* CopyText(const char* text, SIZE_T textLength) noexcept
    {
        if (text == nullptr && textLength != 0) {
            return nullptr;
        }
        char* copy = ::wknet::AllocateNonPagedArray<char>(textLength + 1);
        if (copy == nullptr) {
            return nullptr;
        }
        if (textLength != 0) {
            RtlCopyMemory(copy, text, textLength);
        }
        copy[textLength] = '\0';
        return copy;
    }

    void ReleaseStoredHeader(detail::StoredHeader& header) noexcept
    {
        ::wknet::FreeNonPagedArray(header.Name);
        ::wknet::FreeNonPagedArray(header.Value);
        header = {};
    }

    SIZE_T FindHeader(const Headers& headers, const char* name, SIZE_T nameLength) noexcept
    {
        for (SIZE_T index = 0; index < headers.Count; ++index) {
            if (TextEqualsIgnoreCase(headers.Items[index].Name, headers.Items[index].NameLength, name, nameLength)) {
                return index;
            }
        }
        return headers.Count;
    }
}

NTSTATUS HeadersCreate(Headers** headers) noexcept
{
    if (headers != nullptr) {
        *headers = nullptr;
    }
    if (headers == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* created = ::wknet::AllocateNonPagedObject<Headers>();
    if (created == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    *headers = created;
    return STATUS_SUCCESS;
}

NTSTATUS HeadersAdd(Headers* headers, const char* name, const char* value) noexcept
{
    return HeadersAddEx(headers, name, StringLength(name), value, StringLength(value));
}

NTSTATUS HeadersAddEx(Headers* headers, const char* name, SIZE_T nameLength, const char* value, SIZE_T valueLength) noexcept
{
    if (headers == nullptr || headers->Magic != detail::HighHeadersMagic ||
        !IsValidHeaderName(name, nameLength) ||
        !IsValidHeaderValue(value, valueLength) ||
        IsControlledHeader(name, nameLength)) {
        return STATUS_INVALID_PARAMETER;
    }

    const SIZE_T slot = FindHeader(*headers, name, nameLength);
    if (slot == headers->Count && headers->Count >= ::wknet::session::MaxHeadersPerRequest) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    char* nameCopy = CopyText(name, nameLength);
    if (nameCopy == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    char* valueCopy = CopyText(value, valueLength);
    if (valueCopy == nullptr) {
        ::wknet::FreeNonPagedArray(nameCopy);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    detail::StoredHeader& item = headers->Items[slot];
    if (slot == headers->Count) {
        ++headers->Count;
    }
    else {
        ReleaseStoredHeader(item);
    }
    item.Name = nameCopy;
    item.NameLength = nameLength;
    item.Value = valueCopy;
    item.ValueLength = valueLength;
    return STATUS_SUCCESS;
}

void HeadersRelease(Headers* headers) noexcept
{
    if (headers == nullptr || headers->Magic != detail::HighHeadersMagic) {
        return;
    }
    for (SIZE_T index = 0; index < headers->Count; ++index) {
        ReleaseStoredHeader(headers->Items[index]);
    }
    headers->Count = 0;
    headers->Magic = 0;
    ::wknet::FreeNonPagedObject(headers);
}
}
