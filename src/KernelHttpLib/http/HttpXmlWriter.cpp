#include "HttpXmlWriter.h"

namespace KernelHttp
{
namespace http
{
namespace
{
    _Must_inspect_result_
    bool IsAsciiAlpha(UCHAR value) noexcept
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
    }

    _Must_inspect_result_
    bool IsAsciiDigit(UCHAR value) noexcept
    {
        return value >= '0' && value <= '9';
    }

    _Must_inspect_result_
    bool IsXmlCodePoint(ULONG value) noexcept
    {
        return value == 0x09 ||
            value == 0x0a ||
            value == 0x0d ||
            (value >= 0x20 && value <= 0xd7ff) ||
            (value >= 0xe000 && value <= 0xfffd) ||
            (value >= 0x10000 && value <= 0x10ffff);
    }

    _Must_inspect_result_
    bool ReadUtf8CodePoint(HttpXmlText value, _Inout_ SIZE_T* offset, _Out_ ULONG* codePoint) noexcept
    {
        if (offset == nullptr || codePoint == nullptr || value.Data == nullptr || *offset >= value.Length) {
            return false;
        }

        const UCHAR first = static_cast<UCHAR>(value.Data[*offset]);
        ULONG parsed = 0;
        SIZE_T count = 0;
        if (first <= 0x7f) {
            parsed = first;
            count = 1;
        }
        else if (first >= 0xc2 && first <= 0xdf) {
            parsed = first & 0x1fU;
            count = 2;
        }
        else if (first >= 0xe0 && first <= 0xef) {
            parsed = first & 0x0fU;
            count = 3;
        }
        else if (first >= 0xf0 && first <= 0xf4) {
            parsed = first & 0x07U;
            count = 4;
        }
        else {
            return false;
        }
        if (count > value.Length - *offset) {
            return false;
        }
        for (SIZE_T index = 1; index < count; ++index) {
            const UCHAR continuation = static_cast<UCHAR>(value.Data[*offset + index]);
            if ((continuation & 0xc0U) != 0x80U) {
                return false;
            }
            parsed = (parsed << 6) | (continuation & 0x3fU);
        }
        if ((count == 3 && parsed < 0x800) ||
            (count == 4 && parsed < 0x10000) ||
            !IsXmlCodePoint(parsed)) {
            return false;
        }

        *offset += count;
        *codePoint = parsed;
        return true;
    }

    _Must_inspect_result_
    bool IsNameStartCodePoint(ULONG value) noexcept
    {
        return (value <= 0x7f && IsAsciiAlpha(static_cast<UCHAR>(value))) ||
            value == '_' ||
            (value >= 0xc0 && value <= 0xd6) ||
            (value >= 0xd8 && value <= 0xf6) ||
            (value >= 0xf8 && value <= 0x2ff) ||
            (value >= 0x370 && value <= 0x37d) ||
            (value >= 0x37f && value <= 0x1fff) ||
            (value >= 0x200c && value <= 0x200d) ||
            (value >= 0x2070 && value <= 0x218f) ||
            (value >= 0x2c00 && value <= 0x2fef) ||
            (value >= 0x3001 && value <= 0xd7ff) ||
            (value >= 0xf900 && value <= 0xfdcf) ||
            (value >= 0xfdf0 && value <= 0xfffd) ||
            (value >= 0x10000 && value <= 0xeffff);
    }

    _Must_inspect_result_
    bool IsNameCodePoint(ULONG value) noexcept
    {
        return IsNameStartCodePoint(value) ||
            (value <= 0x7f && IsAsciiDigit(static_cast<UCHAR>(value))) ||
            value == '-' ||
            value == '.' ||
            value == 0xb7 ||
            (value >= 0x300 && value <= 0x36f) ||
            (value >= 0x203f && value <= 0x2040);
    }

    _Must_inspect_result_
    SIZE_T LiteralLength(const char* value) noexcept
    {
        if (value == nullptr) {
            return 0;
        }
        SIZE_T length = 0;
        while (value[length] != '\0') {
            ++length;
        }
        return length;
    }

    _Must_inspect_result_
    bool TextContains(HttpXmlText value, const char* needle) noexcept
    {
        const SIZE_T needleLength = LiteralLength(needle);
        if (value.Data == nullptr || needleLength == 0 || needleLength > value.Length) {
            return false;
        }

        for (SIZE_T offset = 0; offset + needleLength <= value.Length; ++offset) {
            SIZE_T matched = 0;
            while (matched < needleLength && value.Data[offset + matched] == needle[matched]) {
                ++matched;
            }
            if (matched == needleLength) {
                return true;
            }
        }
        return false;
    }

    _Must_inspect_result_
    bool TextHasOnlyXmlBytes(HttpXmlText value) noexcept
    {
        if (value.Length != 0 && value.Data == nullptr) {
            return false;
        }
        SIZE_T offset = 0;
        while (offset < value.Length) {
            ULONG codePoint = 0;
            if (!ReadUtf8CodePoint(value, &offset, &codePoint)) {
                return false;
            }
        }
        return true;
    }
}

    HttpXmlWriter::HttpXmlWriter(char* buffer, SIZE_T capacity) noexcept :
        buffer_(buffer),
        capacity_(capacity)
    {
    }

    SIZE_T HttpXmlWriter::Length() const noexcept
    {
        return length_;
    }

    NTSTATUS HttpXmlWriter::WriteStartElement(HttpXmlName name) noexcept
    {
        NTSTATUS status = EnsureStartElementClosed();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!HttpXmlNameIsValid(name.LocalName) ||
            (name.Prefix.Length != 0 && !HttpXmlNameIsValid(name.Prefix))) {
            return STATUS_INVALID_PARAMETER;
        }

        status = AppendByte('<');
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendName(name);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        startElementOpen_ = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpXmlWriter::WriteNamespace(HttpXmlText prefix, HttpXmlText uri) noexcept
    {
        if (!startElementOpen_) {
            return STATUS_INVALID_PARAMETER;
        }
        if (prefix.Length != 0 && !HttpXmlNameIsValid(prefix)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = AppendLiteral(" xmlns");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (prefix.Length != 0) {
            status = AppendByte(':');
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendBytes(prefix.Data, prefix.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = AppendLiteral("=\"");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendEscapedAttribute(uri);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendByte('"');
    }

    NTSTATUS HttpXmlWriter::WriteAttribute(HttpXmlName name, HttpXmlText value) noexcept
    {
        if (!startElementOpen_ ||
            !HttpXmlNameIsValid(name.LocalName) ||
            (name.Prefix.Length != 0 && !HttpXmlNameIsValid(name.Prefix))) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = AppendByte(' ');
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendName(name);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLiteral("=\"");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendEscapedAttribute(value);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendByte('"');
    }

    NTSTATUS HttpXmlWriter::WriteQNameAttribute(HttpXmlName name, HttpXmlName value) noexcept
    {
        if (!startElementOpen_ ||
            !HttpXmlNameIsValid(name.LocalName) ||
            !HttpXmlNameIsValid(value.LocalName) ||
            (name.Prefix.Length != 0 && !HttpXmlNameIsValid(name.Prefix)) ||
            (value.Prefix.Length != 0 && !HttpXmlNameIsValid(value.Prefix))) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = AppendByte(' ');
        if (NT_SUCCESS(status)) {
            status = AppendName(name);
        }
        if (NT_SUCCESS(status)) {
            status = AppendLiteral("=\"");
        }
        if (NT_SUCCESS(status)) {
            status = AppendName(value);
        }
        if (NT_SUCCESS(status)) {
            status = AppendByte('"');
        }
        return status;
    }

    NTSTATUS HttpXmlWriter::WriteEndStartElement() noexcept
    {
        if (!startElementOpen_) {
            return STATUS_SUCCESS;
        }
        startElementOpen_ = false;
        return AppendByte('>');
    }

    NTSTATUS HttpXmlWriter::WriteEmptyElementEnd() noexcept
    {
        if (!startElementOpen_) {
            return STATUS_INVALID_PARAMETER;
        }
        startElementOpen_ = false;
        return AppendLiteral("/>");
    }

    NTSTATUS HttpXmlWriter::WriteEndElement(HttpXmlName name) noexcept
    {
        NTSTATUS status = EnsureStartElementClosed();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!HttpXmlNameIsValid(name.LocalName) ||
            (name.Prefix.Length != 0 && !HttpXmlNameIsValid(name.Prefix))) {
            return STATUS_INVALID_PARAMETER;
        }

        status = AppendLiteral("</");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendName(name);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendByte('>');
    }

    NTSTATUS HttpXmlWriter::WriteCharacters(HttpXmlText value) noexcept
    {
        NTSTATUS status = EnsureStartElementClosed();
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendEscapedText(value);
    }

    NTSTATUS HttpXmlWriter::WriteComment(HttpXmlText value) noexcept
    {
        NTSTATUS status = EnsureStartElementClosed();
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (!TextHasOnlyXmlBytes(value) ||
            TextContains(value, "--") ||
            (value.Length != 0 && value.Data != nullptr && value.Data[value.Length - 1] == '-')) {
            return STATUS_INVALID_PARAMETER;
        }

        status = AppendLiteral("<!--");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBytes(value.Data, value.Length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendLiteral("-->");
    }

    NTSTATUS HttpXmlWriter::WriteProcessingInstruction(HttpXmlText target, HttpXmlText value) noexcept
    {
        NTSTATUS status = EnsureStartElementClosed();
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (!HttpXmlNameIsValid(target) ||
            HttpXmlTextEqualsAsciiIgnoreCase(target, "xml") ||
            !TextHasOnlyXmlBytes(value) ||
            TextContains(value, "?>")) {
            return STATUS_INVALID_PARAMETER;
        }

        status = AppendLiteral("<?");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBytes(target.Data, target.Length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (value.Length != 0) {
            status = AppendByte(' ');
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendBytes(value.Data, value.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return AppendLiteral("?>");
    }

    NTSTATUS HttpXmlWriter::WriteDtd(
        HttpXmlText name,
        HttpXmlText publicId,
        HttpXmlText systemId,
        HttpXmlText text) noexcept
    {
        NTSTATUS status = EnsureStartElementClosed();
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (!HttpXmlNameIsValid(name) ||
            !TextHasOnlyXmlBytes(publicId) ||
            !TextHasOnlyXmlBytes(systemId) ||
            !TextHasOnlyXmlBytes(text) ||
            TextContains(text, "]>")) {
            return STATUS_INVALID_PARAMETER;
        }

        status = AppendLiteral("<!DOCTYPE ");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBytes(name.Data, name.Length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (publicId.Length != 0) {
            if (systemId.Length == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            status = AppendLiteral(" PUBLIC ");
            if (NT_SUCCESS(status)) {
                status = AppendQuotedLiteral(publicId);
            }
            if (NT_SUCCESS(status)) {
                status = AppendByte(' ');
            }
            if (NT_SUCCESS(status)) {
                status = AppendQuotedLiteral(systemId);
            }
        }
        else if (systemId.Length != 0) {
            status = AppendLiteral(" SYSTEM ");
            if (NT_SUCCESS(status)) {
                status = AppendQuotedLiteral(systemId);
            }
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (text.Length != 0) {
            status = AppendLiteral(" [");
            if (NT_SUCCESS(status)) {
                status = AppendBytes(text.Data, text.Length);
            }
            if (NT_SUCCESS(status)) {
                status = AppendByte(']');
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return AppendByte('>');
    }

    NTSTATUS HttpXmlWriter::WriteEntityReference(HttpXmlText name) noexcept
    {
        NTSTATUS status = EnsureStartElementClosed();
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (!HttpXmlNameIsValid(name)) {
            return STATUS_INVALID_PARAMETER;
        }
        status = AppendByte('&');
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBytes(name.Data, name.Length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendByte(';');
    }

    NTSTATUS HttpXmlWriter::EnsureStartElementClosed() noexcept
    {
        return WriteEndStartElement();
    }

    NTSTATUS HttpXmlWriter::AppendByte(char value) noexcept
    {
        if (buffer_ == nullptr || length_ >= capacity_) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        buffer_[length_] = value;
        ++length_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpXmlWriter::AppendQuotedLiteral(HttpXmlText value) noexcept
    {
        char quote = '"';
        if (TextContains(value, "\"")) {
            if (TextContains(value, "'")) {
                return STATUS_INVALID_PARAMETER;
            }
            quote = '\'';
        }
        NTSTATUS status = AppendByte(quote);
        if (NT_SUCCESS(status)) {
            status = AppendBytes(value.Data, value.Length);
        }
        if (NT_SUCCESS(status)) {
            status = AppendByte(quote);
        }
        return status;
    }

    NTSTATUS HttpXmlWriter::AppendBytes(const char* value, SIZE_T valueLength) noexcept
    {
        if (valueLength == 0) {
            return STATUS_SUCCESS;
        }
        if (value == nullptr || buffer_ == nullptr || valueLength > capacity_ || length_ > capacity_ - valueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(buffer_ + length_, value, valueLength);
        length_ += valueLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpXmlWriter::AppendLiteral(const char* value) noexcept
    {
        return AppendBytes(value, LiteralLength(value));
    }

    NTSTATUS HttpXmlWriter::AppendName(HttpXmlName name) noexcept
    {
        if (name.Prefix.Length != 0) {
            NTSTATUS status = AppendBytes(name.Prefix.Data, name.Prefix.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendByte(':');
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return AppendBytes(name.LocalName.Data, name.LocalName.Length);
    }

    NTSTATUS HttpXmlWriter::AppendEscapedText(HttpXmlText value) noexcept
    {
        if (!TextHasOnlyXmlBytes(value)) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T index = 0; index < value.Length; ++index) {
            const UCHAR byte = static_cast<UCHAR>(value.Data[index]);

            NTSTATUS status = STATUS_SUCCESS;
            switch (byte) {
            case '&':
                status = AppendLiteral("&amp;");
                break;
            case '<':
                status = AppendLiteral("&lt;");
                break;
            case '>':
                status = AppendLiteral("&gt;");
                break;
            default:
                status = AppendByte(static_cast<char>(byte));
                break;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpXmlWriter::AppendEscapedAttribute(HttpXmlText value) noexcept
    {
        if (!TextHasOnlyXmlBytes(value)) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T index = 0; index < value.Length; ++index) {
            const UCHAR byte = static_cast<UCHAR>(value.Data[index]);

            NTSTATUS status = STATUS_SUCCESS;
            switch (byte) {
            case '&':
                status = AppendLiteral("&amp;");
                break;
            case '<':
                status = AppendLiteral("&lt;");
                break;
            case '"':
                status = AppendLiteral("&quot;");
                break;
            case '\t':
                status = AppendLiteral("&#x9;");
                break;
            case '\n':
                status = AppendLiteral("&#xA;");
                break;
            case '\r':
                status = AppendLiteral("&#xD;");
                break;
            default:
                status = AppendByte(static_cast<char>(byte));
                break;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    bool HttpXmlTextEqualsAsciiIgnoreCase(HttpXmlText value, const char* ascii) noexcept
    {
        const SIZE_T asciiLength = LiteralLength(ascii);
        if (value.Data == nullptr || value.Length != asciiLength) {
            return false;
        }
        for (SIZE_T index = 0; index < asciiLength; ++index) {
            UCHAR left = static_cast<UCHAR>(value.Data[index]);
            const UCHAR right = static_cast<UCHAR>(ascii[index]);
            if (left >= 'A' && left <= 'Z') {
                left = static_cast<UCHAR>(left + ('a' - 'A'));
            }
            if (left != right) {
                return false;
            }
        }
        return true;
    }

    bool HttpXmlNameIsValid(HttpXmlText value) noexcept
    {
        if (value.Data == nullptr || value.Length == 0) {
            return false;
        }
        SIZE_T offset = 0;
        ULONG codePoint = 0;
        if (!ReadUtf8CodePoint(value, &offset, &codePoint) || !IsNameStartCodePoint(codePoint)) {
            return false;
        }
        while (offset < value.Length) {
            if (!ReadUtf8CodePoint(value, &offset, &codePoint) || !IsNameCodePoint(codePoint)) {
                return false;
            }
        }
        return true;
    }
}
}
