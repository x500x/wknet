#pragma once

#include "codec/CodecInternal.h"

namespace wknet
{
namespace codec
{
    struct HttpXmlText final
    {
        const char* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct HttpXmlName final
    {
        HttpXmlText Uri = {};
        HttpXmlText Prefix = {};
        HttpXmlText LocalName = {};
    };

    class HttpXmlWriter final
    {
    public:
        HttpXmlWriter(_Out_writes_bytes_(capacity) char* buffer, SIZE_T capacity) noexcept;

        _Must_inspect_result_
        SIZE_T Length() const noexcept;

        _Must_inspect_result_
        NTSTATUS WriteStartElement(HttpXmlName name) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteNamespace(HttpXmlText prefix, HttpXmlText uri) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteAttribute(HttpXmlName name, HttpXmlText value) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteQNameAttribute(HttpXmlName name, HttpXmlName value) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteEndStartElement() noexcept;

        _Must_inspect_result_
        NTSTATUS WriteEmptyElementEnd() noexcept;

        _Must_inspect_result_
        NTSTATUS WriteEndElement(HttpXmlName name) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteCharacters(HttpXmlText value) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteComment(HttpXmlText value) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteProcessingInstruction(HttpXmlText target, HttpXmlText value) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteDtd(
            HttpXmlText name,
            HttpXmlText publicId,
            HttpXmlText systemId,
            HttpXmlText text) noexcept;

        _Must_inspect_result_
        NTSTATUS WriteEntityReference(HttpXmlText name) noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS EnsureStartElementClosed() noexcept;

        _Must_inspect_result_
        NTSTATUS AppendByte(char value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendBytes(const char* value, SIZE_T valueLength) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendLiteral(const char* value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendName(HttpXmlName name) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendEscapedText(HttpXmlText value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendQuotedLiteral(HttpXmlText value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendEscapedAttribute(HttpXmlText value) noexcept;

        char* buffer_ = nullptr;
        SIZE_T capacity_ = 0;
        SIZE_T length_ = 0;
        bool startElementOpen_ = false;
    };

    _Must_inspect_result_
    bool HttpXmlTextEqualsAsciiIgnoreCase(HttpXmlText value, const char* ascii) noexcept;

    _Must_inspect_result_
    bool HttpXmlNameIsValid(HttpXmlText value) noexcept;
}
}
