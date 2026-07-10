#pragma once

#include <KernelHttp/http/HttpTypes.h>
#include "HttpExiGrammar.h"
#include "HttpExiStringTable.h"

namespace KernelHttp
{
namespace http
{
    enum class HttpExiInputMode : UCHAR
    {
        BitPacked,
        ByteAligned
    };

    class HttpExiBitInput final
    {
    public:
        HttpExiBitInput(
            const UCHAR* data,
            SIZE_T length,
            HttpExiInputMode mode = HttpExiInputMode::BitPacked,
            SIZE_T initialBitOffset = 0) noexcept;

        void Reset(
            const UCHAR* data,
            SIZE_T length,
            HttpExiInputMode mode = HttpExiInputMode::BitPacked,
            SIZE_T initialBitOffset = 0) noexcept;

        _Must_inspect_result_
        bool ReadBits(UCHAR bitCount, _Out_ ULONG* value) noexcept;

        _Must_inspect_result_
        bool AlignByte() noexcept;

        _Must_inspect_result_
        bool ReadByte(_Out_ UCHAR* value) noexcept;

        _Must_inspect_result_
        bool ReadUnsignedInteger(_Out_ ULONG* value) noexcept;

        _Must_inspect_result_
        SIZE_T ByteOffset() const noexcept;

        _Must_inspect_result_
        SIZE_T BitOffset() const noexcept;

        _Must_inspect_result_
        SIZE_T ByteLength() const noexcept;

        _Must_inspect_result_
        HttpExiInputMode Mode() const noexcept;

        _Must_inspect_result_
        bool AtEnd() const noexcept;

    private:
        const UCHAR* data_ = nullptr;
        SIZE_T length_ = 0;
        SIZE_T bitOffset_ = 0;
        HttpExiInputMode mode_ = HttpExiInputMode::BitPacked;
    };

    struct HttpExiEventCode final
    {
        ULONG Value = 0;
        UCHAR Width = 0;
    };

    _Must_inspect_result_
    bool HttpExiBitsForProductionCount(ULONG productionCount, _Out_ UCHAR* bitCount) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadEventCode(
        _Inout_ HttpExiBitInput* input,
        HttpExiGrammarKind grammar,
        bool preserveComments,
        bool preservePis,
        bool preserveDtd,
        bool preservePrefixes,
        bool preserveSelfContained,
        _Out_ HttpExiEventCode* eventCode,
        _Out_ HttpExiProduction* production) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadLiteralString(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiStringTable* valueTable,
        _Out_ HttpXmlText* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadStringOnly(
        _Inout_ HttpExiBitInput* input,
        ULONG codePointLength,
        _Inout_ HttpExiStringTable* stringTable,
        _Out_ HttpXmlText* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadValueString(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiStringTable* valueTable,
        _Out_ HttpXmlText* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadValueString(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiValueTable* valueTable,
        ULONG qnameId,
        _Out_ HttpXmlText* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadStringTableReference(
        _Inout_ HttpExiBitInput* input,
        const HttpExiStringTable& valueTable,
        _Out_ HttpXmlText* value) noexcept;
}
}
