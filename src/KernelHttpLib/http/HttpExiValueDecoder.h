#pragma once

#include <KernelHttp/http/HttpTypes.h>
#include "HttpExiEventReader.h"

namespace KernelHttp
{
namespace http
{
    struct HttpExiDecimalValue final
    {
        bool Negative = false;
        ULONG Integral = 0;
        ULONG Fractional = 0;
    };

    struct HttpExiFloatValue final
    {
        LONG Mantissa = 0;
        LONG Exponent = 0;
    };

    enum class HttpExiDatatypeKind : UCHAR
    {
        None,
        Boolean,
        Integer,
        Decimal,
        Float,
        Base64Binary,
        HexBinary,
        String,
        Byte,
        Short,
        Int,
        Long,
        UnsignedByte,
        UnsignedShort,
        UnsignedInt,
        UnsignedLong,
        NonNegativeInteger,
        PositiveInteger,
        GYear,
        GYearMonth,
        Date,
        DateTime,
        GMonth,
        GMonthDay,
        GDay,
        Time
    };

    _Must_inspect_result_
    NTSTATUS HttpExiReadBoolean(_Inout_ HttpExiBitInput* input, _Out_ bool* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadInteger(_Inout_ HttpExiBitInput* input, _Out_ LONG* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadDecimal(_Inout_ HttpExiBitInput* input, _Out_ HttpExiDecimalValue* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadFloat(_Inout_ HttpExiBitInput* input, _Out_ HttpExiFloatValue* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadTypedValue(
        _Inout_ HttpExiBitInput* input,
        HttpExiDatatypeKind datatype,
        _Inout_ HeapArray<char>* storage,
        _Out_ HttpXmlText* value) noexcept;
}
}
