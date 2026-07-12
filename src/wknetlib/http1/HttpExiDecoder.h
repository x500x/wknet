#pragma once

#include <wknet/http1/HttpTypes.h>

namespace wknet
{
namespace http1
{
    _Must_inspect_result_
    NTSTATUS DecodeExiContent(
        _In_reads_bytes_(sourceLength) const UCHAR* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength) noexcept;
}
}
