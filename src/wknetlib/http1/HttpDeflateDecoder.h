#pragma once

#include "http1/HttpTypes.h"

namespace wknet
{
namespace http1
{
    _Must_inspect_result_
    NTSTATUS HttpDecodeRawDeflate(
        _In_reads_bytes_(compressedLength) const UCHAR* compressed,
        SIZE_T compressedLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength) noexcept;
}
}
