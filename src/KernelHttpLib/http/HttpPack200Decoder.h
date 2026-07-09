#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace http
{
    _Must_inspect_result_
    NTSTATUS DecodePack200GzipContent(
        _In_reads_bytes_(sourceLength) const UCHAR* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength) noexcept;
}
}
