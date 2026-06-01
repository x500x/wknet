#pragma once

#include <KernelHttp/engine/HandleTypes.h>

namespace KernelHttp
{
namespace engine
{
    _Must_inspect_result_
    NTSTATUS ParseUrlIntoRequest(
        _Inout_ KhRequest& request,
        const char* url,
        SIZE_T urlLength) noexcept;

    _Must_inspect_result_
    NTSTATUS ParseUrlParts(
        const char* url,
        SIZE_T urlLength,
        bool websocketUrl,
        _Out_writes_bytes_(schemeCapacity) char* scheme,
        SIZE_T schemeCapacity,
        _Out_ SIZE_T* schemeLength,
        _Out_writes_bytes_(hostCapacity) char* host,
        SIZE_T hostCapacity,
        _Out_ SIZE_T* hostLength,
        _Out_writes_bytes_(pathCapacity) char* path,
        SIZE_T pathCapacity,
        _Out_ SIZE_T* pathLength,
        _Out_ USHORT* port) noexcept;
}
}
