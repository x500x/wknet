#pragma once

#include "Types.h"

namespace KernelHttp
{
namespace khttp
{
    ULONG ResponseStatusCode(_In_opt_ const Response* response) noexcept;
    const UCHAR* ResponseBody(_In_opt_ const Response* response) noexcept;
    SIZE_T ResponseBodyLength(_In_opt_ const Response* response) noexcept;

    _Must_inspect_result_
    NTSTATUS ResponseGetHeader(
        _In_ const Response* response,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    void ResponseRelease(_In_opt_ Response* response) noexcept;
}
}
