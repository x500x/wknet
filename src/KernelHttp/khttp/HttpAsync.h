#pragma once

#include "Types.h"

namespace KernelHttp
{
namespace khttp
{
    _Must_inspect_result_
    NTSTATUS GetAsync(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS PostAsync(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
        SIZE_T bodyLength,
        _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS SendAsync(
        _In_ Session* session,
        _In_ Request* request,
        _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS SendAsyncEx(
        _In_ Session* session,
        _In_ Request* request,
        _In_opt_ const SendOptions* options,
        _Out_ AsyncOp** operation) noexcept;
}
}
