#pragma once

#include "Types.h"

namespace KernelHttp
{
namespace khttp
{
    _Must_inspect_result_
    NTSTATUS Get(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Post(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
        SIZE_T bodyLength,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Put(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
        SIZE_T bodyLength,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Patch(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
        SIZE_T bodyLength,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Delete(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Head(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Options(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Send(
        _In_ Session* session,
        _In_ Request* request,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS SendEx(
        _In_ Session* session,
        _In_ Request* request,
        _In_opt_ const SendOptions* options,
        _Out_opt_ Response** response) noexcept;
}
}
