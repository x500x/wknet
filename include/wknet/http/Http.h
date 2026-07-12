#pragma once

#include <wknet/http/Body.h>
#include <wknet/http/Headers.h>
#include <wknet/http/Options.h>
#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS Send(
        _In_ Session* session,
        Method method,
        _In_z_ const char* url,
        _In_opt_ const Headers* headers,
        _In_opt_ const Body* body,
        _In_opt_ const SendOptions* options,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS SendEx(
        _In_ Session* session,
        Method method,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _In_opt_ const Headers* headers,
        _In_opt_ const Body* body,
        _In_opt_ const SendOptions* options,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Send(
        _In_ Request* request,
        Method method,
        _In_z_ const char* url,
        _In_opt_ const Headers* headers,
        _In_opt_ const Body* body,
        _In_opt_ const SendOptions* options,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS SendEx(
        _In_ Request* request,
        Method method,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _In_opt_ const Headers* headers,
        _In_opt_ const Body* body,
        _In_opt_ const SendOptions* options,
        _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Get(_In_ Session* session, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS GetEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Post(_In_ Session* session, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS PostEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Put(_In_ Session* session, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS PutEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Patch(_In_ Session* session, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS PatchEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Delete(_In_ Session* session, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS DeleteEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Head(_In_ Session* session, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS HeadEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Options(_In_ Session* session, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS OptionsEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Trace(_In_ Session* session, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS TraceEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS Get(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Post(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_reads_bytes_opt_(bodyLength) const UCHAR* body, SIZE_T bodyLength, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Put(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_reads_bytes_opt_(bodyLength) const UCHAR* body, SIZE_T bodyLength, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Patch(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_reads_bytes_opt_(bodyLength) const UCHAR* body, SIZE_T bodyLength, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Delete(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Head(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Options(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Trace(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _Out_ Response** response) noexcept;

#if defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS Send(_In_ Session* session, _In_ Request* request, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Send(_In_ Session* session, _In_ Request* request, _In_opt_ const SendOptions* options, _Out_opt_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS SendEx(_In_ Session* session, _In_ Request* request, _In_opt_ const SendOptions* options, _Out_opt_ Response** response) noexcept;
#endif

    _Must_inspect_result_
    NTSTATUS Get(_In_ Request* request, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS GetEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Post(_In_ Request* request, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS PostEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Put(_In_ Request* request, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS PutEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Patch(_In_ Request* request, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS PatchEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Delete(_In_ Request* request, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS DeleteEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Head(_In_ Request* request, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS HeadEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Options(_In_ Request* request, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS OptionsEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS Trace(_In_ Request* request, _In_z_ const char* url, _Out_ Response** response) noexcept;
    _Must_inspect_result_
    NTSTATUS TraceEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const SendOptions* options, _Out_ Response** response) noexcept;
}
