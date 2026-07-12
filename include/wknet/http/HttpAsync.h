#pragma once

#include <wknet/http/Body.h>
#include <wknet/http/Headers.h>
#include <wknet/http/Options.h>
#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS AsyncSend(_In_ Session* session, Method method, _In_z_ const char* url, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncSendEx(_In_ Session* session, Method method, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncSend(_In_ Request* request, Method method, _In_z_ const char* url, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncSendEx(_In_ Request* request, Method method, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGet(_In_ Session* session, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncGetEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPost(_In_ Session* session, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPostEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPut(_In_ Session* session, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPutEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPatch(_In_ Session* session, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPatchEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncDelete(_In_ Session* session, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncDeleteEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncHead(_In_ Session* session, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncHeadEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncOptionsRequest(_In_ Session* session, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncOptionsRequestEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncTrace(_In_ Session* session, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncTraceEx(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGet(_In_ Request* request, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncGetEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPost(_In_ Request* request, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPostEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPut(_In_ Request* request, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPutEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPatch(_In_ Request* request, _In_z_ const char* url, _In_opt_ const Body* body, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncPatchEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const Body* body, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncDelete(_In_ Request* request, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncDeleteEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncHead(_In_ Request* request, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncHeadEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncOptionsRequest(_In_ Request* request, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncOptionsRequestEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncTrace(_In_ Request* request, _In_z_ const char* url, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS AsyncTraceEx(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_opt_ const Headers* headers, _In_opt_ const AsyncOptions* options, _Out_ AsyncOp** operation) noexcept;

#if defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS GetAsync(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS PostAsync(_In_ Session* session, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength, _In_reads_bytes_opt_(bodyLength) const UCHAR* body, SIZE_T bodyLength, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS SendAsync(_In_ Session* session, _In_ Request* request, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS SendAsync(_In_ Session* session, _In_ Request* request, _In_opt_ const SendOptions* options, _Out_ AsyncOp** operation) noexcept;
    _Must_inspect_result_
    NTSTATUS SendAsyncEx(_In_ Session* session, _In_ Request* request, _In_opt_ const SendOptions* options, _Out_ AsyncOp** operation) noexcept;
#endif
}
