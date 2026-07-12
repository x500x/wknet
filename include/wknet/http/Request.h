#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS RequestCreate(_In_ Session* session, _Out_ Request** out) noexcept;

    void RequestRelease(_In_opt_ Request* request) noexcept;

#if defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS RequestSetUrl(_In_ Request* request, _In_reads_bytes_(urlLength) const char* url, SIZE_T urlLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetMethod(_In_ Request* request, Method method) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetHeader(_In_ Request* request, _In_reads_bytes_(nameLength) const char* name, SIZE_T nameLength, _In_reads_bytes_(valueLength) const char* value, SIZE_T valueLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetRangeBytes(_In_ Request* request, ULONGLONG firstByte, ULONGLONG lastByte, bool hasLastByte) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetRangeSuffix(_In_ Request* request, ULONGLONG suffixLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetIfMatch(_In_ Request* request, _In_reads_bytes_(valueLength) const char* value, SIZE_T valueLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetIfNoneMatch(_In_ Request* request, _In_reads_bytes_(valueLength) const char* value, SIZE_T valueLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetIfModifiedSince(_In_ Request* request, _In_reads_bytes_(valueLength) const char* value, SIZE_T valueLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetIfUnmodifiedSince(_In_ Request* request, _In_reads_bytes_(valueLength) const char* value, SIZE_T valueLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetBody(_In_ Request* request, _In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetBodyMode(_In_ Request* request, RequestBodyMode mode) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestAddTrailer(_In_ Request* request, _In_reads_bytes_(nameLength) const char* name, SIZE_T nameLength, _In_reads_bytes_(valueLength) const char* value, SIZE_T valueLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestClearBody(_In_ Request* request) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetTextBody(_In_ Request* request, _In_reads_bytes_opt_(textLength) const char* text, SIZE_T textLength, _In_reads_bytes_opt_(contentTypeLength) const char* contentType, SIZE_T contentTypeLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetJsonBody(_In_ Request* request, _In_reads_bytes_opt_(jsonLength) const char* json, SIZE_T jsonLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetRawBody(_In_ Request* request, _In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength, _In_reads_bytes_opt_(contentTypeLength) const char* contentType, SIZE_T contentTypeLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetFormBody(_In_ Request* request, _In_reads_(pairCount) const NameValuePair* pairs, SIZE_T pairCount) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetMultipartBody(_In_ Request* request, _In_reads_(partCount) const MultipartPart* parts, SIZE_T partCount) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetFileBody(_In_ Request* request, _In_reads_bytes_(filePathLength) const char* filePath, SIZE_T filePathLength, _In_reads_bytes_opt_(contentTypeLength) const char* contentType, SIZE_T contentTypeLength) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetTls(_In_ Request* request, _In_ const TlsConfig* config) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetConnPolicy(_In_ Request* request, ConnPolicy policy) noexcept;
    _Must_inspect_result_
    NTSTATUS RequestSetAddressFamily(_In_ Request* request, AddressFamily family) noexcept;
#endif
}
