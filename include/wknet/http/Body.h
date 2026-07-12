#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS BodyCreateBytes(_In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateBytesEx(_In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateBytesCopy(_In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateBytesCopyEx(_In_reads_bytes_opt_(dataLength) const UCHAR* data, SIZE_T dataLength, _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyCreateText(_In_reads_bytes_opt_(textLength) const char* text, SIZE_T textLength, _In_opt_ const char* contentType, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateTextEx(_In_reads_bytes_opt_(textLength) const char* text, SIZE_T textLength, _In_reads_bytes_opt_(contentTypeLength) const char* contentType, SIZE_T contentTypeLength, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateTextCopy(_In_reads_bytes_opt_(textLength) const char* text, SIZE_T textLength, _In_opt_ const char* contentType, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateTextCopyEx(_In_reads_bytes_opt_(textLength) const char* text, SIZE_T textLength, _In_reads_bytes_opt_(contentTypeLength) const char* contentType, SIZE_T contentTypeLength, _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyCreateJson(_In_reads_bytes_opt_(jsonLength) const char* json, SIZE_T jsonLength, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateJsonEx(_In_reads_bytes_opt_(jsonLength) const char* json, SIZE_T jsonLength, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateJsonCopy(_In_reads_bytes_opt_(jsonLength) const char* json, SIZE_T jsonLength, _Out_ Body** body) noexcept;
    _Must_inspect_result_
    NTSTATUS BodyCreateJsonCopyEx(_In_reads_bytes_opt_(jsonLength) const char* json, SIZE_T jsonLength, _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyCreateForm(_In_reads_(pairCount) const NameValuePair* pairs, SIZE_T pairCount, _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyCreateMultipart(_In_reads_(partCount) const MultipartPart* parts, SIZE_T partCount, _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyCreateFile(_In_z_ const char* filePath, _In_opt_ const char* contentType, _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyCreateFileEx(
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength,
        _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyCreateStream(
        _In_ RequestBodyReadCallback callback,
        _In_opt_ void* context,
        SIZE_T contentLength,
        bool contentLengthKnown,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength,
        _Out_ Body** body) noexcept;

    _Must_inspect_result_
    NTSTATUS BodySetMode(_In_ Body* body, RequestBodyMode mode) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyAddTrailer(_In_ Body* body, _In_z_ const char* name, _In_z_ const char* value) noexcept;

    _Must_inspect_result_
    NTSTATUS BodyAddTrailerEx(
        _In_ Body* body,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    void BodyRelease(_In_opt_ Body* body) noexcept;
}
