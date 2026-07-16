#pragma once

#include "http1/HttpContentEncoding.h"
#include "http1/HttpResponse.h"

namespace wknet
{
namespace http1
{
    struct HttpParseOptions final
    {
        HttpHeader* Headers = nullptr;
        SIZE_T HeaderCapacity = 0;
        HttpHeader* Trailers = nullptr;
        SIZE_T TrailerCapacity = 0;
        char* DecodedBody = nullptr;
        SIZE_T DecodedBodyCapacity = 0;
        char* ScratchBody = nullptr;
        SIZE_T ScratchBodyCapacity = 0;
        bool MessageCompleteOnConnectionClose = false;
        bool ResponseBodyForbidden = false;
        const HttpAcceptEncodingPolicy* AcceptEncodingPolicy = nullptr;
        const codec::DecodeMaterials* ContentCodingMaterials = nullptr;
    };

    class HttpParser final
    {
    public:
        HttpParser() = delete;

        // Full response parse (headers + transfer-decoded body + content-coding).
        _Must_inspect_result_
        static NTSTATUS ParseResponse(
            _In_reads_bytes_(dataLength) const char* data,
            SIZE_T dataLength,
            _In_ const HttpParseOptions& options,
            _Inout_ HttpResponse& response) noexcept;

        // Headers-only parse for streaming body consumers.
        // On success: response headers filled, BodyKind set, BytesConsumed = header block end
        // (including final CRLF), Body/BodyLength left empty. ContentLength (if CL framed)
        // is returned via optional out parameter.
        // STATUS_MORE_PROCESSING_REQUIRED if header block incomplete.
        _Must_inspect_result_
        static NTSTATUS ParseResponseHeaders(
            _In_reads_bytes_(dataLength) const char* data,
            SIZE_T dataLength,
            _In_ const HttpParseOptions& options,
            _Inout_ HttpResponse& response,
            _Out_opt_ SIZE_T* contentLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeChunkedBody(
            _In_reads_bytes_(dataLength) const char* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(decodedBodyCapacity) char* decodedBody,
            SIZE_T decodedBodyCapacity,
            _Out_ SIZE_T* decodedBodyLength,
            _Out_ SIZE_T* bytesConsumed) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeChunkedBodyWithTrailers(
            _In_reads_bytes_(dataLength) const char* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(decodedBodyCapacity) char* decodedBody,
            SIZE_T decodedBodyCapacity,
            _Out_writes_(trailerCapacity) HttpHeader* trailers,
            SIZE_T trailerCapacity,
            _Out_ SIZE_T* decodedBodyLength,
            _Out_ SIZE_T* bytesConsumed,
            _Out_ SIZE_T* trailerCount) noexcept;
    };
}
}
