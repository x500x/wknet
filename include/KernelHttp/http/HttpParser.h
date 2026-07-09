#pragma once

#include <KernelHttp/http/HttpContentEncoding.h>
#include <KernelHttp/http/HttpResponse.h>

namespace KernelHttp
{
namespace http
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
    };

    class HttpParser final
    {
    public:
        HttpParser() = delete;

        _Must_inspect_result_
        static NTSTATUS ParseResponse(
            _In_reads_bytes_(dataLength) const char* data,
            SIZE_T dataLength,
            _In_ const HttpParseOptions& options,
            _Inout_ HttpResponse& response) noexcept;

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
