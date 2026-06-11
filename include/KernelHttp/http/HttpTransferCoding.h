#pragma once

#include <KernelHttp/http/HttpCoding.h>
#include <KernelHttp/http/HttpResponse.h>

namespace KernelHttp
{
namespace http
{
    constexpr SIZE_T HttpMaxTransferCodings = 4;

    enum class HttpTransferCodingKind : UCHAR
    {
        Chunked,
        Gzip,
        Deflate,
        Compress
    };

    struct HttpTransferCodingInfo final
    {
        HttpTransferCodingKind Coding0 = HttpTransferCodingKind::Chunked;
        HttpTransferCodingKind Coding1 = HttpTransferCodingKind::Chunked;
        HttpTransferCodingKind Coding2 = HttpTransferCodingKind::Chunked;
        HttpTransferCodingKind Coding3 = HttpTransferCodingKind::Chunked;
        SIZE_T CodingCount = 0;
        bool HasTransferEncoding = false;
        bool FinalCodingIsChunked = false;
    };

    struct HttpTransferDecodeResult final
    {
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        SIZE_T BytesConsumed = 0;
        HttpBodyKind BodyKind = HttpBodyKind::None;
    };

    class HttpTransferCoding final
    {
    public:
        HttpTransferCoding() = delete;

        _Must_inspect_result_
        static NTSTATUS Parse(
            _In_reads_(headerCount) const HttpHeader* headers,
            SIZE_T headerCount,
            _Out_ HttpTransferCodingInfo& info) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeResponseBody(
            _In_ const HttpTransferCodingInfo& info,
            _In_reads_bytes_(wireBodyLength) const char* wireBody,
            SIZE_T wireBodyLength,
            bool messageCompleteOnConnectionClose,
            _In_ const HttpCodingDecodeBuffers& buffers,
            _Out_writes_(trailerCapacity) HttpHeader* trailers,
            SIZE_T trailerCapacity,
            _Out_opt_ SIZE_T* trailerCount,
            _Out_ HttpTransferDecodeResult& result) noexcept;
    };
}
}
