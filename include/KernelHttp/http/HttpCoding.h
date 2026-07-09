#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace http
{
    enum class HttpCoding : UCHAR
    {
        Identity,
        Gzip,
        Deflate,
        Brotli,
        Compress,
        Zstd,
        DictionaryCompressedBrotli,
        DictionaryCompressedZstd,
        Aes128Gcm,
        Exi,
        Pack200Gzip
    };

    struct HttpCodingDecodeBuffers final
    {
        char* DecodedBody = nullptr;
        SIZE_T DecodedBodyCapacity = 0;
        char* ScratchBody = nullptr;
        SIZE_T ScratchBodyCapacity = 0;
    };

    struct HttpCodingDecodeResult final
    {
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool AppliedCoding = false;
    };

    class HttpCodingCodec final
    {
    public:
        HttpCodingCodec() = delete;

        _Must_inspect_result_
        static bool DeflateRuntimeAvailable() noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeOne(
            HttpCoding coding,
            _In_reads_bytes_(sourceLength) const char* source,
            SIZE_T sourceLength,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* decodedLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeChainReverse(
            _In_reads_(codingCount) const HttpCoding* codings,
            SIZE_T codingCount,
            _In_reads_bytes_(bodyLength) const char* body,
            SIZE_T bodyLength,
            _In_ const HttpCodingDecodeBuffers& buffers,
            _Out_ HttpCodingDecodeResult& result) noexcept;
    };
}
}
