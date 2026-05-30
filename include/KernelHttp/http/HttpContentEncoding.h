#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace http
{
    struct HttpContentDecodeBuffers final
    {
        char* DecodedBody = nullptr;
        SIZE_T DecodedBodyCapacity = 0;
        char* ScratchBody = nullptr;
        SIZE_T ScratchBodyCapacity = 0;
    };

    struct HttpContentDecodeResult final
    {
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool AppliedContentCoding = false;
    };

    class HttpContentEncoding final
    {
    public:
        HttpContentEncoding() = delete;

        _Must_inspect_result_
        static NTSTATUS Decode(
            _In_reads_(headerCount) const HttpHeader* headers,
            SIZE_T headerCount,
            _In_reads_bytes_(bodyLength) const char* body,
            SIZE_T bodyLength,
            _In_ const HttpContentDecodeBuffers& buffers,
            _Out_ HttpContentDecodeResult& result) noexcept;
    };
}
}
