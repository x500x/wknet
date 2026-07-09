#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace http
{
    constexpr SIZE_T HttpMaxAcceptEncodingPreferences = 8;
    constexpr USHORT HttpAcceptEncodingQValueMax = 1000;

    enum class HttpAcceptCoding : UCHAR
    {
        Identity = 0,
        Gzip = 1,
        Deflate = 2,
        Brotli = 3,
        Compress = 4,
        Any = 5
    };

    struct HttpAcceptEncodingPreference final
    {
        HttpAcceptCoding Coding = HttpAcceptCoding::Identity;
        // RFC qvalue scaled by 1000. 1000 means q=1, 0 means not acceptable.
        USHORT QValue = HttpAcceptEncodingQValueMax;
    };

    struct HttpAcceptEncodingPolicy final
    {
        const HttpAcceptEncodingPreference* Preferences = nullptr;
        SIZE_T PreferenceCount = 0;
    };

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
            _Out_ HttpContentDecodeResult& result,
            _In_opt_ const HttpAcceptEncodingPolicy* acceptPolicy = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS ValidateAcceptEncodingPreferences(
            _In_reads_(preferenceCount) const HttpAcceptEncodingPreference* preferences,
            SIZE_T preferenceCount) noexcept;

        _Must_inspect_result_
        static NTSTATUS BuildAcceptEncodingHeader(
            _In_reads_(preferenceCount) const HttpAcceptEncodingPreference* preferences,
            SIZE_T preferenceCount,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_ HttpText* value) noexcept;
    };
}
}
