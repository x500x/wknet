#pragma once

#include <wknet/codec/Codec.h>
#include "http1/HttpTypes.h"

namespace wknet
{
namespace http1
{
    constexpr SIZE_T HttpMaxAcceptEncodingPreferences = 8;
    constexpr SIZE_T HttpMaxAcceptEncodingEntries = 16;
    constexpr USHORT HttpAcceptEncodingQValueMax = 1000;

    enum class HttpAcceptCoding : UCHAR
    {
        Identity = 0,
        Gzip = 1,
        Deflate = 2,
        Brotli = 3,
        Compress = 4,
        Zstd = 5,
        DictionaryCompressedBrotli = 6,
        DictionaryCompressedZstd = 7,
        Aes128Gcm = 8,
        Exi = 9,
        Pack200Gzip = 10,
        Any = 11,
        Extension = 12
    };

    struct HttpAcceptEncodingPreference final
    {
        HttpAcceptCoding Coding = HttpAcceptCoding::Identity;
        // RFC qvalue scaled by 1000. 1000 means q=1, 0 means not acceptable.
        USHORT QValue = HttpAcceptEncodingQValueMax;
    };

    struct HttpAcceptEncodingEntry final
    {
        HttpText Token = {};
        HttpAcceptCoding Coding = HttpAcceptCoding::Identity;
        USHORT QValue = HttpAcceptEncodingQValueMax;
        SIZE_T Order = 0;
        bool Wildcard = false;
        bool Extension = false;
    };

    struct HttpAcceptEncodingRules final
    {
        HttpAcceptEncodingEntry* Entries = nullptr;
        SIZE_T EntryCapacity = 0;
        SIZE_T EntryCount = 0;
        bool EmptyHeader = false;
    };

    struct HttpAcceptEncodingPolicy final
    {
        const HttpAcceptEncodingPreference* Preferences = nullptr;
        SIZE_T PreferenceCount = 0;
        const HttpAcceptEncodingRules* Rules = nullptr;
    };

    struct HttpContentDecodeBuffers final
    {
        char* DecodedBody = nullptr;
        SIZE_T DecodedBodyCapacity = 0;
        char* ScratchBody = nullptr;
        SIZE_T ScratchBodyCapacity = 0;
        const codec::DecodeMaterials* Materials = nullptr;
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

        _Must_inspect_result_
        static NTSTATUS ParseAcceptEncoding(
            HttpText value,
            _Inout_ HttpAcceptEncodingRules* rules) noexcept;

        _Must_inspect_result_
        static NTSTATUS BuildAcceptEncodingRulesFromPreferences(
            _In_reads_(preferenceCount) const HttpAcceptEncodingPreference* preferences,
            SIZE_T preferenceCount,
            _Inout_ HttpAcceptEncodingRules* rules) noexcept;

        _Must_inspect_result_
        static NTSTATUS IsContentCodingAcceptable(
            _In_ const HttpAcceptEncodingRules* rules,
            HttpText coding,
            _Out_ bool* acceptable,
            _Out_opt_ USHORT* qvalue = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS NegotiateContentCoding(
            _In_ const HttpAcceptEncodingRules* rules,
            _In_reads_(codingCount) const HttpText* serverCodings,
            SIZE_T codingCount,
            _Out_ HttpText* selected,
            _Out_opt_ USHORT* qvalue = nullptr) noexcept;
    };
}
}
