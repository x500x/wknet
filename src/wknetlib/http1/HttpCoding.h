#pragma once

#include "http1/HttpTypes.h"

namespace wknet
{
namespace http1
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

    struct HttpCodingExternalMaterial final
    {
        HttpCoding Coding = HttpCoding::Identity;
        const UCHAR* Dictionary = nullptr;
        SIZE_T DictionaryLength = 0;
        const UCHAR* Aes128GcmKeyingMaterial = nullptr;
        SIZE_T Aes128GcmKeyingMaterialLength = 0;
    };

    using HttpCodingMaterialCallback = NTSTATUS(*)(
        _In_opt_ void* context,
        HttpCoding coding,
        _Out_ HttpCodingExternalMaterial* material);

    struct HttpCodingDecodeMaterials final
    {
        const HttpCodingExternalMaterial* Items = nullptr;
        SIZE_T ItemCount = 0;
        HttpCodingMaterialCallback Callback = nullptr;
        void* CallbackContext = nullptr;
    };

    struct HttpCodingDecodeBuffers final
    {
        char* DecodedBody = nullptr;
        SIZE_T DecodedBodyCapacity = 0;
        char* ScratchBody = nullptr;
        SIZE_T ScratchBodyCapacity = 0;
        const HttpCodingDecodeMaterials* Materials = nullptr;
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
            _Out_ SIZE_T* decodedLength,
            _In_opt_ const HttpCodingDecodeMaterials* materials = nullptr) noexcept;

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
