#pragma once

// Public content-coding / EXI / Pack200 decode surface.
// Scope:
// - EXI: W3C EXI 1.0 Second Edition schema-less streams only (external Schema/strict grammar
//   returns STATUS_NOT_SUPPORTED). Output is Infoset-equivalent XML.
// - Pack200: Java 5-8 stable formats 150.7/160.1/170.1/171.0; output is a semantically
//   equivalent JAR (raw or gzip-wrapped Pack200 input).

#include <wknet/WknetConfig.h>

namespace wknet::codec
{
    enum class Coding : UCHAR
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
        Pack200Gzip = 10
    };

    struct ExternalMaterial final
    {
        Coding CodingKind = Coding::Identity;
        const UCHAR* Dictionary = nullptr;
        SIZE_T DictionaryLength = 0;
        const UCHAR* Aes128GcmKeyingMaterial = nullptr;
        SIZE_T Aes128GcmKeyingMaterialLength = 0;
    };

    using MaterialCallback = NTSTATUS(*)(
        _In_opt_ void* context,
        Coding coding,
        _Out_ ExternalMaterial* material);

    struct DecodeMaterials final
    {
        const ExternalMaterial* Items = nullptr;
        SIZE_T ItemCount = 0;
        MaterialCallback Callback = nullptr;
        void* CallbackContext = nullptr;
    };

    struct DecodeBuffers final
    {
        char* DecodedBody = nullptr;
        SIZE_T DecodedBodyCapacity = 0;
        char* ScratchBody = nullptr;
        SIZE_T ScratchBodyCapacity = 0;
        const DecodeMaterials* Materials = nullptr;
    };

    struct DecodeResult final
    {
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool AppliedCoding = false;
    };

    _Must_inspect_result_
    bool DeflateRuntimeAvailable() noexcept;

    // Decode a single content-coding into destination.
    _Must_inspect_result_
    NTSTATUS DecodeOne(
        Coding coding,
        _In_reads_bytes_(sourceLength) const char* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength,
        _In_opt_ const DecodeMaterials* materials = nullptr) noexcept;

    // Apply codings in reverse list order (as Content-Encoding lists are decoded).
    _Must_inspect_result_
    NTSTATUS DecodeChain(
        _In_reads_(codingCount) const Coding* codings,
        SIZE_T codingCount,
        _In_reads_bytes_(bodyLength) const char* body,
        SIZE_T bodyLength,
        _In_ const DecodeBuffers& buffers,
        _Out_ DecodeResult& result) noexcept;

    // Schema-less EXI 1.0 → Infoset-equivalent XML.
    _Must_inspect_result_
    NTSTATUS DecodeExi(
        _In_reads_bytes_(sourceLength) const UCHAR* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength) noexcept;

    // Pack200 (raw or gzip) → JAR bytes.
    _Must_inspect_result_
    NTSTATUS DecodePack200(
        _In_reads_bytes_(sourceLength) const UCHAR* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength) noexcept;
}
