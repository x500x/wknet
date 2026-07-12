#include <wknet/codec/Codec.h>

#include "codec/ContentCoding.h"
#include "codec/ExiDecoder.h"
#include "codec/Pack200Decoder.h"

namespace wknet::codec
{
bool DeflateRuntimeAvailable() noexcept
{
    return ContentCoding::DeflateRuntimeAvailable();
}

NTSTATUS DecodeOne(
    Coding coding,
    const char* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength,
    const DecodeMaterials* materials) noexcept
{
    WKNET_TRACE(
        ::wknet::ComponentCodec,
        ::wknet::TraceLevel::Verbose,
        "codec.decode_one.start coding=%u input_bytes=%Iu output_capacity=%Iu",
        static_cast<ULONG>(coding),
        sourceLength,
        destinationCapacity);
    const NTSTATUS status = ContentCoding::DecodeOne(
        coding,
        source,
        sourceLength,
        destination,
        destinationCapacity,
        decodedLength,
        materials);
    if (NT_SUCCESS(status)) {
        WKNET_TRACE(
            ::wknet::ComponentCodec,
            ::wknet::TraceLevel::Info,
            "codec.decode_one.complete coding=%u input_bytes=%Iu output_bytes=%Iu",
            static_cast<ULONG>(coding),
            sourceLength,
            decodedLength != nullptr ? *decodedLength : static_cast<SIZE_T>(0));
    }
    else {
        WKNET_TRACE(
            ::wknet::ComponentCodec,
            ::wknet::TraceLevel::Error,
            "codec.decode_one.failed coding=%u status=0x%08X input_bytes=%Iu",
            static_cast<ULONG>(coding),
            static_cast<ULONG>(status),
            sourceLength);
    }
    return status;
}

NTSTATUS DecodeChain(
    const Coding* codings,
    SIZE_T codingCount,
    const char* body,
    SIZE_T bodyLength,
    const DecodeBuffers& buffers,
    DecodeResult& result) noexcept
{
    WKNET_TRACE(
        ::wknet::ComponentCodec,
        ::wknet::TraceLevel::Verbose,
        "codec.decode_chain.start codings=%Iu input_bytes=%Iu",
        codingCount,
        bodyLength);
    const NTSTATUS status = ContentCoding::DecodeChainReverse(
        codings,
        codingCount,
        body,
        bodyLength,
        buffers,
        result);
    WKNET_TRACE(
        ::wknet::ComponentCodec,
        NT_SUCCESS(status) ? ::wknet::TraceLevel::Info : ::wknet::TraceLevel::Error,
        NT_SUCCESS(status) ? "codec.decode_chain.complete codings=%Iu output_bytes=%Iu" :
            "codec.decode_chain.failed codings=%Iu status=0x%08X",
        codingCount,
        NT_SUCCESS(status) ? result.BodyLength : static_cast<SIZE_T>(static_cast<ULONG>(status)));
    return status;
}

NTSTATUS DecodeExi(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    const NTSTATUS status = DecodeExiContent(source, sourceLength, destination, destinationCapacity, decodedLength);
    WKNET_TRACE(
        ::wknet::ComponentCodec,
        NT_SUCCESS(status) ? ::wknet::TraceLevel::Info : ::wknet::TraceLevel::Error,
        NT_SUCCESS(status) ? "codec.exi.complete input_bytes=%Iu output_bytes=%Iu" :
            "codec.exi.failed input_bytes=%Iu status=0x%08X",
        sourceLength,
        NT_SUCCESS(status) ? (decodedLength != nullptr ? *decodedLength : static_cast<SIZE_T>(0)) :
            static_cast<SIZE_T>(static_cast<ULONG>(status)));
    return status;
}

NTSTATUS DecodePack200(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    const NTSTATUS status = DecodePack200GzipContent(source, sourceLength, destination, destinationCapacity, decodedLength);
    WKNET_TRACE(
        ::wknet::ComponentCodec,
        NT_SUCCESS(status) ? ::wknet::TraceLevel::Info : ::wknet::TraceLevel::Error,
        NT_SUCCESS(status) ? "codec.pack200.complete input_bytes=%Iu output_bytes=%Iu" :
            "codec.pack200.failed input_bytes=%Iu status=0x%08X",
        sourceLength,
        NT_SUCCESS(status) ? (decodedLength != nullptr ? *decodedLength : static_cast<SIZE_T>(0)) :
            static_cast<SIZE_T>(static_cast<ULONG>(status)));
    return status;
}
}
