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
    return ContentCoding::DecodeOne(
        coding,
        source,
        sourceLength,
        destination,
        destinationCapacity,
        decodedLength,
        materials);
}

NTSTATUS DecodeChain(
    const Coding* codings,
    SIZE_T codingCount,
    const char* body,
    SIZE_T bodyLength,
    const DecodeBuffers& buffers,
    DecodeResult& result) noexcept
{
    return ContentCoding::DecodeChainReverse(
        codings,
        codingCount,
        body,
        bodyLength,
        buffers,
        result);
}

NTSTATUS DecodeExi(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    return DecodeExiContent(source, sourceLength, destination, destinationCapacity, decodedLength);
}

NTSTATUS DecodePack200(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    return DecodePack200GzipContent(source, sourceLength, destination, destinationCapacity, decodedLength);
}
}
