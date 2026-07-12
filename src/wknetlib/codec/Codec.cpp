#include <wknet/codec/Codec.h>

#include <wknet/http1/HttpCoding.h>
#include "../http1/HttpExiDecoder.h"
#include "../http1/HttpPack200Decoder.h"

namespace wknet::codec
{
namespace
{
    static_assert(static_cast<UCHAR>(Coding::Identity) == static_cast<UCHAR>(http1::HttpCoding::Identity), "coding enum mismatch");
    static_assert(static_cast<UCHAR>(Coding::Pack200Gzip) == static_cast<UCHAR>(http1::HttpCoding::Pack200Gzip), "coding enum mismatch");

    http1::HttpCoding ToHttpCoding(Coding coding) noexcept
    {
        return static_cast<http1::HttpCoding>(coding);
    }

    const http1::HttpCodingDecodeMaterials* ToHttpMaterials(
        const DecodeMaterials* materials) noexcept
    {
        // Public ExternalMaterial/DecodeMaterials match http1 layouts field-for-field.
        return reinterpret_cast<const http1::HttpCodingDecodeMaterials*>(materials);
    }
}

_Must_inspect_result_
bool DeflateRuntimeAvailable() noexcept
{
    return http1::HttpCodingCodec::DeflateRuntimeAvailable();
}

_Must_inspect_result_
NTSTATUS DecodeOne(
    Coding coding,
    _In_reads_bytes_(sourceLength) const char* source,
    SIZE_T sourceLength,
    _Out_writes_bytes_(destinationCapacity) char* destination,
    SIZE_T destinationCapacity,
    _Out_ SIZE_T* decodedLength,
    _In_opt_ const DecodeMaterials* materials) noexcept
{
    return http1::HttpCodingCodec::DecodeOne(
        ToHttpCoding(coding),
        source,
        sourceLength,
        destination,
        destinationCapacity,
        decodedLength,
        ToHttpMaterials(materials));
}

_Must_inspect_result_
NTSTATUS DecodeChain(
    _In_reads_(codingCount) const Coding* codings,
    SIZE_T codingCount,
    _In_reads_bytes_(bodyLength) const char* body,
    SIZE_T bodyLength,
    _In_ const DecodeBuffers& buffers,
    _Out_ DecodeResult& result) noexcept
{
    result = {};
    if (codingCount != 0 && codings == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    http1::HttpCodingDecodeBuffers httpBuffers = {};
    httpBuffers.DecodedBody = buffers.DecodedBody;
    httpBuffers.DecodedBodyCapacity = buffers.DecodedBodyCapacity;
    httpBuffers.ScratchBody = buffers.ScratchBody;
    httpBuffers.ScratchBodyCapacity = buffers.ScratchBodyCapacity;
    httpBuffers.Materials = ToHttpMaterials(buffers.Materials);

    http1::HttpCodingDecodeResult httpResult = {};
    const auto* httpCodings = reinterpret_cast<const http1::HttpCoding*>(codings);
    const NTSTATUS status = http1::HttpCodingCodec::DecodeChainReverse(
        httpCodings,
        codingCount,
        body,
        bodyLength,
        httpBuffers,
        httpResult);
    if (NT_SUCCESS(status)) {
        result.Body = httpResult.Body;
        result.BodyLength = httpResult.BodyLength;
        result.AppliedCoding = httpResult.AppliedCoding;
    }
    return status;
}

_Must_inspect_result_
NTSTATUS DecodeExi(
    _In_reads_bytes_(sourceLength) const UCHAR* source,
    SIZE_T sourceLength,
    _Out_writes_bytes_(destinationCapacity) char* destination,
    SIZE_T destinationCapacity,
    _Out_ SIZE_T* decodedLength) noexcept
{
    return http1::DecodeExiContent(
        source,
        sourceLength,
        destination,
        destinationCapacity,
        decodedLength);
}

_Must_inspect_result_
NTSTATUS DecodePack200(
    _In_reads_bytes_(sourceLength) const UCHAR* source,
    SIZE_T sourceLength,
    _Out_writes_bytes_(destinationCapacity) char* destination,
    SIZE_T destinationCapacity,
    _Out_ SIZE_T* decodedLength) noexcept
{
    return http1::DecodePack200GzipContent(
        source,
        sourceLength,
        destination,
        destinationCapacity,
        decodedLength);
}
}
