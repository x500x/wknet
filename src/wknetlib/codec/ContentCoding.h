#pragma once

#include <wknet/codec/Codec.h>

namespace wknet::codec
{
    class ContentCoding final
    {
    public:
        ContentCoding() = delete;

        _Must_inspect_result_
        static bool DeflateRuntimeAvailable() noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeOne(
            Coding coding,
            _In_reads_bytes_(sourceLength) const char* source,
            SIZE_T sourceLength,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* decodedLength,
            _In_opt_ const DecodeMaterials* materials = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeChainReverse(
            _In_reads_(codingCount) const Coding* codings,
            SIZE_T codingCount,
            _In_reads_bytes_(bodyLength) const char* body,
            SIZE_T bodyLength,
            _In_ const DecodeBuffers& buffers,
            _Out_ DecodeResult& result) noexcept;
    };
}
