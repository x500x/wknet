#pragma once

#include "codec/CodecInternal.h"
#include "ExiEventReader.h"

namespace wknet
{
namespace codec
{
    enum class HttpExiAlignment : UCHAR
    {
        BitPacked,
        ByteAligned,
        PreCompression,
        Compression
    };

    struct HttpExiOptions final
    {
        HttpExiAlignment Alignment = HttpExiAlignment::BitPacked;
        bool HasCookie = false;
        bool HasOptions = false;
        bool Fragment = false;
        bool Strict = false;
        bool PreserveComments = false;
        bool PreservePis = false;
        bool PreserveDtd = false;
        bool PreservePrefixes = false;
        bool PreserveLexicalValues = false;
        bool SelfContained = false;
        bool HasSchemaId = false;
        bool BuiltInSchemaTypesOnly = false;
        ULONG BlockSize = 1000000;
        ULONG ValueMaxLength = 0xffffffffUL;
        ULONG ValuePartitionCapacity = 0xffffffffUL;
    };

    _Must_inspect_result_
    NTSTATUS HttpExiParseHeader(
        _In_reads_bytes_(sourceLength) const UCHAR* source,
        SIZE_T sourceLength,
        _Out_ HttpExiOptions* options,
        _Out_ SIZE_T* bodyBitOffset) noexcept;
}
}
