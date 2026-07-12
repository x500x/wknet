#pragma once

#include "http1/HttpTypes.h"
#include "HttpPack200Bands.h"
#include "HttpPack200Codec.h"
#include "HttpPack200AttributeLayout.h"

namespace wknet
{
namespace http1
{
    _Must_inspect_result_
    NTSTATUS HttpPack200ReadCpBands(
        _Inout_ HttpPack200BandReader* reader,
        _Inout_ HttpPack200BandReader* bandHeaderReader,
        _Inout_ HttpPack200CodecArena* arena,
        const HttpPack200CpCounts& counts,
        _Inout_ HttpPack200CpBands* bands) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadFileBands(
        _Inout_ HttpPack200BandReader* reader,
        _Inout_ HttpPack200BandReader* bandHeaderReader,
        _Inout_ HttpPack200CodecArena* arena,
        SIZE_T fileCount,
        bool haveSizeHigh,
        bool haveModtime,
        bool haveOptions,
        _Inout_ HttpPack200FileBands* bands) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadClassBands(
        _Inout_ HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        SIZE_T classCount,
        _Inout_ HttpPack200ClassBands* bands) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadClassBandsWithMeta(
        _Inout_ HttpPack200BandReader* reader,
        _Inout_ HttpPack200BandReader* bandHeaderReader,
        _Inout_ HttpPack200CodecArena* arena,
        SIZE_T classCount,
        bool haveClassFlagsHigh,
        bool haveFieldFlagsHigh,
        bool haveMethodFlagsHigh,
        bool allCodeHasFlags,
        bool haveCodeFlagsHigh,
        _Inout_ HttpPack200ClassBands* bands,
        _In_opt_ const HttpPack200CpBands* cpBands = nullptr,
        _In_opt_ const HttpPack200AttributeDefinitionBands* attributeDefinitions = nullptr,
        _Inout_opt_ HttpPack200CustomAttributeStore* customAttributes = nullptr) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadCodeBands(
        _Inout_ HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        SIZE_T codeCount,
        _Inout_ HttpPack200CodeBands* bands) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadBytecodeBands(
        _Inout_ HttpPack200BandReader* reader,
        _Inout_ HttpPack200BandReader* bandHeaderReader,
        _Inout_ HttpPack200CodecArena* arena,
        SIZE_T codeCount,
        _Inout_ HttpPack200CodeBands* bands) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadAttributeBands(
        _Inout_ HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        SIZE_T attributeLayoutCount,
        _Inout_ HttpPack200AttributeBands* bands) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadAttributeDefinitionBands(
        _Inout_ HttpPack200BandReader* reader,
        _Inout_ HttpPack200BandReader* bandHeaderReader,
        _Inout_ HttpPack200CodecArena* arena,
        SIZE_T definitionCount,
        SIZE_T utf8Count,
        _Inout_ HttpPack200AttributeDefinitionBands* bands) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ReadInnerClassBands(
        _Inout_ HttpPack200BandReader* reader,
        _Inout_ HttpPack200BandReader* bandHeaderReader,
        _Inout_ HttpPack200CodecArena* arena,
        SIZE_T innerClassCount,
        SIZE_T classCount,
        SIZE_T utf8Count,
        _Inout_ HttpPack200InnerClassBands* bands) noexcept;
}
}
