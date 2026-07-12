#pragma once

#include "http1/HttpTypes.h"
#include "HttpPack200BandCodec.h"

namespace wknet
{
namespace http1
{
    enum class HttpPack200BandCodecKind : UCHAR
    {
        Canonical,
        Run,
        Population,
        Adaptive
    };

    struct HttpPack200BandCodec final
    {
        HttpPack200BandCodecKind Kind = HttpPack200BandCodecKind::Canonical;
        HttpPack200Coding Canonical = HttpPack200CodingFor(HttpPack200CodingKind::Unsigned5);
        const HttpPack200BandCodec* First = nullptr;
        const HttpPack200BandCodec* Second = nullptr;
        const HttpPack200BandCodec* Third = nullptr;
        ULONG FirstCount = 0;
        UCHAR TokenDefL = 0;
    };

    class HttpPack200CodecArena final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxCodecs) noexcept;

        void Reset() noexcept;

        void Rewind() noexcept;

        _Must_inspect_result_
        NTSTATUS Allocate(_Outptr_ HttpPack200BandCodec** codec) noexcept;

    private:
        HeapArray<HttpPack200BandCodec> codecs_ = {};
        SIZE_T codecCount_ = 0;
    };

    _Must_inspect_result_
    NTSTATUS HttpPack200ParseMetaCodec(
        _Inout_ HttpPack200BandReader* reader,
        _Out_ HttpPack200BandCodec* codec) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200ParseMetaCodec(
        _Inout_ HttpPack200BandReader* reader,
        HttpPack200Coding defaultCoding,
        SIZE_T valueCount,
        _Inout_ HttpPack200CodecArena* arena,
        _Outptr_ const HttpPack200BandCodec** codec) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200DecodeBand(
        _Inout_ HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        _Out_writes_(valueCount) LONG* values,
        SIZE_T valueCount) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200DecodeBandWithMeta(
        _Inout_ HttpPack200BandReader* reader,
        _Inout_ HttpPack200BandReader* bandHeaderReader,
        HttpPack200Coding defaultCoding,
        _Out_writes_(valueCount) LONG* values,
        SIZE_T valueCount,
        _Inout_ HttpPack200CodecArena* arena) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpPack200DecodePopulationBand(
        _Inout_ HttpPack200BandReader* tokenReader,
        const LONG* favouredValues,
        SIZE_T favouredCount,
        _Out_writes_(valueCount) LONG* values,
        SIZE_T valueCount) noexcept;
}
}
