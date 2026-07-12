#pragma once

#include "http1/HttpTypes.h"
#include "HttpPack200Codec.h"
#include "HttpXmlWriter.h"

namespace wknet
{
namespace http1
{
    enum class HttpPack200AttributeElementKind : UCHAR
    {
        Sequence,
        Callable,
        Integral,
        Reference,
        Replication,
        Union,
        UnionCase,
        Call,
    };

    enum class HttpPack200AttributeBciKind : UCHAR
    {
        None,
        Index,
        Offset,
        PreviousOffset,
    };

    enum class HttpPack200AttributeReferenceKind : UCHAR
    {
        None,
        Integer,
        Long,
        Float,
        Double,
        String,
        FieldSpecific,
        Class,
        Signature,
        Descriptor,
        Field,
        Method,
        InterfaceMethod,
        Utf8,
        Loadable,
        MethodHandle,
        MethodType,
        Any,
        AnyMember,
        BootstrapMethod,
        InvokeDynamic,
    };

    struct HttpPack200AttributeBandDescriptor final
    {
        HttpPack200CodingKind Coding = HttpPack200CodingKind::Unsigned5;
        HttpPack200AttributeReferenceKind ReferenceKind = HttpPack200AttributeReferenceKind::None;
        UCHAR OutputSize = 0;
        bool Nullable = false;
    };

    struct HttpPack200AttributeLayoutElement final
    {
        HttpPack200AttributeElementKind Kind = HttpPack200AttributeElementKind::Sequence;
        HttpPack200AttributeBciKind BciKind = HttpPack200AttributeBciKind::None;
        HttpPack200AttributeReferenceKind ReferenceKind = HttpPack200AttributeReferenceKind::None;
        ULONG FirstChild = 0xffffffffUL;
        ULONG NextSibling = 0xffffffffUL;
        ULONG BandIndex = 0xffffffffUL;
        ULONG SelectorOffset = 0;
        ULONG SelectorCount = 0;
        LONG CallOffset = 0;
        ULONG TargetCallable = 0xffffffffUL;
        ULONG CallableIndex = 0xffffffffUL;
        UCHAR OutputSize = 0;
        bool Signed = false;
        bool Nullable = false;
        bool BackwardCall = false;
    };

    struct HttpPack200AttributeCallable final
    {
        ULONG ElementIndex = 0xffffffffUL;
        bool HasBackwardCall = false;
    };

    struct HttpPack200AttributeSelectorRange final
    {
        LONG First = 0;
        LONG Last = 0;
    };

    struct HttpPack200AttributeRelocation final
    {
        SIZE_T Offset = 0;
        LONG Value = 0;
        HttpPack200AttributeReferenceKind ReferenceKind = HttpPack200AttributeReferenceKind::None;
        HttpPack200AttributeBciKind BciKind = HttpPack200AttributeBciKind::None;
        UCHAR Size = 0;
        bool Nullable = false;
        bool Signed = false;
    };

    using HttpPack200AttributeBandDecoder = NTSTATUS(*)(
        _Inout_ void* context,
        HttpPack200CodingKind coding,
        _Out_writes_(valueCount) LONG* values,
        SIZE_T valueCount);

    class HttpPack200AttributeLayout final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Compile(HttpXmlText layout) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        SIZE_T ElementCount() const noexcept;

        _Must_inspect_result_
        SIZE_T BandCount() const noexcept;

        _Must_inspect_result_
        SIZE_T CallableCount() const noexcept;

        _Must_inspect_result_
        SIZE_T BackwardCallableCount() const noexcept;

        _Ret_maybenull_
        const HttpPack200AttributeLayoutElement* Elements() const noexcept;

        _Ret_maybenull_
        const HttpPack200AttributeBandDescriptor* Bands() const noexcept;

        _Ret_maybenull_
        const HttpPack200AttributeCallable* Callables() const noexcept;

        _Ret_maybenull_
        const HttpPack200AttributeSelectorRange* SelectorRanges() const noexcept;

        _Must_inspect_result_
        SIZE_T SelectorCount() const noexcept;

    private:
        HeapArray<HttpPack200AttributeLayoutElement> elements_ = {};
        HeapArray<HttpPack200AttributeBandDescriptor> bands_ = {};
        HeapArray<HttpPack200AttributeCallable> callables_ = {};
        HeapArray<HttpPack200AttributeSelectorRange> selectorRanges_ = {};
        SIZE_T elementCount_ = 0;
        SIZE_T bandCount_ = 0;
        SIZE_T callableCount_ = 0;
        SIZE_T selectorCount_ = 0;
        SIZE_T backwardCallableCount_ = 0;
    };

    class HttpPack200AttributeValueBands final
    {
    public:
        ~HttpPack200AttributeValueBands() noexcept;

        _Must_inspect_result_
        NTSTATUS Decode(
            const HttpPack200AttributeLayout& layout,
            SIZE_T occurrenceCount,
            _In_reads_(backwardCallCount) const ULONG* backwardCalls,
            SIZE_T backwardCallCount,
            HttpPack200AttributeBandDecoder decoder,
            _Inout_ void* decoderContext) noexcept;

        _Must_inspect_result_
        NTSTATUS Measure(
            const HttpPack200AttributeLayout& layout,
            SIZE_T occurrenceCount,
            _Out_writes_(occurrenceCount) SIZE_T* payloadLengths,
            _Out_writes_(occurrenceCount) SIZE_T* relocationCounts) noexcept;

        _Must_inspect_result_
        NTSTATUS Emit(
            const HttpPack200AttributeLayout& layout,
            SIZE_T occurrenceCount,
            _In_reads_(occurrenceCount) const SIZE_T* payloadOffsets,
            _In_reads_(occurrenceCount) const SIZE_T* payloadLengths,
            _In_reads_(occurrenceCount) const SIZE_T* relocationOffsets,
            _In_reads_(occurrenceCount) const SIZE_T* relocationCounts,
            _Out_writes_bytes_(payloadCapacity) UCHAR* payload,
            SIZE_T payloadCapacity,
            _Out_writes_(relocationCapacity) HttpPack200AttributeRelocation* relocations,
            SIZE_T relocationCapacity) noexcept;

        void Reset() noexcept;

    private:
        struct BandData final
        {
            LONG* Values = nullptr;
            SIZE_T Count = 0;
            SIZE_T Cursor = 0;
        };

        HeapArray<BandData> bands_ = {};
    };

    struct HttpPack200CustomAttributeOccurrence final
    {
        ULONG Context = 0;
        ULONG OwnerIndex = 0;
        ULONG DefinitionIndex = 0;
        ULONG AttributeIndex = 0;
        ULONG NameUtf8Index = 0;
        SIZE_T PayloadOffset = 0;
        SIZE_T PayloadLength = 0;
        SIZE_T RelocationOffset = 0;
        SIZE_T RelocationCount = 0;
    };

    class HttpPack200CustomAttributeStore final
    {
    public:
        ~HttpPack200CustomAttributeStore() noexcept;

        _Must_inspect_result_
        NTSTATUS AppendOccurrence(
            ULONG context,
            ULONG ownerIndex,
            ULONG definitionIndex,
            ULONG attributeIndex,
            ULONG nameUtf8Index) noexcept;

        _Must_inspect_result_
        NTSTATUS ReservePayload(SIZE_T length, _Out_ SIZE_T* offset) noexcept;

        _Must_inspect_result_
        NTSTATUS ReserveRelocations(SIZE_T count, _Out_ SIZE_T* offset) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_ SIZE_T OccurrenceCount() const noexcept;
        _Ret_maybenull_ HttpPack200CustomAttributeOccurrence* Occurrences() noexcept;
        _Ret_maybenull_ const HttpPack200CustomAttributeOccurrence* Occurrences() const noexcept;
        _Ret_maybenull_ UCHAR* Payload() noexcept;
        _Ret_maybenull_ const UCHAR* Payload() const noexcept;
        _Must_inspect_result_ SIZE_T PayloadLength() const noexcept;
        _Ret_maybenull_ HttpPack200AttributeRelocation* Relocations() noexcept;
        _Ret_maybenull_ const HttpPack200AttributeRelocation* Relocations() const noexcept;
        _Must_inspect_result_ SIZE_T RelocationCount() const noexcept;

    private:
        HttpPack200CustomAttributeOccurrence* occurrences_ = nullptr;
        SIZE_T occurrenceCount_ = 0;
        SIZE_T occurrenceCapacity_ = 0;
        UCHAR* payload_ = nullptr;
        SIZE_T payloadLength_ = 0;
        SIZE_T payloadCapacity_ = 0;
        HttpPack200AttributeRelocation* relocations_ = nullptr;
        SIZE_T relocationCount_ = 0;
        SIZE_T relocationCapacity_ = 0;
    };
}
}
