#include "Pack200AttributeLayout.h"

namespace wknet
{
namespace codec
{
namespace
{
    constexpr ULONG NoIndex = 0xffffffffUL;
    constexpr SIZE_T MaximumLayoutLength = 64 * 1024;

    enum class ParseFrameKind : UCHAR
    {
        Sequence,
        Union,
    };

    struct ParseFrame final
    {
        ParseFrameKind Kind = ParseFrameKind::Sequence;
        ULONG Parent = NoIndex;
        ULONG LastChild = NoIndex;
        ULONG CallableIndex = NoIndex;
        bool HasClosingBracket = false;
        bool SawDefaultUnionCase = false;
    };

    struct DemandFrame final
    {
        ULONG NextElement = NoIndex;
        SIZE_T Count = 0;
    };

    struct ExecutionFrame final
    {
        ULONG NextElement = NoIndex;
        ULONG RepeatStart = NoIndex;
        SIZE_T Remaining = 1;
    };

    constexpr SIZE_T MaximumExecutionFrames = 4096;
    constexpr SIZE_T MaximumExecutionSteps = 16 * 1024 * 1024;

    _Must_inspect_result_
    bool CheckedAddSize(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
    {
        if (result == nullptr || right > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - left) {
            return false;
        }
        *result = left + right;
        return true;
    }

    _Must_inspect_result_
    bool IsWidth(char value) noexcept
    {
        return value == 'B' || value == 'H' || value == 'I' || value == 'V';
    }

    _Must_inspect_result_
    UCHAR WidthBytes(char value) noexcept
    {
        switch (value) {
        case 'B': return 1;
        case 'H': return 2;
        case 'I': return 4;
        default: return 0;
        }
    }

    _Must_inspect_result_
    bool ParseSignedNumber(
        const char* data,
        SIZE_T length,
        _Inout_ SIZE_T* position,
        _Out_ LONG* value) noexcept
    {
        if (data == nullptr || position == nullptr || value == nullptr || *position >= length) {
            return false;
        }
        bool negative = false;
        if (data[*position] == '-') {
            negative = true;
            ++(*position);
        }
        if (*position >= length || data[*position] < '0' || data[*position] > '9') {
            return false;
        }
        ULONG magnitude = 0;
        while (*position < length && data[*position] >= '0' && data[*position] <= '9') {
            const ULONG digit = static_cast<ULONG>(data[*position] - '0');
            if (magnitude > (0x80000000UL - digit) / 10UL) {
                return false;
            }
            magnitude = magnitude * 10UL + digit;
            ++(*position);
        }
        if (negative) {
            if (magnitude > 0x80000000UL) {
                return false;
            }
            *value = magnitude == 0x80000000UL ? static_cast<LONG>(0x80000000UL) :
                -static_cast<LONG>(magnitude);
        }
        else {
            if (magnitude > 0x7fffffffUL) {
                return false;
            }
            *value = static_cast<LONG>(magnitude);
        }
        return true;
    }

    _Must_inspect_result_
    bool SelectorRangeContains(
        const HttpPack200AttributeSelectorRange& range,
        LONG value) noexcept
    {
        return value >= range.First && value <= range.Last;
    }

    _Must_inspect_result_
    bool SelectorRangesOverlap(
        const HttpPack200AttributeSelectorRange& left,
        const HttpPack200AttributeSelectorRange& right) noexcept
    {
        return left.First <= right.Last && right.First <= left.Last;
    }

    _Must_inspect_result_
    HttpPack200AttributeReferenceKind ReferenceKind(char prefix, char type) noexcept
    {
        if (prefix == 'K') {
            switch (type) {
            case 'I': return HttpPack200AttributeReferenceKind::Integer;
            case 'J': return HttpPack200AttributeReferenceKind::Long;
            case 'F': return HttpPack200AttributeReferenceKind::Float;
            case 'D': return HttpPack200AttributeReferenceKind::Double;
            case 'S': return HttpPack200AttributeReferenceKind::String;
            case 'Q': return HttpPack200AttributeReferenceKind::FieldSpecific;
            case 'L': return HttpPack200AttributeReferenceKind::Loadable;
            case 'M': return HttpPack200AttributeReferenceKind::MethodHandle;
            case 'T': return HttpPack200AttributeReferenceKind::MethodType;
            default: return HttpPack200AttributeReferenceKind::None;
            }
        }
        switch (type) {
        case 'C': return HttpPack200AttributeReferenceKind::Class;
        case 'S': return HttpPack200AttributeReferenceKind::Signature;
        case 'D': return HttpPack200AttributeReferenceKind::Descriptor;
        case 'F': return HttpPack200AttributeReferenceKind::Field;
        case 'M': return HttpPack200AttributeReferenceKind::Method;
        case 'I': return HttpPack200AttributeReferenceKind::InterfaceMethod;
        case 'U': return HttpPack200AttributeReferenceKind::Utf8;
        case 'Q': return HttpPack200AttributeReferenceKind::Any;
        case 'N': return HttpPack200AttributeReferenceKind::AnyMember;
        case 'B': return HttpPack200AttributeReferenceKind::BootstrapMethod;
        case 'Y': return HttpPack200AttributeReferenceKind::InvokeDynamic;
        default: return HttpPack200AttributeReferenceKind::None;
        }
    }
}

NTSTATUS HttpPack200AttributeLayout::Compile(HttpXmlText layout) noexcept
{
    Reset();
    if ((layout.Data == nullptr && layout.Length != 0) ||
        layout.Length > MaximumLayoutLength) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T capacity = layout.Length + 1;
    if (capacity == 0) {
        return STATUS_INTEGER_OVERFLOW;
    }
    NTSTATUS status = elements_.Allocate(capacity);
    if (NT_SUCCESS(status)) status = bands_.Allocate(capacity);
    if (NT_SUCCESS(status)) status = callables_.Allocate(capacity);
    if (NT_SUCCESS(status)) status = selectorRanges_.Allocate(capacity);
    HeapArray<ParseFrame> frames(capacity);
    if (!NT_SUCCESS(status) || !frames.IsValid()) {
        Reset();
        return NT_SUCCESS(status) ? STATUS_INSUFFICIENT_RESOURCES : status;
    }

    auto addElement = [&](HttpPack200AttributeElementKind kind, ULONG parent,
                          _Inout_ ParseFrame* frame, _Out_ ULONG* elementIndex) noexcept -> NTSTATUS {
        if (frame == nullptr || elementIndex == nullptr || elementCount_ >= elements_.Count()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const ULONG index = static_cast<ULONG>(elementCount_++);
        elements_[index] = {};
        elements_[index].Kind = kind;
        if (parent != NoIndex) {
            if (frame->LastChild == NoIndex) {
                elements_[parent].FirstChild = index;
            }
            else {
                elements_[frame->LastChild].NextSibling = index;
            }
            frame->LastChild = index;
        }
        *elementIndex = index;
        return STATUS_SUCCESS;
    };

    auto addBand = [&](HttpPack200CodingKind coding,
                       HttpPack200AttributeReferenceKind referenceKind,
                       UCHAR outputSize, bool nullable,
                       _Out_ ULONG* bandIndex) noexcept -> NTSTATUS {
        if (bandIndex == nullptr || bandCount_ >= bands_.Count()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const ULONG index = static_cast<ULONG>(bandCount_++);
        bands_[index] = {};
        bands_[index].Coding = coding;
        bands_[index].ReferenceKind = referenceKind;
        bands_[index].OutputSize = outputSize;
        bands_[index].Nullable = nullable;
        *bandIndex = index;
        return STATUS_SUCCESS;
    };

    elements_[0] = {};
    elements_[0].Kind = HttpPack200AttributeElementKind::Sequence;
    elementCount_ = 1;
    SIZE_T frameCount = 1;
    frames[0] = {};
    frames[0].Kind = ParseFrameKind::Sequence;
    frames[0].Parent = 0;
    frames[0].CallableIndex = NoIndex;

    SIZE_T position = 0;
    while (frameCount != 0) {
        ParseFrame& frame = frames[frameCount - 1];
        if (frame.Kind == ParseFrameKind::Union) {
            if (frame.SawDefaultUnionCase) {
                --frameCount;
                continue;
            }
            if (position >= layout.Length || layout.Data[position] != '(') {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++position;
            const SIZE_T selectorStart = selectorCount_;
            bool defaultCase = false;
            if (position < layout.Length && layout.Data[position] == ')') {
                defaultCase = true;
                ++position;
            }
            else {
                while (true) {
                    HttpPack200AttributeSelectorRange selectorRange = {};
                    if (!ParseSignedNumber(
                            layout.Data,
                            layout.Length,
                            &position,
                            &selectorRange.First) ||
                        selectorCount_ >= selectorRanges_.Count()) {
                        Reset();
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    selectorRange.Last = selectorRange.First;
                    if (position < layout.Length && layout.Data[position] == '-') {
                        ++position;
                        if (!ParseSignedNumber(
                                layout.Data,
                                layout.Length,
                                &position,
                                &selectorRange.Last) ||
                            selectorRange.Last < selectorRange.First) {
                            Reset();
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                    }
                    ULONG caseIndex = elements_[frame.Parent].FirstChild;
                    while (caseIndex != NoIndex) {
                        const HttpPack200AttributeLayoutElement& priorCase = elements_[caseIndex];
                        for (SIZE_T selectorIndex = 0;
                             selectorIndex < priorCase.SelectorCount;
                             ++selectorIndex) {
                            if (SelectorRangesOverlap(
                                    selectorRanges_[priorCase.SelectorOffset + selectorIndex],
                                    selectorRange)) {
                                Reset();
                                return STATUS_INVALID_NETWORK_RESPONSE;
                            }
                        }
                        caseIndex = priorCase.NextSibling;
                    }
                    selectorRanges_[selectorCount_++] = selectorRange;
                    if (position >= layout.Length) {
                        Reset();
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (layout.Data[position] == ')') {
                        ++position;
                        break;
                    }
                    if (layout.Data[position] != ',') {
                        Reset();
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    ++position;
                }
            }
            if (position >= layout.Length || layout.Data[position] != '[') {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++position;
            ULONG caseIndex = NoIndex;
            status = addElement(
                HttpPack200AttributeElementKind::UnionCase,
                frame.Parent,
                &frame,
                &caseIndex);
            if (!NT_SUCCESS(status)) {
                Reset();
                return status;
            }
            elements_[caseIndex].SelectorOffset = static_cast<ULONG>(selectorStart);
            elements_[caseIndex].SelectorCount = static_cast<ULONG>(selectorCount_ - selectorStart);
            frame.SawDefaultUnionCase = defaultCase;
            if (frameCount >= frames.Count()) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            frames[frameCount] = {};
            frames[frameCount].Kind = ParseFrameKind::Sequence;
            frames[frameCount].Parent = caseIndex;
            frames[frameCount].CallableIndex = frame.CallableIndex;
            frames[frameCount].HasClosingBracket = true;
            ++frameCount;
            continue;
        }

        if (position >= layout.Length) {
            if (frame.HasClosingBracket || frameCount != 1) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            --frameCount;
            continue;
        }
        const char token = layout.Data[position];
        if (token == ']') {
            if (!frame.HasClosingBracket) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++position;
            --frameCount;
            continue;
        }

        if (token == '[') {
            if (frameCount != 1 || frame.Parent != 0 || callableCount_ >= callables_.Count()) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++position;
            ULONG callableElement = NoIndex;
            status = addElement(HttpPack200AttributeElementKind::Callable, frame.Parent, &frame, &callableElement);
            if (!NT_SUCCESS(status)) {
                Reset();
                return status;
            }
            const ULONG callableIndex = static_cast<ULONG>(callableCount_++);
            callables_[callableIndex] = {};
            callables_[callableIndex].ElementIndex = callableElement;
            elements_[callableElement].CallableIndex = callableIndex;
            if (frameCount >= frames.Count()) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            frames[frameCount] = {};
            frames[frameCount].Kind = ParseFrameKind::Sequence;
            frames[frameCount].Parent = callableElement;
            frames[frameCount].CallableIndex = callableIndex;
            frames[frameCount].HasClosingBracket = true;
            ++frameCount;
            continue;
        }

        if (token == 'N') {
            if (position + 2 >= layout.Length || !IsWidth(layout.Data[position + 1]) ||
                layout.Data[position + 2] != '[') {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ULONG elementIndex = NoIndex;
            status = addElement(HttpPack200AttributeElementKind::Replication, frame.Parent, &frame, &elementIndex);
            if (NT_SUCCESS(status)) {
                status = addBand(
                    layout.Data[position + 1] == 'B' ? HttpPack200CodingKind::Byte1 : HttpPack200CodingKind::Unsigned5,
                    HttpPack200AttributeReferenceKind::None,
                    WidthBytes(layout.Data[position + 1]),
                    false,
                    &elements_[elementIndex].BandIndex);
            }
            if (!NT_SUCCESS(status)) {
                Reset();
                return status;
            }
            elements_[elementIndex].OutputSize = WidthBytes(layout.Data[position + 1]);
            position += 3;
            if (frameCount >= frames.Count()) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            frames[frameCount] = {};
            frames[frameCount].Kind = ParseFrameKind::Sequence;
            frames[frameCount].Parent = elementIndex;
            frames[frameCount].CallableIndex = frame.CallableIndex;
            frames[frameCount].HasClosingBracket = true;
            ++frameCount;
            continue;
        }

        if (token == 'T') {
            ++position;
            bool isSigned = false;
            if (position < layout.Length && layout.Data[position] == 'S') {
                isSigned = true;
                ++position;
            }
            if (position >= layout.Length || !IsWidth(layout.Data[position])) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const char width = layout.Data[position++];
            ULONG elementIndex = NoIndex;
            status = addElement(HttpPack200AttributeElementKind::Union, frame.Parent, &frame, &elementIndex);
            if (NT_SUCCESS(status)) {
                status = addBand(
                    isSigned ? HttpPack200CodingKind::Signed5 :
                        (width == 'B' ? HttpPack200CodingKind::Byte1 : HttpPack200CodingKind::Unsigned5),
                    HttpPack200AttributeReferenceKind::None,
                    WidthBytes(width),
                    false,
                    &elements_[elementIndex].BandIndex);
            }
            if (!NT_SUCCESS(status)) {
                Reset();
                return status;
            }
            elements_[elementIndex].OutputSize = WidthBytes(width);
            elements_[elementIndex].Signed = isSigned;
            if (frameCount >= frames.Count()) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            frames[frameCount] = {};
            frames[frameCount].Kind = ParseFrameKind::Union;
            frames[frameCount].Parent = elementIndex;
            frames[frameCount].CallableIndex = frame.CallableIndex;
            ++frameCount;
            continue;
        }

        if (token == '(') {
            if (frame.CallableIndex == NoIndex) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++position;
            LONG callOffset = 0;
            if (!ParseSignedNumber(layout.Data, layout.Length, &position, &callOffset) ||
                position >= layout.Length || layout.Data[position] != ')') {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++position;
            ULONG elementIndex = NoIndex;
            status = addElement(HttpPack200AttributeElementKind::Call, frame.Parent, &frame, &elementIndex);
            if (!NT_SUCCESS(status)) {
                Reset();
                return status;
            }
            elements_[elementIndex].CallOffset = callOffset;
            elements_[elementIndex].CallableIndex = frame.CallableIndex;
            continue;
        }

        if (token == 'K' || token == 'R') {
            if (position + 2 >= layout.Length) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const char type = layout.Data[position + 1];
            const HttpPack200AttributeReferenceKind referenceKind = ReferenceKind(token, type);
            if (referenceKind == HttpPack200AttributeReferenceKind::None) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            position += 2;
            bool nullable = false;
            if (position < layout.Length && layout.Data[position] == 'N') {
                nullable = true;
                ++position;
            }
            if (position >= layout.Length || !IsWidth(layout.Data[position])) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const char width = layout.Data[position++];
            ULONG elementIndex = NoIndex;
            status = addElement(HttpPack200AttributeElementKind::Reference, frame.Parent, &frame, &elementIndex);
            if (NT_SUCCESS(status)) {
                status = addBand(
                    HttpPack200CodingKind::Unsigned5,
                    referenceKind,
                    WidthBytes(width),
                    nullable,
                    &elements_[elementIndex].BandIndex);
            }
            if (!NT_SUCCESS(status)) {
                Reset();
                return status;
            }
            elements_[elementIndex].ReferenceKind = referenceKind;
            elements_[elementIndex].Nullable = nullable;
            elements_[elementIndex].OutputSize = WidthBytes(width);
            continue;
        }

        bool isSigned = false;
        bool isFlag = false;
        HttpPack200AttributeBciKind bciKind = HttpPack200AttributeBciKind::None;
        HttpPack200CodingKind coding = HttpPack200CodingKind::Unsigned5;
        char width = 0;
        if (IsWidth(token)) {
            width = token;
            ++position;
        }
        else if (token == 'S' || token == 'F') {
            if (position + 1 >= layout.Length || !IsWidth(layout.Data[position + 1])) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            isSigned = token == 'S';
            isFlag = token == 'F';
            width = layout.Data[position + 1];
            position += 2;
        }
        else if (token == 'P') {
            ++position;
            bciKind = HttpPack200AttributeBciKind::Index;
            coding = HttpPack200CodingKind::Bci5;
            if (position < layout.Length && layout.Data[position] == 'O') {
                bciKind = HttpPack200AttributeBciKind::PreviousOffset;
                coding = HttpPack200CodingKind::Branch5;
                ++position;
            }
            if (position >= layout.Length || !IsWidth(layout.Data[position])) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            width = layout.Data[position++];
        }
        else if (token == 'O') {
            ++position;
            bciKind = HttpPack200AttributeBciKind::Offset;
            coding = HttpPack200CodingKind::Branch5;
            if (position < layout.Length && layout.Data[position] == 'S') {
                isSigned = true;
                ++position;
            }
            if (position >= layout.Length || !IsWidth(layout.Data[position])) {
                Reset();
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            width = layout.Data[position++];
        }
        else {
            Reset();
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ULONG elementIndex = NoIndex;
        status = addElement(HttpPack200AttributeElementKind::Integral, frame.Parent, &frame, &elementIndex);
        if (NT_SUCCESS(status)) {
            if (bciKind == HttpPack200AttributeBciKind::None) {
                coding = isSigned ? HttpPack200CodingKind::Signed5 :
                    (width == 'B' ? HttpPack200CodingKind::Byte1 : HttpPack200CodingKind::Unsigned5);
            }
            status = addBand(
                coding,
                HttpPack200AttributeReferenceKind::None,
                WidthBytes(width),
                false,
                &elements_[elementIndex].BandIndex);
        }
        if (!NT_SUCCESS(status)) {
            Reset();
            return status;
        }
        elements_[elementIndex].BciKind = bciKind;
        elements_[elementIndex].OutputSize = WidthBytes(width);
        elements_[elementIndex].Signed = isSigned;
        UNREFERENCED_PARAMETER(isFlag);
    }

    if (position != layout.Length || frameCount != 0) {
        Reset();
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    for (SIZE_T index = 0; index < elementCount_; ++index) {
        HttpPack200AttributeLayoutElement& element = elements_[index];
        if (element.Kind != HttpPack200AttributeElementKind::Call) {
            continue;
        }
        const LONGLONG target = static_cast<LONGLONG>(element.CallableIndex) + element.CallOffset;
        if (target < 0 || target >= static_cast<LONGLONG>(callableCount_)) {
            Reset();
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        element.TargetCallable = static_cast<ULONG>(target);
        element.BackwardCall = element.CallOffset <= 0;
        if (element.BackwardCall && !callables_[element.TargetCallable].HasBackwardCall) {
            callables_[element.TargetCallable].HasBackwardCall = true;
            ++backwardCallableCount_;
        }
    }
    if (callableCount_ != 0 && elements_[0].FirstChild != callables_[0].ElementIndex) {
        Reset();
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    return STATUS_SUCCESS;
}

void HttpPack200AttributeLayout::Reset() noexcept
{
    elements_.Reset();
    bands_.Reset();
    callables_.Reset();
    selectorRanges_.Reset();
    elementCount_ = 0;
    bandCount_ = 0;
    callableCount_ = 0;
    selectorCount_ = 0;
    backwardCallableCount_ = 0;
}

SIZE_T HttpPack200AttributeLayout::ElementCount() const noexcept { return elementCount_; }
SIZE_T HttpPack200AttributeLayout::BandCount() const noexcept { return bandCount_; }
SIZE_T HttpPack200AttributeLayout::CallableCount() const noexcept { return callableCount_; }
SIZE_T HttpPack200AttributeLayout::BackwardCallableCount() const noexcept { return backwardCallableCount_; }
const HttpPack200AttributeLayoutElement* HttpPack200AttributeLayout::Elements() const noexcept { return elements_.Get(); }
const HttpPack200AttributeBandDescriptor* HttpPack200AttributeLayout::Bands() const noexcept { return bands_.Get(); }
const HttpPack200AttributeCallable* HttpPack200AttributeLayout::Callables() const noexcept { return callables_.Get(); }
const HttpPack200AttributeSelectorRange* HttpPack200AttributeLayout::SelectorRanges() const noexcept
{
    return selectorRanges_.Get();
}
SIZE_T HttpPack200AttributeLayout::SelectorCount() const noexcept { return selectorCount_; }

HttpPack200AttributeValueBands::~HttpPack200AttributeValueBands() noexcept
{
    Reset();
}

void HttpPack200AttributeValueBands::Reset() noexcept
{
    for (SIZE_T index = 0; index < bands_.Count(); ++index) {
        FreeNonPagedArray(bands_[index].Values);
        bands_[index] = {};
    }
    bands_.Reset();
}

NTSTATUS HttpPack200AttributeValueBands::Decode(
    const HttpPack200AttributeLayout& layout,
    SIZE_T occurrenceCount,
    const ULONG* backwardCalls,
    SIZE_T backwardCallCount,
    HttpPack200AttributeBandDecoder decoder,
    void* decoderContext) noexcept
{
    Reset();
    if (decoder == nullptr ||
        (backwardCalls == nullptr && backwardCallCount != 0) ||
        backwardCallCount != layout.BackwardCallableCount()) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = STATUS_SUCCESS;
    if (layout.BandCount() != 0) status = bands_.Allocate(layout.BandCount());
    if (!NT_SUCCESS(status)) return status;
    for (SIZE_T index = 0; index < bands_.Count(); ++index) bands_[index] = {};

    HeapArray<SIZE_T> forwardCounts(layout.CallableCount());
    HeapArray<ULONG> callableBackwardCounts(layout.CallableCount());
    HeapArray<DemandFrame> frames(layout.ElementCount() + 1);
    if ((layout.CallableCount() != 0 && (!forwardCounts.IsValid() || !callableBackwardCounts.IsValid())) ||
        !frames.IsValid()) {
        Reset();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (SIZE_T index = 0; index < layout.CallableCount(); ++index) {
        forwardCounts[index] = 0;
        callableBackwardCounts[index] = 0;
    }
    SIZE_T backwardIndex = 0;
    for (SIZE_T index = 0; index < layout.CallableCount(); ++index) {
        if (layout.Callables()[index].HasBackwardCall) {
            callableBackwardCounts[index] = backwardCalls[backwardIndex++];
        }
    }
    if (backwardIndex != backwardCallCount) {
        Reset();
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    auto readSequence = [&](ULONG firstElement, SIZE_T count, ULONG currentCallable) noexcept -> NTSTATUS {
        SIZE_T frameCount = 0;
        if (firstElement != NoIndex) {
            frames[frameCount++] = { firstElement, count };
        }
        while (frameCount != 0) {
            DemandFrame& frame = frames[frameCount - 1];
            if (frame.NextElement == NoIndex) {
                --frameCount;
                continue;
            }
            const ULONG elementIndex = frame.NextElement;
            const HttpPack200AttributeLayoutElement& element = layout.Elements()[elementIndex];
            frame.NextElement = element.NextSibling;
            LONG* values = nullptr;
            if (element.BandIndex != NoIndex) {
                if (element.BandIndex >= bands_.Count() || bands_[element.BandIndex].Values != nullptr) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (frame.Count != 0) {
                    values = AllocateNonPagedArray<LONG>(frame.Count);
                    if (values == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
                }
                bands_[element.BandIndex].Values = values;
                bands_[element.BandIndex].Count = frame.Count;
                const HttpPack200AttributeBandDescriptor& descriptor =
                    layout.Bands()[element.BandIndex];
                NTSTATUS localStatus = decoder(
                    decoderContext,
                    descriptor.Coding,
                    values,
                    frame.Count);
                if (!NT_SUCCESS(localStatus)) return localStatus;
            }

            if (element.Kind == HttpPack200AttributeElementKind::Replication) {
                SIZE_T childCount = 0;
                for (SIZE_T index = 0; index < frame.Count; ++index) {
                    if (values[index] < 0 ||
                        !CheckedAddSize(childCount, static_cast<SIZE_T>(values[index]), &childCount)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
                if (element.FirstChild != NoIndex) {
                    if (frameCount >= frames.Count()) return STATUS_INVALID_NETWORK_RESPONSE;
                    frames[frameCount++] = { element.FirstChild, childCount };
                }
            }
            else if (element.Kind == HttpPack200AttributeElementKind::Union) {
                ULONG caseIndex = element.FirstChild;
                HeapArray<DemandFrame> caseFrames(layout.ElementCount() + 1);
                if (!caseFrames.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
                SIZE_T caseFrameCount = 0;
                while (caseIndex != NoIndex) {
                    const HttpPack200AttributeLayoutElement& unionCase = layout.Elements()[caseIndex];
                    SIZE_T caseCount = 0;
                    for (SIZE_T valueIndex = 0; valueIndex < frame.Count; ++valueIndex) {
                        bool matched = unionCase.SelectorCount == 0;
                        if (unionCase.SelectorCount == 0) {
                            ULONG priorCase = element.FirstChild;
                            while (priorCase != caseIndex && matched) {
                                const auto& candidate = layout.Elements()[priorCase];
                                for (SIZE_T selectorIndex = 0; selectorIndex < candidate.SelectorCount; ++selectorIndex) {
                                    if (SelectorRangeContains(
                                            layout.SelectorRanges()[candidate.SelectorOffset + selectorIndex],
                                            values[valueIndex])) {
                                        matched = false;
                                        break;
                                    }
                                }
                                priorCase = candidate.NextSibling;
                            }
                        }
                        else {
                            for (SIZE_T selectorIndex = 0; selectorIndex < unionCase.SelectorCount; ++selectorIndex) {
                                if (SelectorRangeContains(
                                        layout.SelectorRanges()[unionCase.SelectorOffset + selectorIndex],
                                        values[valueIndex])) {
                                    matched = true;
                                    break;
                                }
                            }
                        }
                        if (matched) ++caseCount;
                    }
                    if (unionCase.FirstChild != NoIndex && caseCount != 0) {
                        caseFrames[caseFrameCount++] = { unionCase.FirstChild, caseCount };
                    }
                    caseIndex = unionCase.NextSibling;
                }
                while (caseFrameCount != 0) {
                    if (frameCount >= frames.Count()) return STATUS_INVALID_NETWORK_RESPONSE;
                    frames[frameCount++] = caseFrames[--caseFrameCount];
                }
            }
            else if (element.Kind == HttpPack200AttributeElementKind::Call) {
                if (!element.BackwardCall) {
                    if (element.TargetCallable >= forwardCounts.Count() ||
                        !CheckedAddSize(
                            forwardCounts[element.TargetCallable],
                            frame.Count,
                            &forwardCounts[element.TargetCallable])) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                }
                UNREFERENCED_PARAMETER(currentCallable);
            }
        }
        return STATUS_SUCCESS;
    };

    if (layout.CallableCount() == 0) {
        status = readSequence(layout.Elements()[0].FirstChild, occurrenceCount, NoIndex);
    }
    else {
        forwardCounts[0] = occurrenceCount;
        for (SIZE_T callableIndex = 0; callableIndex < layout.CallableCount(); ++callableIndex) {
            SIZE_T entryCount = 0;
            if (!CheckedAddSize(
                    forwardCounts[callableIndex],
                    callableBackwardCounts[callableIndex],
                    &entryCount)) {
                status = STATUS_INTEGER_OVERFLOW;
                break;
            }
            const ULONG callableElement = layout.Callables()[callableIndex].ElementIndex;
            status = readSequence(
                layout.Elements()[callableElement].FirstChild,
                entryCount,
                static_cast<ULONG>(callableIndex));
            if (!NT_SUCCESS(status)) break;
        }
    }
    if (!NT_SUCCESS(status)) Reset();
    return status;
}

namespace
{
    template<typename BandData>
    NTSTATUS ExecuteAttributeOccurrence(
        const HttpPack200AttributeLayout& layout,
        BandData* bands,
        SIZE_T bandCount,
        UCHAR* payload,
        SIZE_T payloadCapacity,
        SIZE_T* payloadLength,
        HttpPack200AttributeRelocation* relocations,
        SIZE_T relocationCapacity,
        SIZE_T* relocationCount,
        ExecutionFrame* frames,
        SIZE_T frameCapacity) noexcept
    {
        if (payloadLength == nullptr || relocationCount == nullptr || frames == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *payloadLength = 0;
        *relocationCount = 0;
        ULONG firstElement = layout.Elements()[0].FirstChild;
        if (layout.CallableCount() != 0) {
            firstElement = layout.Elements()[layout.Callables()[0].ElementIndex].FirstChild;
        }
        SIZE_T frameCount = 0;
        if (firstElement != NoIndex) frames[frameCount++] = { firstElement, firstElement, 1 };
        SIZE_T steps = 0;
        while (frameCount != 0) {
            if (++steps > MaximumExecutionSteps) return STATUS_INVALID_NETWORK_RESPONSE;
            ExecutionFrame& frame = frames[frameCount - 1];
            if (frame.NextElement == NoIndex) {
                if (--frame.Remaining != 0) {
                    frame.NextElement = frame.RepeatStart;
                }
                else {
                    --frameCount;
                }
                continue;
            }
            const ULONG elementIndex = frame.NextElement;
            const auto& element = layout.Elements()[elementIndex];
            frame.NextElement = element.NextSibling;
            LONG value = 0;
            if (element.BandIndex != NoIndex) {
                if (element.BandIndex >= bandCount ||
                    bands[element.BandIndex].Cursor >= bands[element.BandIndex].Count) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                value = bands[element.BandIndex].Values[bands[element.BandIndex].Cursor++];
            }
            auto writeInteger = [&](LONG integer, UCHAR size) noexcept -> NTSTATUS {
                SIZE_T end = 0;
                if (!CheckedAddSize(*payloadLength, size, &end) || end > payloadCapacity) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if (payload != nullptr) {
                    const ULONG bits = static_cast<ULONG>(integer);
                    for (UCHAR byteIndex = 0; byteIndex < size; ++byteIndex) {
                        payload[*payloadLength + byteIndex] = static_cast<UCHAR>(
                            bits >> ((size - byteIndex - 1) * 8));
                    }
                }
                *payloadLength = end;
                return STATUS_SUCCESS;
            };
            if (element.Kind == HttpPack200AttributeElementKind::Integral ||
                element.Kind == HttpPack200AttributeElementKind::Replication ||
                element.Kind == HttpPack200AttributeElementKind::Union) {
                if (element.BciKind == HttpPack200AttributeBciKind::None) {
                    NTSTATUS status = writeInteger(value, element.OutputSize);
                    if (!NT_SUCCESS(status)) return status;
                }
                else {
                    SIZE_T end = 0;
                    if (!CheckedAddSize(*payloadLength, element.OutputSize, &end) || end > payloadCapacity ||
                        *relocationCount >= relocationCapacity) {
                        return STATUS_BUFFER_TOO_SMALL;
                    }
                    if (payload != nullptr && element.OutputSize != 0) {
                        RtlZeroMemory(payload + *payloadLength, element.OutputSize);
                    }
                    if (relocations != nullptr) {
                        auto& relocation = relocations[(*relocationCount)];
                        relocation = {};
                        relocation.Offset = *payloadLength;
                        relocation.Value = value;
                        relocation.BciKind = element.BciKind;
                        relocation.Size = element.OutputSize;
                        relocation.Signed = element.Signed;
                    }
                    ++(*relocationCount);
                    *payloadLength = end;
                }
            }
            else if (element.Kind == HttpPack200AttributeElementKind::Reference) {
                SIZE_T end = 0;
                if (!CheckedAddSize(*payloadLength, element.OutputSize, &end) || end > payloadCapacity ||
                    *relocationCount >= relocationCapacity) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if (payload != nullptr && element.OutputSize != 0) {
                    RtlZeroMemory(payload + *payloadLength, element.OutputSize);
                }
                if (relocations != nullptr) {
                    auto& relocation = relocations[(*relocationCount)];
                    relocation = {};
                    relocation.Offset = *payloadLength;
                    relocation.Value = value;
                    relocation.ReferenceKind = element.ReferenceKind;
                    relocation.Size = element.OutputSize;
                    relocation.Nullable = element.Nullable;
                }
                ++(*relocationCount);
                *payloadLength = end;
            }

            if (element.Kind == HttpPack200AttributeElementKind::Replication) {
                if (value < 0) return STATUS_INVALID_NETWORK_RESPONSE;
                if (value != 0 && element.FirstChild != NoIndex) {
                    if (frameCount >= frameCapacity) return STATUS_INVALID_NETWORK_RESPONSE;
                    frames[frameCount++] = {
                        element.FirstChild,
                        element.FirstChild,
                        static_cast<SIZE_T>(value),
                    };
                }
            }
            else if (element.Kind == HttpPack200AttributeElementKind::Union) {
                ULONG selected = NoIndex;
                ULONG defaultCase = NoIndex;
                ULONG caseIndex = element.FirstChild;
                while (caseIndex != NoIndex) {
                    const auto& unionCase = layout.Elements()[caseIndex];
                    if (unionCase.SelectorCount == 0) {
                        defaultCase = caseIndex;
                    }
                    else {
                        for (SIZE_T selectorIndex = 0; selectorIndex < unionCase.SelectorCount; ++selectorIndex) {
                            if (SelectorRangeContains(
                                    layout.SelectorRanges()[unionCase.SelectorOffset + selectorIndex],
                                    value)) {
                                selected = caseIndex;
                                break;
                            }
                        }
                    }
                    if (selected != NoIndex) break;
                    caseIndex = unionCase.NextSibling;
                }
                if (selected == NoIndex) selected = defaultCase;
                if (selected == NoIndex) return STATUS_INVALID_NETWORK_RESPONSE;
                if (layout.Elements()[selected].FirstChild != NoIndex) {
                    if (frameCount >= frameCapacity) return STATUS_INVALID_NETWORK_RESPONSE;
                    const ULONG body = layout.Elements()[selected].FirstChild;
                    frames[frameCount++] = { body, body, 1 };
                }
            }
            else if (element.Kind == HttpPack200AttributeElementKind::Call) {
                if (element.TargetCallable >= layout.CallableCount() || frameCount >= frameCapacity) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                const ULONG callableElement = layout.Callables()[element.TargetCallable].ElementIndex;
                const ULONG body = layout.Elements()[callableElement].FirstChild;
                if (body != NoIndex) frames[frameCount++] = { body, body, 1 };
            }
        }
        return STATUS_SUCCESS;
    }
}

NTSTATUS HttpPack200AttributeValueBands::Measure(
    const HttpPack200AttributeLayout& layout,
    SIZE_T occurrenceCount,
    SIZE_T* payloadLengths,
    SIZE_T* relocationCounts) noexcept
{
    if ((payloadLengths == nullptr || relocationCounts == nullptr) && occurrenceCount != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    HeapArray<ExecutionFrame> frames(MaximumExecutionFrames);
    if (!frames.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
    for (SIZE_T bandIndex = 0; bandIndex < bands_.Count(); ++bandIndex) bands_[bandIndex].Cursor = 0;
    for (SIZE_T occurrence = 0; occurrence < occurrenceCount; ++occurrence) {
        NTSTATUS status = ExecuteAttributeOccurrence(
            layout,
            bands_.Get(),
            bands_.Count(),
            nullptr,
            static_cast<SIZE_T>(~static_cast<SIZE_T>(0)),
            &payloadLengths[occurrence],
            nullptr,
            static_cast<SIZE_T>(~static_cast<SIZE_T>(0)),
            &relocationCounts[occurrence],
            frames.Get(),
            frames.Count());
        if (!NT_SUCCESS(status)) return status;
    }
    for (SIZE_T bandIndex = 0; bandIndex < bands_.Count(); ++bandIndex) {
        if (bands_[bandIndex].Cursor != bands_[bandIndex].Count) return STATUS_INVALID_NETWORK_RESPONSE;
    }
    return STATUS_SUCCESS;
}

NTSTATUS HttpPack200AttributeValueBands::Emit(
    const HttpPack200AttributeLayout& layout,
    SIZE_T occurrenceCount,
    const SIZE_T* payloadOffsets,
    const SIZE_T* payloadLengths,
    const SIZE_T* relocationOffsets,
    const SIZE_T* relocationCounts,
    UCHAR* payload,
    SIZE_T payloadCapacity,
    HttpPack200AttributeRelocation* relocations,
    SIZE_T relocationCapacity) noexcept
{
    if (occurrenceCount != 0 &&
        (payloadOffsets == nullptr || payloadLengths == nullptr || relocationOffsets == nullptr ||
            relocationCounts == nullptr || (payload == nullptr && payloadCapacity != 0) ||
            (relocations == nullptr && relocationCapacity != 0))) {
        return STATUS_INVALID_PARAMETER;
    }
    HeapArray<ExecutionFrame> frames(MaximumExecutionFrames);
    if (!frames.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
    for (SIZE_T bandIndex = 0; bandIndex < bands_.Count(); ++bandIndex) bands_[bandIndex].Cursor = 0;
    for (SIZE_T occurrence = 0; occurrence < occurrenceCount; ++occurrence) {
        if (payloadOffsets[occurrence] > payloadCapacity ||
            payloadLengths[occurrence] > payloadCapacity - payloadOffsets[occurrence] ||
            relocationOffsets[occurrence] > relocationCapacity ||
            relocationCounts[occurrence] > relocationCapacity - relocationOffsets[occurrence]) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        SIZE_T written = 0;
        SIZE_T relocationWritten = 0;
        NTSTATUS status = ExecuteAttributeOccurrence(
            layout,
            bands_.Get(),
            bands_.Count(),
            payload == nullptr ? nullptr : payload + payloadOffsets[occurrence],
            payloadLengths[occurrence],
            &written,
            relocations == nullptr ? nullptr : relocations + relocationOffsets[occurrence],
            relocationCounts[occurrence],
            &relocationWritten,
            frames.Get(),
            frames.Count());
        if (!NT_SUCCESS(status)) return status;
        if (written != payloadLengths[occurrence] || relocationWritten != relocationCounts[occurrence]) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        for (SIZE_T index = 0; index < relocationWritten; ++index) {
            relocations[relocationOffsets[occurrence] + index].Offset += payloadOffsets[occurrence];
        }
    }
    for (SIZE_T bandIndex = 0; bandIndex < bands_.Count(); ++bandIndex) {
        if (bands_[bandIndex].Cursor != bands_[bandIndex].Count) return STATUS_INVALID_NETWORK_RESPONSE;
    }
    return STATUS_SUCCESS;
}

namespace
{
    template<typename T>
    NTSTATUS GrowBuffer(
        _Inout_ T** buffer,
        _Inout_ SIZE_T* capacity,
        SIZE_T used,
        SIZE_T required) noexcept
    {
        if (buffer == nullptr || capacity == nullptr || used > *capacity) {
            return STATUS_INVALID_PARAMETER;
        }
        if (required <= *capacity) return STATUS_SUCCESS;
        SIZE_T newCapacity = *capacity == 0 ? 16 : *capacity;
        while (newCapacity < required) {
            if (newCapacity > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / 2) {
                newCapacity = required;
                break;
            }
            newCapacity *= 2;
        }
        if (!NonPagedArrayCountIsValid<T>(newCapacity)) return STATUS_INTEGER_OVERFLOW;
        T* replacement = AllocateNonPagedArray<T>(newCapacity);
        if (replacement == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        if (*buffer != nullptr && used != 0) {
            RtlCopyMemory(replacement, *buffer, used * sizeof(T));
        }
        FreeNonPagedArray(*buffer);
        *buffer = replacement;
        *capacity = newCapacity;
        return STATUS_SUCCESS;
    }
}

HttpPack200CustomAttributeStore::~HttpPack200CustomAttributeStore() noexcept
{
    Reset();
}

void HttpPack200CustomAttributeStore::Reset() noexcept
{
    FreeNonPagedArray(occurrences_);
    FreeNonPagedArray(payload_);
    FreeNonPagedArray(relocations_);
    occurrences_ = nullptr;
    occurrenceCount_ = 0;
    occurrenceCapacity_ = 0;
    payload_ = nullptr;
    payloadLength_ = 0;
    payloadCapacity_ = 0;
    relocations_ = nullptr;
    relocationCount_ = 0;
    relocationCapacity_ = 0;
}

NTSTATUS HttpPack200CustomAttributeStore::AppendOccurrence(
    ULONG context,
    ULONG ownerIndex,
    ULONG definitionIndex,
    ULONG attributeIndex,
    ULONG nameUtf8Index) noexcept
{
    SIZE_T required = 0;
    if (!CheckedAddSize(occurrenceCount_, 1, &required)) return STATUS_INTEGER_OVERFLOW;
    NTSTATUS status = GrowBuffer(
        &occurrences_, &occurrenceCapacity_, occurrenceCount_, required);
    if (!NT_SUCCESS(status)) return status;
    auto& occurrence = occurrences_[occurrenceCount_++];
    occurrence = {};
    occurrence.Context = context;
    occurrence.OwnerIndex = ownerIndex;
    occurrence.DefinitionIndex = definitionIndex;
    occurrence.AttributeIndex = attributeIndex;
    occurrence.NameUtf8Index = nameUtf8Index;
    return STATUS_SUCCESS;
}

NTSTATUS HttpPack200CustomAttributeStore::ReservePayload(SIZE_T length, SIZE_T* offset) noexcept
{
    if (offset == nullptr) return STATUS_INVALID_PARAMETER;
    SIZE_T required = 0;
    if (!CheckedAddSize(payloadLength_, length, &required)) return STATUS_INTEGER_OVERFLOW;
    NTSTATUS status = GrowBuffer(&payload_, &payloadCapacity_, payloadLength_, required);
    if (!NT_SUCCESS(status)) return status;
    *offset = payloadLength_;
    payloadLength_ = required;
    return STATUS_SUCCESS;
}

NTSTATUS HttpPack200CustomAttributeStore::ReserveRelocations(SIZE_T count, SIZE_T* offset) noexcept
{
    if (offset == nullptr) return STATUS_INVALID_PARAMETER;
    SIZE_T required = 0;
    if (!CheckedAddSize(relocationCount_, count, &required)) return STATUS_INTEGER_OVERFLOW;
    NTSTATUS status = GrowBuffer(
        &relocations_, &relocationCapacity_, relocationCount_, required);
    if (!NT_SUCCESS(status)) return status;
    *offset = relocationCount_;
    relocationCount_ = required;
    return STATUS_SUCCESS;
}

SIZE_T HttpPack200CustomAttributeStore::OccurrenceCount() const noexcept { return occurrenceCount_; }
HttpPack200CustomAttributeOccurrence* HttpPack200CustomAttributeStore::Occurrences() noexcept { return occurrences_; }
const HttpPack200CustomAttributeOccurrence* HttpPack200CustomAttributeStore::Occurrences() const noexcept { return occurrences_; }
UCHAR* HttpPack200CustomAttributeStore::Payload() noexcept { return payload_; }
const UCHAR* HttpPack200CustomAttributeStore::Payload() const noexcept { return payload_; }
SIZE_T HttpPack200CustomAttributeStore::PayloadLength() const noexcept { return payloadLength_; }
HttpPack200AttributeRelocation* HttpPack200CustomAttributeStore::Relocations() noexcept { return relocations_; }
const HttpPack200AttributeRelocation* HttpPack200CustomAttributeStore::Relocations() const noexcept { return relocations_; }
SIZE_T HttpPack200CustomAttributeStore::RelocationCount() const noexcept { return relocationCount_; }
}
}
