#include "HttpExiEventReader.h"

namespace wknet
{
namespace http1
{
namespace
{
    _Must_inspect_result_
    bool IsXmlCodePoint(ULONG value) noexcept
    {
        return value == 0x09 ||
            value == 0x0a ||
            value == 0x0d ||
            (value >= 0x20 && value <= 0xd7ff) ||
            (value >= 0xe000 && value <= 0xfffd) ||
            (value >= 0x10000 && value <= 0x10ffff);
    }

    _Must_inspect_result_
    bool AppendUtf8CodePoint(
        ULONG value,
        _Out_writes_bytes_(capacity) char* destination,
        SIZE_T capacity,
        _Inout_ SIZE_T* length) noexcept
    {
        if (destination == nullptr || length == nullptr || !IsXmlCodePoint(value)) {
            return false;
        }

        SIZE_T required = 0;
        if (value <= 0x7f) {
            required = 1;
        }
        else if (value <= 0x7ff) {
            required = 2;
        }
        else if (value <= 0xffff) {
            required = 3;
        }
        else {
            required = 4;
        }
        if (*length > capacity || required > capacity - *length) {
            return false;
        }

        char* output = destination + *length;
        switch (required) {
        case 1:
            output[0] = static_cast<char>(value);
            break;
        case 2:
            output[0] = static_cast<char>(0xc0U | (value >> 6));
            output[1] = static_cast<char>(0x80U | (value & 0x3fU));
            break;
        case 3:
            output[0] = static_cast<char>(0xe0U | (value >> 12));
            output[1] = static_cast<char>(0x80U | ((value >> 6) & 0x3fU));
            output[2] = static_cast<char>(0x80U | (value & 0x3fU));
            break;
        case 4:
            output[0] = static_cast<char>(0xf0U | (value >> 18));
            output[1] = static_cast<char>(0x80U | ((value >> 12) & 0x3fU));
            output[2] = static_cast<char>(0x80U | ((value >> 6) & 0x3fU));
            output[3] = static_cast<char>(0x80U | (value & 0x3fU));
            break;
        default:
            return false;
        }
        *length += required;
        return true;
    }

    void SetProduction(
        HttpExiEventKind event,
        HttpExiGrammarKind nextGrammar,
        bool pushElementGrammar,
        bool popGrammar,
        _Out_ HttpExiProduction* production) noexcept
    {
        production->Event = event;
        production->NextGrammar = nextGrammar;
        production->PushElementGrammar = pushElementGrammar;
        production->PopGrammar = popGrammar;
    }

    _Must_inspect_result_
    bool ReadChoice(
        _Inout_ HttpExiBitInput* input,
        ULONG choiceCount,
        _Out_ ULONG* choice,
        _Out_ UCHAR* width) noexcept
    {
        if (input == nullptr || choice == nullptr || width == nullptr) {
            return false;
        }
        *choice = 0;
        if (!HttpExiBitsForProductionCount(choiceCount, width)) {
            return false;
        }
        return *width == 0 || input->ReadBits(*width, choice);
    }
}

    HttpExiBitInput::HttpExiBitInput(
        const UCHAR* data,
        SIZE_T length,
        HttpExiInputMode mode,
        SIZE_T initialBitOffset) noexcept :
        data_(data),
        length_(length),
        bitOffset_(initialBitOffset),
        mode_(mode)
    {
    }

    void HttpExiBitInput::Reset(
        const UCHAR* data,
        SIZE_T length,
        HttpExiInputMode mode,
        SIZE_T initialBitOffset) noexcept
    {
        data_ = data;
        length_ = length;
        bitOffset_ = initialBitOffset;
        mode_ = mode;
    }

    bool HttpExiBitInput::ReadBits(UCHAR bitCount, ULONG* value) noexcept
    {
        if (value == nullptr || bitCount > 32) {
            return false;
        }

        if (mode_ == HttpExiInputMode::ByteAligned) {
            if ((bitOffset_ % 8) != 0) {
                return false;
            }
            const SIZE_T byteCount = (static_cast<SIZE_T>(bitCount) + 7) / 8;
            const SIZE_T byteOffset = bitOffset_ / 8;
            if (byteOffset > length_ || byteCount > length_ - byteOffset) {
                return false;
            }

            ULONG result = 0;
            for (SIZE_T index = 0; index < byteCount; ++index) {
                result |= static_cast<ULONG>(data_[byteOffset + index]) << (index * 8);
            }
            if (bitCount < 32 && result >= (1UL << bitCount)) {
                return false;
            }
            bitOffset_ += byteCount * 8;
            *value = result;
            return true;
        }

        ULONG result = 0;
        for (UCHAR index = 0; index < bitCount; ++index) {
            const SIZE_T byteOffset = bitOffset_ / 8;
            if (byteOffset >= length_) {
                return false;
            }
            const UCHAR bitInByte = static_cast<UCHAR>(7 - (bitOffset_ % 8));
            result = (result << 1) | ((data_[byteOffset] >> bitInByte) & 1U);
            ++bitOffset_;
        }
        *value = result;
        return true;
    }

    bool HttpExiBitInput::AlignByte() noexcept
    {
        const SIZE_T remainder = bitOffset_ % 8;
        if (remainder == 0) {
            return true;
        }
        bitOffset_ += 8 - remainder;
        return (bitOffset_ / 8) <= length_;
    }

    bool HttpExiBitInput::ReadByte(UCHAR* value) noexcept
    {
        ULONG parsed = 0;
        if (!ReadBits(8, &parsed) || value == nullptr) {
            return false;
        }
        *value = static_cast<UCHAR>(parsed);
        return true;
    }

    bool HttpExiBitInput::ReadUnsignedInteger(ULONG* value) noexcept
    {
        if (value == nullptr) {
            return false;
        }
        ULONG result = 0;
        UCHAR shift = 0;
        for (UCHAR octetIndex = 0; octetIndex < 5; ++octetIndex) {
            UCHAR byte = 0;
            if (!ReadByte(&byte)) {
                return false;
            }
            if (shift >= 32 && (byte & 0x7fU) != 0) {
                return false;
            }
            result |= static_cast<ULONG>(byte & 0x7fU) << shift;
            if ((byte & 0x80U) == 0) {
                *value = result;
                return true;
            }
            shift = static_cast<UCHAR>(shift + 7);
        }
        return false;
    }

    SIZE_T HttpExiBitInput::ByteOffset() const noexcept
    {
        return bitOffset_ / 8;
    }

    SIZE_T HttpExiBitInput::BitOffset() const noexcept
    {
        return bitOffset_;
    }

    SIZE_T HttpExiBitInput::ByteLength() const noexcept
    {
        return length_;
    }

    HttpExiInputMode HttpExiBitInput::Mode() const noexcept
    {
        return mode_;
    }

    bool HttpExiBitInput::AtEnd() const noexcept
    {
        const SIZE_T byteOffset = bitOffset_ / 8;
        return byteOffset >= length_;
    }

    bool HttpExiBitsForProductionCount(ULONG productionCount, UCHAR* bitCount) noexcept
    {
        if (bitCount == nullptr || productionCount == 0) {
            return false;
        }
        ULONG slots = 1;
        UCHAR bits = 0;
        while (slots < productionCount) {
            if (bits >= 31) {
                return false;
            }
            slots <<= 1;
            ++bits;
        }
        *bitCount = bits;
        return true;
    }

    NTSTATUS HttpExiReadEventCode(
        HttpExiBitInput* input,
        HttpExiGrammarKind grammar,
        bool preserveComments,
        bool preservePis,
        bool preserveDtd,
        bool preservePrefixes,
        bool preserveSelfContained,
        HttpExiEventCode* eventCode,
        HttpExiProduction* production) noexcept
    {
        if (input == nullptr || eventCode == nullptr || production == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *eventCode = {};
        *production = {};

        ULONG value = 0;
        UCHAR width = 0;
        switch (grammar) {
        case HttpExiGrammarKind::Document:
            SetProduction(HttpExiEventKind::StartDocument, HttpExiGrammarKind::DocContent, false, false, production);
            break;

        case HttpExiGrammarKind::Fragment:
            SetProduction(HttpExiEventKind::StartDocument, HttpExiGrammarKind::FragmentContent, false, false, production);
            break;

        case HttpExiGrammarKind::DocContent:
            if (!preserveDtd && !preserveComments && !preservePis) {
                SetProduction(HttpExiEventKind::StartElement, HttpExiGrammarKind::DocumentEnd, true, false, production);
                break;
            }
            if (!ReadChoice(input, 2, &value, &width)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (value == 0) {
                SetProduction(HttpExiEventKind::StartElement, HttpExiGrammarKind::DocumentEnd, true, false, production);
                break;
            }
            {
                const bool hasThirdLevel = preserveComments || preservePis;
                const ULONG secondaryCount =
                    (preserveDtd ? 1UL : 0UL) +
                    (hasThirdLevel ? 1UL : 0UL);
                ULONG secondary = 0;
                UCHAR secondaryWidth = 0;
                if (!ReadChoice(input, secondaryCount, &secondary, &secondaryWidth)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                width = static_cast<UCHAR>(width + secondaryWidth);
                ULONG cursor = 0;
                if (preserveDtd && secondary == cursor++) {
                    SetProduction(HttpExiEventKind::Dtd, HttpExiGrammarKind::DocContent, false, false, production);
                }
                else if (!hasThirdLevel || secondary != cursor) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                else {
                    const ULONG thirdLevelCount =
                        (preserveComments ? 1UL : 0UL) +
                        (preservePis ? 1UL : 0UL);
                    ULONG third = 0;
                    UCHAR thirdWidth = 0;
                    if (!ReadChoice(input, thirdLevelCount, &third, &thirdWidth)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    width = static_cast<UCHAR>(width + thirdWidth);
                    if (preserveComments && third == 0) {
                        SetProduction(HttpExiEventKind::Comment, HttpExiGrammarKind::DocContent, false, false, production);
                    }
                    else if (preservePis && third == (preserveComments ? 1UL : 0UL)) {
                        SetProduction(HttpExiEventKind::ProcessingInstruction, HttpExiGrammarKind::DocContent, false, false, production);
                    }
                    else {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
            }
            break;

        case HttpExiGrammarKind::DocumentEnd:
            if (!preserveComments && !preservePis) {
                SetProduction(HttpExiEventKind::EndDocument, HttpExiGrammarKind::DocumentEnd, false, true, production);
                break;
            }
            if (!ReadChoice(input, 2, &value, &width)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (value == 0) {
                SetProduction(HttpExiEventKind::EndDocument, HttpExiGrammarKind::DocumentEnd, false, true, production);
                break;
            }
            {
                const ULONG secondaryCount = (preserveComments ? 1UL : 0UL) + (preservePis ? 1UL : 0UL);
                ULONG secondary = 0;
                UCHAR secondaryWidth = 0;
                if (!ReadChoice(input, secondaryCount, &secondary, &secondaryWidth)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                width = static_cast<UCHAR>(width + secondaryWidth);
                if (preserveComments && secondary == 0) {
                    SetProduction(HttpExiEventKind::Comment, HttpExiGrammarKind::DocumentEnd, false, false, production);
                }
                else if (preservePis && secondary == (preserveComments ? 1UL : 0UL)) {
                    SetProduction(HttpExiEventKind::ProcessingInstruction, HttpExiGrammarKind::DocumentEnd, false, false, production);
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            break;

        case HttpExiGrammarKind::StartTagContent:
            {
                const ULONG choiceCount = 4UL +
                    (preservePrefixes ? 1UL : 0UL) +
                    (preserveSelfContained ? 1UL : 0UL) +
                    (preserveDtd ? 1UL : 0UL) +
                    (preserveComments ? 1UL : 0UL) +
                    (preservePis ? 1UL : 0UL);
                if (!ReadChoice(input, choiceCount, &value, &width)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                ULONG cursor = 0;
                if (value == cursor++) {
                    SetProduction(HttpExiEventKind::EndElement, HttpExiGrammarKind::StartTagContent, false, true, production);
                }
                else if (value == cursor++) {
                    SetProduction(HttpExiEventKind::Attribute, HttpExiGrammarKind::StartTagContent, false, false, production);
                }
                else if (preservePrefixes && value == cursor++) {
                    SetProduction(HttpExiEventKind::NamespaceDeclaration, HttpExiGrammarKind::StartTagContent, false, false, production);
                }
                else if (preserveSelfContained && value == cursor++) {
                    SetProduction(
                        HttpExiEventKind::SelfContained,
                        HttpExiGrammarKind::StartTagContent,
                        false,
                        false,
                        production);
                }
                else if (value == cursor++) {
                    SetProduction(HttpExiEventKind::StartElement, HttpExiGrammarKind::ElementContent, true, false, production);
                }
                else if (value == cursor++) {
                    SetProduction(HttpExiEventKind::Characters, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else if (preserveDtd && value == cursor++) {
                    SetProduction(HttpExiEventKind::EntityReference, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else if (preserveComments && value == cursor++) {
                    SetProduction(HttpExiEventKind::Comment, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else if (preservePis && value == cursor) {
                    SetProduction(HttpExiEventKind::ProcessingInstruction, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            break;

        case HttpExiGrammarKind::ElementContent:
            if (!ReadChoice(input, 2, &value, &width)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (value == 0) {
                SetProduction(HttpExiEventKind::EndElement, HttpExiGrammarKind::ElementContent, false, true, production);
                break;
            }
            {
                const ULONG secondaryCount = 2UL +
                    (preserveDtd ? 1UL : 0UL) +
                    (preserveComments ? 1UL : 0UL) +
                    (preservePis ? 1UL : 0UL);
                ULONG secondary = 0;
                UCHAR secondaryWidth = 0;
                if (!ReadChoice(input, secondaryCount, &secondary, &secondaryWidth)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                width = static_cast<UCHAR>(width + secondaryWidth);
                ULONG cursor = 0;
                if (secondary == cursor++) {
                    SetProduction(HttpExiEventKind::StartElement, HttpExiGrammarKind::ElementContent, true, false, production);
                }
                else if (secondary == cursor++) {
                    SetProduction(HttpExiEventKind::Characters, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else if (preserveDtd && secondary == cursor++) {
                    SetProduction(HttpExiEventKind::EntityReference, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else if (preserveComments && secondary == cursor++) {
                    SetProduction(HttpExiEventKind::Comment, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else if (preservePis && secondary == cursor) {
                    SetProduction(HttpExiEventKind::ProcessingInstruction, HttpExiGrammarKind::ElementContent, false, false, production);
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            break;

        case HttpExiGrammarKind::FragmentContent:
        default:
            return STATUS_NOT_SUPPORTED;
        }

        eventCode->Value = value;
        eventCode->Width = width;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiReadLiteralString(
        HttpExiBitInput* input,
        HttpExiStringTable* valueTable,
        HttpXmlText* value) noexcept
    {
        if (input == nullptr || valueTable == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};

        ULONG length = 0;
        if (!input->ReadUnsignedInteger(&length)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return HttpExiReadStringOnly(input, length, valueTable, value);
    }

    NTSTATUS HttpExiReadStringOnly(
        HttpExiBitInput* input,
        ULONG codePointLength,
        HttpExiStringTable* stringTable,
        HttpXmlText* value) noexcept
    {
        if (input == nullptr || stringTable == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};
        if (codePointLength == 0) {
            return STATUS_SUCCESS;
        }

        const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        if (static_cast<SIZE_T>(codePointLength) > maxSize / 4) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T byteCapacity = static_cast<SIZE_T>(codePointLength) * 4;
        HeapArray<char> bytes(byteCapacity);
        if (!bytes.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T byteLength = 0;
        for (ULONG index = 0; index < codePointLength; ++index) {
            ULONG codePoint = 0;
            if (!input->ReadUnsignedInteger(&codePoint) ||
                !AppendUtf8CodePoint(codePoint, bytes.Get(), byteCapacity, &byteLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        HttpXmlText literal = {};
        literal.Data = bytes.Get();
        literal.Length = byteLength;
        ULONG tableIndex = 0;
        NTSTATUS status = stringTable->Add(literal, &tableIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        UNREFERENCED_PARAMETER(tableIndex);
        return stringTable->Get(tableIndex, value) ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }

    NTSTATUS HttpExiReadValueString(
        HttpExiBitInput* input,
        HttpExiStringTable* valueTable,
        HttpXmlText* value) noexcept
    {
        if (input == nullptr || valueTable == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};

        ULONG marker = 0;
        if (!input->ReadUnsignedInteger(&marker)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (marker == 0) {
            // Local partitions are resolved by the higher-level value context.
            // Until a local partition is present, zero is necessarily invalid.
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (marker == 1) {
            if (valueTable->Count() == 0 || valueTable->Count() > 0xffffffffULL) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            UCHAR bitCount = 0;
            if (!HttpExiBitsForProductionCount(static_cast<ULONG>(valueTable->Count()), &bitCount)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ULONG index = 0;
            if (bitCount != 0 && !input->ReadBits(bitCount, &index)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            return valueTable->Get(index, value) ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }
        return HttpExiReadStringOnly(input, marker - 2, valueTable, value);
    }

    NTSTATUS HttpExiReadValueString(
        HttpExiBitInput* input,
        HttpExiValueTable* valueTable,
        ULONG qnameId,
        HttpXmlText* value) noexcept
    {
        if (input == nullptr || valueTable == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};

        ULONG marker = 0;
        if (!input->ReadUnsignedInteger(&marker)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (marker == 0) {
            return valueTable->ReadLocal(input, qnameId, value);
        }
        if (marker == 1) {
            return valueTable->ReadGlobal(input, value);
        }

        const ULONG codePointLength = marker - 2;
        if (codePointLength == 0) {
            return STATUS_SUCCESS;
        }
        const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        if (static_cast<SIZE_T>(codePointLength) > maxSize / 4) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T byteCapacity = static_cast<SIZE_T>(codePointLength) * 4;
        HeapArray<char> bytes(byteCapacity);
        if (!bytes.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T byteLength = 0;
        for (ULONG index = 0; index < codePointLength; ++index) {
            ULONG codePoint = 0;
            if (!input->ReadUnsignedInteger(&codePoint) ||
                !AppendUtf8CodePoint(codePoint, bytes.Get(), byteCapacity, &byteLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        HttpXmlText literal = {};
        literal.Data = bytes.Get();
        literal.Length = byteLength;
        return valueTable->AddLiteral(qnameId, codePointLength, literal, value);
    }

    NTSTATUS HttpExiReadRestrictedValueString(
        HttpExiBitInput* input,
        HttpExiValueTable* valueTable,
        ULONG qnameId,
        const ULONG* characters,
        SIZE_T characterCount,
        HttpXmlText* value) noexcept
    {
        if (input == nullptr || valueTable == nullptr || value == nullptr ||
            characters == nullptr || characterCount == 0 || characterCount >= 0xffffffffULL) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};

        ULONG marker = 0;
        if (!input->ReadUnsignedInteger(&marker)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (marker == 0) {
            return valueTable->ReadLocal(input, qnameId, value);
        }
        if (marker == 1) {
            return valueTable->ReadGlobal(input, value);
        }

        const ULONG codePointLength = marker - 2;
        if (codePointLength == 0) {
            return STATUS_SUCCESS;
        }
        const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        if (static_cast<SIZE_T>(codePointLength) > maxSize / 4) {
            return STATUS_INTEGER_OVERFLOW;
        }
        UCHAR width = 0;
        if (!HttpExiBitsForProductionCount(static_cast<ULONG>(characterCount + 1), &width)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        HeapArray<char> bytes(static_cast<SIZE_T>(codePointLength) * 4);
        if (!bytes.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T byteLength = 0;
        for (ULONG index = 0; index < codePointLength; ++index) {
            ULONG selector = 0;
            if ((width != 0 && !input->ReadBits(width, &selector)) ||
                selector > characterCount) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ULONG codePoint = 0;
            if (selector == characterCount) {
                if (!input->ReadUnsignedInteger(&codePoint)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            else {
                codePoint = characters[selector];
            }
            if (!AppendUtf8CodePoint(
                    codePoint,
                    bytes.Get(),
                    static_cast<SIZE_T>(codePointLength) * 4,
                    &byteLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        HttpXmlText literal = {};
        literal.Data = bytes.Get();
        literal.Length = byteLength;
        return valueTable->AddLiteral(qnameId, codePointLength, literal, value);
    }

    NTSTATUS HttpExiReadStringTableReference(
        HttpExiBitInput* input,
        const HttpExiStringTable& valueTable,
        HttpXmlText* value) noexcept
    {
        if (input == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};
        ULONG index = 0;
        if (!input->ReadUnsignedInteger(&index)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return valueTable.Get(index, value) ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }
}
}
