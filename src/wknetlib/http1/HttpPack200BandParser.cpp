#include "HttpPack200BandParser.h"


namespace wknet
{
namespace http1
{
namespace
{
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
    NTSTATUS DecodeLongBandWithMeta(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        HttpPack200CodingKind defaultCoding,
        LONG* values,
        SIZE_T valueCount) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr ||
            (values == nullptr && valueCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        arena->Rewind();
        return HttpPack200DecodeBandWithMeta(
            reader,
            bandHeaderReader,
            HttpPack200CodingFor(defaultCoding),
            values,
            valueCount,
            arena);
    }

    _Must_inspect_result_
    NTSTATUS DecodeUlongBandWithMeta(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        HttpPack200CodingKind defaultCoding,
        ULONG* values,
        SIZE_T valueCount) noexcept
    {
        if ((values == nullptr && valueCount != 0) || reader == nullptr ||
            bandHeaderReader == nullptr || arena == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (valueCount == 0) {
            return STATUS_SUCCESS;
        }

        HeapArray<LONG> signedValues(valueCount);
        if (!signedValues.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NTSTATUS status = DecodeLongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            defaultCoding,
            signedValues.Get(),
            valueCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < valueCount; ++index) {
            if (signedValues[index] < 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            values[index] = static_cast<ULONG>(signedValues[index]);
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS DecodeRawUlongBandWithMeta(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        HttpPack200CodingKind defaultCoding,
        ULONG* values,
        SIZE_T valueCount) noexcept
    {
        if ((values == nullptr && valueCount != 0) || reader == nullptr ||
            bandHeaderReader == nullptr || arena == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (valueCount == 0) {
            return STATUS_SUCCESS;
        }
        HeapArray<LONG> signedValues(valueCount);
        if (!signedValues.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NTSTATUS status = DecodeLongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            defaultCoding,
            signedValues.Get(),
            valueCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < valueCount; ++index) {
            values[index] = static_cast<ULONG>(signedValues[index]);
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool IsPredefinedAttributeIndex(ULONG context, ULONG index) noexcept
    {
        switch (context) {
        case 0:
            return index >= 17 && index <= 24;
        case 1:
            return index == 17 || (index >= 19 && index <= 22);
        case 2:
            return index >= 17 && index <= 25;
        case 3:
            return index >= 1 && index <= 3;
        default:
            return false;
        }
    }

    _Must_inspect_result_
    bool AttributeFlagSet(ULONG low, ULONG high, ULONG index) noexcept
    {
        if (index < 32) return (low & (1UL << index)) != 0;
        return index < 64 && (high & (1UL << (index - 32))) != 0;
    }

    _Must_inspect_result_
    NTSTATUS ValidateAttributeFlags(
        ULONG context,
        ULONG low,
        ULONG high,
        ULONG allowedLow,
        const HttpPack200AttributeDefinitionBands* definitions) noexcept
    {
        ULONG unsupportedLow = low & ~allowedLow;
        ULONG unsupportedHigh = high;
        if (definitions != nullptr) {
            for (SIZE_T definition = 0; definition < definitions->Count(); ++definition) {
                if ((definitions->Headers()[definition] & 0x03UL) != context) continue;
                const ULONG index = definitions->Indexes()[definition];
                if (index < 32) unsupportedLow &= ~(1UL << index);
                else if (index < 64) unsupportedHigh &= ~(1UL << (index - 32));
            }
        }
        if (unsupportedLow != 0 || unsupportedHigh != 0) {
            return STATUS_NOT_SUPPORTED;
        }
        return STATUS_SUCCESS;
    }

    struct AttributeBandDecodeContext final
    {
        HttpPack200BandReader* Reader = nullptr;
        HttpPack200BandReader* BandHeaderReader = nullptr;
        HttpPack200CodecArena* Arena = nullptr;
    };

    NTSTATUS DecodeAttributeLayoutBand(
        void* context,
        HttpPack200CodingKind coding,
        LONG* values,
        SIZE_T valueCount) noexcept
    {
        auto* state = static_cast<AttributeBandDecodeContext*>(context);
        if (state == nullptr || state->Reader == nullptr || state->BandHeaderReader == nullptr ||
            state->Arena == nullptr || (values == nullptr && valueCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (valueCount == 0) return STATUS_SUCCESS;
        state->Arena->Rewind();
        return HttpPack200DecodeBandWithMeta(
            state->Reader,
            state->BandHeaderReader,
            HttpPack200CodingFor(coding),
            values,
            valueCount,
            state->Arena);
    }

    _Must_inspect_result_
    NTSTATUS ReadCustomAttributeControlBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        ULONG context,
        const ULONG* flagsLow,
        const ULONG* flagsHigh,
        SIZE_T ownerCount,
        SIZE_T fixedBackwardCallCount,
        const HttpPack200CpBands* cpBands,
        const HttpPack200AttributeDefinitionBands* definitions,
        HttpPack200CustomAttributeStore* store,
        _Out_ HeapArray<ULONG>* allCalls,
        _Out_ SIZE_T* customCallOffset) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr ||
            allCalls == nullptr || customCallOffset == nullptr ||
            (ownerCount != 0 && (flagsLow == nullptr || flagsHigh == nullptr))) {
            return STATUS_INVALID_PARAMETER;
        }
        *customCallOffset = fixedBackwardCallCount;
        if (cpBands == nullptr || definitions == nullptr || store == nullptr) {
            if (fixedBackwardCallCount == 0) return STATUS_SUCCESS;
            NTSTATUS status = allCalls->Allocate(fixedBackwardCallCount);
            if (!NT_SUCCESS(status)) return status;
            return DecodeRawUlongBandWithMeta(
                reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
                allCalls->Get(), fixedBackwardCallCount);
        }
        SIZE_T overflowOwnerCount = 0;
        for (SIZE_T owner = 0; owner < ownerCount; ++owner) {
            if ((flagsLow[owner] & (1UL << 16)) != 0) ++overflowOwnerCount;
        }
        HeapArray<ULONG> overflowCounts(overflowOwnerCount);
        if (overflowOwnerCount != 0 && !overflowCounts.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
        NTSTATUS status = DecodeUlongBandWithMeta(
            reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
            overflowCounts.Get(), overflowOwnerCount);
        if (!NT_SUCCESS(status)) return status;
        SIZE_T overflowIndexCount = 0;
        for (SIZE_T index = 0; index < overflowOwnerCount; ++index) {
            if (!CheckedAddSize(overflowIndexCount, overflowCounts[index], &overflowIndexCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        HeapArray<ULONG> overflowIndexes(overflowIndexCount);
        if (overflowIndexCount != 0 && !overflowIndexes.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
        status = DecodeUlongBandWithMeta(
            reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
            overflowIndexes.Get(), overflowIndexCount);
        if (!NT_SUCCESS(status)) return status;

        HeapArray<SIZE_T> occurrenceCounts(definitions->Count());
        if (definitions->Count() != 0 && !occurrenceCounts.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
        for (SIZE_T definition = 0; definition < definitions->Count(); ++definition) {
            occurrenceCounts[definition] = 0;
        }
        SIZE_T overflowOwnerIndex = 0;
        SIZE_T overflowValueIndex = 0;
        const ULONG firstFlagIndex = 0;
        for (SIZE_T owner = 0; owner < ownerCount; ++owner) {
            for (ULONG attributeIndex = firstFlagIndex; attributeIndex < 64; ++attributeIndex) {
                if (attributeIndex == 16 ||
                    !AttributeFlagSet(flagsLow[owner], flagsHigh[owner], attributeIndex)) {
                    continue;
                }
                SIZE_T definition = 0;
                if (definitions->Find(context, attributeIndex, &definition)) {
                    status = store->AppendOccurrence(
                        context, static_cast<ULONG>(owner), static_cast<ULONG>(definition),
                        attributeIndex, definitions->NameIndexes()[definition]);
                    if (!NT_SUCCESS(status)) return status;
                    ++occurrenceCounts[definition];
                }
                else if (context != 3 && attributeIndex < 16) {
                    continue;
                }
                else if (!IsPredefinedAttributeIndex(context, attributeIndex)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            if ((flagsLow[owner] & (1UL << 16)) != 0) {
                if (overflowOwnerIndex >= overflowCounts.Count()) return STATUS_INVALID_NETWORK_RESPONSE;
                const ULONG count = overflowCounts[overflowOwnerIndex++];
                for (ULONG item = 0; item < count; ++item) {
                    if (overflowValueIndex >= overflowIndexes.Count()) return STATUS_INVALID_NETWORK_RESPONSE;
                    const ULONG attributeIndex = overflowIndexes[overflowValueIndex++];
                    SIZE_T definition = 0;
                    if (definitions->Find(context, attributeIndex, &definition)) {
                        status = store->AppendOccurrence(
                            context, static_cast<ULONG>(owner), static_cast<ULONG>(definition),
                            attributeIndex, definitions->NameIndexes()[definition]);
                        if (!NT_SUCCESS(status)) return status;
                        ++occurrenceCounts[definition];
                    }
                    else if (!IsPredefinedAttributeIndex(context, attributeIndex)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
            }
        }
        if (overflowOwnerIndex != overflowOwnerCount || overflowValueIndex != overflowIndexCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T customBackwardCallCount = 0;
        ULONG previousAttributeIndex = 0;
        bool havePrevious = false;
        for (SIZE_T selectedCount = 0; selectedCount < definitions->Count();) {
            SIZE_T selected = definitions->Count();
            ULONG selectedAttributeIndex = 0xffffffffUL;
            for (SIZE_T definition = 0; definition < definitions->Count(); ++definition) {
                if ((definitions->Headers()[definition] & 0x03UL) != context ||
                    occurrenceCounts[definition] == 0) continue;
                const ULONG attributeIndex = definitions->Indexes()[definition];
                if ((havePrevious && attributeIndex <= previousAttributeIndex) ||
                    attributeIndex >= selectedAttributeIndex) continue;
                selected = definition;
                selectedAttributeIndex = attributeIndex;
            }
            if (selected == definitions->Count()) break;
            HttpXmlText layoutText = {};
            if (!cpBands->GetUtf8(definitions->LayoutIndexes()[selected], &layoutText)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpPack200AttributeLayout layout = {};
            status = layout.Compile(layoutText);
            if (!NT_SUCCESS(status) ||
                !CheckedAddSize(
                    customBackwardCallCount,
                    layout.BackwardCallableCount(),
                    &customBackwardCallCount)) {
                return NT_SUCCESS(status) ? STATUS_INTEGER_OVERFLOW : status;
            }
            previousAttributeIndex = selectedAttributeIndex;
            havePrevious = true;
            ++selectedCount;
        }
        SIZE_T totalCallCount = 0;
        if (!CheckedAddSize(fixedBackwardCallCount, customBackwardCallCount, &totalCallCount)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        if (totalCallCount == 0) return STATUS_SUCCESS;
        status = allCalls->Allocate(totalCallCount);
        if (!NT_SUCCESS(status)) return status;
        return DecodeRawUlongBandWithMeta(
            reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
            allCalls->Get(), totalCallCount);
    }

    _Must_inspect_result_
    NTSTATUS DecodeCustomAttributeBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        ULONG context,
        const HttpPack200CpBands* cpBands,
        const HttpPack200AttributeDefinitionBands* definitions,
        const ULONG* customCalls,
        SIZE_T customCallCount,
        HttpPack200CustomAttributeStore* store) noexcept
    {
        if (cpBands == nullptr || definitions == nullptr || store == nullptr) {
            return customCallCount == 0 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        }
        SIZE_T callIndex = 0;
        ULONG previousAttributeIndex = 0;
        bool havePrevious = false;
        for (;;) {
            SIZE_T selected = definitions->Count();
            ULONG selectedAttributeIndex = 0xffffffffUL;
            SIZE_T occurrenceCount = 0;
            for (SIZE_T definition = 0; definition < definitions->Count(); ++definition) {
                if ((definitions->Headers()[definition] & 0x03UL) != context) continue;
                const ULONG attributeIndex = definitions->Indexes()[definition];
                if ((havePrevious && attributeIndex <= previousAttributeIndex) ||
                    attributeIndex >= selectedAttributeIndex) continue;
                SIZE_T count = 0;
                for (SIZE_T occurrence = 0; occurrence < store->OccurrenceCount(); ++occurrence) {
                    const auto& item = store->Occurrences()[occurrence];
                    if (item.Context == context && item.DefinitionIndex == definition) ++count;
                }
                if (count != 0) {
                    selected = definition;
                    selectedAttributeIndex = attributeIndex;
                    occurrenceCount = count;
                }
            }
            if (selected == definitions->Count()) break;

            HttpXmlText layoutText = {};
            if (!cpBands->GetUtf8(definitions->LayoutIndexes()[selected], &layoutText)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpPack200AttributeLayout layout = {};
            NTSTATUS status = layout.Compile(layoutText);
            if (!NT_SUCCESS(status) || layout.BackwardCallableCount() > customCallCount - callIndex) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            HttpPack200AttributeValueBands values = {};
            AttributeBandDecodeContext decodeContext = { reader, bandHeaderReader, arena };
            status = values.Decode(
                layout,
                occurrenceCount,
                customCalls == nullptr ? nullptr : customCalls + callIndex,
                layout.BackwardCallableCount(),
                DecodeAttributeLayoutBand,
                &decodeContext);
            if (!NT_SUCCESS(status)) return status;
            callIndex += layout.BackwardCallableCount();

            HeapArray<SIZE_T> occurrenceIndexes(occurrenceCount);
            HeapArray<SIZE_T> payloadOffsets(occurrenceCount);
            HeapArray<SIZE_T> payloadLengths(occurrenceCount);
            HeapArray<SIZE_T> relocationOffsets(occurrenceCount);
            HeapArray<SIZE_T> relocationCounts(occurrenceCount);
            if (occurrenceCount != 0 &&
                (!occurrenceIndexes.IsValid() || !payloadOffsets.IsValid() || !payloadLengths.IsValid() ||
                    !relocationOffsets.IsValid() || !relocationCounts.IsValid())) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            SIZE_T occurrenceOutput = 0;
            for (SIZE_T occurrence = 0; occurrence < store->OccurrenceCount(); ++occurrence) {
                const auto& item = store->Occurrences()[occurrence];
                if (item.Context == context && item.DefinitionIndex == selected) {
                    occurrenceIndexes[occurrenceOutput++] = occurrence;
                }
            }
            if (occurrenceOutput != occurrenceCount) return STATUS_INVALID_NETWORK_RESPONSE;
            status = values.Measure(
                layout, occurrenceCount, payloadLengths.Get(), relocationCounts.Get());
            if (!NT_SUCCESS(status)) return status;
            for (SIZE_T occurrence = 0; occurrence < occurrenceCount; ++occurrence) {
                status = store->ReservePayload(payloadLengths[occurrence], &payloadOffsets[occurrence]);
                if (NT_SUCCESS(status)) {
                    status = store->ReserveRelocations(
                        relocationCounts[occurrence], &relocationOffsets[occurrence]);
                }
                if (!NT_SUCCESS(status)) return status;
                auto& item = store->Occurrences()[occurrenceIndexes[occurrence]];
                item.PayloadOffset = payloadOffsets[occurrence];
                item.PayloadLength = payloadLengths[occurrence];
                item.RelocationOffset = relocationOffsets[occurrence];
                item.RelocationCount = relocationCounts[occurrence];
            }
            status = values.Emit(
                layout,
                occurrenceCount,
                payloadOffsets.Get(),
                payloadLengths.Get(),
                relocationOffsets.Get(),
                relocationCounts.Get(),
                store->Payload(),
                store->PayloadLength(),
                store->Relocations(),
                store->RelocationCount());
            if (!NT_SUCCESS(status)) return status;
            previousAttributeIndex = selectedAttributeIndex;
            havePrevious = true;
        }
        return callIndex == customCallCount ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS DecodeUlongBand(
        HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        ULONG* values,
        SIZE_T valueCount) noexcept
    {
        if (reader == nullptr || (values == nullptr && valueCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (valueCount == 0) {
            return STATUS_SUCCESS;
        }

        HeapArray<LONG> signedValues(valueCount);
        if (!signedValues.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NTSTATUS status = HttpPack200DecodeBand(reader, codec, signedValues.Get(), valueCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < valueCount; ++index) {
            if (signedValues[index] < 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            values[index] = static_cast<ULONG>(signedValues[index]);
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadUtf8Bands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        HttpPack200CpBands* bands) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr || bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T utf8Count = bands->Utf8Count();
        if (utf8Count == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const SIZE_T prefixCount = utf8Count > 2 ? utf8Count - 2 : 0;
        const SIZE_T suffixCount = utf8Count - 1;
        HeapArray<LONG> prefixes;
        HeapArray<ULONG> suffixes;
        if (prefixCount != 0) {
            NTSTATUS status = prefixes.Allocate(prefixCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = DecodeLongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                prefixes.Get(),
                prefixCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            for (SIZE_T index = 0; index < prefixCount; ++index) {
                if (prefixes[index] < 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }
        if (suffixCount != 0) {
            NTSTATUS status = suffixes.Allocate(suffixCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                suffixes.Get(),
                suffixCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        SIZE_T normalCharCount = 0;
        SIZE_T bigSuffixCount = 0;
        for (SIZE_T index = 0; index < suffixCount; ++index) {
            if (suffixes[index] == 0) {
                ++bigSuffixCount;
            }
            else if (!CheckedAddSize(normalCharCount, suffixes[index], &normalCharCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }

        HeapArray<LONG> normalChars;
        if (normalCharCount != 0) {
            NTSTATUS status = normalChars.Allocate(normalCharCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = DecodeLongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Char3,
                normalChars.Get(),
                normalCharCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            for (SIZE_T index = 0; index < normalCharCount; ++index) {
                if (normalChars[index] < 0 || normalChars[index] > 0xffffL) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }

        HeapArray<ULONG> bigSuffixLengths;
        HeapArray<ULONG> bigSuffixOffsets;
        SIZE_T bigCharCount = 0;
        if (bigSuffixCount != 0) {
            NTSTATUS status = bigSuffixLengths.Allocate(bigSuffixCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                bigSuffixLengths.Get(),
                bigSuffixCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = bigSuffixOffsets.Allocate(bigSuffixCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            for (SIZE_T index = 0; index < bigSuffixCount; ++index) {
                if (bigCharCount > 0xffffffffULL) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                bigSuffixOffsets[index] = static_cast<ULONG>(bigCharCount);
                if (!CheckedAddSize(bigCharCount, bigSuffixLengths[index], &bigCharCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
        }

        HeapArray<USHORT> bigChars;
        if (bigCharCount != 0) {
            NTSTATUS status = bigChars.Allocate(bigCharCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            for (SIZE_T index = 0; index < bigSuffixCount; ++index) {
                const SIZE_T count = bigSuffixLengths[index];
                HeapArray<LONG> decoded;
                if (count != 0) {
                    status = decoded.Allocate(count);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = DecodeLongBandWithMeta(
                        reader,
                        bandHeaderReader,
                        arena,
                        HttpPack200CodingKind::Delta5,
                        decoded.Get(),
                        count);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    for (SIZE_T charIndex = 0; charIndex < count; ++charIndex) {
                        if (decoded[charIndex] < 0 || decoded[charIndex] > 0xffffL) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        bigChars[static_cast<SIZE_T>(bigSuffixOffsets[index]) + charIndex] =
                            static_cast<USHORT>(decoded[charIndex]);
                    }
                }
            }
        }

        ULONG* suffixLengths = bands->Utf8SuffixLengths();
        ULONG* utf16Offsets = bands->Utf16CharOffsets();
        ULONG* utf16Lengths = bands->Utf16CharLengths();
        if (suffixLengths == nullptr || utf16Offsets == nullptr || utf16Lengths == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        suffixLengths[0] = 0;
        utf16Offsets[0] = 0;
        utf16Lengths[0] = 0;

        SIZE_T totalUtf16Chars = 0;
        SIZE_T bigSuffixIndex = 0;
        for (SIZE_T stringIndex = 1; stringIndex < utf8Count; ++stringIndex) {
            const SIZE_T prefixLength = stringIndex > 1 ?
                static_cast<SIZE_T>(prefixes[stringIndex - 2]) :
                0;
            if (prefixLength > utf16Lengths[stringIndex - 1]) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            SIZE_T suffixLength = suffixes[stringIndex - 1];
            if (suffixLength == 0) {
                if (bigSuffixIndex >= bigSuffixCount) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                suffixLength = bigSuffixLengths[bigSuffixIndex++];
            }
            if (suffixLength > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            suffixLengths[stringIndex] = static_cast<ULONG>(suffixLength);
            SIZE_T stringLength = 0;
            if (!CheckedAddSize(prefixLength, suffixLength, &stringLength) ||
                !CheckedAddSize(totalUtf16Chars, stringLength, &totalUtf16Chars) ||
                totalUtf16Chars > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            utf16Lengths[stringIndex] = static_cast<ULONG>(stringLength);
        }
        if (bigSuffixIndex != bigSuffixCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        NTSTATUS status = bands->AllocateUtf16Chars(totalUtf16Chars);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        USHORT* utf16Chars = bands->Utf16Chars();
        SIZE_T utf16Cursor = 0;
        SIZE_T normalCursor = 0;
        bigSuffixIndex = 0;
        for (SIZE_T stringIndex = 1; stringIndex < utf8Count; ++stringIndex) {
            const SIZE_T prefixLength = stringIndex > 1 ?
                static_cast<SIZE_T>(prefixes[stringIndex - 2]) :
                0;
            const SIZE_T suffixLength = suffixLengths[stringIndex];
            const SIZE_T stringOffset = utf16Cursor;
            if (stringOffset > 0xffffffffULL || prefixLength + suffixLength > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            utf16Offsets[stringIndex] = static_cast<ULONG>(stringOffset);
            utf16Lengths[stringIndex] = static_cast<ULONG>(prefixLength + suffixLength);
            if (prefixLength != 0) {
                const SIZE_T previousOffset = utf16Offsets[stringIndex - 1];
                RtlCopyMemory(
                    utf16Chars + utf16Cursor,
                    utf16Chars + previousOffset,
                    prefixLength * sizeof(USHORT));
                utf16Cursor += prefixLength;
            }
            if (suffixes[stringIndex - 1] == 0) {
                const SIZE_T bigOffset = bigSuffixOffsets[bigSuffixIndex++];
                if (suffixLength != 0) {
                    RtlCopyMemory(
                        utf16Chars + utf16Cursor,
                        bigChars.Get() + bigOffset,
                        suffixLength * sizeof(USHORT));
                    utf16Cursor += suffixLength;
                }
            }
            else {
                for (SIZE_T charIndex = 0; charIndex < suffixLength; ++charIndex) {
                    utf16Chars[utf16Cursor++] = static_cast<USHORT>(normalChars[normalCursor++]);
                }
            }
        }
        if (utf16Cursor != totalUtf16Chars || normalCursor != normalCharCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ULONG* utf8Offsets = bands->Utf8CharOffsets();
        ULONG* utf8Lengths = bands->Utf8ByteLengths();
        if (utf8Offsets == nullptr || utf8Lengths == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        utf8Offsets[0] = 0;
        utf8Lengths[0] = 0;
        SIZE_T totalUtf8Bytes = 0;
        for (SIZE_T stringIndex = 1; stringIndex < utf8Count; ++stringIndex) {
            const SIZE_T offset = utf16Offsets[stringIndex];
            const SIZE_T length = utf16Lengths[stringIndex];
            SIZE_T byteLength = 0;
            for (SIZE_T charIndex = 0; charIndex < length; ++charIndex) {
                const USHORT first = utf16Chars[offset + charIndex];
                SIZE_T encodedLength = 0;
                if (first <= 0x7fU) {
                    encodedLength = 1;
                }
                else if (first <= 0x7ffU) {
                    encodedLength = 2;
                }
                else if (first >= 0xd800U && first <= 0xdbffU &&
                    charIndex + 1 < length &&
                    utf16Chars[offset + charIndex + 1] >= 0xdc00U &&
                    utf16Chars[offset + charIndex + 1] <= 0xdfffU) {
                    encodedLength = 4;
                    ++charIndex;
                }
                else {
                    encodedLength = 3;
                }
                if (!CheckedAddSize(byteLength, encodedLength, &byteLength)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
            if (totalUtf8Bytes > 0xffffffffULL || byteLength > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            utf8Offsets[stringIndex] = static_cast<ULONG>(totalUtf8Bytes);
            utf8Lengths[stringIndex] = static_cast<ULONG>(byteLength);
            if (!CheckedAddSize(totalUtf8Bytes, byteLength, &totalUtf8Bytes) ||
                totalUtf8Bytes > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        status = bands->AllocateUtf8Chars(totalUtf8Bytes);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        char* utf8Chars = bands->Utf8Chars();
        SIZE_T utf8Cursor = 0;
        for (SIZE_T stringIndex = 1; stringIndex < utf8Count; ++stringIndex) {
            const SIZE_T offset = utf16Offsets[stringIndex];
            const SIZE_T length = utf16Lengths[stringIndex];
            for (SIZE_T charIndex = 0; charIndex < length; ++charIndex) {
                ULONG codePoint = utf16Chars[offset + charIndex];
                if (codePoint >= 0xd800U && codePoint <= 0xdbffU &&
                    charIndex + 1 < length) {
                    const ULONG low = utf16Chars[offset + charIndex + 1];
                    if (low >= 0xdc00U && low <= 0xdfffU) {
                        codePoint = 0x10000UL + ((codePoint - 0xd800UL) << 10) + (low - 0xdc00UL);
                        ++charIndex;
                    }
                }
                if (codePoint <= 0x7fU) {
                    utf8Chars[utf8Cursor++] = static_cast<char>(codePoint);
                }
                else if (codePoint <= 0x7ffU) {
                    utf8Chars[utf8Cursor++] = static_cast<char>(0xc0U | (codePoint >> 6));
                    utf8Chars[utf8Cursor++] = static_cast<char>(0x80U | (codePoint & 0x3fU));
                }
                else if (codePoint <= 0xffffU) {
                    utf8Chars[utf8Cursor++] = static_cast<char>(0xe0U | (codePoint >> 12));
                    utf8Chars[utf8Cursor++] = static_cast<char>(0x80U | ((codePoint >> 6) & 0x3fU));
                    utf8Chars[utf8Cursor++] = static_cast<char>(0x80U | (codePoint & 0x3fU));
                }
                else {
                    utf8Chars[utf8Cursor++] = static_cast<char>(0xf0U | (codePoint >> 18));
                    utf8Chars[utf8Cursor++] = static_cast<char>(0x80U | ((codePoint >> 12) & 0x3fU));
                    utf8Chars[utf8Cursor++] = static_cast<char>(0x80U | ((codePoint >> 6) & 0x3fU));
                    utf8Chars[utf8Cursor++] = static_cast<char>(0x80U | (codePoint & 0x3fU));
                }
            }
        }
        return utf8Cursor == totalUtf8Bytes ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }
}

    NTSTATUS HttpPack200ReadCpBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        const HttpPack200CpCounts& counts,
        HttpPack200CpBands* bands) noexcept
    {
        if (bands == nullptr || reader == nullptr || bandHeaderReader == nullptr || arena == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(counts);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = ReadUtf8Bands(reader, bandHeaderReader, arena, bands);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->IntBits(),
            counts.Int);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->FloatBits(),
            counts.Float);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->LongHighBits(),
            counts.Long);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->LongLowBits(),
            counts.Long);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->DoubleHighBits(),
            counts.Double);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->DoubleLowBits(),
            counts.Double);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->StringUtf8Indexes(),
            counts.String);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->ClassNameIndexes(),
            bands->ClassCount());
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->SignatureFormIndexes(),
            counts.Signature);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T signatureClassCount = 0;
        for (SIZE_T signatureIndex = 0; signatureIndex < counts.Signature; ++signatureIndex) {
            const ULONG formIndex = bands->SignatureFormIndexes()[signatureIndex];
            HttpXmlText form = {};
            if (!bands->GetUtf8(formIndex, &form)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            for (SIZE_T charIndex = 0; charIndex < form.Length; ++charIndex) {
                if (form.Data[charIndex] == 'L') {
                    if (!CheckedAddSize(signatureClassCount, 1, &signatureClassCount)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                }
            }
        }
        status = bands->AllocateSignatureClassIndexes(signatureClassCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->SignatureClassIndexes(),
            signatureClassCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->DescriptorNameIndexes(),
            counts.Descriptor);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->DescriptorTypeIndexes(),
            counts.Descriptor);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->FieldClassIndexes(),
            counts.Field);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->FieldDescriptorIndexes(),
            counts.Field);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->MethodClassIndexes(),
            counts.Method);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->MethodDescriptorIndexes(),
            counts.Method);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->InterfaceMethodClassIndexes(),
            counts.InterfaceMethod);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->InterfaceMethodDescriptorIndexes(),
            counts.InterfaceMethod);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->MethodHandleReferenceKinds(),
            counts.MethodHandle);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->MethodHandleMemberIndexes(),
            counts.MethodHandle);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->MethodTypeSignatureIndexes(),
            counts.MethodType);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->BootstrapMethodReferenceIndexes(),
            counts.BootstrapMethod);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->BootstrapMethodArgumentCounts(),
            counts.BootstrapMethod);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T bootstrapArgumentCount = 0;
        for (SIZE_T index = 0; index < counts.BootstrapMethod; ++index) {
            if (!CheckedAddSize(
                    bootstrapArgumentCount,
                    bands->BootstrapMethodArgumentCounts()[index],
                    &bootstrapArgumentCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        status = bands->AllocateBootstrapMethodArgumentIndexes(bootstrapArgumentCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->BootstrapMethodArgumentIndexes(),
            bootstrapArgumentCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->InvokeDynamicBootstrapIndexes(),
            counts.InvokeDynamic);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->InvokeDynamicDescriptorIndexes(),
            counts.InvokeDynamic);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < counts.String; ++index) {
            if (bands->StringUtf8Indexes()[index] >= counts.Utf8) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < counts.Class; ++index) {
            if (bands->ClassNameIndexes()[index] >= counts.Utf8) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < signatureClassCount; ++index) {
            if (bands->SignatureClassIndexes()[index] >= counts.Class) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < counts.Descriptor; ++index) {
            if (bands->DescriptorNameIndexes()[index] >= counts.Utf8 ||
                bands->DescriptorTypeIndexes()[index] >= counts.Signature) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < counts.Field; ++index) {
            if (bands->FieldClassIndexes()[index] >= counts.Class ||
                bands->FieldDescriptorIndexes()[index] >= counts.Descriptor) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < counts.Method; ++index) {
            if (bands->MethodClassIndexes()[index] >= counts.Class ||
                bands->MethodDescriptorIndexes()[index] >= counts.Descriptor) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < counts.InterfaceMethod; ++index) {
            if (bands->InterfaceMethodClassIndexes()[index] >= counts.Class ||
                bands->InterfaceMethodDescriptorIndexes()[index] >= counts.Descriptor) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        SIZE_T anyMemberCount = 0;
        if (!CheckedAddSize(counts.Field, counts.Method, &anyMemberCount) ||
            !CheckedAddSize(anyMemberCount, counts.InterfaceMethod, &anyMemberCount)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        for (SIZE_T index = 0; index < counts.MethodHandle; ++index) {
            const ULONG referenceKind = bands->MethodHandleReferenceKinds()[index];
            if (referenceKind < 1 || referenceKind > 9 ||
                bands->MethodHandleMemberIndexes()[index] >= anyMemberCount) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < counts.MethodType; ++index) {
            if (bands->MethodTypeSignatureIndexes()[index] >= counts.Signature) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        SIZE_T loadableValueCount = 0;
        const SIZE_T loadableCounts[] = {
            counts.Int,
            counts.Float,
            counts.Long,
            counts.Double,
            counts.String,
            counts.Class,
            counts.MethodHandle,
            counts.MethodType
        };
        for (SIZE_T index = 0; index < sizeof(loadableCounts) / sizeof(loadableCounts[0]); ++index) {
            if (!CheckedAddSize(loadableValueCount, loadableCounts[index], &loadableValueCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        for (SIZE_T index = 0; index < counts.BootstrapMethod; ++index) {
            if (bands->BootstrapMethodReferenceIndexes()[index] >= counts.MethodHandle) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < bootstrapArgumentCount; ++index) {
            if (bands->BootstrapMethodArgumentIndexes()[index] >= loadableValueCount) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        for (SIZE_T index = 0; index < counts.InvokeDynamic; ++index) {
            if (bands->InvokeDynamicBootstrapIndexes()[index] >= counts.BootstrapMethod ||
                bands->InvokeDynamicDescriptorIndexes()[index] >= counts.Descriptor) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ReadFileBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        SIZE_T fileCount,
        bool haveSizeHigh,
        bool haveModtime,
        bool haveOptions,
        HttpPack200FileBands* bands) noexcept
    {
        if (bands == nullptr || reader == nullptr || bandHeaderReader == nullptr || arena == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(fileCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            bands->NameIndexes(),
            fileCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (haveSizeHigh) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->SizesHigh(),
                fileCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else if (fileCount != 0) {
            RtlZeroMemory(bands->SizesHigh(), fileCount * sizeof(ULONG));
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            bands->SizesLow(),
            fileCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (haveModtime) {
            status = DecodeLongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                bands->Modtimes(),
                fileCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else if (fileCount != 0) {
            RtlZeroMemory(bands->Modtimes(), fileCount * sizeof(LONG));
        }
        if (haveOptions) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->Options(),
                fileCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else if (fileCount != 0) {
            RtlZeroMemory(bands->Options(), fileCount * sizeof(ULONG));
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ReadClassBands(
        HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        SIZE_T classCount,
        HttpPack200ClassBands* bands) noexcept
    {
        if (bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBand(reader, codec, bands->ThisClassIndexes(), classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return DecodeUlongBand(reader, codec, bands->SuperClassIndexes(), classCount);
    }

    NTSTATUS ReadMetadataBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        SIZE_T occurrenceCount,
        SIZE_T backwardCallCount,
        bool parameterAnnotations,
        bool annotationDefault,
        HttpPack200MetadataBands* bands) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr || bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        bands->Reset();
        bands->OccurrenceCount = occurrenceCount;
        auto allocate = [](HeapArray<ULONG>* values, SIZE_T count) noexcept -> NTSTATUS {
            values->Reset();
            return count == 0 ? STATUS_SUCCESS : values->Allocate(count);
        };
        auto decode = [&](HeapArray<ULONG>* values, SIZE_T count,
                          HttpPack200CodingKind coding) noexcept -> NTSTATUS {
            NTSTATUS status = allocate(values, count);
            return NT_SUCCESS(status) ? DecodeRawUlongBandWithMeta(
                reader, bandHeaderReader, arena, coding, values->Get(), count) : status;
        };
        auto sum = [](const HeapArray<ULONG>& values, SIZE_T* total) noexcept -> bool {
            *total = 0;
            for (SIZE_T index = 0; index < values.Count(); ++index) {
                if (!CheckedAddSize(*total, values[index], total)) return false;
            }
            return true;
        };

        SIZE_T annotationRecordCount = occurrenceCount;
        NTSTATUS status = STATUS_SUCCESS;
        if (parameterAnnotations) {
            status = decode(&bands->ParamCounts, occurrenceCount, HttpPack200CodingKind::Byte1);
            if (!NT_SUCCESS(status) || !sum(bands->ParamCounts, &annotationRecordCount)) {
                return NT_SUCCESS(status) ? STATUS_INTEGER_OVERFLOW : status;
            }
        }

        SIZE_T annotationCount = 0;
        SIZE_T pairCount = occurrenceCount;
        if (!annotationDefault) {
            status = decode(
                &bands->AnnotationCounts, annotationRecordCount, HttpPack200CodingKind::Unsigned5);
            if (!NT_SUCCESS(status) || !sum(bands->AnnotationCounts, &annotationCount)) {
                return NT_SUCCESS(status) ? STATUS_INTEGER_OVERFLOW : status;
            }
            status = decode(&bands->TypeIndexes, annotationCount, HttpPack200CodingKind::Unsigned5);
            if (NT_SUCCESS(status)) {
                status = decode(&bands->PairCounts, annotationCount, HttpPack200CodingKind::Unsigned5);
            }
            if (!NT_SUCCESS(status) || !sum(bands->PairCounts, &pairCount)) {
                return NT_SUCCESS(status) ? STATUS_INTEGER_OVERFLOW : status;
            }
            status = decode(&bands->NameIndexes, pairCount, HttpPack200CodingKind::Unsigned5);
            if (!NT_SUCCESS(status)) return status;
        }

        SIZE_T tagCount = 0;
        if (!CheckedAddSize(pairCount, backwardCallCount, &tagCount)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        status = decode(&bands->Tags, tagCount, HttpPack200CodingKind::Byte1);
        if (!NT_SUCCESS(status)) return status;
        SIZE_T integerCount = 0, doubleCount = 0, floatCount = 0, longCount = 0;
        SIZE_T classCount = 0, enumCount = 0, stringCount = 0, arrayCount = 0, nestedCount = 0;
        for (SIZE_T index = 0; index < tagCount; ++index) {
            switch (bands->Tags[index]) {
            case 'B': case 'C': case 'I': case 'S': case 'Z': ++integerCount; break;
            case 'D': ++doubleCount; break;
            case 'F': ++floatCount; break;
            case 'J': ++longCount; break;
            case 'c': ++classCount; break;
            case 'e': ++enumCount; break;
            case 's': ++stringCount; break;
            case '[': ++arrayCount; break;
            case '@': ++nestedCount; break;
            default: return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        if (NT_SUCCESS(status)) status = decode(&bands->IntegerIndexes, integerCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->DoubleIndexes, doubleCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->FloatIndexes, floatCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->LongIndexes, longCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->ClassSignatureIndexes, classCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->EnumTypeIndexes, enumCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->EnumNameIndexes, enumCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->StringIndexes, stringCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->ArrayCounts, arrayCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->NestedTypeIndexes, nestedCount, HttpPack200CodingKind::Unsigned5);
        if (NT_SUCCESS(status)) status = decode(&bands->NestedPairCounts, nestedCount, HttpPack200CodingKind::Unsigned5);
        SIZE_T nestedPairCount = 0;
        if (!NT_SUCCESS(status) || !sum(bands->NestedPairCounts, &nestedPairCount)) {
            return NT_SUCCESS(status) ? STATUS_INTEGER_OVERFLOW : status;
        }
        return decode(&bands->NestedNameIndexes, nestedPairCount, HttpPack200CodingKind::Unsigned5);
    }

    NTSTATUS HttpPack200ReadClassBandsWithMeta(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        SIZE_T classCount,
        bool haveClassFlagsHigh,
        bool haveFieldFlagsHigh,
        bool haveMethodFlagsHigh,
        bool allCodeHasFlags,
        bool haveCodeFlagsHigh,
        HttpPack200ClassBands* bands,
        const HttpPack200CpBands* cpBands,
        const HttpPack200AttributeDefinitionBands* attributeDefinitions,
        HttpPack200CustomAttributeStore* customAttributes) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr || bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->ThisClassIndexes(),
            classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->SuperClassIndexes(),
            classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->InterfaceCounts(),
            classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T interfaceCount = 0;
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            if (!CheckedAddSize(interfaceCount, bands->InterfaceCounts()[classIndex], &interfaceCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        status = bands->AllocateInterfaceIndexes(interfaceCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->InterfaceIndexes(),
            interfaceCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->FieldCounts(),
            classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->MethodCounts(),
            classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T fieldCount = 0;
        SIZE_T methodCount = 0;
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            if (!CheckedAddSize(fieldCount, bands->FieldCounts()[classIndex], &fieldCount) ||
                !CheckedAddSize(methodCount, bands->MethodCounts()[classIndex], &methodCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        status = bands->AllocateMemberBands(fieldCount, methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->FieldDescriptorIndexes(),
            fieldCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (haveFieldFlagsHigh) {
            status = DecodeRawUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->FieldFlagsHigh(),
                fieldCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else if (fieldCount != 0) {
            RtlZeroMemory(bands->FieldFlagsHigh(), fieldCount * sizeof(ULONG));
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            bands->FieldFlagsLow(),
            fieldCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        constexpr ULONG FieldConstantValueFlag = 1UL << 17;
        constexpr ULONG FieldSignatureFlag = 1UL << 19;
        constexpr ULONG FieldDeprecatedFlag = 1UL << 20;
        constexpr ULONG FieldVisibleAnnotationsFlag = 1UL << 21;
        constexpr ULONG FieldInvisibleAnnotationsFlag = 1UL << 22;
        SIZE_T constantValueCount = 0;
        SIZE_T fieldSignatureCount = 0;
        SIZE_T fieldVisibleAnnotationCount = 0;
        SIZE_T fieldInvisibleAnnotationCount = 0;
        ULONG* fieldConstantValues = bands->FieldConstantValueIndexes();
        ULONG* fieldSignatures = bands->FieldSignatureIndexes();
        if (fieldCount != 0 && (fieldConstantValues == nullptr || fieldSignatures == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
            fieldConstantValues[fieldIndex] = 0xffffffffUL;
            fieldSignatures[fieldIndex] = 0xffffffffUL;
            status = ValidateAttributeFlags(
                1,
                bands->FieldFlagsLow()[fieldIndex],
                bands->FieldFlagsHigh()[fieldIndex],
                0xffffUL | (1UL << 16) | FieldConstantValueFlag | FieldSignatureFlag |
                    FieldDeprecatedFlag | FieldVisibleAnnotationsFlag |
                    FieldInvisibleAnnotationsFlag,
                attributeDefinitions);
            if (!NT_SUCCESS(status)) return status;
            if ((bands->FieldFlagsLow()[fieldIndex] & FieldConstantValueFlag) != 0 &&
                !CheckedAddSize(constantValueCount, 1, &constantValueCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            if ((bands->FieldFlagsLow()[fieldIndex] & FieldSignatureFlag) != 0 &&
                !CheckedAddSize(fieldSignatureCount, 1, &fieldSignatureCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            if ((bands->FieldFlagsLow()[fieldIndex] & FieldVisibleAnnotationsFlag) != 0) {
                ++fieldVisibleAnnotationCount;
            }
            if ((bands->FieldFlagsLow()[fieldIndex] & FieldInvisibleAnnotationsFlag) != 0) {
                ++fieldInvisibleAnnotationCount;
            }
        }
        const SIZE_T fieldMetadataCallCount =
            (fieldVisibleAnnotationCount != 0 ? 1 : 0) +
            (fieldInvisibleAnnotationCount != 0 ? 1 : 0);
        HeapArray<ULONG> fieldAttributeCalls = {};
        SIZE_T fieldCustomCallOffset = 0;
        status = ReadCustomAttributeControlBands(
            reader, bandHeaderReader, arena, 1,
            bands->FieldFlagsLow(), bands->FieldFlagsHigh(), fieldCount,
            fieldMetadataCallCount, cpBands, attributeDefinitions, customAttributes,
            &fieldAttributeCalls, &fieldCustomCallOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HeapArray<ULONG> constantValues = {};
        if (constantValueCount != 0) {
            status = constantValues.Allocate(constantValueCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            constantValues.Get(),
            constantValueCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T constantValueIndex = 0;
        for (SIZE_T fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
            if ((bands->FieldFlagsLow()[fieldIndex] & FieldConstantValueFlag) != 0) {
                fieldConstantValues[fieldIndex] = constantValues[constantValueIndex++];
            }
        }
        HeapArray<ULONG> fieldSignatureValues = {};
        if (fieldSignatureCount != 0) {
            status = fieldSignatureValues.Allocate(fieldSignatureCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            fieldSignatureValues.Get(),
            fieldSignatureCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T fieldSignatureIndex = 0;
        for (SIZE_T fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
            if ((bands->FieldFlagsLow()[fieldIndex] & FieldSignatureFlag) != 0) {
                fieldSignatures[fieldIndex] = fieldSignatureValues[fieldSignatureIndex++];
            }
        }
        SIZE_T fieldMetadataCallIndex = 0;
        status = ReadMetadataBands(
            reader, bandHeaderReader, arena, fieldVisibleAnnotationCount,
            fieldVisibleAnnotationCount == 0 ? 0 : fieldAttributeCalls[fieldMetadataCallIndex++],
            false, false, bands->FieldVisibleAnnotations());
        if (!NT_SUCCESS(status)) return status;
        status = ReadMetadataBands(
            reader, bandHeaderReader, arena, fieldInvisibleAnnotationCount,
            fieldInvisibleAnnotationCount == 0 ? 0 : fieldAttributeCalls[fieldMetadataCallIndex++],
            false, false, bands->FieldInvisibleAnnotations());
        if (!NT_SUCCESS(status) || fieldMetadataCallIndex != fieldMetadataCallCount) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        status = DecodeCustomAttributeBands(
            reader, bandHeaderReader, arena, 1, cpBands, attributeDefinitions,
            fieldAttributeCalls.Count() == fieldCustomCallOffset ? nullptr :
                fieldAttributeCalls.Get() + fieldCustomCallOffset,
            fieldAttributeCalls.Count() - fieldCustomCallOffset,
            customAttributes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::MDelta5,
            bands->MethodDescriptorIndexes(),
            methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (haveMethodFlagsHigh) {
            status = DecodeRawUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->MethodFlagsHigh(),
                methodCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else if (methodCount != 0) {
            RtlZeroMemory(bands->MethodFlagsHigh(), methodCount * sizeof(ULONG));
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            bands->MethodFlagsLow(),
            methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        constexpr ULONG MethodCodeFlag = 1UL << 17;
        constexpr ULONG MethodExceptionsFlag = 1UL << 18;
        constexpr ULONG MethodSignatureFlag = 1UL << 19;
        constexpr ULONG MethodDeprecatedFlag = 1UL << 20;
        constexpr ULONG MethodVisibleAnnotationsFlag = 1UL << 21;
        constexpr ULONG MethodInvisibleAnnotationsFlag = 1UL << 22;
        constexpr ULONG MethodVisibleParameterAnnotationsFlag = 1UL << 23;
        constexpr ULONG MethodInvisibleParameterAnnotationsFlag = 1UL << 24;
        constexpr ULONG MethodAnnotationDefaultFlag = 1UL << 25;
        SIZE_T codeCount = 0;
        SIZE_T exceptionMethodCount = 0;
        SIZE_T methodSignatureCount = 0;
        HeapArray<SIZE_T> methodMetadataCounts(5);
        if (!methodMetadataCounts.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
        ULONG* methodCodeIndexes = bands->MethodCodeIndexes();
        ULONG* methodExceptionCounts = bands->MethodExceptionCounts();
        ULONG* methodSignatures = bands->MethodSignatureIndexes();
        if (methodCount != 0 &&
            (methodCodeIndexes == nullptr || methodExceptionCounts == nullptr ||
                methodSignatures == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T methodIndex = 0; methodIndex < methodCount; ++methodIndex) {
            methodCodeIndexes[methodIndex] = 0xffffffffUL;
            methodExceptionCounts[methodIndex] = 0;
            methodSignatures[methodIndex] = 0xffffffffUL;
            status = ValidateAttributeFlags(
                2,
                bands->MethodFlagsLow()[methodIndex],
                bands->MethodFlagsHigh()[methodIndex],
                0xffffUL | (1UL << 16) | MethodCodeFlag | MethodExceptionsFlag |
                    MethodSignatureFlag | MethodDeprecatedFlag |
                    MethodVisibleAnnotationsFlag | MethodInvisibleAnnotationsFlag |
                    MethodVisibleParameterAnnotationsFlag |
                    MethodInvisibleParameterAnnotationsFlag |
                    MethodAnnotationDefaultFlag,
                attributeDefinitions);
            if (!NT_SUCCESS(status)) return status;
            if ((bands->MethodFlagsLow()[methodIndex] & MethodCodeFlag) != 0) {
                if (codeCount > 0xffffffffULL) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                methodCodeIndexes[methodIndex] = static_cast<ULONG>(codeCount++);
            }
            if ((bands->MethodFlagsLow()[methodIndex] & MethodExceptionsFlag) != 0 &&
                !CheckedAddSize(exceptionMethodCount, 1, &exceptionMethodCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            if ((bands->MethodFlagsLow()[methodIndex] & MethodSignatureFlag) != 0 &&
                !CheckedAddSize(methodSignatureCount, 1, &methodSignatureCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            if ((bands->MethodFlagsLow()[methodIndex] & MethodVisibleAnnotationsFlag) != 0) ++methodMetadataCounts[0];
            if ((bands->MethodFlagsLow()[methodIndex] & MethodInvisibleAnnotationsFlag) != 0) ++methodMetadataCounts[1];
            if ((bands->MethodFlagsLow()[methodIndex] & MethodVisibleParameterAnnotationsFlag) != 0) ++methodMetadataCounts[2];
            if ((bands->MethodFlagsLow()[methodIndex] & MethodInvisibleParameterAnnotationsFlag) != 0) ++methodMetadataCounts[3];
            if ((bands->MethodFlagsLow()[methodIndex] & MethodAnnotationDefaultFlag) != 0) ++methodMetadataCounts[4];
        }
        SIZE_T methodMetadataCallCount = 0;
        for (SIZE_T metadataIndex = 0; metadataIndex < 5; ++metadataIndex) {
            if (methodMetadataCounts[metadataIndex] != 0) ++methodMetadataCallCount;
        }
        HeapArray<ULONG> methodAttributeCalls = {};
        SIZE_T methodCustomCallOffset = 0;
        status = ReadCustomAttributeControlBands(
            reader, bandHeaderReader, arena, 2,
            bands->MethodFlagsLow(), bands->MethodFlagsHigh(), methodCount,
            methodMetadataCallCount, cpBands, attributeDefinitions, customAttributes,
            &methodAttributeCalls, &methodCustomCallOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<ULONG> exceptionCounts = {};
        if (exceptionMethodCount != 0) {
            status = exceptionCounts.Allocate(exceptionMethodCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            exceptionCounts.Get(),
            exceptionMethodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T exceptionIndexCount = 0;
        SIZE_T exceptionCountIndex = 0;
        for (SIZE_T methodIndex = 0; methodIndex < methodCount; ++methodIndex) {
            if ((bands->MethodFlagsLow()[methodIndex] & MethodExceptionsFlag) == 0) {
                continue;
            }
            const ULONG count = exceptionCounts[exceptionCountIndex++];
            methodExceptionCounts[methodIndex] = count;
            if (!CheckedAddSize(exceptionIndexCount, count, &exceptionIndexCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        status = bands->AllocateMethodExceptionIndexes(exceptionIndexCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            bands->MethodExceptionClassIndexes(),
            exceptionIndexCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HeapArray<ULONG> methodSignatureValues = {};
        if (methodSignatureCount != 0) {
            status = methodSignatureValues.Allocate(methodSignatureCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            methodSignatureValues.Get(),
            methodSignatureCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T methodSignatureIndex = 0;
        for (SIZE_T methodIndex = 0; methodIndex < methodCount; ++methodIndex) {
            if ((bands->MethodFlagsLow()[methodIndex] & MethodSignatureFlag) != 0) {
                methodSignatures[methodIndex] = methodSignatureValues[methodSignatureIndex++];
            }
        }
        HeapArray<HttpPack200MetadataBands*> methodMetadataBands(5);
        if (!methodMetadataBands.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;
        methodMetadataBands[0] = bands->MethodVisibleAnnotations();
        methodMetadataBands[1] = bands->MethodInvisibleAnnotations();
        methodMetadataBands[2] = bands->MethodVisibleParameterAnnotations();
        methodMetadataBands[3] = bands->MethodInvisibleParameterAnnotations();
        methodMetadataBands[4] = bands->MethodAnnotationDefaults();
        SIZE_T methodMetadataCallIndex = 0;
        for (SIZE_T metadataIndex = 0; metadataIndex < 5; ++metadataIndex) {
            const SIZE_T count = methodMetadataCounts[metadataIndex];
            status = ReadMetadataBands(
                reader, bandHeaderReader, arena, count,
                count == 0 ? 0 : methodAttributeCalls[methodMetadataCallIndex++],
                metadataIndex == 2 || metadataIndex == 3,
                metadataIndex == 4,
                methodMetadataBands[metadataIndex]);
            if (!NT_SUCCESS(status)) return status;
        }
        if (methodMetadataCallIndex != methodMetadataCallCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        status = DecodeCustomAttributeBands(
            reader, bandHeaderReader, arena, 2, cpBands, attributeDefinitions,
            methodAttributeCalls.Count() == methodCustomCallOffset ? nullptr :
                methodAttributeCalls.Get() + methodCustomCallOffset,
            methodAttributeCalls.Count() - methodCustomCallOffset,
            customAttributes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (haveClassFlagsHigh) {
            status = DecodeRawUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->FlagsHigh(),
                classCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else if (classCount != 0) {
            RtlZeroMemory(bands->FlagsHigh(), classCount * sizeof(ULONG));
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            bands->FlagsLow(),
            classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        constexpr ULONG ClassSourceFileFlag = 1UL << 17;
        constexpr ULONG ClassEnclosingMethodFlag = 1UL << 18;
        constexpr ULONG ClassSignatureFlag = 1UL << 19;
        constexpr ULONG ClassDeprecatedFlag = 1UL << 20;
        constexpr ULONG ClassVisibleAnnotationsFlag = 1UL << 21;
        constexpr ULONG ClassInvisibleAnnotationsFlag = 1UL << 22;
        constexpr ULONG ClassInnerClassesFlag = 1UL << 23;
        constexpr ULONG ClassFileVersionFlag = 1UL << 24;
        SIZE_T sourceFileCount = 0;
        SIZE_T enclosingMethodCount = 0;
        SIZE_T classSignatureCount = 0;
        SIZE_T classVisibleAnnotationCount = 0;
        SIZE_T classInvisibleAnnotationCount = 0;
        SIZE_T classFileVersionCount = 0;
        SIZE_T classInnerClassesCount = 0;
        ULONG* sourceFileIndexes = bands->SourceFileIndexes();
        ULONG* enclosingMethodClasses = bands->EnclosingMethodClassIndexes();
        ULONG* enclosingMethodDescriptors = bands->EnclosingMethodDescriptorIndexes();
        ULONG* classSignatures = bands->ClassSignatureIndexes();
        ULONG* classMinorVersions = bands->ClassMinorVersions();
        ULONG* classMajorVersions = bands->ClassMajorVersions();
        if (classCount != 0 &&
            (sourceFileIndexes == nullptr || enclosingMethodClasses == nullptr ||
                enclosingMethodDescriptors == nullptr || classSignatures == nullptr ||
                classMinorVersions == nullptr || classMajorVersions == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            sourceFileIndexes[classIndex] = 0xffffffffUL;
            enclosingMethodClasses[classIndex] = 0xffffffffUL;
            enclosingMethodDescriptors[classIndex] = 0xffffffffUL;
            classSignatures[classIndex] = 0xffffffffUL;
            classMinorVersions[classIndex] = 0xffffffffUL;
            classMajorVersions[classIndex] = 0xffffffffUL;
            status = ValidateAttributeFlags(
                0,
                bands->FlagsLow()[classIndex],
                bands->FlagsHigh()[classIndex],
                0xffffUL | (1UL << 16) | ClassSourceFileFlag | ClassEnclosingMethodFlag |
                    ClassSignatureFlag | ClassDeprecatedFlag | ClassVisibleAnnotationsFlag |
                    ClassInvisibleAnnotationsFlag | ClassInnerClassesFlag |
                    ClassFileVersionFlag,
                attributeDefinitions);
            if (!NT_SUCCESS(status)) return status;
            if ((bands->FlagsLow()[classIndex] & ClassSourceFileFlag) != 0 &&
                !CheckedAddSize(sourceFileCount, 1, &sourceFileCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            if ((bands->FlagsLow()[classIndex] & ClassEnclosingMethodFlag) != 0 &&
                !CheckedAddSize(enclosingMethodCount, 1, &enclosingMethodCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            if ((bands->FlagsLow()[classIndex] & ClassSignatureFlag) != 0 &&
                !CheckedAddSize(classSignatureCount, 1, &classSignatureCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            if ((bands->FlagsLow()[classIndex] & ClassVisibleAnnotationsFlag) != 0) {
                ++classVisibleAnnotationCount;
            }
            if ((bands->FlagsLow()[classIndex] & ClassInvisibleAnnotationsFlag) != 0) {
                ++classInvisibleAnnotationCount;
            }
            if ((bands->FlagsLow()[classIndex] & ClassFileVersionFlag) != 0) {
                ++classFileVersionCount;
            }
            if ((bands->FlagsLow()[classIndex] & ClassInnerClassesFlag) != 0) {
                ++classInnerClassesCount;
            }
        }
        const SIZE_T classMetadataCallCount =
            (classVisibleAnnotationCount != 0 ? 1 : 0) +
            (classInvisibleAnnotationCount != 0 ? 1 : 0);
        HeapArray<ULONG> classAttributeCalls = {};
        SIZE_T classCustomCallOffset = 0;
        status = ReadCustomAttributeControlBands(
            reader, bandHeaderReader, arena, 0,
            bands->FlagsLow(), bands->FlagsHigh(), classCount,
            classMetadataCallCount, cpBands, attributeDefinitions, customAttributes,
            &classAttributeCalls, &classCustomCallOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HeapArray<ULONG> sourceFiles = {};
        if (sourceFileCount != 0) {
            status = sourceFiles.Allocate(sourceFileCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            sourceFiles.Get(),
            sourceFileCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T sourceFileIndex = 0;
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            if ((bands->FlagsLow()[classIndex] & ClassSourceFileFlag) != 0) {
                sourceFileIndexes[classIndex] = sourceFiles[sourceFileIndex++];
            }
        }
        HeapArray<ULONG> enclosingClasses = {};
        HeapArray<ULONG> enclosingDescriptors = {};
        if (enclosingMethodCount != 0) {
            status = enclosingClasses.Allocate(enclosingMethodCount);
            if (NT_SUCCESS(status)) {
                status = enclosingDescriptors.Allocate(enclosingMethodCount);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            enclosingClasses.Get(),
            enclosingMethodCount);
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                enclosingDescriptors.Get(),
                enclosingMethodCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T enclosingMethodIndex = 0;
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            if ((bands->FlagsLow()[classIndex] & ClassEnclosingMethodFlag) != 0) {
                enclosingMethodClasses[classIndex] = enclosingClasses[enclosingMethodIndex];
                enclosingMethodDescriptors[classIndex] = enclosingDescriptors[enclosingMethodIndex++];
            }
        }
        HeapArray<ULONG> classSignatureValues = {};
        if (classSignatureCount != 0) {
            status = classSignatureValues.Allocate(classSignatureCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            classSignatureValues.Get(),
            classSignatureCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T classSignatureIndex = 0;
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            if ((bands->FlagsLow()[classIndex] & ClassSignatureFlag) != 0) {
                classSignatures[classIndex] = classSignatureValues[classSignatureIndex++];
            }
        }
        SIZE_T classMetadataCallIndex = 0;
        status = ReadMetadataBands(
            reader, bandHeaderReader, arena, classVisibleAnnotationCount,
            classVisibleAnnotationCount == 0 ? 0 : classAttributeCalls[classMetadataCallIndex++],
            false, false, bands->ClassVisibleAnnotations());
        if (!NT_SUCCESS(status)) return status;
        status = ReadMetadataBands(
            reader, bandHeaderReader, arena, classInvisibleAnnotationCount,
            classInvisibleAnnotationCount == 0 ? 0 : classAttributeCalls[classMetadataCallIndex++],
            false, false, bands->ClassInvisibleAnnotations());
        if (!NT_SUCCESS(status) || classMetadataCallIndex != classMetadataCallCount) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        HeapArray<ULONG> localInnerCounts = {};
        if (classInnerClassesCount != 0) {
            status = localInnerCounts.Allocate(classInnerClassesCount);
            if (!NT_SUCCESS(status)) return status;
        }
        status = DecodeUlongBandWithMeta(
            reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
            localInnerCounts.Get(), classInnerClassesCount);
        if (!NT_SUCCESS(status)) return status;
        SIZE_T localInnerTotal = 0;
        SIZE_T localInnerCountIndex = 0;
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            bands->LocalInnerClassOffsets()[classIndex] = static_cast<ULONG>(localInnerTotal);
            bands->LocalInnerClassCounts()[classIndex] = 0;
            if ((bands->FlagsLow()[classIndex] & ClassInnerClassesFlag) == 0) continue;
            const ULONG count = localInnerCounts[localInnerCountIndex++];
            bands->LocalInnerClassCounts()[classIndex] = count;
            if (!CheckedAddSize(localInnerTotal, count, &localInnerTotal) ||
                localInnerTotal > 0xffffffffULL) return STATUS_INTEGER_OVERFLOW;
        }
        status = bands->AllocateLocalInnerClasses(localInnerTotal);
        if (!NT_SUCCESS(status)) return status;
        status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalInnerClassIndexes(), localInnerTotal);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalInnerClassFlags(), localInnerTotal);
        if (!NT_SUCCESS(status)) return status;
        SIZE_T explicitLocalInnerCount = 0;
        for (SIZE_T index = 0; index < localInnerTotal; ++index) {
            bands->LocalInnerClassOuterIndexes()[index] = 0xffffffffUL;
            bands->LocalInnerClassNameIndexes()[index] = 0xffffffffUL;
            if (bands->LocalInnerClassFlags()[index] != 0) ++explicitLocalInnerCount;
        }
        HeapArray<ULONG> explicitOuter = {};
        HeapArray<ULONG> explicitName = {};
        if (explicitLocalInnerCount != 0) {
            status = explicitOuter.Allocate(explicitLocalInnerCount);
            if (NT_SUCCESS(status)) status = explicitName.Allocate(explicitLocalInnerCount);
            if (!NT_SUCCESS(status)) return status;
        }
        status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, explicitOuter.Get(), explicitLocalInnerCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, explicitName.Get(), explicitLocalInnerCount);
        if (!NT_SUCCESS(status)) return status;
        SIZE_T explicitLocalIndex = 0;
        for (SIZE_T index = 0; index < localInnerTotal; ++index) {
            if (bands->LocalInnerClassFlags()[index] != 0) {
                bands->LocalInnerClassOuterIndexes()[index] = explicitOuter[explicitLocalIndex];
                bands->LocalInnerClassNameIndexes()[index] = explicitName[explicitLocalIndex++];
            }
        }
        HeapArray<ULONG> classMinorVersionValues = {};
        HeapArray<ULONG> classMajorVersionValues = {};
        if (classFileVersionCount != 0) {
            status = classMinorVersionValues.Allocate(classFileVersionCount);
            if (NT_SUCCESS(status)) status = classMajorVersionValues.Allocate(classFileVersionCount);
            if (!NT_SUCCESS(status)) return status;
        }
        status = DecodeUlongBandWithMeta(
            reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
            classMinorVersionValues.Get(), classFileVersionCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(
            reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
            classMajorVersionValues.Get(), classFileVersionCount);
        if (!NT_SUCCESS(status)) return status;
        SIZE_T classVersionIndex = 0;
        for (SIZE_T classIndex = 0; classIndex < classCount; ++classIndex) {
            if ((bands->FlagsLow()[classIndex] & ClassFileVersionFlag) != 0) {
                classMinorVersions[classIndex] = classMinorVersionValues[classVersionIndex];
                classMajorVersions[classIndex] = classMajorVersionValues[classVersionIndex++];
            }
        }
        status = DecodeCustomAttributeBands(
            reader, bandHeaderReader, arena, 0, cpBands, attributeDefinitions,
            classAttributeCalls.Count() == classCustomCallOffset ? nullptr :
                classAttributeCalls.Get() + classCustomCallOffset,
            classAttributeCalls.Count() - classCustomCallOffset,
            customAttributes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = bands->AllocateCodeBands(codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HeapArray<ULONG> codeHeaders = {};
        if (codeCount != 0) {
            status = codeHeaders.Allocate(codeCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Byte1,
            codeHeaders.Get(),
            codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T specialCount = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            if (codeHeaders[codeIndex] == 0 &&
                !CheckedAddSize(specialCount, 1, &specialCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        HeapArray<ULONG> specialMaxStacks = {};
        HeapArray<ULONG> specialMaxLocals = {};
        HeapArray<ULONG> specialHandlerCounts = {};
        if (specialCount != 0) {
            status = specialMaxStacks.Allocate(specialCount);
            if (NT_SUCCESS(status)) {
                status = specialMaxLocals.Allocate(specialCount);
            }
            if (NT_SUCCESS(status)) {
                status = specialHandlerCounts.Allocate(specialCount);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            specialMaxStacks.Get(),
            specialCount);
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                specialMaxLocals.Get(),
                specialCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                specialHandlerCounts.Get(),
                specialCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T specialIndex = 0;
        SIZE_T handlerCount = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            const ULONG header = codeHeaders[codeIndex];
            if (header == 0) {
                bands->CodeMaxStacks()[codeIndex] = specialMaxStacks[specialIndex];
                bands->CodeMaxNonArgumentLocals()[codeIndex] = specialMaxLocals[specialIndex];
                bands->CodeHandlerCounts()[codeIndex] = specialHandlerCounts[specialIndex++];
            }
            else if (header <= 144) {
                bands->CodeMaxStacks()[codeIndex] = (header - 1) % 12;
                bands->CodeMaxNonArgumentLocals()[codeIndex] = (header - 1) / 12;
                bands->CodeHandlerCounts()[codeIndex] = 0;
            }
            else if (header <= 208) {
                bands->CodeMaxStacks()[codeIndex] = (header - 145) % 8;
                bands->CodeMaxNonArgumentLocals()[codeIndex] = (header - 145) / 8;
                bands->CodeHandlerCounts()[codeIndex] = 1;
            }
            else if (header <= 255) {
                bands->CodeMaxStacks()[codeIndex] = (header - 209) % 7;
                bands->CodeMaxNonArgumentLocals()[codeIndex] = (header - 209) / 7;
                bands->CodeHandlerCounts()[codeIndex] = 2;
            }
            else {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (!CheckedAddSize(
                    handlerCount,
                    bands->CodeHandlerCounts()[codeIndex],
                    &handlerCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        status = bands->AllocateHandlerBands(handlerCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Bci5,
            bands->HandlerStartIndexes(),
            handlerCount);
        if (NT_SUCCESS(status)) {
            status = DecodeLongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Branch5,
                bands->HandlerEndOffsets(),
                handlerCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeLongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Branch5,
                bands->HandlerCatchOffsets(),
                handlerCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->HandlerClassIndexes(),
                handlerCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T codeFlagsCount = allCodeHasFlags ? codeCount : specialCount;
        HeapArray<ULONG> codeFlagsLow = {};
        HeapArray<ULONG> codeFlagsHigh = {};
        if (codeFlagsCount != 0) {
            status = codeFlagsLow.Allocate(codeFlagsCount);
            if (NT_SUCCESS(status)) {
                status = codeFlagsHigh.Allocate(codeFlagsCount);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        if (haveCodeFlagsHigh) {
            status = DecodeRawUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                codeFlagsHigh.Get(),
                codeFlagsCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else if (codeFlagsCount != 0) {
            RtlZeroMemory(codeFlagsHigh.Get(), codeFlagsCount * sizeof(ULONG));
        }
        status = DecodeRawUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            codeFlagsLow.Get(),
            codeFlagsCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T flagIndex = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            const bool hasFlags = allCodeHasFlags || codeHeaders[codeIndex] == 0;
            bands->CodeFlagsLow()[codeIndex] = hasFlags ? codeFlagsLow[flagIndex] : 0;
            bands->CodeFlagsHigh()[codeIndex] = hasFlags ? codeFlagsHigh[flagIndex] : 0;
            if (hasFlags) {
                ++flagIndex;
            }
        }
        if (flagIndex != codeFlagsCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        constexpr ULONG LineNumberTableFlag = 1UL << 1;
        constexpr ULONG LocalVariableTableFlag = 1UL << 2;
        constexpr ULONG LocalVariableTypeTableFlag = 1UL << 3;
        constexpr ULONG SupportedCodeFlags =
            LineNumberTableFlag | LocalVariableTableFlag | LocalVariableTypeTableFlag;
        SIZE_T lineTableCount = 0;
        SIZE_T localTableCount = 0;
        SIZE_T localTypeTableCount = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            status = ValidateAttributeFlags(
                3,
                bands->CodeFlagsLow()[codeIndex],
                bands->CodeFlagsHigh()[codeIndex],
                SupportedCodeFlags | (1UL << 16),
                attributeDefinitions);
            if (!NT_SUCCESS(status)) return status;
            if ((bands->CodeFlagsLow()[codeIndex] & LineNumberTableFlag) != 0) ++lineTableCount;
            if ((bands->CodeFlagsLow()[codeIndex] & LocalVariableTableFlag) != 0) ++localTableCount;
            if ((bands->CodeFlagsLow()[codeIndex] & LocalVariableTypeTableFlag) != 0) ++localTypeTableCount;
        }

        HeapArray<ULONG> codeAttributeCalls = {};
        SIZE_T codeCustomCallOffset = 0;
        status = ReadCustomAttributeControlBands(
            reader, bandHeaderReader, arena, 3,
            bands->CodeFlagsLow(), bands->CodeFlagsHigh(), codeCount,
            0, cpBands, attributeDefinitions, customAttributes,
            &codeAttributeCalls, &codeCustomCallOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<ULONG> compactCounts = {};
        const SIZE_T maximumTableCount =
            lineTableCount > localTableCount ?
                (lineTableCount > localTypeTableCount ? lineTableCount : localTypeTableCount) :
                (localTableCount > localTypeTableCount ? localTableCount : localTypeTableCount);
        if (maximumTableCount != 0) {
            status = compactCounts.Allocate(maximumTableCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        auto decodeCounts = [&](ULONG flag, SIZE_T tableCount, ULONG* counts, ULONG* offsets,
                                SIZE_T* total) noexcept -> NTSTATUS {
            *total = 0;
            NTSTATUS localStatus = DecodeRawUlongBandWithMeta(
                reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
                compactCounts.Get(), tableCount);
            if (!NT_SUCCESS(localStatus)) {
                return localStatus;
            }
            SIZE_T compactIndex = 0;
            for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
                offsets[codeIndex] = static_cast<ULONG>(*total);
                counts[codeIndex] = 0;
                if ((bands->CodeFlagsLow()[codeIndex] & flag) == 0) {
                    continue;
                }
                const ULONG count = compactCounts[compactIndex++];
                if (*total > 0xffffffffULL ||
                    !CheckedAddSize(*total, static_cast<SIZE_T>(count), total) ||
                    *total > 0xffffffffULL) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                counts[codeIndex] = count;
            }
            return compactIndex == tableCount ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        };

        SIZE_T lineCount = 0;
        status = decodeCounts(
            LineNumberTableFlag, lineTableCount, bands->LineNumberCounts(),
            bands->LineNumberOffsets(), &lineCount);
        if (!NT_SUCCESS(status)) return status;
        status = bands->AllocateLineNumbers(lineCount);
        if (!NT_SUCCESS(status)) return status;
        status = DecodeUlongBandWithMeta(
            reader, bandHeaderReader, arena, HttpPack200CodingKind::Bci5,
            bands->LineNumberBcis(), lineCount);
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader, bandHeaderReader, arena, HttpPack200CodingKind::Unsigned5,
                bands->LineNumbers(), lineCount);
        }
        if (!NT_SUCCESS(status)) return status;

        SIZE_T localCount = 0;
        status = decodeCounts(
            LocalVariableTableFlag, localTableCount, bands->LocalVariableCounts(),
            bands->LocalVariableOffsets(), &localCount);
        if (!NT_SUCCESS(status)) return status;
        status = bands->AllocateLocalVariables(localCount);
        if (!NT_SUCCESS(status)) return status;
        status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Bci5, bands->LocalVariableBcis(), localCount);
        if (NT_SUCCESS(status)) status = DecodeLongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Branch5, bands->LocalVariableSpans(), localCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalVariableNameIndexes(), localCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalVariableTypeIndexes(), localCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalVariableSlots(), localCount);
        if (!NT_SUCCESS(status)) return status;

        SIZE_T localTypeCount = 0;
        status = decodeCounts(
            LocalVariableTypeTableFlag, localTypeTableCount, bands->LocalVariableTypeCounts(),
            bands->LocalVariableTypeOffsets(), &localTypeCount);
        if (!NT_SUCCESS(status)) return status;
        status = bands->AllocateLocalVariableTypes(localTypeCount);
        if (!NT_SUCCESS(status)) return status;
        status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Bci5, bands->LocalVariableTypeBcis(), localTypeCount);
        if (NT_SUCCESS(status)) status = DecodeLongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Branch5, bands->LocalVariableTypeSpans(), localTypeCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalVariableTypeNameIndexes(), localTypeCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalVariableTypeSignatureIndexes(), localTypeCount);
        if (NT_SUCCESS(status)) status = DecodeUlongBandWithMeta(reader, bandHeaderReader, arena,
            HttpPack200CodingKind::Unsigned5, bands->LocalVariableTypeSlots(), localTypeCount);
        if (!NT_SUCCESS(status)) return status;
        return DecodeCustomAttributeBands(
            reader, bandHeaderReader, arena, 3, cpBands, attributeDefinitions,
            codeAttributeCalls.Count() == codeCustomCallOffset ? nullptr :
                codeAttributeCalls.Get() + codeCustomCallOffset,
            codeAttributeCalls.Count() - codeCustomCallOffset,
            customAttributes);
    }

    NTSTATUS HttpPack200ReadCodeBands(
        HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        SIZE_T codeCount,
        HttpPack200CodeBands* bands) noexcept
    {
        if (bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBand(reader, codec, bands->MaxStacks(), codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return DecodeUlongBand(reader, codec, bands->MaxLocals(), codeCount);
    }

    NTSTATUS HttpPack200ReadBytecodeBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        SIZE_T codeCount,
        HttpPack200CodeBands* bands) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr || bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> packedCodes = {};
        HeapArray<UCHAR> switchKinds = {};
        if (reader->Remaining() != 0) {
            status = packedCodes.Allocate(reader->Remaining());
            if (NT_SUCCESS(status)) {
                status = switchKinds.Allocate(reader->Remaining());
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        HeapArray<ULONG> packedOffsets = {};
        HeapArray<ULONG> packedLengths = {};
        if (codeCount != 0) {
            status = packedOffsets.Allocate(codeCount);
            if (NT_SUCCESS(status)) {
                status = packedLengths.Allocate(codeCount);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        SIZE_T packedCount = 0;
        SIZE_T byteOperandCount = 0;
        SIZE_T shortOperandCount = 0;
        SIZE_T localOperandCount = 0;
        SIZE_T labelOperandCount = 0;
        SIZE_T switchCount = 0;
        SIZE_T initOperandCount = 0;
        SIZE_T thisMethodOperandCount = 0;
        SIZE_T superMethodOperandCount = 0;
        SIZE_T intReferenceCount = 0;
        SIZE_T floatReferenceCount = 0;
        SIZE_T longReferenceCount = 0;
        SIZE_T doubleReferenceCount = 0;
        SIZE_T stringReferenceCount = 0;
        SIZE_T loadableValueReferenceCount = 0;
        SIZE_T classReferenceCount = 0;
        SIZE_T fieldReferenceCount = 0;
        SIZE_T methodReferenceCount = 0;
        SIZE_T interfaceMethodReferenceCount = 0;
        SIZE_T invokeDynamicReferenceCount = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            if (packedCount > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            packedOffsets[codeIndex] = static_cast<ULONG>(packedCount);
            bool terminated = false;
            for (;;) {
                UCHAR opcode = 0;
                if (!reader->ReadByte(&opcode)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (opcode == 0xff) {
                    terminated = true;
                    break;
                }
                const bool noOperand =
                    opcode <= 15 ||
                    (opcode >= 26 && opcode <= 131) ||
                    (opcode >= 133 && opcode <= 152) ||
                    (opcode >= 172 && opcode <= 177) ||
                    opcode == 190 || opcode == 191 || opcode == 194 || opcode == 195;
                const bool byteOperand = opcode == 16 || opcode == 188;
                const bool shortOperand = opcode == 17;
                const bool localOperand =
                    (opcode >= 21 && opcode <= 25) ||
                    (opcode >= 54 && opcode <= 58) ||
                    opcode == 169;
                const bool increment = opcode == 132;
                const bool switchOperand = opcode == 170 || opcode == 171;
                const bool initOperand = opcode == 230 || opcode == 231;
                const bool thisMethodOperand =
                    (opcode >= 206 && opcode <= 208) ||
                    (opcode >= 213 && opcode <= 215);
                const bool superMethodOperand =
                    (opcode >= 220 && opcode <= 222) ||
                    (opcode >= 227 && opcode <= 229);
                const bool intReference = opcode == 234 || opcode == 237;
                const bool floatReference = opcode == 235 || opcode == 238;
                const bool longReference = opcode == 20;
                const bool doubleReference = opcode == 239;
                const bool stringReference = opcode == 18 || opcode == 19;
                const bool loadableValueReference = opcode == 240 || opcode == 241;
                const bool classReference =
                    opcode == 187 || opcode == 189 || opcode == 192 || opcode == 193 ||
                    opcode == 197 || opcode == 233 || opcode == 236;
                const bool fieldReference = opcode >= 178 && opcode <= 181;
                const bool methodReference = opcode >= 182 && opcode <= 184;
                const bool interfaceMethodReference = opcode == 185 || opcode == 242 || opcode == 243;
                const bool invokeDynamicReference = opcode == 186;
                const bool labelOperand =
                    (opcode >= 153 && opcode <= 168) ||
                    opcode == 198 || opcode == 199 || opcode == 200 || opcode == 201;
                if (!noOperand && !byteOperand && !shortOperand && !localOperand &&
                    !increment && !labelOperand && !switchOperand && !initOperand &&
                    !thisMethodOperand && !superMethodOperand && !intReference &&
                    !floatReference && !longReference && !doubleReference &&
                    !stringReference && !loadableValueReference && !classReference &&
                    !fieldReference && !methodReference && !interfaceMethodReference &&
                    !invokeDynamicReference) {
                    return STATUS_NOT_SUPPORTED;
                }
                if (packedCount >= packedCodes.Count()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                packedCodes[packedCount++] = opcode;
                if ((byteOperand || increment) &&
                    !CheckedAddSize(byteOperandCount, 1, &byteOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (opcode == 197 &&
                    !CheckedAddSize(byteOperandCount, 1, &byteOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (shortOperand &&
                    !CheckedAddSize(shortOperandCount, 1, &shortOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if ((localOperand || increment) &&
                    !CheckedAddSize(localOperandCount, 1, &localOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (labelOperand &&
                    !CheckedAddSize(labelOperandCount, 1, &labelOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (switchOperand) {
                    if (switchCount >= switchKinds.Count() ||
                        !CheckedAddSize(labelOperandCount, 1, &labelOperandCount)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    switchKinds[switchCount++] = opcode;
                }
                if (initOperand &&
                    !CheckedAddSize(initOperandCount, 1, &initOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (thisMethodOperand &&
                    !CheckedAddSize(thisMethodOperandCount, 1, &thisMethodOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (superMethodOperand &&
                    !CheckedAddSize(superMethodOperandCount, 1, &superMethodOperandCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (intReference &&
                    !CheckedAddSize(intReferenceCount, 1, &intReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (floatReference &&
                    !CheckedAddSize(floatReferenceCount, 1, &floatReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (longReference &&
                    !CheckedAddSize(longReferenceCount, 1, &longReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (doubleReference &&
                    !CheckedAddSize(doubleReferenceCount, 1, &doubleReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (stringReference &&
                    !CheckedAddSize(stringReferenceCount, 1, &stringReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (loadableValueReference &&
                    !CheckedAddSize(
                        loadableValueReferenceCount,
                        1,
                        &loadableValueReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (classReference &&
                    !CheckedAddSize(classReferenceCount, 1, &classReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (fieldReference &&
                    !CheckedAddSize(fieldReferenceCount, 1, &fieldReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (methodReference &&
                    !CheckedAddSize(methodReferenceCount, 1, &methodReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (interfaceMethodReference &&
                    !CheckedAddSize(
                        interfaceMethodReferenceCount,
                        1,
                        &interfaceMethodReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (invokeDynamicReference &&
                    !CheckedAddSize(
                        invokeDynamicReferenceCount,
                        1,
                        &invokeDynamicReferenceCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
            if (!terminated || packedCount < packedOffsets[codeIndex] ||
                packedCount - packedOffsets[codeIndex] > 0xffffffffULL) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            packedLengths[codeIndex] = static_cast<ULONG>(packedCount - packedOffsets[codeIndex]);
            if (packedLengths[codeIndex] == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        HeapArray<ULONG> caseCounts = {};
        if (switchCount != 0) {
            status = caseCounts.Allocate(switchCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Unsigned5,
            caseCounts.Get(),
            switchCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T caseValueCount = 0;
        for (SIZE_T index = 0; index < switchCount; ++index) {
            const SIZE_T valueCount = switchKinds[index] == 170 ? 1 : caseCounts[index];
            if (!CheckedAddSize(caseValueCount, valueCount, &caseValueCount) ||
                !CheckedAddSize(labelOperandCount, caseCounts[index], &labelOperandCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        HeapArray<LONG> caseValues = {};
        if (caseValueCount != 0) {
            status = caseValues.Allocate(caseValueCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = DecodeLongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            caseValues.Get(),
            caseValueCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<ULONG> byteOperands = {};
        HeapArray<LONG> shortOperands = {};
        HeapArray<ULONG> localOperands = {};
        HeapArray<LONG> labelOperands = {};
        HeapArray<ULONG> initOperands = {};
        HeapArray<ULONG> thisMethodOperands = {};
        HeapArray<ULONG> superMethodOperands = {};
        HeapArray<ULONG> intReferences = {};
        HeapArray<ULONG> floatReferences = {};
        HeapArray<ULONG> longReferences = {};
        HeapArray<ULONG> doubleReferences = {};
        HeapArray<ULONG> stringReferences = {};
        HeapArray<ULONG> loadableValueReferences = {};
        HeapArray<ULONG> classReferences = {};
        HeapArray<ULONG> fieldReferences = {};
        HeapArray<ULONG> methodReferences = {};
        HeapArray<ULONG> interfaceMethodReferences = {};
        HeapArray<ULONG> invokeDynamicReferences = {};
        if (byteOperandCount != 0) {
            status = byteOperands.Allocate(byteOperandCount);
        }
        if (NT_SUCCESS(status) && shortOperandCount != 0) {
            status = shortOperands.Allocate(shortOperandCount);
        }
        if (NT_SUCCESS(status) && localOperandCount != 0) {
            status = localOperands.Allocate(localOperandCount);
        }
        if (NT_SUCCESS(status) && labelOperandCount != 0) {
            status = labelOperands.Allocate(labelOperandCount);
        }
        if (NT_SUCCESS(status) && initOperandCount != 0) {
            status = initOperands.Allocate(initOperandCount);
        }
        if (NT_SUCCESS(status) && thisMethodOperandCount != 0) {
            status = thisMethodOperands.Allocate(thisMethodOperandCount);
        }
        if (NT_SUCCESS(status) && superMethodOperandCount != 0) {
            status = superMethodOperands.Allocate(superMethodOperandCount);
        }
        if (NT_SUCCESS(status) && intReferenceCount != 0) {
            status = intReferences.Allocate(intReferenceCount);
        }
        if (NT_SUCCESS(status) && floatReferenceCount != 0) {
            status = floatReferences.Allocate(floatReferenceCount);
        }
        if (NT_SUCCESS(status) && longReferenceCount != 0) {
            status = longReferences.Allocate(longReferenceCount);
        }
        if (NT_SUCCESS(status) && doubleReferenceCount != 0) {
            status = doubleReferences.Allocate(doubleReferenceCount);
        }
        if (NT_SUCCESS(status) && stringReferenceCount != 0) {
            status = stringReferences.Allocate(stringReferenceCount);
        }
        if (NT_SUCCESS(status) && loadableValueReferenceCount != 0) {
            status = loadableValueReferences.Allocate(loadableValueReferenceCount);
        }
        if (NT_SUCCESS(status) && classReferenceCount != 0) {
            status = classReferences.Allocate(classReferenceCount);
        }
        if (NT_SUCCESS(status) && fieldReferenceCount != 0) {
            status = fieldReferences.Allocate(fieldReferenceCount);
        }
        if (NT_SUCCESS(status) && methodReferenceCount != 0) {
            status = methodReferences.Allocate(methodReferenceCount);
        }
        if (NT_SUCCESS(status) && interfaceMethodReferenceCount != 0) {
            status = interfaceMethodReferences.Allocate(interfaceMethodReferenceCount);
        }
        if (NT_SUCCESS(status) && invokeDynamicReferenceCount != 0) {
            status = invokeDynamicReferences.Allocate(invokeDynamicReferenceCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Byte1,
            byteOperands.Get(),
            byteOperandCount);
        if (NT_SUCCESS(status)) {
            status = DecodeLongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                shortOperands.Get(),
                shortOperandCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                intReferences.Get(),
                intReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                floatReferences.Get(),
                floatReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                longReferences.Get(),
                longReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                doubleReferences.Get(),
                doubleReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                stringReferences.Get(),
                stringReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                loadableValueReferences.Get(),
                loadableValueReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                classReferences.Get(),
                classReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                fieldReferences.Get(),
                fieldReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                methodReferences.Get(),
                methodReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                interfaceMethodReferences.Get(),
                interfaceMethodReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                invokeDynamicReferences.Get(),
                invokeDynamicReferenceCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                localOperands.Get(),
                localOperandCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeLongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Branch5,
                labelOperands.Get(),
                labelOperandCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                thisMethodOperands.Get(),
                thisMethodOperandCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                superMethodOperands.Get(),
                superMethodOperandCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                initOperands.Get(),
                initOperandCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<ULONG> instructionOffsets = {};
        if (packedCount != 0) {
            status = instructionOffsets.Allocate(packedCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        SIZE_T totalCodeLength = 0;
        SIZE_T switchLengthIndex = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            if (totalCodeLength > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            bands->CodeOffsets()[codeIndex] = static_cast<ULONG>(totalCodeLength);
            const SIZE_T packedOffset = packedOffsets[codeIndex];
            const SIZE_T packedLength = packedLengths[codeIndex];
            SIZE_T codeLength = 0;
            for (SIZE_T index = 0; index < packedLength; ++index) {
                if (codeLength > 0xffffffffULL) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                instructionOffsets[packedOffset + index] = static_cast<ULONG>(codeLength);
                const UCHAR opcode = packedCodes[packedOffset + index];
                SIZE_T instructionLength = 1;
                if (opcode == 16 || opcode == 188 ||
                    (opcode >= 21 && opcode <= 25) ||
                    (opcode >= 54 && opcode <= 58) || opcode == 169) {
                    instructionLength = 2;
                }
                else if (opcode == 17 || opcode == 132 ||
                    (opcode >= 153 && opcode <= 168) ||
                    opcode == 198 || opcode == 199) {
                    instructionLength = 3;
                }
                else if (opcode == 200 || opcode == 201) {
                    instructionLength = 5;
                }
                else if (opcode == 230 || opcode == 231) {
                    instructionLength = 3;
                }
                else if ((opcode >= 206 && opcode <= 208) ||
                    (opcode >= 220 && opcode <= 222)) {
                    instructionLength = 3;
                }
                else if ((opcode >= 213 && opcode <= 215) ||
                    (opcode >= 227 && opcode <= 229)) {
                    instructionLength = 4;
                }
                else if (opcode == 18 || opcode == 233 || opcode == 234 || opcode == 240) {
                    instructionLength = 2;
                }
                else if (opcode == 19 || opcode == 20 || opcode == 187 || opcode == 189 ||
                    opcode == 192 || opcode == 193 || opcode == 236 || opcode == 237 ||
                    opcode == 238 || opcode == 239 || opcode == 241 ||
                    opcode == 242 || opcode == 243) {
                    instructionLength = 3;
                }
                else if (opcode == 235) {
                    instructionLength = 2;
                }
                else if (opcode == 197) {
                    instructionLength = 4;
                }
                else if ((opcode >= 178 && opcode <= 184)) {
                    instructionLength = 3;
                }
                else if (opcode == 185) {
                    instructionLength = 5;
                }
                else if (opcode == 186) {
                    instructionLength = 5;
                }
                else if (opcode == 170 || opcode == 171) {
                    if (switchLengthIndex >= switchCount) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T count = caseCounts[switchLengthIndex++];
                    const SIZE_T padding = 3 - (codeLength % 4);
                    const SIZE_T unitSize = opcode == 170 ? 4 : 8;
                    if (count >
                        (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 1 - padding -
                            (opcode == 170 ? 12 : 8)) / unitSize) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    instructionLength = 1 + padding + (opcode == 170 ? 12 : 8) + count * unitSize;
                }
                if (!CheckedAddSize(codeLength, instructionLength, &codeLength)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
            if (codeLength > 0xffffffffULL ||
                !CheckedAddSize(totalCodeLength, codeLength, &totalCodeLength)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            bands->CodeLengths()[codeIndex] = static_cast<ULONG>(codeLength);
        }
        if (switchLengthIndex != switchCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        SIZE_T instructionOffsetCount = 0;
        if (!CheckedAddSize(packedCount, codeCount, &instructionOffsetCount)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        status = bands->AllocateInstructionMap(instructionOffsetCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T instructionMapOffset = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            const SIZE_T packedOffset = packedOffsets[codeIndex];
            const SIZE_T packedLength = packedLengths[codeIndex];
            if (instructionMapOffset > 0xffffffffULL || packedLength > 0xffffffffULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            bands->InstructionMapOffsets()[codeIndex] =
                static_cast<ULONG>(instructionMapOffset);
            bands->InstructionCounts()[codeIndex] = static_cast<ULONG>(packedLength);
            for (SIZE_T index = 0; index < packedLength; ++index) {
                bands->InstructionByteOffsets()[instructionMapOffset++] =
                    instructionOffsets[packedOffset + index];
            }
            bands->InstructionByteOffsets()[instructionMapOffset++] =
                bands->CodeLengths()[codeIndex];
        }
        if (instructionMapOffset != instructionOffsetCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        status = bands->AllocateCodeBytes(totalCodeLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T relocationCount = 0;
        if (!CheckedAddSize(initOperandCount, thisMethodOperandCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, superMethodOperandCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, intReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, floatReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, longReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, doubleReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, stringReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, loadableValueReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, classReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, fieldReferenceCount, &relocationCount) ||
            !CheckedAddSize(relocationCount, methodReferenceCount, &relocationCount) ||
            !CheckedAddSize(
                relocationCount,
                interfaceMethodReferenceCount,
                &relocationCount) ||
            !CheckedAddSize(
                relocationCount,
                invokeDynamicReferenceCount,
                &relocationCount)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        status = bands->AllocateRelocations(relocationCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T outputOffset = 0;
        SIZE_T byteOperandIndex = 0;
        SIZE_T shortOperandIndex = 0;
        SIZE_T localOperandIndex = 0;
        SIZE_T labelOperandIndex = 0;
        SIZE_T switchOutputIndex = 0;
        SIZE_T caseValueIndex = 0;
        SIZE_T initOperandIndex = 0;
        SIZE_T thisMethodOperandIndex = 0;
        SIZE_T superMethodOperandIndex = 0;
        SIZE_T intReferenceIndex = 0;
        SIZE_T floatReferenceIndex = 0;
        SIZE_T longReferenceIndex = 0;
        SIZE_T doubleReferenceIndex = 0;
        SIZE_T stringReferenceIndex = 0;
        SIZE_T loadableValueReferenceIndex = 0;
        SIZE_T classReferenceIndex = 0;
        SIZE_T fieldReferenceIndex = 0;
        SIZE_T methodReferenceIndex = 0;
        SIZE_T interfaceMethodReferenceIndex = 0;
        SIZE_T invokeDynamicReferenceIndex = 0;
        SIZE_T relocationIndex = 0;
        for (SIZE_T codeIndex = 0; codeIndex < codeCount; ++codeIndex) {
            const SIZE_T packedOffset = packedOffsets[codeIndex];
            const SIZE_T packedLength = packedLengths[codeIndex];
            for (SIZE_T index = 0; index < packedLength; ++index) {
                const UCHAR opcode = packedCodes[packedOffset + index];
                const bool combinedThisMethod = opcode >= 213 && opcode <= 215;
                const bool combinedSuperMethod = opcode >= 227 && opcode <= 229;
                if (combinedThisMethod || combinedSuperMethod) {
                    bands->CodeBytes()[outputOffset++] = 42;
                }
                if ((opcode >= 206 && opcode <= 208) || combinedThisMethod) {
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(
                        182 + (combinedThisMethod ? opcode - 213 : opcode - 206));
                }
                else if ((opcode >= 220 && opcode <= 222) || combinedSuperMethod) {
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(
                        182 + (combinedSuperMethod ? opcode - 227 : opcode - 220));
                }
                else if (opcode == 233 || opcode == 234 || opcode == 235) {
                    bands->CodeBytes()[outputOffset++] = 18;
                }
                else if (opcode == 236 || opcode == 237 || opcode == 238) {
                    bands->CodeBytes()[outputOffset++] = 19;
                }
                else if (opcode == 239) {
                    bands->CodeBytes()[outputOffset++] = 20;
                }
                else if (opcode == 240) {
                    bands->CodeBytes()[outputOffset++] = 18;
                }
                else if (opcode == 241) {
                    bands->CodeBytes()[outputOffset++] = 19;
                }
                else if (opcode == 242) {
                    bands->CodeBytes()[outputOffset++] = 183;
                }
                else if (opcode == 243) {
                    bands->CodeBytes()[outputOffset++] = 184;
                }
                else {
                    bands->CodeBytes()[outputOffset++] =
                        opcode == 230 || opcode == 231 ? 183 : opcode;
                }
                if (opcode == 16 || opcode == 188) {
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(byteOperands[byteOperandIndex++]);
                }
                else if (opcode == 17) {
                    const USHORT operand = static_cast<USHORT>(shortOperands[shortOperandIndex++]);
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((operand >> 8) & 0xff);
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(operand & 0xff);
                }
                else if ((opcode >= 21 && opcode <= 25) ||
                    (opcode >= 54 && opcode <= 58) || opcode == 169) {
                    if (localOperands[localOperandIndex] > 0xffUL) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    bands->CodeBytes()[outputOffset++] =
                        static_cast<UCHAR>(localOperands[localOperandIndex++]);
                }
                else if (opcode == 132) {
                    if (localOperands[localOperandIndex] > 0xffUL) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    bands->CodeBytes()[outputOffset++] =
                        static_cast<UCHAR>(localOperands[localOperandIndex++]);
                    bands->CodeBytes()[outputOffset++] =
                        static_cast<UCHAR>(byteOperands[byteOperandIndex++]);
                }
                else if (opcode == 170 || opcode == 171) {
                    if (switchOutputIndex >= switchCount ||
                        switchKinds[switchOutputIndex] != opcode) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T count = caseCounts[switchOutputIndex++];
                    const SIZE_T sourceOffset = instructionOffsets[packedOffset + index];
                    const SIZE_T padding = 3 - (sourceOffset % 4);
                    for (SIZE_T pad = 0; pad < padding; ++pad) {
                        bands->CodeBytes()[outputOffset++] = 0;
                    }

                    if (labelOperandIndex >= labelOperandCount) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    LONGLONG targetIndex =
                        static_cast<LONGLONG>(index) + labelOperands[labelOperandIndex++];
                    if (targetIndex < 0 || targetIndex >= static_cast<LONGLONG>(packedLength)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    LONGLONG targetOffset =
                        instructionOffsets[packedOffset + static_cast<SIZE_T>(targetIndex)];
                    LONGLONG displacement = targetOffset - static_cast<LONGLONG>(sourceOffset);
                    if (displacement < static_cast<LONGLONG>(-2147483647L) - 1 ||
                        displacement > static_cast<LONGLONG>(2147483647L)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    ULONG encoded = static_cast<ULONG>(static_cast<LONG>(displacement));
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 24) & 0xff);
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 16) & 0xff);
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                    bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);

                    if (opcode == 170) {
                        if (caseValueIndex >= caseValueCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        const LONG low = caseValues[caseValueIndex++];
                        const LONGLONG highValue =
                            static_cast<LONGLONG>(low) + static_cast<LONGLONG>(count) - 1;
                        if (highValue < static_cast<LONGLONG>(-2147483647L) - 1 ||
                            highValue > static_cast<LONGLONG>(2147483647L)) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                        encoded = static_cast<ULONG>(low);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 24) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 16) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);
                        encoded = static_cast<ULONG>(static_cast<LONG>(highValue));
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 24) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 16) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);
                    }
                    else {
                        if (count > 0xffffffffULL) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                        encoded = static_cast<ULONG>(count);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 24) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 16) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);
                    }

                    for (SIZE_T caseIndex = 0; caseIndex < count; ++caseIndex) {
                        if (opcode == 171) {
                            if (caseValueIndex >= caseValueCount) {
                                return STATUS_INVALID_NETWORK_RESPONSE;
                            }
                            encoded = static_cast<ULONG>(caseValues[caseValueIndex++]);
                            bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 24) & 0xff);
                            bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 16) & 0xff);
                            bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                            bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);
                        }
                        if (labelOperandIndex >= labelOperandCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        targetIndex = static_cast<LONGLONG>(index) +
                            labelOperands[labelOperandIndex++];
                        if (targetIndex < 0 || targetIndex >= static_cast<LONGLONG>(packedLength)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        targetOffset =
                            instructionOffsets[packedOffset + static_cast<SIZE_T>(targetIndex)];
                        displacement = targetOffset - static_cast<LONGLONG>(sourceOffset);
                        if (displacement < static_cast<LONGLONG>(-2147483647L) - 1 ||
                            displacement > static_cast<LONGLONG>(2147483647L)) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                        encoded = static_cast<ULONG>(static_cast<LONG>(displacement));
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 24) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 16) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);
                    }
                }
                else if (opcode == 230 || opcode == 231) {
                    if (initOperandIndex >= initOperandCount ||
                        relocationIndex >= bands->RelocationCount() ||
                        outputOffset - bands->CodeOffsets()[codeIndex] > 0xffffffffULL) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    HttpPack200CodeRelocation& relocation =
                        bands->Relocations()[relocationIndex++];
                    relocation.CodeIndex = static_cast<ULONG>(codeIndex);
                    relocation.OperandOffset = static_cast<ULONG>(
                        outputOffset - bands->CodeOffsets()[codeIndex]);
                    relocation.ReferenceIndex = initOperands[initOperandIndex++];
                    relocation.Kind = opcode == 230 ?
                        HttpPack200RelocationKind::InitThis :
                        HttpPack200RelocationKind::InitSuper;
                    bands->CodeBytes()[outputOffset++] = 0;
                    bands->CodeBytes()[outputOffset++] = 0;
                }
                else if ((opcode >= 206 && opcode <= 208) ||
                    (opcode >= 213 && opcode <= 215) ||
                    (opcode >= 220 && opcode <= 222) ||
                    (opcode >= 227 && opcode <= 229)) {
                    const bool isThis =
                        (opcode >= 206 && opcode <= 208) ||
                        (opcode >= 213 && opcode <= 215);
                    if (relocationIndex >= bands->RelocationCount() ||
                        outputOffset - bands->CodeOffsets()[codeIndex] > 0xffffffffULL ||
                        (isThis && thisMethodOperandIndex >= thisMethodOperandCount) ||
                        (!isThis && superMethodOperandIndex >= superMethodOperandCount)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    HttpPack200CodeRelocation& relocation =
                        bands->Relocations()[relocationIndex++];
                    relocation.CodeIndex = static_cast<ULONG>(codeIndex);
                    relocation.OperandOffset = static_cast<ULONG>(
                        outputOffset - bands->CodeOffsets()[codeIndex]);
                    relocation.ReferenceIndex = isThis ?
                        thisMethodOperands[thisMethodOperandIndex++] :
                        superMethodOperands[superMethodOperandIndex++];
                    relocation.Kind = isThis ?
                        HttpPack200RelocationKind::MethodThis :
                        HttpPack200RelocationKind::MethodSuper;
                    bands->CodeBytes()[outputOffset++] = 0;
                    bands->CodeBytes()[outputOffset++] = 0;
                }
                else if (opcode == 18 || opcode == 19 || opcode == 20 ||
                    opcode == 233 || opcode == 234 || opcode == 235 ||
                    opcode == 236 || opcode == 237 || opcode == 238 || opcode == 239 ||
                    opcode == 240 || opcode == 241 ||
                    opcode == 187 || opcode == 189 ||
                    opcode == 192 || opcode == 193 || opcode == 197 ||
                    (opcode >= 178 && opcode <= 186) || opcode == 242 || opcode == 243) {
                    if (relocationIndex >= bands->RelocationCount() ||
                        outputOffset - bands->CodeOffsets()[codeIndex] > 0xffffffffULL) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    HttpPack200CodeRelocation& relocation =
                        bands->Relocations()[relocationIndex++];
                    relocation.CodeIndex = static_cast<ULONG>(codeIndex);
                    relocation.OperandOffset = static_cast<ULONG>(
                        outputOffset - bands->CodeOffsets()[codeIndex]);
                    if (opcode == 234 || opcode == 237) {
                        if (intReferenceIndex >= intReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = intReferences[intReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::Integer;
                    }
                    else if (opcode == 235 || opcode == 238) {
                        if (floatReferenceIndex >= floatReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = floatReferences[floatReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::Float;
                    }
                    else if (opcode == 20) {
                        if (longReferenceIndex >= longReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = longReferences[longReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::Long;
                    }
                    else if (opcode == 239) {
                        if (doubleReferenceIndex >= doubleReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = doubleReferences[doubleReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::Double;
                    }
                    else if (opcode == 18 || opcode == 19) {
                        if (stringReferenceIndex >= stringReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = stringReferences[stringReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::String;
                    }
                    else if (opcode == 240 || opcode == 241) {
                        if (loadableValueReferenceIndex >= loadableValueReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex =
                            loadableValueReferences[loadableValueReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::LoadableValue;
                    }
                    else if (opcode >= 178 && opcode <= 181) {
                        if (fieldReferenceIndex >= fieldReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = fieldReferences[fieldReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::Field;
                    }
                    else if (opcode >= 182 && opcode <= 184) {
                        if (methodReferenceIndex >= methodReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = methodReferences[methodReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::Method;
                    }
                    else if (opcode == 185 || opcode == 242 || opcode == 243) {
                        if (interfaceMethodReferenceIndex >= interfaceMethodReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex =
                            interfaceMethodReferences[interfaceMethodReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::InterfaceMethod;
                    }
                    else if (opcode == 186) {
                        if (invokeDynamicReferenceIndex >= invokeDynamicReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex =
                            invokeDynamicReferences[invokeDynamicReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::InvokeDynamic;
                    }
                    else {
                        if (classReferenceIndex >= classReferenceCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        relocation.ReferenceIndex = classReferences[classReferenceIndex++];
                        relocation.Kind = HttpPack200RelocationKind::Class;
                    }
                    relocation.OperandWidth =
                        opcode == 18 || opcode == 233 || opcode == 234 || opcode == 235 ||
                        opcode == 240 ? 1 : 2;
                    bands->CodeBytes()[outputOffset++] = 0;
                    if (relocation.OperandWidth == 2) {
                        bands->CodeBytes()[outputOffset++] = 0;
                    }
                    if (opcode == 185) {
                        bands->CodeBytes()[outputOffset++] = 0;
                        bands->CodeBytes()[outputOffset++] = 0;
                    }
                    if (opcode == 186) {
                        bands->CodeBytes()[outputOffset++] = 0;
                        bands->CodeBytes()[outputOffset++] = 0;
                    }
                    if (opcode == 197) {
                        bands->CodeBytes()[outputOffset++] =
                            static_cast<UCHAR>(byteOperands[byteOperandIndex++]);
                    }
                }
                else if ((opcode >= 153 && opcode <= 168) ||
                    opcode == 198 || opcode == 199 || opcode == 200 || opcode == 201) {
                    const LONGLONG targetIndex =
                        static_cast<LONGLONG>(index) + labelOperands[labelOperandIndex++];
                    if (targetIndex < 0 || targetIndex >= static_cast<LONGLONG>(packedLength)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const LONGLONG sourceOffset = instructionOffsets[packedOffset + index];
                    const LONGLONG targetOffset =
                        instructionOffsets[packedOffset + static_cast<SIZE_T>(targetIndex)];
                    const LONGLONG displacement = targetOffset - sourceOffset;
                    if (opcode == 200 || opcode == 201) {
                        if (displacement < static_cast<LONGLONG>(-2147483647L) - 1 ||
                            displacement > static_cast<LONGLONG>(2147483647L)) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                        const ULONG encoded = static_cast<ULONG>(static_cast<LONG>(displacement));
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 24) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 16) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);
                    }
                    else {
                        if (displacement < -32768 || displacement > 32767) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                        const USHORT encoded = static_cast<USHORT>(static_cast<LONG>(displacement));
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>((encoded >> 8) & 0xff);
                        bands->CodeBytes()[outputOffset++] = static_cast<UCHAR>(encoded & 0xff);
                    }
                }
            }
        }
        if (byteOperandIndex != byteOperandCount || shortOperandIndex != shortOperandCount ||
            localOperandIndex != localOperandCount || labelOperandIndex != labelOperandCount ||
            switchOutputIndex != switchCount || caseValueIndex != caseValueCount ||
            initOperandIndex != initOperandCount || relocationIndex != bands->RelocationCount() ||
            thisMethodOperandIndex != thisMethodOperandCount ||
            superMethodOperandIndex != superMethodOperandCount ||
            intReferenceIndex != intReferenceCount ||
            floatReferenceIndex != floatReferenceCount ||
            longReferenceIndex != longReferenceCount ||
            doubleReferenceIndex != doubleReferenceCount ||
            stringReferenceIndex != stringReferenceCount ||
            loadableValueReferenceIndex != loadableValueReferenceCount ||
            classReferenceIndex != classReferenceCount ||
            fieldReferenceIndex != fieldReferenceCount ||
            methodReferenceIndex != methodReferenceCount ||
            interfaceMethodReferenceIndex != interfaceMethodReferenceCount ||
            invokeDynamicReferenceIndex != invokeDynamicReferenceCount ||
            outputOffset != totalCodeLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        bands->SetCodeByteCount(outputOffset);
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ReadAttributeBands(
        HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        SIZE_T attributeLayoutCount,
        HttpPack200AttributeBands* bands) noexcept
    {
        if (bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(attributeLayoutCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return DecodeUlongBand(reader, codec, bands->LayoutNameIndexes(), attributeLayoutCount);
    }

    NTSTATUS HttpPack200ReadAttributeDefinitionBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        SIZE_T definitionCount,
        SIZE_T utf8Count,
        HttpPack200AttributeDefinitionBands* bands) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr || bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(definitionCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Byte1,
            bands->Headers(),
            definitionCount);
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->NameIndexes(),
                definitionCount);
        }
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->LayoutIndexes(),
                definitionCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < definitionCount; ++index) {
            const ULONG context = bands->Headers()[index] & 0x03UL;
            if (context > 3 || bands->NameIndexes()[index] >= utf8Count ||
                bands->LayoutIndexes()[index] >= utf8Count) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ReadInnerClassBands(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200CodecArena* arena,
        SIZE_T innerClassCount,
        SIZE_T classCount,
        SIZE_T utf8Count,
        HttpPack200InnerClassBands* bands) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr || bands == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = bands->Initialize(innerClassCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::UnsignedDelta5,
            bands->ThisClassIndexes(),
            innerClassCount);
        if (NT_SUCCESS(status)) {
            status = DecodeRawUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Unsigned5,
                bands->Flags(),
                innerClassCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T explicitCount = 0;
        for (SIZE_T index = 0; index < innerClassCount; ++index) {
            if (bands->ThisClassIndexes()[index] >= classCount) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if ((bands->Flags()[index] & 0x00010000UL) != 0 &&
                !CheckedAddSize(explicitCount, 1, &explicitCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        status = bands->AllocateExplicitBands(explicitCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = DecodeUlongBandWithMeta(
            reader,
            bandHeaderReader,
            arena,
            HttpPack200CodingKind::Delta5,
            bands->OuterClassIndexes(),
            explicitCount);
        if (NT_SUCCESS(status)) {
            status = DecodeUlongBandWithMeta(
                reader,
                bandHeaderReader,
                arena,
                HttpPack200CodingKind::Delta5,
                bands->NameIndexes(),
                explicitCount);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < explicitCount; ++index) {
            if (bands->OuterClassIndexes()[index] > classCount ||
                bands->NameIndexes()[index] > utf8Count) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        return STATUS_SUCCESS;
    }
}
}
