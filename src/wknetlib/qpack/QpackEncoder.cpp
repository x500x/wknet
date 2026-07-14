#include "qpack/QpackEncoder.h"
#include "qpack/QpackDecoder.h"
#include "qpack/QpackHuffman.h"
#include "qpack/QpackInteger.h"
#include "qpack/QpackStaticTable.h"
#include "rtl/ProtocolAllocator.h"

namespace wknet::qpack
{
namespace
{
struct FieldMatch final
{
    bool Exact = false;
    bool Static = false;
    ULONGLONG Index = 0;
};

bool BytesEqual(const UCHAR *left, const UCHAR *right, SIZE_T length) noexcept
{
    if (length == 0)
    {
        return true;
    }
    return RtlCompareMemory(left, right, length) == length;
}

UCHAR LowerAscii(UCHAR value) noexcept
{
    if (value >= 'A' && value <= 'Z')
    {
        return static_cast<UCHAR>(value + ('a' - 'A'));
    }
    return value;
}

bool NameEquals(const UCHAR *name, SIZE_T nameLength, const char *expected) noexcept
{
    SIZE_T expectedLength = 0;
    while (expected[expectedLength] != '\0')
    {
        ++expectedLength;
    }
    if (nameLength != expectedLength)
    {
        return false;
    }
    for (SIZE_T index = 0; index < nameLength; ++index)
    {
        if (LowerAscii(name[index]) != static_cast<UCHAR>(expected[index]))
        {
            return false;
        }
    }
    return true;
}

NTSTATUS FindStaticMatch(const QpackFieldView &field, bool requireExact, _Out_ FieldMatch *match) noexcept
{
    if (match == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *match = {};

    for (SIZE_T index = 0; index < QpackStaticTableSize; ++index)
    {
        QpackStaticEntryView entry = {};
        const NTSTATUS status = QpackStaticTableLookup(index, &entry);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (entry.Name.Length != field.Name.Length || !BytesEqual(entry.Name.Data, field.Name.Data, field.Name.Length))
        {
            continue;
        }
        const bool exact = entry.Value.Length == field.Value.Length &&
                           BytesEqual(entry.Value.Data, field.Value.Data, field.Value.Length);
        if (exact || !requireExact)
        {
            match->Exact = exact;
            match->Static = true;
            match->Index = index;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS EncodeRawString(const UCHAR *source, SIZE_T sourceLength, bool huffman, UCHAR prefix, UCHAR prefixBits,
                         UCHAR huffmanMask, UCHAR *destination, SIZE_T capacity, _Out_ SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (destination == nullptr || bytesWritten == nullptr || (source == nullptr && sourceLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T encodedLength = sourceLength;
    if (huffman)
    {
        encodedLength = QpackHuffmanEncodedLength(source, sourceLength);
        if (encodedLength == static_cast<SIZE_T>(~static_cast<SIZE_T>(0)))
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        prefix = static_cast<UCHAR>(prefix | huffmanMask);
    }

    SIZE_T prefixLength = 0;
    NTSTATUS status = QpackEncodeInteger(encodedLength, prefix, prefixBits, destination, capacity, &prefixLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (encodedLength > capacity - prefixLength)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    SIZE_T payloadLength = 0;
    if (huffman)
    {
        status = QpackHuffmanEncode(source, sourceLength, destination + prefixLength, capacity - prefixLength,
                                    &payloadLength);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    else
    {
        if (sourceLength != 0)
        {
            RtlCopyMemory(destination + prefixLength, source, sourceLength);
        }
        payloadLength = sourceLength;
    }

    *bytesWritten = prefixLength + payloadLength;
    return STATUS_SUCCESS;
}

NTSTATUS AppendInteger(ULONGLONG value, UCHAR prefix, UCHAR prefixBits, UCHAR *destination, SIZE_T capacity,
                       _Inout_ SIZE_T *offset) noexcept
{
    if (offset == nullptr || *offset > capacity)
    {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T written = 0;
    const NTSTATUS status =
        QpackEncodeInteger(value, prefix, prefixBits, destination + *offset, capacity - *offset, &written);
    if (NT_SUCCESS(status))
    {
        *offset += written;
    }
    return status;
}

NTSTATUS AppendString(const QpackStringView &value, bool huffman, UCHAR prefix, UCHAR prefixBits, UCHAR huffmanMask,
                      UCHAR *destination, SIZE_T capacity, _Inout_ SIZE_T *offset) noexcept
{
    if (offset == nullptr || *offset > capacity)
    {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T written = 0;
    const NTSTATUS status = EncodeRawString(value.Data, value.Length, huffman, prefix, prefixBits, huffmanMask,
                                            destination + *offset, capacity - *offset, &written);
    if (NT_SUCCESS(status))
    {
        *offset += written;
    }
    return status;
}

bool ReferenceExists(const ULONGLONG *references, SIZE_T referenceCount, ULONGLONG absoluteIndex) noexcept
{
    for (SIZE_T index = 0; index < referenceCount; ++index)
    {
        if (references[index] == absoluteIndex)
        {
            return true;
        }
    }
    return false;
}
} // namespace

QpackEncoder::~QpackEncoder() noexcept
{
    Reset();
}

NTSTATUS QpackEncoder::Initialize(SIZE_T peerMaximumCapacity, ULONG peerBlockedStreams) noexcept
{
    Reset();
    effectiveMaximumCapacity_ = peerMaximumCapacity;
    if (effectiveMaximumCapacity_ > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES)
    {
        effectiveMaximumCapacity_ = WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES;
    }
    effectiveBlockedStreams_ = peerBlockedStreams;
    if (effectiveBlockedStreams_ > WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS)
    {
        effectiveBlockedStreams_ = WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS;
    }
    return table_.Initialize(effectiveMaximumCapacity_, 0);
}

void QpackEncoder::Reset() noexcept
{
    OutstandingSection *section = outstandingHead_;
    while (section != nullptr)
    {
        OutstandingSection *next = section->Next;
        const SIZE_T allocationSize = sizeof(OutstandingSection) + section->ReferenceCount * sizeof(ULONGLONG);
        RtlSecureZeroMemory(section, allocationSize);
        FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackEncoderOutstandingSection, section);
        section = next;
    }
    outstandingHead_ = nullptr;
    outstandingTail_ = nullptr;
    table_.Reset();
    effectiveMaximumCapacity_ = 0;
    effectiveBlockedStreams_ = 0;
    knownReceivedCount_ = 0;
    outstandingSectionCount_ = 0;
    outstandingReferenceBytes_ = 0;
    pendingCapacity_ = 0;
    pendingCapacityValid_ = false;
}

NTSTATUS QpackEncoder::SetCapacity(SIZE_T capacity, UCHAR *instruction, SIZE_T instructionCapacity,
                                   SIZE_T *instructionLength) noexcept
{
    if (instructionLength != nullptr)
    {
        *instructionLength = 0;
    }
    if (capacity > effectiveMaximumCapacity_)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const NTSTATUS status = ApplyCapacity(capacity, instruction, instructionCapacity, instructionLength);
    if (status == STATUS_DEVICE_BUSY)
    {
        pendingCapacity_ = capacity;
        pendingCapacityValid_ = true;
        return STATUS_PENDING;
    }
    if (NT_SUCCESS(status))
    {
        pendingCapacityValid_ = false;
    }
    return status;
}

NTSTATUS QpackEncoder::DrainPendingCapacity(UCHAR *instruction, SIZE_T instructionCapacity,
                                            SIZE_T *instructionLength) noexcept
{
    if (instructionLength != nullptr)
    {
        *instructionLength = 0;
    }
    if (!pendingCapacityValid_)
    {
        return STATUS_NOT_FOUND;
    }

    const NTSTATUS status = ApplyCapacity(pendingCapacity_, instruction, instructionCapacity, instructionLength);
    if (NT_SUCCESS(status))
    {
        pendingCapacityValid_ = false;
    }
    return status == STATUS_DEVICE_BUSY ? STATUS_PENDING : status;
}

NTSTATUS QpackEncoder::InsertWithNameReference(bool staticReference, ULONGLONG nameIndex, const UCHAR *value,
                                               SIZE_T valueLength, bool huffmanValue, UCHAR *instruction,
                                               SIZE_T instructionCapacity, SIZE_T *instructionLength,
                                               ULONGLONG *absoluteIndex) noexcept
{
    if (instructionLength != nullptr)
    {
        *instructionLength = 0;
    }
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = 0;
    }
    if (instruction == nullptr || instructionLength == nullptr || (value == nullptr && valueLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (pendingCapacityValid_)
    {
        return STATUS_DEVICE_BUSY;
    }

    QpackStringView name = {};
    if (staticReference)
    {
        QpackStaticEntryView entry = {};
        const NTSTATUS lookupStatus = QpackStaticTableLookup(static_cast<SIZE_T>(nameIndex), &entry);
        if (!NT_SUCCESS(lookupStatus))
        {
            return STATUS_INVALID_PARAMETER;
        }
        name = entry.Name;
    }
    else
    {
        QpackDynamicEntryView entry = {};
        const NTSTATUS lookupStatus = table_.LookupRelative(table_.InsertCount(), nameIndex, &entry);
        if (!NT_SUCCESS(lookupStatus))
        {
            return STATUS_INVALID_PARAMETER;
        }
        name = entry.Name;
    }

    SIZE_T offset = 0;
    NTSTATUS status = AppendInteger(nameIndex, static_cast<UCHAR>(0x80U | (staticReference ? 0x40U : 0U)), 6,
                                    instruction, instructionCapacity, &offset);
    if (NT_SUCCESS(status))
    {
        const QpackStringView valueView = {value, valueLength};
        status = AppendString(valueView, huffmanValue, 0, 7, 0x80, instruction, instructionCapacity, &offset);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = table_.Insert(name.Data, name.Length, value, valueLength, absoluteIndex);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *instructionLength = offset;
    return STATUS_SUCCESS;
}

NTSTATUS QpackEncoder::InsertWithLiteralName(const UCHAR *name, SIZE_T nameLength, bool huffmanName, const UCHAR *value,
                                             SIZE_T valueLength, bool huffmanValue, UCHAR *instruction,
                                             SIZE_T instructionCapacity, SIZE_T *instructionLength,
                                             ULONGLONG *absoluteIndex) noexcept
{
    if (instructionLength != nullptr)
    {
        *instructionLength = 0;
    }
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = 0;
    }
    if (instruction == nullptr || instructionLength == nullptr || (name == nullptr && nameLength != 0) ||
        (value == nullptr && valueLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (pendingCapacityValid_)
    {
        return STATUS_DEVICE_BUSY;
    }

    SIZE_T offset = 0;
    QpackStringView nameView = {name, nameLength};
    NTSTATUS status = AppendString(nameView, huffmanName, 0x40, 5, 0x20, instruction, instructionCapacity, &offset);
    if (NT_SUCCESS(status))
    {
        QpackStringView valueView = {value, valueLength};
        status = AppendString(valueView, huffmanValue, 0, 7, 0x80, instruction, instructionCapacity, &offset);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = table_.Insert(name, nameLength, value, valueLength, absoluteIndex);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *instructionLength = offset;
    return STATUS_SUCCESS;
}

NTSTATUS QpackEncoder::Duplicate(ULONGLONG relativeIndex, UCHAR *instruction, SIZE_T instructionCapacity,
                                 SIZE_T *instructionLength, ULONGLONG *absoluteIndex) noexcept
{
    if (instructionLength != nullptr)
    {
        *instructionLength = 0;
    }
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = 0;
    }
    if (instruction == nullptr || instructionLength == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (pendingCapacityValid_)
    {
        return STATUS_DEVICE_BUSY;
    }

    SIZE_T encodedLength = 0;
    NTSTATUS status = QpackEncodeInteger(relativeIndex, 0, 5, instruction, instructionCapacity, &encodedLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = table_.DuplicateRelative(relativeIndex, absoluteIndex);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *instructionLength = encodedLength;
    return STATUS_SUCCESS;
}

NTSTATUS QpackEncoder::EncodeFieldSection(ULONGLONG streamId, const QpackFieldView *fields, SIZE_T fieldCount,
                                          UCHAR *destination, SIZE_T capacity, SIZE_T *bytesWritten,
                                          ULONGLONG *applicationError) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (applicationError != nullptr)
    {
        *applicationError = 0;
    }
    if (destination == nullptr || bytesWritten == nullptr || (fields == nullptr && fieldCount != 0) ||
        fieldCount > WKNET_HARD_MAX_HTTP3_FIELDS || capacity > WKNET_HARD_MAX_HTTP3_FIELD_SECTION_BYTES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    UCHAR *fieldLines = static_cast<UCHAR *>(AllocateProtocolNonPagedPoolBytes(
        rtl::ProtocolAllocationSite::QpackEncoderFieldLines, capacity == 0 ? 1 : capacity));
    if (fieldLines == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ULONGLONG *references = nullptr;
    if (fieldCount != 0)
    {
        references = static_cast<ULONGLONG *>(AllocateProtocolNonPagedPoolBytes(
            rtl::ProtocolAllocationSite::QpackEncoderReferences, fieldCount * sizeof(ULONGLONG)));
        if (references == nullptr)
        {
            RtlSecureZeroMemory(fieldLines, capacity == 0 ? 1 : capacity);
            FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackEncoderFieldLines, fieldLines);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T fieldOffset = 0;
    SIZE_T referenceCount = 0;
    ULONGLONG requiredInsertCount = 0;
    const ULONGLONG base = table_.InsertCount();
    bool sectionWillBlock = false;
    const bool streamAlreadyBlocked = StreamIsBlocked(streamId);

    for (SIZE_T fieldIndex = 0; fieldIndex < fieldCount && NT_SUCCESS(status); ++fieldIndex)
    {
        const QpackFieldView &field = fields[fieldIndex];
        if ((field.Name.Data == nullptr && field.Name.Length != 0) ||
            (field.Value.Data == nullptr && field.Value.Length != 0))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        const bool sensitive = field.Sensitive || IsSensitiveName(field.Name.Data, field.Name.Length);
        FieldMatch exactStatic = {};
        FieldMatch nameStatic = {};
        const NTSTATUS exactStaticStatus = FindStaticMatch(field, true, &exactStatic);
        const NTSTATUS nameStaticStatus = FindStaticMatch(field, false, &nameStatic);

        ULONGLONG dynamicExact = 0;
        ULONGLONG dynamicName = 0;
        const bool hasDynamicExact = NT_SUCCESS(
            table_.FindExact(field.Name.Data, field.Name.Length, field.Value.Data, field.Value.Length, &dynamicExact));
        const bool hasDynamicName = NT_SUCCESS(table_.FindName(field.Name.Data, field.Name.Length, &dynamicName));

        bool useDynamicExact = hasDynamicExact && !sensitive;
        bool useDynamicName = hasDynamicName;
        ULONGLONG candidate = useDynamicExact ? dynamicExact : dynamicName;
        if ((useDynamicExact || useDynamicName) && candidate + 1 > knownReceivedCount_ && !sectionWillBlock &&
            !streamAlreadyBlocked && CountBlockedStreams() >= effectiveBlockedStreams_)
        {
            useDynamicExact = false;
            useDynamicName = false;
        }

        if (!sensitive && NT_SUCCESS(exactStaticStatus))
        {
            status = AppendInteger(exactStatic.Index, 0xc0, 6, fieldLines, capacity, &fieldOffset);
        }
        else if (useDynamicExact)
        {
            const ULONGLONG relative = base - dynamicExact - 1;
            status = AppendInteger(relative, 0x80, 6, fieldLines, capacity, &fieldOffset);
            candidate = dynamicExact;
        }
        else if (NT_SUCCESS(nameStaticStatus))
        {
            const UCHAR prefix = static_cast<UCHAR>(0x50U | (sensitive ? 0x20U : 0U));
            status = AppendInteger(nameStatic.Index, prefix, 4, fieldLines, capacity, &fieldOffset);
            if (NT_SUCCESS(status))
            {
                status = AppendString(field.Value, false, 0, 7, 0x80, fieldLines, capacity, &fieldOffset);
            }
        }
        else if (useDynamicName)
        {
            const ULONGLONG relative = base - dynamicName - 1;
            const UCHAR prefix = static_cast<UCHAR>(0x40U | (sensitive ? 0x20U : 0U));
            status = AppendInteger(relative, prefix, 4, fieldLines, capacity, &fieldOffset);
            if (NT_SUCCESS(status))
            {
                status = AppendString(field.Value, false, 0, 7, 0x80, fieldLines, capacity, &fieldOffset);
            }
            candidate = dynamicName;
        }
        else
        {
            const UCHAR prefix = static_cast<UCHAR>(0x20U | (sensitive ? 0x10U : 0U));
            status = AppendString(field.Name, false, prefix, 3, 0x08, fieldLines, capacity, &fieldOffset);
            if (NT_SUCCESS(status))
            {
                status = AppendString(field.Value, false, 0, 7, 0x80, fieldLines, capacity, &fieldOffset);
            }
        }

        if (NT_SUCCESS(status) && (useDynamicExact || useDynamicName))
        {
            if (!ReferenceExists(references, referenceCount, candidate))
            {
                references[referenceCount++] = candidate;
            }
            if (candidate + 1 > requiredInsertCount)
            {
                requiredInsertCount = candidate + 1;
            }
            if (candidate + 1 > knownReceivedCount_)
            {
                sectionWillBlock = true;
            }
        }
    }

    ULONGLONG encodedInsertCount = 0;
    if (NT_SUCCESS(status))
    {
        status = QpackDecoder::EncodeRequiredInsertCount(requiredInsertCount, effectiveMaximumCapacity_,
                                                         &encodedInsertCount);
    }
    SIZE_T prefixLength = 0;
    if (NT_SUCCESS(status))
    {
        status = AppendInteger(encodedInsertCount, 0, 8, destination, capacity, &prefixLength);
    }
    if (NT_SUCCESS(status))
    {
        const ULONGLONG deltaBase = requiredInsertCount == 0 ? 0 : base - requiredInsertCount;
        status = AppendInteger(deltaBase, 0, 7, destination, capacity, &prefixLength);
    }
    if (NT_SUCCESS(status) && fieldOffset > capacity - prefixLength)
    {
        status = STATUS_BUFFER_TOO_SMALL;
    }
    if (NT_SUCCESS(status) && fieldOffset != 0)
    {
        RtlCopyMemory(destination + prefixLength, fieldLines, fieldOffset);
    }
    if (NT_SUCCESS(status) && referenceCount != 0)
    {
        status = TrackSection(streamId, requiredInsertCount, references, referenceCount);
    }
    if (NT_SUCCESS(status))
    {
        *bytesWritten = prefixLength + fieldOffset;
    }
    else if (applicationError != nullptr && status == STATUS_INVALID_NETWORK_RESPONSE)
    {
        *applicationError = QpackDecompressionFailed;
    }

    if (references != nullptr)
    {
        RtlSecureZeroMemory(references, fieldCount * sizeof(ULONGLONG));
        FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackEncoderReferences, references);
    }
    RtlSecureZeroMemory(fieldLines, capacity == 0 ? 1 : capacity);
    FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackEncoderFieldLines, fieldLines);
    if (!NT_SUCCESS(status))
    {
        const ULONGLONG error = applicationError != nullptr ? *applicationError : QpackDecompressionFailed;
        WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                    "qpack.decode.failed status=0x%08X application_error=0x%I64X stream_id=%I64u field_count=%Iu",
                    status, error, streamId, fieldCount);
    }
    return status;
}

NTSTATUS QpackEncoder::ProcessDecoderInstructions(const UCHAR *source, SIZE_T length, SIZE_T *bytesConsumed,
                                                  ULONGLONG *applicationError) noexcept
{
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (applicationError != nullptr)
    {
        *applicationError = 0;
    }
    if (source == nullptr || bytesConsumed == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T offset = 0;
    while (offset < length)
    {
        const UCHAR first = source[offset];
        UCHAR prefixBits = 0;
        enum class InstructionKind : UCHAR
        {
            SectionAcknowledgment,
            StreamCancellation,
            InsertCountIncrement
        } kind = InstructionKind::InsertCountIncrement;
        if ((first & 0x80U) != 0)
        {
            prefixBits = 7;
            kind = InstructionKind::SectionAcknowledgment;
        }
        else if ((first & 0x40U) != 0)
        {
            prefixBits = 6;
            kind = InstructionKind::StreamCancellation;
        }
        else
        {
            prefixBits = 6;
        }

        ULONGLONG value = 0;
        SIZE_T consumed = 0;
        NTSTATUS status = QpackDecodeInteger(source + offset, length - offset, prefixBits, &value, &consumed);
        if (status == STATUS_BUFFER_TOO_SMALL)
        {
            *bytesConsumed = offset;
            return STATUS_MORE_PROCESSING_REQUIRED;
        }
        if (!NT_SUCCESS(status))
        {
            if (applicationError != nullptr)
            {
                *applicationError = QpackDecoderStreamError;
            }
            WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                        "qpack.decode.failed status=0x%08X application_error=0x%I64X instruction_offset=%Iu", status,
                        QpackDecoderStreamError, offset);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (kind == InstructionKind::SectionAcknowledgment)
        {
            status = AcknowledgeSection(value);
        }
        else if (kind == InstructionKind::StreamCancellation)
        {
            status = CancelStream(value);
        }
        else
        {
            if (value == 0 || value > table_.InsertCount() - knownReceivedCount_)
            {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            else
            {
                knownReceivedCount_ += value;
                status = STATUS_SUCCESS;
            }
        }
        if (!NT_SUCCESS(status))
        {
            if (applicationError != nullptr)
            {
                *applicationError = QpackDecoderStreamError;
            }
            WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                        "qpack.decode.failed status=0x%08X application_error=0x%I64X instruction_offset=%Iu", status,
                        QpackDecoderStreamError, offset);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        offset += consumed;
    }

    *bytesConsumed = offset;
    return STATUS_SUCCESS;
}

bool QpackEncoder::IsSensitiveName(const UCHAR *name, SIZE_T nameLength) noexcept
{
    if (name == nullptr)
    {
        return false;
    }
    return NameEquals(name, nameLength, "authorization") || NameEquals(name, nameLength, "proxy-authorization") ||
           NameEquals(name, nameLength, "cookie");
}

SIZE_T QpackEncoder::EffectiveMaximumCapacity() const noexcept
{
    return effectiveMaximumCapacity_;
}

ULONG QpackEncoder::EffectiveBlockedStreams() const noexcept
{
    return effectiveBlockedStreams_;
}

ULONGLONG QpackEncoder::KnownReceivedCount() const noexcept
{
    return knownReceivedCount_;
}

SIZE_T QpackEncoder::OutstandingSectionCount() const noexcept
{
    return outstandingSectionCount_;
}

ULONG QpackEncoder::BlockedStreamCount() const noexcept
{
    return CountBlockedStreams();
}

const QpackDynamicTable &QpackEncoder::Table() const noexcept
{
    return table_;
}

NTSTATUS QpackEncoder::ApplyCapacity(SIZE_T capacity, UCHAR *instruction, SIZE_T instructionCapacity,
                                     SIZE_T *instructionLength) noexcept
{
    if (instructionLength != nullptr)
    {
        *instructionLength = 0;
    }
    if (instruction == nullptr || instructionLength == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T encodedLength = 0;
    NTSTATUS status = QpackEncodeInteger(capacity, 0x20, 5, instruction, instructionCapacity, &encodedLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = table_.SetCapacity(capacity);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *instructionLength = encodedLength;
    return STATUS_SUCCESS;
}

NTSTATUS QpackEncoder::TrackSection(ULONGLONG streamId, ULONGLONG requiredInsertCount, const ULONGLONG *references,
                                    SIZE_T referenceCount) noexcept
{
    if (referenceCount == 0)
    {
        return STATUS_SUCCESS;
    }
    if (outstandingSectionCount_ >= QpackMaximumOutstandingSections ||
        referenceCount > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / sizeof(ULONGLONG))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    const SIZE_T referenceBytes = referenceCount * sizeof(ULONGLONG);
    if (referenceBytes > QpackMaximumOutstandingReferenceBytes - outstandingReferenceBytes_ ||
        referenceBytes > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - sizeof(OutstandingSection))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const SIZE_T allocationSize = sizeof(OutstandingSection) + referenceBytes;
    OutstandingSection *section = static_cast<OutstandingSection *>(
        AllocateProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackEncoderOutstandingSection, allocationSize));
    if (section == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    section->StreamId = streamId;
    section->RequiredInsertCount = requiredInsertCount;
    section->ReferenceCount = referenceCount;
    ULONGLONG *storedReferences = reinterpret_cast<ULONGLONG *>(section + 1);
    RtlCopyMemory(storedReferences, references, referenceBytes);

    SIZE_T added = 0;
    for (; added < referenceCount; ++added)
    {
        const NTSTATUS status = table_.AddReference(storedReferences[added]);
        if (!NT_SUCCESS(status))
        {
            for (SIZE_T rollback = 0; rollback < added; ++rollback)
            {
                static_cast<void>(table_.ReleaseReference(storedReferences[rollback]));
            }
            RtlSecureZeroMemory(section, allocationSize);
            FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackEncoderOutstandingSection, section);
            return status;
        }
    }

    if (outstandingTail_ == nullptr)
    {
        outstandingHead_ = section;
    }
    else
    {
        outstandingTail_->Next = section;
    }
    outstandingTail_ = section;
    ++outstandingSectionCount_;
    outstandingReferenceBytes_ += referenceBytes;
    return STATUS_SUCCESS;
}

void QpackEncoder::ReleaseSection(OutstandingSection *section) noexcept
{
    ULONGLONG *references = reinterpret_cast<ULONGLONG *>(section + 1);
    for (SIZE_T index = 0; index < section->ReferenceCount; ++index)
    {
        static_cast<void>(table_.ReleaseReference(references[index]));
    }
    const SIZE_T referenceBytes = section->ReferenceCount * sizeof(ULONGLONG);
    const SIZE_T allocationSize = sizeof(OutstandingSection) + referenceBytes;
    outstandingReferenceBytes_ -= referenceBytes;
    --outstandingSectionCount_;
    RtlSecureZeroMemory(section, allocationSize);
    FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackEncoderOutstandingSection, section);
}

NTSTATUS QpackEncoder::AcknowledgeSection(ULONGLONG streamId) noexcept
{
    OutstandingSection *previous = nullptr;
    OutstandingSection *section = outstandingHead_;
    while (section != nullptr && section->StreamId != streamId)
    {
        previous = section;
        section = section->Next;
    }
    if (section == nullptr)
    {
        return STATUS_NOT_FOUND;
    }

    if (section->RequiredInsertCount > knownReceivedCount_)
    {
        knownReceivedCount_ = section->RequiredInsertCount;
    }

    if (previous == nullptr)
    {
        outstandingHead_ = section->Next;
    }
    else
    {
        previous->Next = section->Next;
    }
    if (outstandingTail_ == section)
    {
        outstandingTail_ = previous;
    }
    ReleaseSection(section);
    return STATUS_SUCCESS;
}

NTSTATUS QpackEncoder::CancelStream(ULONGLONG streamId) noexcept
{
    bool found = false;
    OutstandingSection *previous = nullptr;
    OutstandingSection *section = outstandingHead_;
    while (section != nullptr)
    {
        OutstandingSection *next = section->Next;
        if (section->StreamId == streamId)
        {
            found = true;
            if (previous == nullptr)
            {
                outstandingHead_ = next;
            }
            else
            {
                previous->Next = next;
            }
            if (outstandingTail_ == section)
            {
                outstandingTail_ = previous;
            }
            ReleaseSection(section);
        }
        else
        {
            previous = section;
        }
        section = next;
    }
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

ULONG QpackEncoder::CountBlockedStreams() const noexcept
{
    ULONG count = 0;
    for (const OutstandingSection *section = outstandingHead_; section != nullptr; section = section->Next)
    {
        if (section->RequiredInsertCount <= knownReceivedCount_)
        {
            continue;
        }
        bool counted = false;
        for (const OutstandingSection *earlier = outstandingHead_; earlier != section; earlier = earlier->Next)
        {
            if (earlier->StreamId == section->StreamId && earlier->RequiredInsertCount > knownReceivedCount_)
            {
                counted = true;
                break;
            }
        }
        if (!counted)
        {
            ++count;
        }
    }
    return count;
}

bool QpackEncoder::StreamIsBlocked(ULONGLONG streamId) const noexcept
{
    for (const OutstandingSection *section = outstandingHead_; section != nullptr; section = section->Next)
    {
        if (section->StreamId == streamId && section->RequiredInsertCount > knownReceivedCount_)
        {
            return true;
        }
    }
    return false;
}
} // namespace wknet::qpack
