#include "qpack/QpackDecoder.h"
#include "qpack/QpackHuffman.h"
#include "qpack/QpackInteger.h"
#include "qpack/QpackStaticTable.h"

namespace wknet::qpack
{
namespace
{
bool AdditionOverflows(SIZE_T left, SIZE_T right) noexcept
{
    return left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right;
}

NTSTATUS DecodeStringView(const UCHAR *source, SIZE_T length, UCHAR prefixBits, UCHAR huffmanMask,
                          _Out_ QpackStringView *value, _Out_ SIZE_T *bytesConsumed, _Out_opt_ UCHAR **allocated,
                          _Out_opt_ SIZE_T *allocatedCapacity) noexcept
{
    if (value != nullptr)
    {
        *value = {};
    }
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (allocated != nullptr)
    {
        *allocated = nullptr;
    }
    if (allocatedCapacity != nullptr)
    {
        *allocatedCapacity = 0;
    }
    if (source == nullptr || length == 0 || value == nullptr || bytesConsumed == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const bool huffman = (source[0] & huffmanMask) != 0;
    ULONGLONG encodedLengthValue = 0;
    SIZE_T prefixLength = 0;
    NTSTATUS status = QpackDecodeInteger(source, length, prefixBits, &encodedLengthValue, &prefixLength);
    if (status == STATUS_BUFFER_TOO_SMALL)
    {
        return STATUS_MORE_PROCESSING_REQUIRED;
    }
    if (!NT_SUCCESS(status))
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (encodedLengthValue > static_cast<ULONGLONG>(length - prefixLength))
    {
        return STATUS_MORE_PROCESSING_REQUIRED;
    }
    const SIZE_T encodedLength = static_cast<SIZE_T>(encodedLengthValue);
    if (!huffman)
    {
        value->Data = source + prefixLength;
        value->Length = encodedLength;
        *bytesConsumed = prefixLength + encodedLength;
        return STATUS_SUCCESS;
    }
    if (allocated == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (encodedLength > (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 1) / 2)
    {
        return STATUS_INTEGER_OVERFLOW;
    }

    SIZE_T decodedCapacity = encodedLength * 2 + 1;
    if (decodedCapacity > WKNET_HARD_MAX_HTTP3_FIELD_SECTION_BYTES)
    {
        decodedCapacity = WKNET_HARD_MAX_HTTP3_FIELD_SECTION_BYTES;
    }
    UCHAR *decoded = static_cast<UCHAR *>(AllocateNonPagedPoolBytes(decodedCapacity));
    if (decoded == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SIZE_T decodedLength = 0;
    status = QpackHuffmanDecode(source + prefixLength, encodedLength, decoded, decodedCapacity, &decodedLength);
    if (!NT_SUCCESS(status))
    {
        RtlSecureZeroMemory(decoded, decodedCapacity);
        FreeNonPagedPoolBytes(decoded);
        return status == STATUS_BUFFER_TOO_SMALL ? STATUS_INVALID_NETWORK_RESPONSE : status;
    }
    value->Data = decoded;
    value->Length = decodedLength;
    *bytesConsumed = prefixLength + encodedLength;
    *allocated = decoded;
    if (allocatedCapacity != nullptr)
    {
        *allocatedCapacity = decodedCapacity;
    }
    return STATUS_SUCCESS;
}

void FreeDecodedString(UCHAR *value, SIZE_T length) noexcept
{
    if (value != nullptr)
    {
        RtlSecureZeroMemory(value, length);
        FreeNonPagedPoolBytes(value);
    }
}

NTSTATUS DecodeStringToBuffer(const UCHAR *source, SIZE_T length, UCHAR prefixBits, UCHAR huffmanMask,
                              UCHAR *fieldBuffer, SIZE_T fieldBufferCapacity, _Inout_ SIZE_T *fieldBufferUsed,
                              _Out_ QpackStringView *value, _Out_ SIZE_T *bytesConsumed) noexcept
{
    if (value != nullptr)
    {
        *value = {};
    }
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (source == nullptr || length == 0 || fieldBuffer == nullptr || fieldBufferUsed == nullptr || value == nullptr ||
        bytesConsumed == nullptr || *fieldBufferUsed > fieldBufferCapacity)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const bool huffman = (source[0] & huffmanMask) != 0;
    ULONGLONG encodedLengthValue = 0;
    SIZE_T prefixLength = 0;
    NTSTATUS status = QpackDecodeInteger(source, length, prefixBits, &encodedLengthValue, &prefixLength);
    if (!NT_SUCCESS(status) || encodedLengthValue > static_cast<ULONGLONG>(length - prefixLength))
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    const SIZE_T encodedLength = static_cast<SIZE_T>(encodedLengthValue);
    UCHAR *destination = fieldBuffer + *fieldBufferUsed;
    SIZE_T decodedLength = 0;
    if (huffman)
    {
        status = QpackHuffmanDecode(source + prefixLength, encodedLength, destination,
                                    fieldBufferCapacity - *fieldBufferUsed, &decodedLength);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    else
    {
        if (encodedLength > fieldBufferCapacity - *fieldBufferUsed)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (encodedLength != 0)
        {
            RtlCopyMemory(destination, source + prefixLength, encodedLength);
        }
        decodedLength = encodedLength;
    }

    value->Data = destination;
    value->Length = decodedLength;
    *fieldBufferUsed += decodedLength;
    *bytesConsumed = prefixLength + encodedLength;
    return STATUS_SUCCESS;
}

NTSTATUS CopyStringToBuffer(const QpackStringView &source, UCHAR *fieldBuffer, SIZE_T fieldBufferCapacity,
                            _Inout_ SIZE_T *fieldBufferUsed, _Out_ QpackStringView *destination) noexcept
{
    if (destination != nullptr)
    {
        *destination = {};
    }
    if (fieldBuffer == nullptr || fieldBufferUsed == nullptr || destination == nullptr ||
        *fieldBufferUsed > fieldBufferCapacity || source.Length > fieldBufferCapacity - *fieldBufferUsed)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    UCHAR *target = fieldBuffer + *fieldBufferUsed;
    if (source.Length != 0)
    {
        RtlCopyMemory(target, source.Data, source.Length);
    }
    destination->Data = target;
    destination->Length = source.Length;
    *fieldBufferUsed += source.Length;
    return STATUS_SUCCESS;
}

NTSTATUS WriteDecoderInstruction(ULONGLONG value, UCHAR prefix, UCHAR prefixBits, UCHAR *instruction,
                                 SIZE_T instructionCapacity, SIZE_T *instructionLength) noexcept
{
    if (instructionLength != nullptr)
    {
        *instructionLength = 0;
    }
    if (instruction == nullptr || instructionLength == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    return QpackEncodeInteger(value, prefix, prefixBits, instruction, instructionCapacity, instructionLength);
}
} // namespace

QpackDecoder::~QpackDecoder() noexcept
{
    Reset();
}

NTSTATUS QpackDecoder::Initialize(SIZE_T localMaximumCapacity, ULONG localBlockedStreams,
                                  SIZE_T maximumFieldSectionBytes, SIZE_T maximumFields) noexcept
{
    Reset();
    if (localMaximumCapacity > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES ||
        localBlockedStreams > WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS ||
        maximumFieldSectionBytes > WKNET_HARD_MAX_QPACK_BLOCKED_SECTION_BYTES ||
        maximumFields > WKNET_HARD_MAX_HTTP3_FIELDS)
    {
        return STATUS_INVALID_PARAMETER;
    }

    localMaximumCapacity_ = localMaximumCapacity;
    localBlockedStreams_ = localBlockedStreams;
    maximumFieldSectionBytes_ = maximumFieldSectionBytes;
    maximumFields_ = maximumFields;
    return table_.Initialize(localMaximumCapacity, 0);
}

void QpackDecoder::Reset() noexcept
{
    BlockedSection *section = blockedHead_;
    while (section != nullptr)
    {
        BlockedSection *next = section->Next;
        FreeBlocked(section);
        section = next;
    }
    blockedHead_ = nullptr;
    table_.Reset();
    localMaximumCapacity_ = 0;
    localBlockedStreams_ = 0;
    maximumFieldSectionBytes_ = 0;
    maximumFields_ = 0;
    blockedStreamCount_ = 0;
    blockedBytes_ = 0;
    reportedInsertCount_ = 0;
}

NTSTATUS QpackDecoder::ProcessEncoderInstructions(const UCHAR *source, SIZE_T length, SIZE_T *bytesConsumed,
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
        NTSTATUS status = STATUS_SUCCESS;
        SIZE_T instructionLength = 0;
        ULONGLONG absoluteIndex = 0;
        if ((first & 0x80U) != 0)
        {
            ULONGLONG nameIndex = 0;
            SIZE_T indexLength = 0;
            status = QpackDecodeInteger(source + offset, length - offset, 6, &nameIndex, &indexLength);
            if (!NT_SUCCESS(status))
            {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            QpackStringView name = {};
            if (NT_SUCCESS(status) && (first & 0x40U) != 0)
            {
                QpackStaticEntryView entry = {};
                status = QpackStaticTableLookup(static_cast<SIZE_T>(nameIndex), &entry);
                name = entry.Name;
            }
            else if (NT_SUCCESS(status))
            {
                QpackDynamicEntryView entry = {};
                status = table_.LookupRelative(table_.InsertCount(), nameIndex, &entry);
                name = entry.Name;
            }

            QpackStringView value = {};
            SIZE_T valueLength = 0;
            UCHAR *allocatedValue = nullptr;
            SIZE_T allocatedValueCapacity = 0;
            if (NT_SUCCESS(status))
            {
                if (indexLength >= length - offset)
                {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                else
                {
                    status = DecodeStringView(source + offset + indexLength, length - offset - indexLength, 7, 0x80,
                                              &value, &valueLength, &allocatedValue, &allocatedValueCapacity);
                }
            }
            if (NT_SUCCESS(status))
            {
                status = table_.Insert(name.Data, name.Length, value.Data, value.Length, &absoluteIndex);
                instructionLength = indexLength + valueLength;
            }
            FreeDecodedString(allocatedValue, allocatedValueCapacity);
        }
        else if ((first & 0xc0U) == 0x40U)
        {
            QpackStringView name = {};
            QpackStringView value = {};
            SIZE_T nameLength = 0;
            SIZE_T valueLength = 0;
            UCHAR *allocatedName = nullptr;
            UCHAR *allocatedValue = nullptr;
            SIZE_T allocatedNameCapacity = 0;
            SIZE_T allocatedValueCapacity = 0;
            status = DecodeStringView(source + offset, length - offset, 5, 0x20, &name, &nameLength, &allocatedName,
                                      &allocatedNameCapacity);
            if (NT_SUCCESS(status))
            {
                if (nameLength >= length - offset)
                {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                else
                {
                    status = DecodeStringView(source + offset + nameLength, length - offset - nameLength, 7, 0x80,
                                              &value, &valueLength, &allocatedValue, &allocatedValueCapacity);
                }
            }
            if (NT_SUCCESS(status))
            {
                status = table_.Insert(name.Data, name.Length, value.Data, value.Length, &absoluteIndex);
                instructionLength = nameLength + valueLength;
            }
            FreeDecodedString(allocatedName, allocatedNameCapacity);
            FreeDecodedString(allocatedValue, allocatedValueCapacity);
        }
        else if ((first & 0xe0U) == 0x20U)
        {
            ULONGLONG capacity = 0;
            status = QpackDecodeInteger(source + offset, length - offset, 5, &capacity, &instructionLength);
            if (NT_SUCCESS(status))
            {
                if (capacity > localMaximumCapacity_)
                {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                else
                {
                    status = table_.SetCapacity(static_cast<SIZE_T>(capacity));
                }
            }
        }
        else
        {
            ULONGLONG relativeIndex = 0;
            status = QpackDecodeInteger(source + offset, length - offset, 5, &relativeIndex, &instructionLength);
            if (NT_SUCCESS(status))
            {
                status = table_.DuplicateRelative(relativeIndex, &absoluteIndex);
            }
        }

        if (status == STATUS_MORE_PROCESSING_REQUIRED || status == STATUS_BUFFER_TOO_SMALL)
        {
            *bytesConsumed = offset;
            return STATUS_MORE_PROCESSING_REQUIRED;
        }
        if (!NT_SUCCESS(status) || instructionLength == 0)
        {
            if (applicationError != nullptr)
            {
                *applicationError = QpackEncoderStreamError;
            }
            WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                        "qpack.decode.failed status=0x%08X application_error=0x%I64X instruction_offset=%Iu", status,
                        QpackEncoderStreamError, offset);
            return status == STATUS_INSUFFICIENT_RESOURCES ? status : STATUS_INVALID_NETWORK_RESPONSE;
        }
        offset += instructionLength;
    }

    *bytesConsumed = offset;
    return STATUS_SUCCESS;
}

NTSTATUS QpackDecoder::DecodeFieldSection(ULONGLONG streamId, const UCHAR *source, SIZE_T length,
                                          QpackFieldView *fields, SIZE_T fieldCapacity, SIZE_T *fieldCount,
                                          UCHAR *fieldBuffer, SIZE_T fieldBufferCapacity, SIZE_T *fieldBufferUsed,
                                          UCHAR *decoderInstruction, SIZE_T decoderInstructionCapacity,
                                          SIZE_T *decoderInstructionLength, ULONGLONG *applicationError) noexcept
{
    if (fieldCount != nullptr)
    {
        *fieldCount = 0;
    }
    if (fieldBufferUsed != nullptr)
    {
        *fieldBufferUsed = 0;
    }
    if (decoderInstructionLength != nullptr)
    {
        *decoderInstructionLength = 0;
    }
    if (applicationError != nullptr)
    {
        *applicationError = 0;
    }
    if (source == nullptr || length == 0 || fields == nullptr || fieldCount == nullptr || fieldBuffer == nullptr ||
        fieldBufferUsed == nullptr || decoderInstruction == nullptr || decoderInstructionLength == nullptr ||
        fieldCapacity > maximumFields_ || fieldBufferCapacity > maximumFieldSectionBytes_ ||
        length > maximumFieldSectionBytes_)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONGLONG encodedInsertCount = 0;
    SIZE_T insertCountLength = 0;
    NTSTATUS status = QpackDecodeInteger(source, length, 8, &encodedInsertCount, &insertCountLength);
    ULONGLONG requiredInsertCount = 0;
    if (NT_SUCCESS(status))
    {
        status = DecodeRequiredInsertCount(encodedInsertCount, table_.InsertCount(), localMaximumCapacity_,
                                           &requiredInsertCount);
    }
    if (!NT_SUCCESS(status))
    {
        if (applicationError != nullptr)
        {
            *applicationError = QpackDecompressionFailed;
        }
        WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                    "qpack.decode.failed status=0x%08X application_error=0x%I64X stream_id=%I64u section_bytes=%Iu",
                    status, QpackDecompressionFailed, streamId, length);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    if (requiredInsertCount > table_.InsertCount())
    {
        status = StoreBlockedSection(streamId, requiredInsertCount, source, length);
        if (status == STATUS_SUCCESS)
        {
            WKNET_TRACE(ComponentHttp3, TraceLevel::Warning,
                        "qpack.decode.blocked stream_id=%I64u required_insert_count=%I64u section_bytes=%Iu "
                        "blocked_streams=%Iu blocked_bytes=%Iu",
                        streamId, requiredInsertCount, length, blockedStreamCount_, blockedBytes_);
            return STATUS_PENDING;
        }
        if (applicationError != nullptr && status != STATUS_INSUFFICIENT_RESOURCES)
        {
            *applicationError = QpackDecompressionFailed;
        }
        return status;
    }

    status = DecodeAvailableFieldSection(streamId, source, length, fields, fieldCapacity, fieldCount, fieldBuffer,
                                         fieldBufferCapacity, fieldBufferUsed, decoderInstruction,
                                         decoderInstructionCapacity, decoderInstructionLength, applicationError);
    if (!NT_SUCCESS(status))
    {
        const ULONGLONG error = applicationError != nullptr ? *applicationError : QpackDecompressionFailed;
        WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                    "qpack.decode.failed status=0x%08X application_error=0x%I64X stream_id=%I64u section_bytes=%Iu",
                    status, error, streamId, length);
    }
    return status;
}

NTSTATUS QpackDecoder::ResumeBlockedFieldSection(ULONGLONG streamId, QpackFieldView *fields, SIZE_T fieldCapacity,
                                                 SIZE_T *fieldCount, UCHAR *fieldBuffer, SIZE_T fieldBufferCapacity,
                                                 SIZE_T *fieldBufferUsed, UCHAR *decoderInstruction,
                                                 SIZE_T decoderInstructionCapacity, SIZE_T *decoderInstructionLength,
                                                 ULONGLONG *applicationError) noexcept
{
    BlockedSection *previous = nullptr;
    BlockedSection *section = FindBlocked(streamId, &previous);
    if (section == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    if (section->RequiredInsertCount > table_.InsertCount())
    {
        return STATUS_PENDING;
    }

    const UCHAR *bytes = reinterpret_cast<const UCHAR *>(section + 1);
    const NTSTATUS status = DecodeAvailableFieldSection(
        streamId, bytes, section->Length, fields, fieldCapacity, fieldCount, fieldBuffer, fieldBufferCapacity,
        fieldBufferUsed, decoderInstruction, decoderInstructionCapacity, decoderInstructionLength, applicationError);
    if (!NT_SUCCESS(status))
    {
        const ULONGLONG error = applicationError != nullptr ? *applicationError : QpackDecompressionFailed;
        WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                    "qpack.decode.failed status=0x%08X application_error=0x%I64X stream_id=%I64u section_bytes=%Iu",
                    status, error, streamId, section->Length);
        return status;
    }

    if (previous == nullptr)
    {
        blockedHead_ = section->Next;
    }
    else
    {
        previous->Next = section->Next;
    }
    FreeBlocked(section);
    return STATUS_SUCCESS;
}

NTSTATUS QpackDecoder::CancelStream(ULONGLONG streamId, UCHAR *instruction, SIZE_T instructionCapacity,
                                    SIZE_T *instructionLength) noexcept
{
    BlockedSection *previous = nullptr;
    BlockedSection *section = FindBlocked(streamId, &previous);
    if (section == nullptr)
    {
        return STATUS_NOT_FOUND;
    }

    const NTSTATUS status =
        WriteDecoderInstruction(streamId, 0x40, 6, instruction, instructionCapacity, instructionLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (previous == nullptr)
    {
        blockedHead_ = section->Next;
    }
    else
    {
        previous->Next = section->Next;
    }
    FreeBlocked(section);
    return STATUS_SUCCESS;
}

NTSTATUS QpackDecoder::WriteInsertCountIncrement(ULONGLONG increment, UCHAR *instruction, SIZE_T instructionCapacity,
                                                 SIZE_T *instructionLength) noexcept
{
    if (increment == 0 || increment > table_.InsertCount() - reportedInsertCount_)
    {
        if (instructionLength != nullptr)
        {
            *instructionLength = 0;
        }
        return STATUS_INVALID_PARAMETER;
    }

    const NTSTATUS status =
        WriteDecoderInstruction(increment, 0, 6, instruction, instructionCapacity, instructionLength);
    if (NT_SUCCESS(status))
    {
        reportedInsertCount_ += increment;
    }
    return status;
}

NTSTATUS QpackDecoder::EncodeRequiredInsertCount(ULONGLONG requiredInsertCount, SIZE_T maximumCapacity,
                                                 ULONGLONG *encodedInsertCount) noexcept
{
    if (encodedInsertCount != nullptr)
    {
        *encodedInsertCount = 0;
    }
    if (encodedInsertCount == nullptr || maximumCapacity > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (requiredInsertCount == 0)
    {
        return STATUS_SUCCESS;
    }

    const ULONGLONG maxEntries = maximumCapacity / QpackEntryOverhead;
    if (maxEntries == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONGLONG fullRange = maxEntries * 2;
    *encodedInsertCount = (requiredInsertCount % fullRange) + 1;
    return STATUS_SUCCESS;
}

NTSTATUS QpackDecoder::DecodeRequiredInsertCount(ULONGLONG encodedInsertCount, ULONGLONG totalInsertCount,
                                                 SIZE_T maximumCapacity, ULONGLONG *requiredInsertCount) noexcept
{
    if (requiredInsertCount != nullptr)
    {
        *requiredInsertCount = 0;
    }
    if (requiredInsertCount == nullptr || maximumCapacity > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (encodedInsertCount == 0)
    {
        return STATUS_SUCCESS;
    }

    const ULONGLONG maxEntries = maximumCapacity / QpackEntryOverhead;
    if (maxEntries == 0)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    const ULONGLONG fullRange = maxEntries * 2;
    if (encodedInsertCount > fullRange || totalInsertCount > QpackIntegerMaximum - maxEntries)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    const ULONGLONG maxValue = totalInsertCount + maxEntries;
    const ULONGLONG maxWrapped = (maxValue / fullRange) * fullRange;
    ULONGLONG required = maxWrapped + encodedInsertCount - 1;
    if (required > maxValue)
    {
        if (required <= fullRange)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        required -= fullRange;
    }
    if (required == 0)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    *requiredInsertCount = required;
    return STATUS_SUCCESS;
}

SIZE_T QpackDecoder::BlockedStreamCount() const noexcept
{
    return blockedStreamCount_;
}

SIZE_T QpackDecoder::BlockedBytes() const noexcept
{
    return blockedBytes_;
}

ULONGLONG QpackDecoder::ReportedInsertCount() const noexcept
{
    return reportedInsertCount_;
}

const QpackDynamicTable &QpackDecoder::Table() const noexcept
{
    return table_;
}

NTSTATUS QpackDecoder::DecodeAvailableFieldSection(ULONGLONG streamId, const UCHAR *source, SIZE_T length,
                                                   QpackFieldView *fields, SIZE_T fieldCapacity, SIZE_T *fieldCount,
                                                   UCHAR *fieldBuffer, SIZE_T fieldBufferCapacity,
                                                   SIZE_T *fieldBufferUsed, UCHAR *decoderInstruction,
                                                   SIZE_T decoderInstructionCapacity, SIZE_T *decoderInstructionLength,
                                                   ULONGLONG *applicationError) noexcept
{
    *fieldCount = 0;
    *fieldBufferUsed = 0;
    *decoderInstructionLength = 0;

    ULONGLONG encodedInsertCount = 0;
    SIZE_T offset = 0;
    SIZE_T consumed = 0;
    NTSTATUS status = QpackDecodeInteger(source, length, 8, &encodedInsertCount, &consumed);
    offset += consumed;
    ULONGLONG requiredInsertCount = 0;
    if (NT_SUCCESS(status))
    {
        status = DecodeRequiredInsertCount(encodedInsertCount, table_.InsertCount(), localMaximumCapacity_,
                                           &requiredInsertCount);
    }
    if (!NT_SUCCESS(status) || offset >= length)
    {
        status = STATUS_INVALID_NETWORK_RESPONSE;
    }

    ULONGLONG deltaBase = 0;
    SIZE_T deltaLength = 0;
    const bool sign = NT_SUCCESS(status) && (source[offset] & 0x80U) != 0;
    if (NT_SUCCESS(status))
    {
        status = QpackDecodeInteger(source + offset, length - offset, 7, &deltaBase, &deltaLength);
        offset += deltaLength;
    }
    ULONGLONG base = 0;
    if (NT_SUCCESS(status))
    {
        if (!sign)
        {
            if (requiredInsertCount > QpackIntegerMaximum - deltaBase)
            {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            else
            {
                base = requiredInsertCount + deltaBase;
            }
        }
        else if (requiredInsertCount == 0 || deltaBase >= requiredInsertCount)
        {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }
        else
        {
            base = requiredInsertCount - deltaBase - 1;
        }
        if (requiredInsertCount == 0 && base != 0)
        {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }
    }

    if (NT_SUCCESS(status) && requiredInsertCount != 0)
    {
        status = WriteDecoderInstruction(streamId, 0x80, 7, decoderInstruction, decoderInstructionCapacity,
                                         decoderInstructionLength);
    }

    while (NT_SUCCESS(status) && offset < length)
    {
        if (*fieldCount >= fieldCapacity || *fieldCount >= maximumFields_)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        const UCHAR first = source[offset];
        QpackStringView name = {};
        QpackStringView value = {};
        bool sensitive = false;
        bool nameInFieldBuffer = false;
        bool valueInFieldBuffer = false;
        QpackDynamicEntryView dynamicEntry = {};
        QpackStaticEntryView staticEntry = {};

        if ((first & 0x80U) != 0)
        {
            ULONGLONG index = 0;
            consumed = 0;
            status = QpackDecodeInteger(source + offset, length - offset, 6, &index, &consumed);
            if (NT_SUCCESS(status) && (first & 0x40U) != 0)
            {
                status = QpackStaticTableLookup(static_cast<SIZE_T>(index), &staticEntry);
                name = staticEntry.Name;
                value = staticEntry.Value;
            }
            else if (NT_SUCCESS(status))
            {
                status = table_.LookupRelative(base, index, &dynamicEntry);
                if (NT_SUCCESS(status) && dynamicEntry.AbsoluteIndex >= requiredInsertCount)
                {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                name = dynamicEntry.Name;
                value = dynamicEntry.Value;
            }
            offset += consumed;
        }
        else if ((first & 0xf0U) == 0x10U)
        {
            ULONGLONG index = 0;
            consumed = 0;
            status = QpackDecodeInteger(source + offset, length - offset, 4, &index, &consumed);
            if (NT_SUCCESS(status))
            {
                status = table_.LookupPostBase(base, index, &dynamicEntry);
                if (NT_SUCCESS(status) && dynamicEntry.AbsoluteIndex >= requiredInsertCount)
                {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                name = dynamicEntry.Name;
                value = dynamicEntry.Value;
            }
            offset += consumed;
        }
        else if ((first & 0xc0U) == 0x40U)
        {
            sensitive = (first & 0x20U) != 0;
            ULONGLONG index = 0;
            consumed = 0;
            status = QpackDecodeInteger(source + offset, length - offset, 4, &index, &consumed);
            if (NT_SUCCESS(status) && (first & 0x10U) != 0)
            {
                status = QpackStaticTableLookup(static_cast<SIZE_T>(index), &staticEntry);
                name = staticEntry.Name;
            }
            else if (NT_SUCCESS(status))
            {
                status = table_.LookupRelative(base, index, &dynamicEntry);
                if (NT_SUCCESS(status) && dynamicEntry.AbsoluteIndex >= requiredInsertCount)
                {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                name = dynamicEntry.Name;
            }
            offset += consumed;
            if (NT_SUCCESS(status))
            {
                status = DecodeStringToBuffer(source + offset, length - offset, 7, 0x80, fieldBuffer,
                                              fieldBufferCapacity, fieldBufferUsed, &value, &consumed);
                valueInFieldBuffer = NT_SUCCESS(status);
                offset += consumed;
            }
        }
        else if ((first & 0xf0U) == 0)
        {
            sensitive = (first & 0x08U) != 0;
            ULONGLONG index = 0;
            consumed = 0;
            status = QpackDecodeInteger(source + offset, length - offset, 3, &index, &consumed);
            if (NT_SUCCESS(status))
            {
                status = table_.LookupPostBase(base, index, &dynamicEntry);
                if (NT_SUCCESS(status) && dynamicEntry.AbsoluteIndex >= requiredInsertCount)
                {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                name = dynamicEntry.Name;
            }
            offset += consumed;
            if (NT_SUCCESS(status))
            {
                status = DecodeStringToBuffer(source + offset, length - offset, 7, 0x80, fieldBuffer,
                                              fieldBufferCapacity, fieldBufferUsed, &value, &consumed);
                valueInFieldBuffer = NT_SUCCESS(status);
                offset += consumed;
            }
        }
        else if ((first & 0xe0U) == 0x20U)
        {
            sensitive = (first & 0x10U) != 0;
            status = DecodeStringToBuffer(source + offset, length - offset, 3, 0x08, fieldBuffer, fieldBufferCapacity,
                                          fieldBufferUsed, &name, &consumed);
            nameInFieldBuffer = NT_SUCCESS(status);
            offset += consumed;
            if (NT_SUCCESS(status))
            {
                status = DecodeStringToBuffer(source + offset, length - offset, 7, 0x80, fieldBuffer,
                                              fieldBufferCapacity, fieldBufferUsed, &value, &consumed);
                valueInFieldBuffer = NT_SUCCESS(status);
                offset += consumed;
            }
        }
        else
        {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (NT_SUCCESS(status))
        {
            QpackFieldView &field = fields[*fieldCount];
            field = {};
            if (nameInFieldBuffer)
            {
                field.Name = name;
            }
            else
            {
                status = CopyStringToBuffer(name, fieldBuffer, fieldBufferCapacity, fieldBufferUsed, &field.Name);
            }
            if (NT_SUCCESS(status))
            {
                if (valueInFieldBuffer)
                {
                    field.Value = value;
                }
                else
                {
                    status = CopyStringToBuffer(value, fieldBuffer, fieldBufferCapacity, fieldBufferUsed, &field.Value);
                }
            }
            if (NT_SUCCESS(status))
            {
                field.Sensitive = sensitive;
                ++*fieldCount;
                if (*fieldBufferUsed > maximumFieldSectionBytes_)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                }
            }
        }
    }

    if (!NT_SUCCESS(status))
    {
        *fieldCount = 0;
        *fieldBufferUsed = 0;
        *decoderInstructionLength = 0;
        if (applicationError != nullptr && status != STATUS_INSUFFICIENT_RESOURCES && status != STATUS_BUFFER_TOO_SMALL)
        {
            *applicationError = QpackDecompressionFailed;
        }
        return status == STATUS_NOT_FOUND ? STATUS_INVALID_NETWORK_RESPONSE : status;
    }
    if (requiredInsertCount > reportedInsertCount_)
    {
        reportedInsertCount_ = requiredInsertCount;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QpackDecoder::StoreBlockedSection(ULONGLONG streamId, ULONGLONG requiredInsertCount, const UCHAR *source,
                                           SIZE_T length) noexcept
{
    if (FindBlocked(streamId, nullptr) != nullptr)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (blockedStreamCount_ >= localBlockedStreams_ || length > maximumFieldSectionBytes_ ||
        length > WKNET_HARD_MAX_QPACK_BLOCKED_SECTION_BYTES ||
        length > WKNET_HARD_MAX_QPACK_TOTAL_BLOCKED_BYTES - blockedBytes_ ||
        AdditionOverflows(sizeof(BlockedSection), length))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const SIZE_T allocationSize = sizeof(BlockedSection) + length;
    BlockedSection *section = static_cast<BlockedSection *>(AllocateNonPagedPoolBytes(allocationSize));
    if (section == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    section->StreamId = streamId;
    section->RequiredInsertCount = requiredInsertCount;
    section->Length = length;
    RtlCopyMemory(section + 1, source, length);
    section->Next = blockedHead_;
    blockedHead_ = section;
    ++blockedStreamCount_;
    blockedBytes_ += length;
    return STATUS_SUCCESS;
}

QpackDecoder::BlockedSection *QpackDecoder::FindBlocked(ULONGLONG streamId, BlockedSection **previous) noexcept
{
    if (previous != nullptr)
    {
        *previous = nullptr;
    }
    BlockedSection *prior = nullptr;
    BlockedSection *section = blockedHead_;
    while (section != nullptr)
    {
        if (section->StreamId == streamId)
        {
            if (previous != nullptr)
            {
                *previous = prior;
            }
            return section;
        }
        prior = section;
        section = section->Next;
    }
    return nullptr;
}

void QpackDecoder::FreeBlocked(BlockedSection *section) noexcept
{
    const SIZE_T allocationSize = sizeof(BlockedSection) + section->Length;
    --blockedStreamCount_;
    blockedBytes_ -= section->Length;
    RtlSecureZeroMemory(section, allocationSize);
    FreeNonPagedPoolBytes(section);
}
} // namespace wknet::qpack
