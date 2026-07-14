#include "qpack/QpackDynamicTable.h"
#include "rtl/ProtocolAllocator.h"

namespace wknet::qpack
{
namespace
{
bool BytesEqual(const UCHAR *left, const UCHAR *right, SIZE_T length) noexcept
{
    if (length == 0)
    {
        return true;
    }

    return RtlCompareMemory(left, right, length) == length;
}

bool AdditionOverflows(SIZE_T left, SIZE_T right) noexcept
{
    return left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right;
}
} // namespace

QpackDynamicTable::~QpackDynamicTable() noexcept
{
    Reset();
}

NTSTATUS QpackDynamicTable::Initialize(SIZE_T maximumCapacity, SIZE_T initialCapacity) noexcept
{
    Reset();
    if (maximumCapacity > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES || initialCapacity > maximumCapacity)
    {
        return STATUS_INVALID_PARAMETER;
    }

    maximumCapacity_ = maximumCapacity;
    capacity_ = initialCapacity;
    if (maximumCapacity == 0)
    {
        return STATUS_SUCCESS;
    }

    data_ = static_cast<UCHAR *>(
        AllocateProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackDynamicTableData, maximumCapacity));
    if (data_ == nullptr)
    {
        Reset();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entryCapacity_ = maximumCapacity / QpackEntryOverhead;
    if (entryCapacity_ == 0)
    {
        entryCapacity_ = 1;
    }
    if (entryCapacity_ > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / sizeof(Entry))
    {
        Reset();
        return STATUS_INTEGER_OVERFLOW;
    }

    entries_ = static_cast<Entry *>(AllocateProtocolNonPagedPoolBytes(
        rtl::ProtocolAllocationSite::QpackDynamicTableEntries, entryCapacity_ * sizeof(Entry)));
    if (entries_ == nullptr)
    {
        Reset();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

void QpackDynamicTable::Reset() noexcept
{
    if (data_ != nullptr)
    {
        RtlSecureZeroMemory(data_, maximumCapacity_);
        FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackDynamicTableData, data_);
    }
    if (entries_ != nullptr)
    {
        RtlSecureZeroMemory(entries_, entryCapacity_ * sizeof(Entry));
        FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackDynamicTableEntries, entries_);
    }

    data_ = nullptr;
    entries_ = nullptr;
    maximumCapacity_ = 0;
    capacity_ = 0;
    currentSize_ = 0;
    dataUsed_ = 0;
    entryCapacity_ = 0;
    entryCount_ = 0;
    insertCount_ = 0;
}

NTSTATUS QpackDynamicTable::SetCapacity(SIZE_T capacity) noexcept
{
    if (capacity > maximumCapacity_)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const NTSTATUS validationStatus = ValidateEviction(capacity);
    if (!NT_SUCCESS(validationStatus))
    {
        return validationStatus;
    }

    while (currentSize_ > capacity && entryCount_ != 0)
    {
        EvictOldest();
    }
    CompactData();
    capacity_ = capacity;
    WKNET_TRACE(ComponentHttp3, TraceLevel::Verbose,
                "qpack.dynamic_table.updated capacity=%Iu size=%Iu entries=%Iu insert_count=%I64u", capacity_,
                currentSize_, entryCount_, insertCount_);
    return STATUS_SUCCESS;
}

NTSTATUS QpackDynamicTable::Insert(const UCHAR *name, SIZE_T nameLength, const UCHAR *value, SIZE_T valueLength,
                                   ULONGLONG *absoluteIndex) noexcept
{
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = 0;
    }
    if ((name == nullptr && nameLength != 0) || (value == nullptr && valueLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (AdditionOverflows(nameLength, valueLength) || AdditionOverflows(nameLength + valueLength, QpackEntryOverhead))
    {
        return STATUS_INTEGER_OVERFLOW;
    }

    const SIZE_T entrySize = nameLength + valueLength + QpackEntryOverhead;
    if (entrySize > capacity_ || insertCount_ == QpackIntegerMaximum)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const SIZE_T targetSize = capacity_ - entrySize;
    const NTSTATUS validationStatus = ValidateEviction(targetSize);
    if (!NT_SUCCESS(validationStatus))
    {
        return validationStatus;
    }

    while (currentSize_ > targetSize && entryCount_ != 0)
    {
        EvictOldest();
    }
    CompactData();

    if (entryCount_ >= entryCapacity_)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const SIZE_T dataLength = nameLength + valueLength;
    if (dataUsed_ > maximumCapacity_ || dataLength > maximumCapacity_ - dataUsed_)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Entry &entry = entries_[entryCount_];
    entry = {};
    entry.NameOffset = dataUsed_;
    entry.NameLength = nameLength;
    if (nameLength != 0)
    {
        RtlCopyMemory(data_ + dataUsed_, name, nameLength);
        dataUsed_ += nameLength;
    }
    entry.ValueOffset = dataUsed_;
    entry.ValueLength = valueLength;
    if (valueLength != 0)
    {
        RtlCopyMemory(data_ + dataUsed_, value, valueLength);
        dataUsed_ += valueLength;
    }
    entry.Size = entrySize;
    entry.AbsoluteIndex = insertCount_;

    ++entryCount_;
    ++insertCount_;
    currentSize_ += entrySize;
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = entry.AbsoluteIndex;
    }
    WKNET_TRACE(ComponentHttp3, TraceLevel::Verbose,
                "qpack.dynamic_table.updated capacity=%Iu size=%Iu entries=%Iu insert_count=%I64u", capacity_,
                currentSize_, entryCount_, insertCount_);
    return STATUS_SUCCESS;
}

NTSTATUS QpackDynamicTable::DuplicateRelative(ULONGLONG relativeIndex, ULONGLONG *absoluteIndex) noexcept
{
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = 0;
    }
    QpackDynamicEntryView source = {};
    NTSTATUS status = LookupRelative(insertCount_, relativeIndex, &source);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (source.Name.Length > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - source.Value.Length)
    {
        return STATUS_INTEGER_OVERFLOW;
    }

    const SIZE_T copyLength = source.Name.Length + source.Value.Length;
    UCHAR *copy = nullptr;
    if (copyLength != 0)
    {
        copy = static_cast<UCHAR *>(
            AllocateProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackDynamicEntryCopy, copyLength));
        if (copy == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (source.Name.Length != 0)
        {
            RtlCopyMemory(copy, source.Name.Data, source.Name.Length);
        }
        if (source.Value.Length != 0)
        {
            RtlCopyMemory(copy + source.Name.Length, source.Value.Data, source.Value.Length);
        }
    }

    status = Insert(copy, source.Name.Length, copy == nullptr ? nullptr : copy + source.Name.Length,
                    source.Value.Length, absoluteIndex);
    if (copy != nullptr)
    {
        RtlSecureZeroMemory(copy, copyLength);
        FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite::QpackDynamicEntryCopy, copy);
    }
    return status;
}

NTSTATUS QpackDynamicTable::LookupAbsolute(ULONGLONG absoluteIndex, QpackDynamicEntryView *entry) const noexcept
{
    if (entry != nullptr)
    {
        *entry = {};
    }
    if (entry == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const Entry *stored = FindEntry(absoluteIndex);
    if (stored == nullptr)
    {
        return STATUS_NOT_FOUND;
    }

    entry->Name = {data_ + stored->NameOffset, stored->NameLength};
    entry->Value = {data_ + stored->ValueOffset, stored->ValueLength};
    entry->AbsoluteIndex = stored->AbsoluteIndex;
    return STATUS_SUCCESS;
}

NTSTATUS QpackDynamicTable::LookupRelative(ULONGLONG base, ULONGLONG relativeIndex,
                                           QpackDynamicEntryView *entry) const noexcept
{
    if (base == 0 || relativeIndex >= base)
    {
        if (entry != nullptr)
        {
            *entry = {};
        }
        return STATUS_NOT_FOUND;
    }
    return LookupAbsolute(base - relativeIndex - 1, entry);
}

NTSTATUS QpackDynamicTable::LookupPostBase(ULONGLONG base, ULONGLONG postBaseIndex,
                                           QpackDynamicEntryView *entry) const noexcept
{
    if (base > QpackIntegerMaximum - postBaseIndex)
    {
        if (entry != nullptr)
        {
            *entry = {};
        }
        return STATUS_INTEGER_OVERFLOW;
    }
    return LookupAbsolute(base + postBaseIndex, entry);
}

NTSTATUS QpackDynamicTable::FindExact(const UCHAR *name, SIZE_T nameLength, const UCHAR *value, SIZE_T valueLength,
                                      ULONGLONG *absoluteIndex) const noexcept
{
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = 0;
    }
    if (absoluteIndex == nullptr || (name == nullptr && nameLength != 0) || (value == nullptr && valueLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (SIZE_T index = entryCount_; index != 0; --index)
    {
        const Entry &entry = entries_[index - 1];
        if (entry.NameLength == nameLength && entry.ValueLength == valueLength &&
            BytesEqual(data_ + entry.NameOffset, name, nameLength) &&
            BytesEqual(data_ + entry.ValueOffset, value, valueLength))
        {
            *absoluteIndex = entry.AbsoluteIndex;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS QpackDynamicTable::FindName(const UCHAR *name, SIZE_T nameLength, ULONGLONG *absoluteIndex) const noexcept
{
    if (absoluteIndex != nullptr)
    {
        *absoluteIndex = 0;
    }
    if (absoluteIndex == nullptr || (name == nullptr && nameLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (SIZE_T index = entryCount_; index != 0; --index)
    {
        const Entry &entry = entries_[index - 1];
        if (entry.NameLength == nameLength && BytesEqual(data_ + entry.NameOffset, name, nameLength))
        {
            *absoluteIndex = entry.AbsoluteIndex;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS QpackDynamicTable::AddReference(ULONGLONG absoluteIndex) noexcept
{
    Entry *entry = FindEntry(absoluteIndex);
    if (entry == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    if (entry->ReferenceCount == static_cast<ULONG>(~static_cast<ULONG>(0)))
    {
        return STATUS_INTEGER_OVERFLOW;
    }
    ++entry->ReferenceCount;
    return STATUS_SUCCESS;
}

NTSTATUS QpackDynamicTable::ReleaseReference(ULONGLONG absoluteIndex) noexcept
{
    Entry *entry = FindEntry(absoluteIndex);
    if (entry == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    if (entry->ReferenceCount == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    --entry->ReferenceCount;
    return STATUS_SUCCESS;
}

SIZE_T QpackDynamicTable::MaximumCapacity() const noexcept
{
    return maximumCapacity_;
}

SIZE_T QpackDynamicTable::Capacity() const noexcept
{
    return capacity_;
}

SIZE_T QpackDynamicTable::CurrentSize() const noexcept
{
    return currentSize_;
}

SIZE_T QpackDynamicTable::EntryCount() const noexcept
{
    return entryCount_;
}

ULONGLONG QpackDynamicTable::InsertCount() const noexcept
{
    return insertCount_;
}

NTSTATUS QpackDynamicTable::ValidateEviction(SIZE_T targetSize) const noexcept
{
    SIZE_T simulatedSize = currentSize_;
    for (SIZE_T index = 0; simulatedSize > targetSize && index < entryCount_; ++index)
    {
        if (entries_[index].ReferenceCount != 0)
        {
            return STATUS_DEVICE_BUSY;
        }
        simulatedSize -= entries_[index].Size;
    }
    return simulatedSize <= targetSize ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

void QpackDynamicTable::EvictOldest() noexcept
{
    if (entryCount_ == 0)
    {
        return;
    }

    const Entry oldest = entries_[0];
    currentSize_ -= oldest.Size;
    if (oldest.NameLength + oldest.ValueLength != 0)
    {
        RtlSecureZeroMemory(data_ + oldest.NameOffset, oldest.NameLength + oldest.ValueLength);
    }
    if (entryCount_ > 1)
    {
        RtlMoveMemory(entries_, entries_ + 1, (entryCount_ - 1) * sizeof(Entry));
    }
    --entryCount_;
    entries_[entryCount_] = {};
}

void QpackDynamicTable::CompactData() noexcept
{
    SIZE_T writeOffset = 0;
    for (SIZE_T index = 0; index < entryCount_; ++index)
    {
        Entry &entry = entries_[index];
        const SIZE_T length = entry.NameLength + entry.ValueLength;
        if (length != 0 && entry.NameOffset != writeOffset)
        {
            RtlMoveMemory(data_ + writeOffset, data_ + entry.NameOffset, length);
        }
        entry.NameOffset = writeOffset;
        writeOffset += entry.NameLength;
        entry.ValueOffset = writeOffset;
        writeOffset += entry.ValueLength;
    }
    if (dataUsed_ > writeOffset)
    {
        RtlSecureZeroMemory(data_ + writeOffset, dataUsed_ - writeOffset);
    }
    dataUsed_ = writeOffset;
}

QpackDynamicTable::Entry *QpackDynamicTable::FindEntry(ULONGLONG absoluteIndex) noexcept
{
    for (SIZE_T index = 0; index < entryCount_; ++index)
    {
        if (entries_[index].AbsoluteIndex == absoluteIndex)
        {
            return &entries_[index];
        }
    }
    return nullptr;
}

const QpackDynamicTable::Entry *QpackDynamicTable::FindEntry(ULONGLONG absoluteIndex) const noexcept
{
    for (SIZE_T index = 0; index < entryCount_; ++index)
    {
        if (entries_[index].AbsoluteIndex == absoluteIndex)
        {
            return &entries_[index];
        }
    }
    return nullptr;
}
} // namespace wknet::qpack
