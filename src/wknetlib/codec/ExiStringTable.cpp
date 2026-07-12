#include "ExiStringTable.h"
#include "ExiEventReader.h"

namespace wknet
{
namespace codec
{
namespace
{
    _Must_inspect_result_
    bool TextEquals(HttpXmlText left, HttpXmlText right) noexcept
    {
        if (left.Length != right.Length) {
            return false;
        }
        if (left.Length == 0) {
            return true;
        }
        return left.Data != nullptr &&
            right.Data != nullptr &&
            RtlCompareMemory(left.Data, right.Data, left.Length) == left.Length;
    }
}

    NTSTATUS HttpExiStringTable::Initialize(SIZE_T maxEntries, SIZE_T textCapacity) noexcept
    {
        Reset();

        NTSTATUS status = entries_.Allocate(maxEntries);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = text_.Allocate(textCapacity);
        if (!NT_SUCCESS(status)) {
            entries_.Reset();
            return status;
        }
        entryCount_ = 0;
        textLength_ = 0;
        return STATUS_SUCCESS;
    }

    void HttpExiStringTable::Reset() noexcept
    {
        entries_.Reset();
        text_.Reset();
        entryCount_ = 0;
        textLength_ = 0;
    }

    NTSTATUS HttpExiStringTable::Add(HttpXmlText value, ULONG* index) noexcept
    {
        if (index == nullptr || (value.Length != 0 && value.Data == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG existing = 0;
        if (Find(value, &existing)) {
            *index = existing;
            return STATUS_SUCCESS;
        }

        if (!entries_.IsValid() ||
            !text_.IsValid() ||
            entryCount_ >= entries_.Count() ||
            entryCount_ > 0xffffffffUL) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        HttpXmlText stored = {};
        NTSTATUS status = CopyText(value, &stored);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        entries_[entryCount_].Value = stored;
        *index = static_cast<ULONG>(entryCount_);
        ++entryCount_;
        return STATUS_SUCCESS;
    }

    bool HttpExiStringTable::Find(HttpXmlText value, ULONG* index) const noexcept
    {
        if (index == nullptr) {
            return false;
        }
        for (SIZE_T entryIndex = 0; entryIndex < entryCount_; ++entryIndex) {
            if (TextEquals(entries_[entryIndex].Value, value)) {
                *index = static_cast<ULONG>(entryIndex);
                return true;
            }
        }
        return false;
    }

    bool HttpExiStringTable::Get(ULONG index, HttpXmlText* value) const noexcept
    {
        if (value == nullptr || index >= entryCount_) {
            return false;
        }
        *value = entries_[index].Value;
        return true;
    }

    SIZE_T HttpExiStringTable::Count() const noexcept
    {
        return entryCount_;
    }

    NTSTATUS HttpExiStringTable::CopyText(HttpXmlText value, HttpXmlText* stored) noexcept
    {
        if (stored == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *stored = {};
        if (value.Length == 0) {
            return STATUS_SUCCESS;
        }
        if (value.Length > text_.Count() || textLength_ > text_.Count() - value.Length) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        char* destination = text_.Get() + textLength_;
        RtlCopyMemory(destination, value.Data, value.Length);
        stored->Data = destination;
        stored->Length = value.Length;
        textLength_ += value.Length;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiValueTable::Initialize(
        SIZE_T maxLiteralEntries,
        SIZE_T textCapacity,
        ULONG valueMaxLength,
        ULONG valuePartitionCapacity) noexcept
    {
        Reset();

        NTSTATUS status = literals_.Initialize(maxLiteralEntries, textCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T boundedCapacity =
            valuePartitionCapacity < maxLiteralEntries ?
                static_cast<SIZE_T>(valuePartitionCapacity) :
                maxLiteralEntries;
        status = globalEntries_.Allocate(boundedCapacity);
        if (!NT_SUCCESS(status)) {
            Reset();
            return status;
        }
        status = localEntries_.Allocate(maxLiteralEntries);
        if (!NT_SUCCESS(status)) {
            Reset();
            return status;
        }

        valueMaxLength_ = valueMaxLength;
        valuePartitionCapacity_ = boundedCapacity;
        return STATUS_SUCCESS;
    }

    void HttpExiValueTable::Reset() noexcept
    {
        literals_.Reset();
        globalEntries_.Reset();
        localEntries_.Reset();
        globalCount_ = 0;
        nextGlobalId_ = 0;
        localEntryCount_ = 0;
        valueMaxLength_ = 0xffffffffUL;
        valuePartitionCapacity_ = 0;
    }

    NTSTATUS HttpExiValueTable::AddLiteral(
        ULONG qnameId,
        ULONG codePointLength,
        HttpXmlText value,
        HttpXmlText* storedValue) noexcept
    {
        if (storedValue == nullptr || (value.Length != 0 && value.Data == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }
        *storedValue = {};

        ULONG literalIndex = 0;
        NTSTATUS status = literals_.Add(value, &literalIndex);
        if (!NT_SUCCESS(status) || !literals_.Get(literalIndex, storedValue)) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        if (codePointLength == 0 ||
            codePointLength > valueMaxLength_ ||
            valuePartitionCapacity_ == 0) {
            return STATUS_SUCCESS;
        }
        if (qnameId == 0xffffffffUL) {
            return STATUS_SUCCESS;
        }
        if (!globalEntries_.IsValid() ||
            !localEntries_.IsValid() ||
            localEntryCount_ >= localEntries_.Count() ||
            nextGlobalId_ >= valuePartitionCapacity_) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        for (SIZE_T index = 0; index < globalCount_; ++index) {
            const HttpExiGlobalValueEntry& entry = globalEntries_[index];
            if (entry.Assigned && TextEquals(entry.Value, *storedValue)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        HttpExiGlobalValueEntry& globalEntry = globalEntries_[nextGlobalId_];
        if (globalEntry.Assigned) {
            if (globalEntry.LocalEntryIndex >= localEntryCount_) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            localEntries_[globalEntry.LocalEntryIndex].Assigned = false;
        }
        else {
            if (globalCount_ >= valuePartitionCapacity_) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++globalCount_;
        }

        HttpExiLocalValueEntry& localEntry = localEntries_[localEntryCount_];
        localEntry.QNameId = qnameId;
        localEntry.GlobalId = static_cast<ULONG>(nextGlobalId_);
        localEntry.Assigned = true;

        globalEntry.Value = *storedValue;
        globalEntry.LocalEntryIndex = localEntryCount_;
        globalEntry.Assigned = true;
        ++localEntryCount_;
        ++nextGlobalId_;
        if (nextGlobalId_ == valuePartitionCapacity_) {
            nextGlobalId_ = 0;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiValueTable::ReadLocal(
        HttpExiBitInput* input,
        ULONG qnameId,
        HttpXmlText* value) const noexcept
    {
        if (input == nullptr || value == nullptr || qnameId == 0xffffffffUL) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};

        const SIZE_T localCount = LocalCount(qnameId);
        if (localCount == 0 || localCount > 0xffffffffULL) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        UCHAR bitCount = 0;
        if (!HttpExiBitsForProductionCount(static_cast<ULONG>(localCount), &bitCount)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG localId = 0;
        if (bitCount != 0 && !input->ReadBits(bitCount, &localId)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T currentLocalId = 0;
        for (SIZE_T index = 0; index < localEntryCount_; ++index) {
            const HttpExiLocalValueEntry& localEntry = localEntries_[index];
            if (localEntry.QNameId != qnameId) {
                continue;
            }
            if (currentLocalId == localId) {
                if (!localEntry.Assigned || localEntry.GlobalId >= globalCount_) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                const HttpExiGlobalValueEntry& globalEntry = globalEntries_[localEntry.GlobalId];
                if (!globalEntry.Assigned || globalEntry.LocalEntryIndex != index) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                *value = globalEntry.Value;
                return STATUS_SUCCESS;
            }
            ++currentLocalId;
        }
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    NTSTATUS HttpExiValueTable::ReadGlobal(
        HttpExiBitInput* input,
        HttpXmlText* value) const noexcept
    {
        if (input == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};
        if (globalCount_ == 0 || globalCount_ > 0xffffffffULL) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        UCHAR bitCount = 0;
        if (!HttpExiBitsForProductionCount(static_cast<ULONG>(globalCount_), &bitCount)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG globalId = 0;
        if (bitCount != 0 && !input->ReadBits(bitCount, &globalId)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (globalId >= globalCount_ || !globalEntries_[globalId].Assigned) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *value = globalEntries_[globalId].Value;
        return STATUS_SUCCESS;
    }

    SIZE_T HttpExiValueTable::GlobalCount() const noexcept
    {
        return globalCount_;
    }

    SIZE_T HttpExiValueTable::LocalCount(ULONG qnameId) const noexcept
    {
        SIZE_T count = 0;
        for (SIZE_T index = 0; index < localEntryCount_; ++index) {
            if (localEntries_[index].QNameId == qnameId) {
                ++count;
            }
        }
        return count;
    }

    NTSTATUS HttpExiQNameTable::Initialize(SIZE_T maxEntries) noexcept
    {
        Reset();
        NTSTATUS status = entries_.Allocate(maxEntries);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        entryCount_ = 0;
        return STATUS_SUCCESS;
    }

    void HttpExiQNameTable::Reset() noexcept
    {
        entries_.Reset();
        entryCount_ = 0;
    }

    NTSTATUS HttpExiQNameTable::Add(HttpExiQNameEntry value, ULONG* index) noexcept
    {
        if (index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG existing = 0;
        if (Find(value, &existing)) {
            *index = existing;
            return STATUS_SUCCESS;
        }

        if (!entries_.IsValid() || entryCount_ >= entries_.Count() || entryCount_ > 0xffffffffUL) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        entries_[entryCount_] = value;
        *index = static_cast<ULONG>(entryCount_);
        ++entryCount_;
        return STATUS_SUCCESS;
    }

    bool HttpExiQNameTable::Find(HttpExiQNameEntry value, ULONG* index) const noexcept
    {
        if (index == nullptr) {
            return false;
        }
        for (SIZE_T entryIndex = 0; entryIndex < entryCount_; ++entryIndex) {
            const HttpExiQNameEntry& stored = entries_[entryIndex];
            if (stored.UriId == value.UriId &&
                stored.LocalNameId == value.LocalNameId &&
                stored.PrefixId == value.PrefixId) {
                *index = static_cast<ULONG>(entryIndex);
                return true;
            }
        }
        return false;
    }

    bool HttpExiQNameTable::Get(ULONG index, HttpExiQNameEntry* value) const noexcept
    {
        if (value == nullptr || index >= entryCount_) {
            return false;
        }
        *value = entries_[index];
        return true;
    }

    SIZE_T HttpExiQNameTable::Count() const noexcept
    {
        return entryCount_;
    }
}
}
