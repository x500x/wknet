#pragma once

#include "qpack/QpackTypes.h"

namespace wknet::qpack
{
constexpr SIZE_T QpackEntryOverhead = 32;

struct QpackDynamicEntryView final
{
    QpackStringView Name = {};
    QpackStringView Value = {};
    ULONGLONG AbsoluteIndex = 0;
};

class QpackDynamicTable final
{
  public:
    QpackDynamicTable() noexcept = default;
    ~QpackDynamicTable() noexcept;

    QpackDynamicTable(const QpackDynamicTable &) = delete;
    QpackDynamicTable &operator=(const QpackDynamicTable &) = delete;

    _Must_inspect_result_ NTSTATUS Initialize(SIZE_T maximumCapacity, SIZE_T initialCapacity = 0) noexcept;

    void Reset() noexcept;

    _Must_inspect_result_ NTSTATUS SetCapacity(SIZE_T capacity) noexcept;

    _Must_inspect_result_ NTSTATUS Insert(_In_reads_bytes_(nameLength) const UCHAR *name, SIZE_T nameLength,
                                          _In_reads_bytes_(valueLength) const UCHAR *value, SIZE_T valueLength,
                                          _Out_opt_ ULONGLONG *absoluteIndex = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS DuplicateRelative(ULONGLONG relativeIndex,
                                                     _Out_opt_ ULONGLONG *absoluteIndex = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS LookupAbsolute(ULONGLONG absoluteIndex,
                                                  _Out_ QpackDynamicEntryView *entry) const noexcept;

    _Must_inspect_result_ NTSTATUS LookupRelative(ULONGLONG base, ULONGLONG relativeIndex,
                                                  _Out_ QpackDynamicEntryView *entry) const noexcept;

    _Must_inspect_result_ NTSTATUS LookupPostBase(ULONGLONG base, ULONGLONG postBaseIndex,
                                                  _Out_ QpackDynamicEntryView *entry) const noexcept;

    _Must_inspect_result_ NTSTATUS FindExact(_In_reads_bytes_(nameLength) const UCHAR *name, SIZE_T nameLength,
                                             _In_reads_bytes_(valueLength) const UCHAR *value, SIZE_T valueLength,
                                             _Out_ ULONGLONG *absoluteIndex) const noexcept;

    _Must_inspect_result_ NTSTATUS FindName(_In_reads_bytes_(nameLength) const UCHAR *name, SIZE_T nameLength,
                                            _Out_ ULONGLONG *absoluteIndex) const noexcept;

    _Must_inspect_result_ NTSTATUS AddReference(ULONGLONG absoluteIndex) noexcept;

    _Must_inspect_result_ NTSTATUS ReleaseReference(ULONGLONG absoluteIndex) noexcept;

    SIZE_T MaximumCapacity() const noexcept;
    SIZE_T Capacity() const noexcept;
    SIZE_T CurrentSize() const noexcept;
    SIZE_T EntryCount() const noexcept;
    ULONGLONG InsertCount() const noexcept;

  private:
    struct Entry final
    {
        SIZE_T NameOffset = 0;
        SIZE_T NameLength = 0;
        SIZE_T ValueOffset = 0;
        SIZE_T ValueLength = 0;
        SIZE_T Size = 0;
        ULONGLONG AbsoluteIndex = 0;
        ULONG ReferenceCount = 0;
    };

    _Must_inspect_result_ NTSTATUS ValidateEviction(SIZE_T targetSize) const noexcept;
    void EvictOldest() noexcept;
    void CompactData() noexcept;
    Entry *FindEntry(ULONGLONG absoluteIndex) noexcept;
    const Entry *FindEntry(ULONGLONG absoluteIndex) const noexcept;

    UCHAR *data_ = nullptr;
    Entry *entries_ = nullptr;
    SIZE_T maximumCapacity_ = 0;
    SIZE_T capacity_ = 0;
    SIZE_T currentSize_ = 0;
    SIZE_T dataUsed_ = 0;
    SIZE_T entryCapacity_ = 0;
    SIZE_T entryCount_ = 0;
    ULONGLONG insertCount_ = 0;
};
} // namespace wknet::qpack
