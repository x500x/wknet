#pragma once

#include "qpack/QpackDynamicTable.h"

namespace wknet::qpack
{
constexpr SIZE_T QpackMaximumOutstandingSections = 256;
constexpr SIZE_T QpackMaximumOutstandingReferenceBytes = WKNET_HARD_MAX_QPACK_TOTAL_BLOCKED_BYTES;

struct QpackFieldView final
{
    QpackStringView Name = {};
    QpackStringView Value = {};
    bool Sensitive = false;
};

class QpackEncoder final
{
  public:
    QpackEncoder() noexcept = default;
    ~QpackEncoder() noexcept;

    QpackEncoder(const QpackEncoder &) = delete;
    QpackEncoder &operator=(const QpackEncoder &) = delete;

    _Must_inspect_result_ NTSTATUS Initialize(SIZE_T peerMaximumCapacity, ULONG peerBlockedStreams) noexcept;

    void Reset() noexcept;

    _Must_inspect_result_ NTSTATUS SetCapacity(SIZE_T capacity,
                                               _Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                               SIZE_T instructionCapacity, _Out_ SIZE_T *instructionLength) noexcept;

    _Must_inspect_result_ NTSTATUS DrainPendingCapacity(_Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                                        SIZE_T instructionCapacity,
                                                        _Out_ SIZE_T *instructionLength) noexcept;

    _Must_inspect_result_ NTSTATUS InsertWithNameReference(bool staticReference, ULONGLONG nameIndex,
                                                           _In_reads_bytes_(valueLength) const UCHAR *value,
                                                           SIZE_T valueLength, bool huffmanValue,
                                                           _Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                                           SIZE_T instructionCapacity, _Out_ SIZE_T *instructionLength,
                                                           _Out_opt_ ULONGLONG *absoluteIndex = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS InsertWithLiteralName(_In_reads_bytes_(nameLength) const UCHAR *name,
                                                         SIZE_T nameLength, bool huffmanName,
                                                         _In_reads_bytes_(valueLength) const UCHAR *value,
                                                         SIZE_T valueLength, bool huffmanValue,
                                                         _Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                                         SIZE_T instructionCapacity, _Out_ SIZE_T *instructionLength,
                                                         _Out_opt_ ULONGLONG *absoluteIndex = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS Duplicate(ULONGLONG relativeIndex,
                                             _Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                             SIZE_T instructionCapacity, _Out_ SIZE_T *instructionLength,
                                             _Out_opt_ ULONGLONG *absoluteIndex = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS EncodeFieldSection(ULONGLONG streamId,
                                                      _In_reads_(fieldCount) const QpackFieldView *fields,
                                                      SIZE_T fieldCount,
                                                      _Out_writes_bytes_(capacity) UCHAR *destination, SIZE_T capacity,
                                                      _Out_ SIZE_T *bytesWritten,
                                                      _Out_opt_ ULONGLONG *applicationError = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS ProcessDecoderInstructions(_In_reads_bytes_(length) const UCHAR *source,
                                                              SIZE_T length, _Out_ SIZE_T *bytesConsumed,
                                                              _Out_opt_ ULONGLONG *applicationError = nullptr) noexcept;

    static bool IsSensitiveName(_In_reads_bytes_(nameLength) const UCHAR *name, SIZE_T nameLength) noexcept;

    SIZE_T EffectiveMaximumCapacity() const noexcept;
    ULONG EffectiveBlockedStreams() const noexcept;
    ULONGLONG KnownReceivedCount() const noexcept;
    SIZE_T OutstandingSectionCount() const noexcept;
    ULONG BlockedStreamCount() const noexcept;
    const QpackDynamicTable &Table() const noexcept;

  private:
    struct OutstandingSection final
    {
        OutstandingSection *Next = nullptr;
        ULONGLONG StreamId = 0;
        ULONGLONG RequiredInsertCount = 0;
        SIZE_T ReferenceCount = 0;
    };

    _Must_inspect_result_ NTSTATUS ApplyCapacity(SIZE_T capacity,
                                                 _Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                                 SIZE_T instructionCapacity, _Out_ SIZE_T *instructionLength) noexcept;
    _Must_inspect_result_ NTSTATUS TrackSection(ULONGLONG streamId, ULONGLONG requiredInsertCount,
                                                _In_reads_(referenceCount) const ULONGLONG *references,
                                                SIZE_T referenceCount) noexcept;
    void ReleaseSection(OutstandingSection *section) noexcept;
    _Must_inspect_result_ NTSTATUS AcknowledgeSection(ULONGLONG streamId) noexcept;
    _Must_inspect_result_ NTSTATUS CancelStream(ULONGLONG streamId) noexcept;
    ULONG CountBlockedStreams() const noexcept;
    bool StreamIsBlocked(ULONGLONG streamId) const noexcept;

    QpackDynamicTable table_ = {};
    OutstandingSection *outstandingHead_ = nullptr;
    OutstandingSection *outstandingTail_ = nullptr;
    SIZE_T effectiveMaximumCapacity_ = 0;
    ULONG effectiveBlockedStreams_ = 0;
    ULONGLONG knownReceivedCount_ = 0;
    SIZE_T outstandingSectionCount_ = 0;
    SIZE_T outstandingReferenceBytes_ = 0;
    SIZE_T pendingCapacity_ = 0;
    bool pendingCapacityValid_ = false;
};
} // namespace wknet::qpack
