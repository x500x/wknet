#pragma once

#include "qpack/QpackEncoder.h"

namespace wknet::qpack
{
class QpackDecoder final
{
  public:
    QpackDecoder() noexcept = default;
    ~QpackDecoder() noexcept;

    QpackDecoder(const QpackDecoder &) = delete;
    QpackDecoder &operator=(const QpackDecoder &) = delete;

    _Must_inspect_result_ NTSTATUS
    Initialize(SIZE_T localMaximumCapacity, ULONG localBlockedStreams,
               SIZE_T maximumFieldSectionBytes = WKNET_HARD_MAX_HTTP3_FIELD_SECTION_BYTES,
               SIZE_T maximumFields = WKNET_HARD_MAX_HTTP3_FIELDS) noexcept;

    void Reset() noexcept;

    _Must_inspect_result_ NTSTATUS ProcessEncoderInstructions(_In_reads_bytes_(length) const UCHAR *source,
                                                              SIZE_T length, _Out_ SIZE_T *bytesConsumed,
                                                              _Out_opt_ ULONGLONG *applicationError = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS DecodeFieldSection(
        ULONGLONG streamId, _In_reads_bytes_(length) const UCHAR *source, SIZE_T length,
        _Out_writes_(fieldCapacity) QpackFieldView *fields, SIZE_T fieldCapacity, _Out_ SIZE_T *fieldCount,
        _Out_writes_bytes_(fieldBufferCapacity) UCHAR *fieldBuffer, SIZE_T fieldBufferCapacity,
        _Out_ SIZE_T *fieldBufferUsed, _Out_writes_bytes_(decoderInstructionCapacity) UCHAR *decoderInstruction,
        SIZE_T decoderInstructionCapacity, _Out_ SIZE_T *decoderInstructionLength,
        _Out_opt_ ULONGLONG *applicationError = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS ResumeBlockedFieldSection(
        ULONGLONG streamId, _Out_writes_(fieldCapacity) QpackFieldView *fields, SIZE_T fieldCapacity,
        _Out_ SIZE_T *fieldCount, _Out_writes_bytes_(fieldBufferCapacity) UCHAR *fieldBuffer,
        SIZE_T fieldBufferCapacity, _Out_ SIZE_T *fieldBufferUsed,
        _Out_writes_bytes_(decoderInstructionCapacity) UCHAR *decoderInstruction, SIZE_T decoderInstructionCapacity,
        _Out_ SIZE_T *decoderInstructionLength, _Out_opt_ ULONGLONG *applicationError = nullptr) noexcept;

    _Must_inspect_result_ NTSTATUS CancelStream(ULONGLONG streamId,
                                                _Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                                SIZE_T instructionCapacity, _Out_ SIZE_T *instructionLength) noexcept;

    _Must_inspect_result_ NTSTATUS WriteInsertCountIncrement(ULONGLONG increment,
                                                             _Out_writes_bytes_(instructionCapacity) UCHAR *instruction,
                                                             SIZE_T instructionCapacity,
                                                             _Out_ SIZE_T *instructionLength) noexcept;

    static NTSTATUS EncodeRequiredInsertCount(ULONGLONG requiredInsertCount, SIZE_T maximumCapacity,
                                              _Out_ ULONGLONG *encodedInsertCount) noexcept;

    static NTSTATUS DecodeRequiredInsertCount(ULONGLONG encodedInsertCount, ULONGLONG totalInsertCount,
                                              SIZE_T maximumCapacity, _Out_ ULONGLONG *requiredInsertCount) noexcept;

    SIZE_T BlockedStreamCount() const noexcept;
    SIZE_T BlockedBytes() const noexcept;
    ULONGLONG ReportedInsertCount() const noexcept;
    const QpackDynamicTable &Table() const noexcept;

  private:
    struct BlockedSection final
    {
        BlockedSection *Next = nullptr;
        ULONGLONG StreamId = 0;
        ULONGLONG RequiredInsertCount = 0;
        SIZE_T Length = 0;
    };

    _Must_inspect_result_ NTSTATUS DecodeAvailableFieldSection(
        ULONGLONG streamId, _In_reads_bytes_(length) const UCHAR *source, SIZE_T length,
        _Out_writes_(fieldCapacity) QpackFieldView *fields, SIZE_T fieldCapacity, _Out_ SIZE_T *fieldCount,
        _Out_writes_bytes_(fieldBufferCapacity) UCHAR *fieldBuffer, SIZE_T fieldBufferCapacity,
        _Out_ SIZE_T *fieldBufferUsed, _Out_writes_bytes_(decoderInstructionCapacity) UCHAR *decoderInstruction,
        SIZE_T decoderInstructionCapacity, _Out_ SIZE_T *decoderInstructionLength,
        _Out_opt_ ULONGLONG *applicationError) noexcept;
    _Must_inspect_result_ NTSTATUS StoreBlockedSection(ULONGLONG streamId, ULONGLONG requiredInsertCount,
                                                       _In_reads_bytes_(length) const UCHAR *source,
                                                       SIZE_T length) noexcept;
    BlockedSection *FindBlocked(ULONGLONG streamId, _Out_opt_ BlockedSection **previous) noexcept;
    void FreeBlocked(BlockedSection *section) noexcept;

    QpackDynamicTable table_ = {};
    BlockedSection *blockedHead_ = nullptr;
    SIZE_T localMaximumCapacity_ = 0;
    ULONG localBlockedStreams_ = 0;
    SIZE_T maximumFieldSectionBytes_ = 0;
    SIZE_T maximumFields_ = 0;
    SIZE_T blockedStreamCount_ = 0;
    SIZE_T blockedBytes_ = 0;
    ULONGLONG reportedInsertCount_ = 0;
};
} // namespace wknet::qpack
