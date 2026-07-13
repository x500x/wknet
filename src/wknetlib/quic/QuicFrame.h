#pragma once

#include "quic/QuicTypes.h"

namespace wknet::quic
{
enum class QuicFrameKind : UCHAR
{
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    HandshakeDone
};

struct QuicFrame final
{
    QuicFrameKind Kind = QuicFrameKind::Padding;
    ULONGLONG WireType = 0;
    ULONGLONG StreamId = 0;
    ULONGLONG Offset = 0;
    ULONGLONG Length = 0;
    ULONGLONG ErrorCode = 0;
    ULONGLONG FinalSize = 0;
    ULONGLONG Maximum = 0;
    ULONGLONG LargestAcknowledged = 0;
    ULONGLONG AckDelay = 0;
    ULONGLONG AckRangeCount = 0;
    ULONGLONG FirstAckRange = 0;
    ULONGLONG Sequence = 0;
    ULONGLONG RetirePriorTo = 0;
    ULONGLONG TriggerFrameType = 0;
    bool Fin = false;
    bool Bidirectional = false;
    bool ApplicationClose = false;
    QuicBufferView Data = {};
    QuicBufferView ConnectionId = {};
    QuicBufferView StatelessResetToken = {};
    QuicBufferView ReasonPhrase = {};
    QuicBufferView AckRangeData = {};
};

NTSTATUS QuicParseFrame(_In_reads_bytes_(dataLength) const UCHAR *data, SIZE_T dataLength, _Out_ QuicFrame *frame,
                        _Out_opt_ SIZE_T *bytesConsumed) noexcept;

NTSTATUS QuicDecodeAckRanges(_In_ const QuicFrame &frame, _Out_writes_(rangeCapacity) QuicAckRange *ranges,
                             SIZE_T rangeCapacity, _Out_ SIZE_T *rangeCount) noexcept;

NTSTATUS QuicEncodeFrame(_In_ const QuicFrame &frame, _In_reads_opt_(ackRangeCount) const QuicAckRange *ackRanges,
                         SIZE_T ackRangeCount, _Out_writes_bytes_(capacity) UCHAR *output, SIZE_T capacity,
                         _Out_ SIZE_T *bytesWritten) noexcept;
} // namespace wknet::quic
