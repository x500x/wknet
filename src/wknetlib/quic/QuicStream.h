#pragma once
#include "quic/QuicTypes.h"
#include <wknet/WknetLimits.h>
namespace wknet::quic
{
bool QuicStreamIsClientInitiated(ULONGLONG streamId) noexcept;
bool QuicStreamIsBidirectional(ULONGLONG streamId) noexcept;

class QuicStream;

using QuicStreamApplicationEvent = void (*)(void *context, QuicStream *stream) noexcept;
using QuicStreamApplicationResetEvent = void (*)(void *context, QuicStream *stream, ULONGLONG errorCode,
                                                 bool peerInitiated) noexcept;

struct QuicStreamApplicationEventSink final
{
    void *Context = nullptr;
    QuicStreamApplicationEvent Opened = nullptr;
    QuicStreamApplicationEvent Readable = nullptr;
    QuicStreamApplicationEvent Writable = nullptr;
    QuicStreamApplicationResetEvent Reset = nullptr;
    QuicStreamApplicationEvent Closed = nullptr;
};

struct QuicStreamChunk final
{
    ULONGLONG Offset = 0;
    SIZE_T Length = 0;
    SIZE_T Capacity = 0;
    SIZE_T DataOffset = 0;
    UCHAR *Data = nullptr;
};
class QuicStream final
{
  public:
    QuicStream() noexcept = default;
    QuicStream(const QuicStream &) = delete;
    QuicStream &operator=(const QuicStream &) = delete;
    ~QuicStream() noexcept;
    NTSTATUS Initialize(ULONGLONG streamId, SIZE_T maxReassemblyBytes = WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES,
                        SIZE_T maxGaps = WKNET_HARD_MAX_QUIC_STREAM_GAPS) noexcept;
    NTSTATUS Receive(ULONGLONG offset, const UCHAR *data, SIZE_T length, bool fin,
                     bool notifyApplication = true) noexcept;
    NTSTATUS Consume(UCHAR *output, SIZE_T capacity, SIZE_T *bytesConsumed, bool *fin) noexcept;
    NTSTATUS SetReceiveLimit(ULONGLONG maximum) noexcept;
    NTSTATUS SetSendLimit(ULONGLONG maximum) noexcept;
    NTSTATUS OnMaxStreamData(ULONGLONG maximum) noexcept;
    NTSTATUS CanWrite(SIZE_T length, bool fin) const noexcept;
    NTSTATUS Write(const UCHAR *data, SIZE_T length, bool fin, SIZE_T *bytesAccepted) noexcept;
    NTSTATUS Reset(ULONGLONG errorCode, ULONGLONG finalSize) noexcept;
    NTSTATUS OnResetReceived(ULONGLONG errorCode, ULONGLONG finalSize) noexcept;
    NTSTATUS StopSending(ULONGLONG errorCode) noexcept;
    bool TakeStreamDataBlocked(ULONGLONG *limit) noexcept;
    ULONGLONG Id() const noexcept
    {
        return streamId_;
    }
    ULONGLONG ReceivedUniqueBytes() const noexcept
    {
        return receivedUniqueBytes_;
    }
    ULONGLONG BufferedBytes() const noexcept
    {
        return bufferedBytes_;
    }
    ULONGLONG ReceiveFlowControlBytes() const noexcept
    {
        return highestReceivedOffset_;
    }
    ULONGLONG SendOffset() const noexcept
    {
        return sendOffset_;
    }
    bool ReceiveFinished() const noexcept
    {
        return finalSizeKnown_ && consumedOffset_ == finalSize_;
    }
    bool ReceiveReset() const noexcept
    {
        return receiveReset_;
    }
    bool SendReset() const noexcept
    {
        return reset_;
    }
    void NotifyApplicationReadable() noexcept;
    void SetApplicationEventSink(const QuicStreamApplicationEventSink *sink) noexcept;
    void Clear() noexcept;

  private:
    bool HasReadableState() const noexcept;
    bool IsClosedState() const noexcept;
    void NotifyOpened() noexcept;
    void RefreshReadableNotification() noexcept;
    void NotifyWritable() noexcept;
    void NotifyReset(ULONGLONG errorCode, bool peerInitiated) noexcept;
    void NotifyClosed() noexcept;
    void NotifyClosedIfNeeded() noexcept;

    ULONGLONG streamId_ = 0;
    ULONGLONG consumedOffset_ = 0;
    ULONGLONG finalSize_ = 0;
    ULONGLONG receivedUniqueBytes_ = 0;
    ULONGLONG bufferedBytes_ = 0;
    ULONGLONG highestReceivedOffset_ = 0;
    ULONGLONG receiveLimit_ = QuicVarIntMaximum;
    ULONGLONG sendOffset_ = 0;
    ULONGLONG sendLimit_ = 0;
    ULONGLONG sendResetError_ = 0;
    ULONGLONG receiveResetError_ = 0;
    ULONGLONG stopError_ = 0;
    SIZE_T maxReassemblyBytes_ = 0;
    SIZE_T maxGaps_ = 0;
    HeapArray<QuicStreamChunk> chunks_;
    HeapArray<UCHAR> affectedScratch_;
    QuicStreamApplicationEventSink applicationSink_ = {};
    SIZE_T chunkCount_ = 0;
    bool initialized_ = false;
    bool finalSizeKnown_ = false;
    bool sendFin_ = false;
    bool reset_ = false;
    bool receiveReset_ = false;
    bool stopped_ = false;
    bool streamDataBlockedPending_ = false;
    bool applicationWriteBlocked_ = false;
    bool openedNotified_ = false;
    bool readableNotified_ = false;
    bool closedNotified_ = false;
};
} // namespace wknet::quic
