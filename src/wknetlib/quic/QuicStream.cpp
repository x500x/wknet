#include "quic/QuicStream.h"
namespace wknet::quic
{
bool QuicStreamIsClientInitiated(ULONGLONG id) noexcept
{
    return (id & 1ULL) == 0;
}
bool QuicStreamIsBidirectional(ULONGLONG id) noexcept
{
    return (id & 2ULL) == 0;
}
QuicStream::~QuicStream() noexcept
{
    Clear();
}
void QuicStream::Clear() noexcept
{
    if (chunks_.IsValid())
    {
        for (SIZE_T i = 0; i < chunkCount_; ++i)
        {
            if (chunks_[i].Data != nullptr)
            {
                RtlSecureZeroMemory(chunks_[i].Data, chunks_[i].Capacity);
                FreeNonPagedArray(chunks_[i].Data);
            }
        }
    }
    chunks_.Reset();
    affectedScratch_.Reset();
    chunkCount_ = 0;
    initialized_ = false;
}
NTSTATUS QuicStream::Initialize(ULONGLONG id, SIZE_T maxBytes, SIZE_T maxGaps) noexcept
{
    Clear();
    if (id > QuicVarIntMaximum || maxBytes == 0 || maxGaps == 0 || maxGaps > WKNET_HARD_MAX_QUIC_STREAM_GAPS)
        return STATUS_INVALID_PARAMETER;
    NTSTATUS s = chunks_.Allocate(maxGaps);
    if (NT_SUCCESS(s))
        s = affectedScratch_.Allocate(maxGaps);
    if (!NT_SUCCESS(s))
    {
        Clear();
        return s;
    }
    streamId_ = id;
    maxReassemblyBytes_ = maxBytes;
    maxGaps_ = maxGaps;
    consumedOffset_ = finalSize_ = receivedUniqueBytes_ = bufferedBytes_ = highestReceivedOffset_ = sendOffset_ =
        sendLimit_ = sendResetError_ = receiveResetError_ = stopError_ = 0;
    receiveLimit_ = QuicVarIntMaximum;
    finalSizeKnown_ = sendFin_ = reset_ = receiveReset_ = stopped_ = streamDataBlockedPending_ = false;
    initialized_ = true;
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::Receive(ULONGLONG offset, const UCHAR *data, SIZE_T length, bool fin) noexcept
{
    if (!initialized_ || (data == nullptr && length != 0) || offset > QuicVarIntMaximum ||
        length > QuicVarIntMaximum - offset)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!QuicStreamIsBidirectional(streamId_) && QuicStreamIsClientInitiated(streamId_))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    ULONGLONG end = offset + length;
    if (end > receiveLimit_)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (finalSizeKnown_ && end > finalSize_)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (fin)
    {
        if (finalSizeKnown_ && finalSize_ != end)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        finalSizeKnown_ = true;
        finalSize_ = end;
    }

    if (receiveReset_)
    {
        return end <= finalSize_ ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }

    if (length == 0)
    {
        if (end > highestReceivedOffset_)
        {
            highestReceivedOffset_ = end;
        }
        return STATUS_SUCCESS;
    }

    if (end <= consumedOffset_)
    {
        return STATUS_SUCCESS;
    }
    if (offset < consumedOffset_)
    {
        const SIZE_T trim = static_cast<SIZE_T>(consumedOffset_ - offset);
        data += trim;
        length -= trim;
        offset = consumedOffset_;
        end = offset + length;
    }

    ULONGLONG unionStart = offset, unionEnd = end;
    SIZE_T overlapBytes = 0;
    RtlZeroMemory(affectedScratch_.Get(), affectedScratch_.Count());
    for (SIZE_T i = 0; i < chunkCount_; ++i)
    {
        QuicStreamChunk &c = chunks_[i];
        const ULONGLONG cEnd = c.Offset + c.Length;
        if (end < c.Offset || offset > cEnd)
            continue;
        affectedScratch_[i] = 1;
        if (c.Offset < unionStart)
            unionStart = c.Offset;
        if (cEnd > unionEnd)
            unionEnd = cEnd;
        const ULONGLONG os = offset > c.Offset ? offset : c.Offset;
        const ULONGLONG oe = end < cEnd ? end : cEnd;
        if (oe > os)
        {
            for (ULONGLONG p = os; p < oe; ++p)
            {
                if (data[p - offset] != c.Data[c.DataOffset + static_cast<SIZE_T>(p - c.Offset)])
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            overlapBytes += static_cast<SIZE_T>(oe - os);
        }
    }
    const SIZE_T unique = length - overlapBytes;
    if (unique > maxReassemblyBytes_ - static_cast<SIZE_T>(bufferedBytes_))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T affectedCount = 0;
    for (SIZE_T i = 0; i < chunkCount_; ++i)
    {
        if (affectedScratch_[i] != 0)
        {
            ++affectedCount;
        }
    }
    if (affectedCount == 0 && chunkCount_ >= maxGaps_)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    const SIZE_T unionLength = static_cast<SIZE_T>(unionEnd - unionStart);
    UCHAR *merged = AllocateNonPagedArray<UCHAR>(unionLength);
    if (merged == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;
    for (SIZE_T i = 0; i < chunkCount_; ++i)
    {
        if (affectedScratch_[i] != 0)
        {
            RtlCopyMemory(merged + (chunks_[i].Offset - unionStart), chunks_[i].Data + chunks_[i].DataOffset,
                          chunks_[i].Length);
        }
    }
    RtlCopyMemory(merged + (offset - unionStart), data, length);
    SIZE_T write = 0;
    for (SIZE_T i = 0; i < chunkCount_; ++i)
    {
        if (affectedScratch_[i] != 0)
        {
            RtlSecureZeroMemory(chunks_[i].Data, chunks_[i].Capacity);
            FreeNonPagedArray(chunks_[i].Data);
        }
        else
        {
            if (write != i)
                chunks_[write] = chunks_[i];
            ++write;
        }
    }
    chunkCount_ = write;
    chunks_[chunkCount_++] = {unionStart, unionLength, unionLength, 0, merged};
    receivedUniqueBytes_ += unique;
    bufferedBytes_ += unique;
    if (end > highestReceivedOffset_)
    {
        highestReceivedOffset_ = end;
    }
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::Consume(UCHAR *output, SIZE_T capacity, SIZE_T *consumed, bool *fin) noexcept
{
    if (consumed != nullptr)
    {
        *consumed = 0;
    }
    if (fin != nullptr)
    {
        *fin = false;
    }
    if (!initialized_ || output == nullptr || consumed == nullptr || fin == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T index = chunkCount_;
    for (SIZE_T i = 0; i < chunkCount_; ++i)
    {
        if (chunks_[i].Offset == consumedOffset_)
        {
            index = i;
            break;
        }
    }
    if (index == chunkCount_)
    {
        *fin = ReceiveFinished();
        return receiveReset_ && bufferedBytes_ == 0 ? STATUS_CONNECTION_RESET : STATUS_SUCCESS;
    }
    QuicStreamChunk &c = chunks_[index];
    const SIZE_T consumeLength = capacity < c.Length ? capacity : c.Length;
    if (consumeLength == 0)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(output, c.Data + c.DataOffset, consumeLength);
    *consumed = consumeLength;
    consumedOffset_ += consumeLength;
    bufferedBytes_ -= consumeLength;
    c.Offset += consumeLength;
    c.DataOffset += consumeLength;
    c.Length -= consumeLength;
    if (c.Length == 0)
    {
        RtlSecureZeroMemory(c.Data, c.Capacity);
        FreeNonPagedArray(c.Data);
        for (SIZE_T i = index + 1; i < chunkCount_; ++i)
        {
            chunks_[i - 1] = chunks_[i];
        }
        --chunkCount_;
    }
    *fin = ReceiveFinished();
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::SetReceiveLimit(ULONGLONG maximum) noexcept
{
    if (!initialized_ || maximum > QuicVarIntMaximum || maximum < highestReceivedOffset_)
    {
        return STATUS_INVALID_PARAMETER;
    }
    receiveLimit_ = maximum;
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::SetSendLimit(ULONGLONG maximum) noexcept
{
    if (!initialized_ || maximum > QuicVarIntMaximum || maximum < sendOffset_)
    {
        return STATUS_INVALID_PARAMETER;
    }
    sendLimit_ = maximum;
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::OnMaxStreamData(ULONGLONG maximum) noexcept
{
    if (!initialized_ || maximum > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (maximum > sendLimit_)
    {
        sendLimit_ = maximum;
        streamDataBlockedPending_ = false;
    }
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::CanWrite(SIZE_T length, bool fin) const noexcept
{
    UNREFERENCED_PARAMETER(fin);
    if (!initialized_)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!QuicStreamIsBidirectional(streamId_) && !QuicStreamIsClientInitiated(streamId_))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (sendFin_ || reset_)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (length > QuicVarIntMaximum - sendOffset_ || sendOffset_ > sendLimit_ || length > sendLimit_ - sendOffset_)
    {
        return STATUS_DEVICE_BUSY;
    }
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::Write(const UCHAR *data, SIZE_T length, bool fin, SIZE_T *accepted) noexcept
{
    if (accepted != nullptr)
    {
        *accepted = 0;
    }
    if (!initialized_ || accepted == nullptr || (data == nullptr && length != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    const NTSTATUS validationStatus = CanWrite(length, fin);
    if (!NT_SUCCESS(validationStatus))
    {
        if (validationStatus == STATUS_DEVICE_BUSY)
        {
            streamDataBlockedPending_ = true;
        }
        return validationStatus;
    }
    sendOffset_ += length;
    sendFin_ = fin;
    *accepted = length;
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::Reset(ULONGLONG error, ULONGLONG finalSize) noexcept
{
    if (!initialized_ || error > QuicVarIntMaximum || finalSize > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!QuicStreamIsBidirectional(streamId_) && !QuicStreamIsClientInitiated(streamId_))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (reset_)
    {
        return sendResetError_ == error && finalSize == sendOffset_ ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
    }
    if (finalSize != sendOffset_)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    reset_ = true;
    sendResetError_ = error;
    sendFin_ = true;
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::OnResetReceived(ULONGLONG error, ULONGLONG finalSize) noexcept
{
    if (!initialized_ || error > QuicVarIntMaximum || finalSize > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!QuicStreamIsBidirectional(streamId_) && QuicStreamIsClientInitiated(streamId_))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if ((finalSizeKnown_ && finalSize_ != finalSize) || finalSize < highestReceivedOffset_ ||
        finalSize < consumedOffset_ || finalSize > receiveLimit_)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (receiveReset_)
    {
        return receiveResetError_ == error ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }
    finalSizeKnown_ = true;
    finalSize_ = finalSize;
    receiveReset_ = true;
    receiveResetError_ = error;
    highestReceivedOffset_ = finalSize;
    return STATUS_SUCCESS;
}
NTSTATUS QuicStream::StopSending(ULONGLONG error) noexcept
{
    if (!initialized_ || error > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!QuicStreamIsBidirectional(streamId_) && !QuicStreamIsClientInitiated(streamId_))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (stopped_)
    {
        return stopError_ == error ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
    }
    stopped_ = true;
    stopError_ = error;
    return STATUS_SUCCESS;
}

bool QuicStream::TakeStreamDataBlocked(ULONGLONG *limit) noexcept
{
    if (limit != nullptr)
    {
        *limit = 0;
    }
    if (!initialized_ || limit == nullptr || !streamDataBlockedPending_)
    {
        return false;
    }
    *limit = sendLimit_;
    streamDataBlockedPending_ = false;
    return true;
}
} // namespace wknet::quic
