#include "quic/QuicAckTracker.h"

namespace wknet::quic
{
NTSTATUS QuicAckTracker::Initialize(SIZE_T capacity) noexcept
{
    if (capacity == 0 || capacity > WKNET_HARD_MAX_QUIC_ACK_RANGES)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ranges_.Reset();
    NTSTATUS status = ranges_.Allocate(capacity);
    if (NT_SUCCESS(status))
    {
        rangeCount_ = 0;
        firstAckElicitingTime100ns_ = 0;
        ackElicitingSinceLastAck_ = 0;
        ackPending_ = false;
        immediateAck_ = false;
    }
    return status;
}

NTSTATUS QuicAckTracker::OnPacketReceived(ULONGLONG packetNumber, bool ackEliciting, bool immediateAck,
                                          ULONGLONG now100ns, bool *duplicate) noexcept
{
    if (duplicate != nullptr)
    {
        *duplicate = false;
    }
    if (!ranges_.IsValid() || duplicate == nullptr || packetNumber > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T insertIndex = rangeCount_;
    for (SIZE_T index = 0; index < rangeCount_; ++index)
    {
        QuicAckRange &range = ranges_[index];
        if (packetNumber >= range.Smallest && packetNumber <= range.Largest)
        {
            *duplicate = true;
            return STATUS_SUCCESS;
        }
        if (packetNumber > range.Largest)
        {
            insertIndex = index;
            break;
        }
    }

    if (rangeCount_ >= ranges_.Count())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (SIZE_T index = rangeCount_; index > insertIndex; --index)
    {
        ranges_[index] = ranges_[index - 1];
    }
    ranges_[insertIndex] = {packetNumber, packetNumber};
    ++rangeCount_;

    if (insertIndex != 0 && ranges_[insertIndex - 1].Smallest != 0 &&
        ranges_[insertIndex - 1].Smallest - 1 <= ranges_[insertIndex].Largest)
    {
        ranges_[insertIndex - 1].Smallest = ranges_[insertIndex].Smallest;
        for (SIZE_T index = insertIndex + 1; index < rangeCount_; ++index)
        {
            ranges_[index - 1] = ranges_[index];
        }
        --rangeCount_;
        --insertIndex;
    }
    if (insertIndex + 1 < rangeCount_ && ranges_[insertIndex].Smallest != 0 &&
        ranges_[insertIndex].Smallest - 1 <= ranges_[insertIndex + 1].Largest)
    {
        ranges_[insertIndex].Smallest = ranges_[insertIndex + 1].Smallest;
        for (SIZE_T index = insertIndex + 2; index < rangeCount_; ++index)
        {
            ranges_[index - 1] = ranges_[index];
        }
        --rangeCount_;
    }

    if (ackEliciting)
    {
        if (ackElicitingSinceLastAck_ == 0)
        {
            firstAckElicitingTime100ns_ = now100ns;
        }
        if (ackElicitingSinceLastAck_ != 0xffffffffUL)
        {
            ++ackElicitingSinceLastAck_;
        }
        ackPending_ = true;
        immediateAck_ = immediateAck_ || immediateAck || ackElicitingSinceLastAck_ >= 2;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicAckTracker::CopyRanges(QuicAckRange *ranges, SIZE_T capacity, SIZE_T *rangeCount) const noexcept
{
    if (rangeCount != nullptr)
    {
        *rangeCount = 0;
    }
    if (!ranges_.IsValid() || ranges == nullptr || rangeCount == nullptr || capacity < rangeCount_)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (rangeCount_ != 0)
    {
        RtlCopyMemory(ranges, ranges_.Get(), rangeCount_ * sizeof(QuicAckRange));
    }
    *rangeCount = rangeCount_;
    return STATUS_SUCCESS;
}

ULONGLONG QuicAckTracker::AckDeadline100ns(ULONGLONG maxAckDelayMilliseconds) const noexcept
{
    if (!ackPending_)
    {
        return 0;
    }
    if (immediateAck_)
    {
        return firstAckElicitingTime100ns_;
    }
    const ULONGLONG delay100ns =
        maxAckDelayMilliseconds > (~0ULL / 10000ULL) ? ~0ULL : maxAckDelayMilliseconds * 10000ULL;
    return firstAckElicitingTime100ns_ > ~0ULL - delay100ns ? ~0ULL : firstAckElicitingTime100ns_ + delay100ns;
}

void QuicAckTracker::OnAckSent() noexcept
{
    firstAckElicitingTime100ns_ = 0;
    ackElicitingSinceLastAck_ = 0;
    ackPending_ = false;
    immediateAck_ = false;
}
} // namespace wknet::quic
