#pragma once

#include "quic/QuicTypes.h"
#include "rtl/ProtocolAllocator.h"
#include <wknet/WknetLimits.h>

namespace wknet::quic
{
class QuicAckTracker final
{
  public:
    NTSTATUS Initialize(SIZE_T capacity = WKNET_HARD_MAX_QUIC_ACK_RANGES) noexcept;
    NTSTATUS OnPacketReceived(ULONGLONG packetNumber, bool ackEliciting, bool immediateAck, ULONGLONG now100ns,
                              bool *duplicate) noexcept;
    NTSTATUS CopyRanges(QuicAckRange *ranges, SIZE_T capacity, SIZE_T *rangeCount) const noexcept;
    void OnAckSent() noexcept;

    ULONGLONG AckDeadline100ns(ULONGLONG maxAckDelayMilliseconds) const noexcept;

    bool AckPending() const noexcept
    {
        return ackPending_;
    }

  private:
    ProtocolHeapArray<QuicAckRange, rtl::ProtocolAllocationSite::QuicAckRanges> ranges_;
    SIZE_T rangeCount_ = 0;
    ULONGLONG firstAckElicitingTime100ns_ = 0;
    ULONG ackElicitingSinceLastAck_ = 0;
    bool ackPending_ = false;
    bool immediateAck_ = false;
};
} // namespace wknet::quic
