#pragma once
#include "quic/QuicClock.h"
#include "quic/QuicCongestion.h"
#include "quic/QuicTypes.h"
#include <wknet/WknetLimits.h>
namespace wknet::quic
{
enum class QuicPacketNumberSpace : UCHAR
{
    Initial,
    Handshake,
    Application
};
struct QuicSentPacket final
{
    QuicPacketNumberSpace Space = QuicPacketNumberSpace::Initial;
    ULONGLONG PacketNumber = 0;
    ULONGLONG SentTime100ns = 0;
    ULONGLONG Bytes = 0;
    bool AckEliciting = false;
    bool InFlight = false;
    bool Terminal = false;
};
class QuicRecovery final
{
  public:
    NTSTATUS Initialize(SIZE_T capacity = WKNET_HARD_MAX_QUIC_SENT_PACKETS) noexcept;
    NTSTATUS OnPacketSent(QuicPacketNumberSpace space, ULONGLONG packetNumber, ULONGLONG bytes,
                          bool ackEliciting) noexcept;
    NTSTATUS OnAckReceived(QuicPacketNumberSpace space, ULONGLONG largestAcknowledged,
                           ULONGLONG ackDelay100ns) noexcept;
    NTSTATUS OnAckRangesReceived(QuicPacketNumberSpace space, const QuicAckRange *ranges, SIZE_T rangeCount,
                                 ULONGLONG ackDelay100ns) noexcept;
    ULONGLONG LossDeadline100ns(QuicPacketNumberSpace space) const noexcept;
    ULONGLONG PtoDeadline100ns(QuicPacketNumberSpace space, ULONGLONG maxAckDelayMilliseconds) const noexcept;
    ULONGLONG PtoPeriod100ns(QuicPacketNumberSpace space, ULONGLONG maxAckDelayMilliseconds) const noexcept;
    NTSTATUS OnLossTimerExpired(QuicPacketNumberSpace space) noexcept;
    void OnPtoFired() noexcept;
    QuicCongestion &Congestion() noexcept
    {
        return congestion_;
    }
    const QuicCongestion &Congestion() const noexcept
    {
        return congestion_;
    }
    ULONGLONG SmoothedRtt100ns() const noexcept
    {
        return smoothedRtt100ns_;
    }
    ULONGLONG LostPacketCount() const noexcept
    {
        return lostPacketCount_;
    }
    SIZE_T OutstandingPacketCount() const noexcept
    {
        return count_;
    }

  private:
    static SIZE_T SpaceIndex(QuicPacketNumberSpace space) noexcept;
    ULONGLONG BasePto100ns(QuicPacketNumberSpace space, ULONGLONG maxAckDelayMilliseconds) const noexcept;
    ULONGLONG LossDelay100ns() const noexcept;
    void CompactTerminalPackets() noexcept;

    HeapArray<QuicSentPacket> packets_;
    SIZE_T count_ = 0;
    ULONGLONG latestRtt100ns_ = 0;
    ULONGLONG smoothedRtt100ns_ = 0;
    ULONGLONG rttVariance100ns_ = 0;
    ULONGLONG minimumRtt100ns_ = 0;
    ULONG ptoCount_ = 0;
    ULONGLONG lostPacketCount_ = 0;
    static constexpr SIZE_T PacketNumberSpaceCount = 3;
    ULONGLONG largestSent_[PacketNumberSpaceCount] = {};
    ULONGLONG largestAcknowledged_[PacketNumberSpaceCount] = {};
    bool hasSent_[PacketNumberSpaceCount] = {};
    bool hasAcknowledged_[PacketNumberSpaceCount] = {};
    QuicCongestion congestion_;
};
} // namespace wknet::quic
