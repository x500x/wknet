#include "quic/QuicRecovery.h"
namespace wknet::quic
{
SIZE_T QuicRecovery::SpaceIndex(QuicPacketNumberSpace space) noexcept
{
    return static_cast<SIZE_T>(space);
}

NTSTATUS QuicRecovery::Initialize(SIZE_T capacity) noexcept
{
    if (capacity == 0 || capacity > WKNET_HARD_MAX_QUIC_SENT_PACKETS)
    {
        return STATUS_INVALID_PARAMETER;
    }

    packets_.Reset();
    NTSTATUS s = packets_.Allocate(capacity);
    if (!NT_SUCCESS(s))
    {
        return s;
    }

    count_ = 0;
    latestRtt100ns_ = smoothedRtt100ns_ = rttVariance100ns_ = minimumRtt100ns_ = 0;
    ptoCount_ = 0;
    lostPacketCount_ = 0;
    RtlZeroMemory(largestSent_, sizeof(largestSent_));
    RtlZeroMemory(largestAcknowledged_, sizeof(largestAcknowledged_));
    RtlZeroMemory(hasSent_, sizeof(hasSent_));
    RtlZeroMemory(hasAcknowledged_, sizeof(hasAcknowledged_));
    congestion_.Reset();
    return STATUS_SUCCESS;
}
NTSTATUS QuicRecovery::OnPacketSent(QuicPacketNumberSpace space, ULONGLONG pn, ULONGLONG bytes, bool ack) noexcept
{
    if (!packets_.IsValid() || pn > QuicVarIntMaximum || bytes == 0 || bytes > QuicCongestion::MaximumDatagramSize)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const SIZE_T spaceIndex = SpaceIndex(space);
    if (spaceIndex >= PacketNumberSpaceCount)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (hasSent_[spaceIndex] && pn <= largestSent_[spaceIndex])
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (count_ >= packets_.Count())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const ULONGLONG now100ns = QuicClockNow100ns();
    QuicSentPacket &p = packets_[count_++];
    p = {space, pn, now100ns, bytes, ack, ack, false};
    largestSent_[spaceIndex] = pn;
    hasSent_[spaceIndex] = true;
    congestion_.OnPacketSent(bytes, ack, now100ns, smoothedRtt100ns_);
    return STATUS_SUCCESS;
}
NTSTATUS QuicRecovery::OnAckReceived(QuicPacketNumberSpace space, ULONGLONG largest, ULONGLONG ackDelay) noexcept
{
    const QuicAckRange range = {largest, largest};
    return OnAckRangesReceived(space, &range, 1, ackDelay);
}

NTSTATUS QuicRecovery::OnAckRangesReceived(QuicPacketNumberSpace space, const QuicAckRange *ranges, SIZE_T rangeCount,
                                           ULONGLONG ackDelay) noexcept
{
    if (!packets_.IsValid())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (ranges == nullptr || rangeCount == 0 || rangeCount > WKNET_HARD_MAX_QUIC_ACK_RANGES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const SIZE_T spaceIndex = SpaceIndex(space);
    if (spaceIndex >= PacketNumberSpaceCount)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (SIZE_T rangeIndex = 0; rangeIndex < rangeCount; ++rangeIndex)
    {
        const QuicAckRange &range = ranges[rangeIndex];
        if (range.Smallest > range.Largest || range.Largest > QuicVarIntMaximum)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (rangeIndex != 0 && range.Largest >= ranges[rangeIndex - 1].Smallest)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
    }

    const ULONGLONG largest = ranges[0].Largest;
    if (!hasSent_[spaceIndex] || largest > largestSent_[spaceIndex])
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    const ULONGLONG now = QuicClockNow100ns();
    QuicSentPacket *largestPacket = nullptr;
    ULONGLONG lostBytes = 0;
    ULONGLONG earliestLostAckElicitingTime = 0;
    ULONGLONG latestLostAckElicitingTime = 0;
    ULONGLONG newlyLostPackets = 0;
    bool newlyAckedAckEliciting = false;

    for (SIZE_T i = 0; i < count_; ++i)
    {
        QuicSentPacket &p = packets_[i];
        if (p.Space != space || p.Terminal)
        {
            continue;
        }

        bool acknowledged = false;
        for (SIZE_T rangeIndex = 0; rangeIndex < rangeCount; ++rangeIndex)
        {
            if (p.PacketNumber >= ranges[rangeIndex].Smallest && p.PacketNumber <= ranges[rangeIndex].Largest)
            {
                acknowledged = true;
                break;
            }
        }

        if (acknowledged)
        {
            p.Terminal = true;
            if (p.PacketNumber == largest)
            {
                largestPacket = &p;
            }
            if (p.InFlight)
            {
                congestion_.OnPacketAcked(p.Bytes, p.SentTime100ns);
                newlyAckedAckEliciting = newlyAckedAckEliciting || p.AckEliciting;
            }
        }
    }

    if (!hasAcknowledged_[spaceIndex] || largest > largestAcknowledged_[spaceIndex])
    {
        largestAcknowledged_[spaceIndex] = largest;
        hasAcknowledged_[spaceIndex] = true;
    }

    const ULONGLONG lossDelay100ns = LossDelay100ns();
    const ULONGLONG lossTimeThreshold100ns = now > lossDelay100ns ? now - lossDelay100ns : 0;
    for (SIZE_T i = 0; i < count_; ++i)
    {
        QuicSentPacket &p = packets_[i];
        if (p.Space != space || p.Terminal || p.PacketNumber >= largest)
        {
            continue;
        }

        const bool packetThresholdLost = largest - p.PacketNumber >= 3;
        const bool timeThresholdLost = p.SentTime100ns <= lossTimeThreshold100ns;
        if (!packetThresholdLost && !timeThresholdLost)
        {
            continue;
        }

        p.Terminal = true;
        ++newlyLostPackets;
        ++lostPacketCount_;
        if (p.InFlight)
        {
            lostBytes += p.Bytes;
        }
        if (p.AckEliciting)
        {
            if (earliestLostAckElicitingTime == 0 || p.SentTime100ns < earliestLostAckElicitingTime)
            {
                earliestLostAckElicitingTime = p.SentTime100ns;
            }
            if (p.SentTime100ns > latestLostAckElicitingTime)
            {
                latestLostAckElicitingTime = p.SentTime100ns;
            }
        }
    }

    if (lostBytes != 0)
    {
        congestion_.OnPacketsLost(lostBytes, now);
    }
    if (newlyLostPackets != 0)
    {
        WKNET_TRACE(ComponentQuic, TraceLevel::Warning, "quic.loss.detected packets=%I64u bytes=%I64u",
                    newlyLostPackets, lostBytes);

        const ULONGLONG persistentCongestionThreshold100ns = BasePto100ns(space, 0) * 3;
        if (earliestLostAckElicitingTime != 0 &&
            latestLostAckElicitingTime - earliestLostAckElicitingTime >= persistentCongestionThreshold100ns)
        {
            congestion_.OnPersistentCongestion();
        }
    }

    if (largestPacket != nullptr)
    {
        latestRtt100ns_ = now - largestPacket->SentTime100ns;
        if (minimumRtt100ns_ == 0 || latestRtt100ns_ < minimumRtt100ns_)
        {
            minimumRtt100ns_ = latestRtt100ns_;
        }

        ULONGLONG adjusted = latestRtt100ns_;
        if (space == QuicPacketNumberSpace::Application && adjusted > minimumRtt100ns_ + ackDelay)
        {
            adjusted -= ackDelay;
        }

        if (smoothedRtt100ns_ == 0)
        {
            smoothedRtt100ns_ = adjusted;
            rttVariance100ns_ = adjusted / 2;
        }
        else
        {
            const ULONGLONG diff =
                smoothedRtt100ns_ > adjusted ? smoothedRtt100ns_ - adjusted : adjusted - smoothedRtt100ns_;
            rttVariance100ns_ = (3 * rttVariance100ns_ + diff) / 4;
            smoothedRtt100ns_ = (7 * smoothedRtt100ns_ + adjusted) / 8;
        }
    }

    if (newlyAckedAckEliciting)
    {
        ptoCount_ = 0;
    }

    CompactTerminalPackets();
    return STATUS_SUCCESS;
}

ULONGLONG QuicRecovery::LossDelay100ns() const noexcept
{
    ULONGLONG lossDelay100ns = latestRtt100ns_ > smoothedRtt100ns_ ? latestRtt100ns_ : smoothedRtt100ns_;
    if (lossDelay100ns == 0)
    {
        lossDelay100ns = 3330000ULL;
    }
    lossDelay100ns = (lossDelay100ns * 9) / 8;
    return lossDelay100ns < 10000ULL ? 10000ULL : lossDelay100ns;
}

ULONGLONG QuicRecovery::LossDeadline100ns(QuicPacketNumberSpace space) const noexcept
{
    const SIZE_T spaceIndex = SpaceIndex(space);
    if (spaceIndex >= PacketNumberSpaceCount || !hasAcknowledged_[spaceIndex])
    {
        return 0;
    }

    const ULONGLONG lossDelay100ns = LossDelay100ns();
    ULONGLONG deadline100ns = 0;
    for (SIZE_T i = 0; i < count_; ++i)
    {
        const QuicSentPacket &p = packets_[i];
        if (p.Space != space || p.Terminal || p.PacketNumber >= largestAcknowledged_[spaceIndex])
        {
            continue;
        }

        const ULONGLONG candidate100ns =
            p.SentTime100ns > ~0ULL - lossDelay100ns ? ~0ULL : p.SentTime100ns + lossDelay100ns;
        if (deadline100ns == 0 || candidate100ns < deadline100ns)
        {
            deadline100ns = candidate100ns;
        }
    }
    return deadline100ns;
}

ULONGLONG QuicRecovery::BasePto100ns(QuicPacketNumberSpace space, ULONGLONG maxAckDelayMs) const noexcept
{
    ULONGLONG base100ns = smoothedRtt100ns_ == 0 ? 3330000ULL : smoothedRtt100ns_;
    ULONGLONG variance100ns = 4 * rttVariance100ns_;
    if (variance100ns < 10000ULL)
    {
        variance100ns = 10000ULL;
    }
    base100ns += variance100ns;
    if (space == QuicPacketNumberSpace::Application)
    {
        const ULONGLONG ackDelay100ns = maxAckDelayMs > (~0ULL / 10000ULL) ? ~0ULL : maxAckDelayMs * 10000ULL;
        base100ns = ackDelay100ns > ~0ULL - base100ns ? ~0ULL : base100ns + ackDelay100ns;
    }
    return base100ns;
}

ULONGLONG QuicRecovery::PtoDeadline100ns(QuicPacketNumberSpace space, ULONGLONG maxAckDelayMs) const noexcept
{
    ULONGLONG last = 0;
    for (SIZE_T i = 0; i < count_; ++i)
    {
        const QuicSentPacket &p = packets_[i];
        if (p.Space == space && !p.Terminal && p.AckEliciting && p.SentTime100ns > last)
        {
            last = p.SentTime100ns;
        }
    }

    if (last == 0)
    {
        return 0;
    }

    ULONGLONG duration100ns = BasePto100ns(space, maxAckDelayMs);
    if (ptoCount_ >= 31 || duration100ns > (~0ULL >> ptoCount_))
    {
        duration100ns = ~0ULL;
    }
    else
    {
        duration100ns <<= ptoCount_;
    }
    return duration100ns > ~0ULL - last ? ~0ULL : last + duration100ns;
}

ULONGLONG QuicRecovery::PtoPeriod100ns(QuicPacketNumberSpace space, ULONGLONG maxAckDelayMs) const noexcept
{
    ULONGLONG duration100ns = BasePto100ns(space, maxAckDelayMs);
    if (ptoCount_ >= 31 || duration100ns > (~0ULL >> ptoCount_))
    {
        return ~0ULL;
    }
    return duration100ns << ptoCount_;
}

NTSTATUS QuicRecovery::OnLossTimerExpired(QuicPacketNumberSpace space) noexcept
{
    const ULONGLONG deadline = LossDeadline100ns(space);
    const ULONGLONG now = QuicClockNow100ns();
    if (deadline == 0 || deadline > now)
    {
        return STATUS_NOT_FOUND;
    }

    const ULONGLONG lossDelay = LossDelay100ns();
    ULONGLONG lostBytes = 0;
    ULONGLONG newlyLost = 0;
    for (SIZE_T index = 0; index < count_; ++index)
    {
        QuicSentPacket &packet = packets_[index];
        if (packet.Terminal || packet.Space != space || packet.SentTime100ns > now ||
            now - packet.SentTime100ns < lossDelay)
        {
            continue;
        }
        packet.Terminal = true;
        ++newlyLost;
        if (packet.InFlight)
        {
            lostBytes += packet.Bytes;
        }
    }
    if (newlyLost == 0)
    {
        return STATUS_NOT_FOUND;
    }
    lostPacketCount_ += newlyLost;
    if (lostBytes != 0)
    {
        congestion_.OnPacketsLost(lostBytes, now);
    }
    CompactTerminalPackets();
    return STATUS_SUCCESS;
}

void QuicRecovery::OnPtoFired() noexcept
{
    if (ptoCount_ < 31)
    {
        ++ptoCount_;
    }
    WKNET_TRACE(ComponentQuic, TraceLevel::Warning, "quic.pto.fired count=%lu", ptoCount_);
}

void QuicRecovery::CompactTerminalPackets() noexcept
{
    SIZE_T writeIndex = 0;
    for (SIZE_T readIndex = 0; readIndex < count_; ++readIndex)
    {
        if (packets_[readIndex].Terminal)
        {
            continue;
        }
        if (writeIndex != readIndex)
        {
            packets_[writeIndex] = packets_[readIndex];
        }
        ++writeIndex;
    }
    count_ = writeIndex;
}
} // namespace wknet::quic
