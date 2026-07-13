#include "quic/QuicCongestion.h"
namespace wknet::quic
{
void QuicCongestion::Reset() noexcept
{
    congestionWindow_ = 10 * MaximumDatagramSize;
    slowStartThreshold_ = ~0ULL;
    bytesInFlight_ = 0;
    recoveryStartTime100ns_ = 0;
    pacingDeadline100ns_ = 0;
}
void QuicCongestion::OnPacketSent(ULONGLONG bytes, bool inFlight, ULONGLONG now100ns,
                                  ULONGLONG smoothedRtt100ns) noexcept
{
    if (inFlight)
    {
        bytesInFlight_ += bytes;
    }

    const ULONGLONG pacingRtt100ns = smoothedRtt100ns == 0 ? 3330000ULL : smoothedRtt100ns;
    ULONGLONG interval100ns = congestionWindow_ == 0 ? pacingRtt100ns : (bytes * pacingRtt100ns) / congestionWindow_;
    if (interval100ns < 1000)
    {
        interval100ns = 1000;
    }

    const ULONGLONG pacingBase100ns = pacingDeadline100ns_ > now100ns ? pacingDeadline100ns_ : now100ns;
    pacingDeadline100ns_ = pacingBase100ns > ~0ULL - interval100ns ? ~0ULL : pacingBase100ns + interval100ns;
}
void QuicCongestion::OnPacketAcked(ULONGLONG bytes, ULONGLONG sentTime) noexcept
{
    bytesInFlight_ = bytes > bytesInFlight_ ? 0 : bytesInFlight_ - bytes;
    if (sentTime <= recoveryStartTime100ns_)
    {
        return;
    }

    if (congestionWindow_ < slowStartThreshold_)
    {
        congestionWindow_ += bytes;
    }
    else
    {
        ULONGLONG increment = (MaximumDatagramSize * bytes) / congestionWindow_;
        if (increment == 0)
        {
            increment = 1;
        }
        congestionWindow_ += increment;
    }
}
void QuicCongestion::OnPacketsLost(ULONGLONG bytes, ULONGLONG now100ns) noexcept
{
    bytesInFlight_ = bytes > bytesInFlight_ ? 0 : bytesInFlight_ - bytes;
    if (now100ns <= recoveryStartTime100ns_)
    {
        return;
    }

    recoveryStartTime100ns_ = now100ns;
    congestionWindow_ /= 2;
    const ULONGLONG minimum = 2 * MaximumDatagramSize;
    if (congestionWindow_ < minimum)
    {
        congestionWindow_ = minimum;
    }
    slowStartThreshold_ = congestionWindow_;

    WKNET_TRACE(ComponentQuic, TraceLevel::Info,
                "quic.congestion.state cwnd=%I64u ssthresh=%I64u bytes_in_flight=%I64u", congestionWindow_,
                slowStartThreshold_, bytesInFlight_);
}

void QuicCongestion::OnPersistentCongestion() noexcept
{
    congestionWindow_ = 2 * MaximumDatagramSize;
    slowStartThreshold_ = congestionWindow_;
    WKNET_TRACE(ComponentQuic, TraceLevel::Warning,
                "quic.congestion.state persistent=1 cwnd=%I64u bytes_in_flight=%I64u", congestionWindow_,
                bytesInFlight_);
}

bool QuicCongestion::CanSend(ULONGLONG bytes, ULONGLONG now100ns) const noexcept
{
    if (bytes == 0 || bytes > MaximumDatagramSize)
    {
        return false;
    }

    if (bytesInFlight_ > congestionWindow_ || bytes > congestionWindow_ - bytesInFlight_)
    {
        return false;
    }

    return now100ns >= pacingDeadline100ns_;
}
} // namespace wknet::quic
