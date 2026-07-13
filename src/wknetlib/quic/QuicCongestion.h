#pragma once
#include <wknet/WknetConfig.h>
namespace wknet::quic
{
class QuicCongestion final
{
  public:
    static constexpr ULONGLONG MaximumDatagramSize = 1200;
    void Reset() noexcept;
    void OnPacketSent(ULONGLONG bytes, bool inFlight, ULONGLONG now100ns, ULONGLONG smoothedRtt100ns) noexcept;
    void OnPacketAcked(ULONGLONG bytes, ULONGLONG sentTime100ns) noexcept;
    void OnPacketsLost(ULONGLONG bytes, ULONGLONG now100ns) noexcept;
    void OnPersistentCongestion() noexcept;
    bool CanSend(ULONGLONG bytes, ULONGLONG now100ns) const noexcept;
    ULONGLONG CongestionWindow() const noexcept
    {
        return congestionWindow_;
    }
    ULONGLONG SlowStartThreshold() const noexcept
    {
        return slowStartThreshold_;
    }
    ULONGLONG BytesInFlight() const noexcept
    {
        return bytesInFlight_;
    }
    ULONGLONG PacingDeadline100ns() const noexcept
    {
        return pacingDeadline100ns_;
    }

  private:
    ULONGLONG congestionWindow_ = 10 * MaximumDatagramSize;
    ULONGLONG slowStartThreshold_ = ~0ULL;
    ULONGLONG bytesInFlight_ = 0;
    ULONGLONG recoveryStartTime100ns_ = 0;
    ULONGLONG pacingDeadline100ns_ = 0;
};
} // namespace wknet::quic
