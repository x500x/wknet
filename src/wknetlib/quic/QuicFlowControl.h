#pragma once

#include "quic/QuicTypes.h"

namespace wknet::quic
{
class QuicFlowController final
{
  public:
    NTSTATUS Initialize(ULONGLONG sendLimit, ULONGLONG receiveLimit) noexcept;
    NTSTATUS CanReserveSend(ULONGLONG bytes) const noexcept;
    NTSTATUS ReserveSend(ULONGLONG bytes) noexcept;
    NTSTATUS OnMaxData(ULONGLONG maximum) noexcept;
    NTSTATUS OnStreamReceiveProgress(ULONGLONG previousMaximumOffset, ULONGLONG currentMaximumOffset) noexcept;
    NTSTATUS OnStreamConsumed(ULONGLONG bytes) noexcept;
    NTSTATUS SetReceiveLimit(ULONGLONG maximum) noexcept;
    bool TakeDataBlocked(ULONGLONG *limit) noexcept;

    ULONGLONG SendOffset() const noexcept
    {
        return sendOffset_;
    }

    ULONGLONG ReceivedBytes() const noexcept
    {
        return receivedBytes_;
    }

    ULONGLONG ConsumedBytes() const noexcept
    {
        return consumedBytes_;
    }

  private:
    ULONGLONG sendLimit_ = 0;
    ULONGLONG sendOffset_ = 0;
    ULONGLONG receiveLimit_ = 0;
    ULONGLONG receivedBytes_ = 0;
    ULONGLONG consumedBytes_ = 0;
    bool initialized_ = false;
    bool dataBlockedPending_ = false;
};
} // namespace wknet::quic
