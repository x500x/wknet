#include "quic/QuicFlowControl.h"

namespace wknet::quic
{
NTSTATUS QuicFlowController::Initialize(ULONGLONG sendLimit, ULONGLONG receiveLimit) noexcept
{
    if (sendLimit > QuicVarIntMaximum || receiveLimit > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    sendLimit_ = sendLimit;
    sendOffset_ = 0;
    receiveLimit_ = receiveLimit;
    receivedBytes_ = 0;
    consumedBytes_ = 0;
    dataBlockedPending_ = false;
    initialized_ = true;
    return STATUS_SUCCESS;
}

NTSTATUS QuicFlowController::ReserveSend(ULONGLONG bytes) noexcept
{
    const NTSTATUS validationStatus = CanReserveSend(bytes);
    if (!NT_SUCCESS(validationStatus))
    {
        if (validationStatus == STATUS_DEVICE_BUSY)
        {
            dataBlockedPending_ = true;
        }
        return validationStatus;
    }
    sendOffset_ += bytes;
    return STATUS_SUCCESS;
}

NTSTATUS QuicFlowController::CanReserveSend(ULONGLONG bytes) const noexcept
{
    if (!initialized_ || bytes > QuicVarIntMaximum - sendOffset_)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (sendOffset_ > sendLimit_ || bytes > sendLimit_ - sendOffset_)
    {
        return STATUS_DEVICE_BUSY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicFlowController::OnMaxData(ULONGLONG maximum) noexcept
{
    if (!initialized_ || maximum > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (maximum > sendLimit_)
    {
        sendLimit_ = maximum;
        dataBlockedPending_ = false;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicFlowController::OnStreamReceiveProgress(ULONGLONG previousMaximumOffset,
                                                     ULONGLONG currentMaximumOffset) noexcept
{
    if (!initialized_ || previousMaximumOffset > currentMaximumOffset || currentMaximumOffset > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONGLONG delta = currentMaximumOffset - previousMaximumOffset;
    if (receivedBytes_ > receiveLimit_ || delta > receiveLimit_ - receivedBytes_)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    receivedBytes_ += delta;
    return STATUS_SUCCESS;
}

NTSTATUS QuicFlowController::OnStreamConsumed(ULONGLONG bytes) noexcept
{
    if (!initialized_ || consumedBytes_ > receivedBytes_ || bytes > receivedBytes_ - consumedBytes_)
    {
        return STATUS_INVALID_PARAMETER;
    }
    consumedBytes_ += bytes;
    return STATUS_SUCCESS;
}

NTSTATUS QuicFlowController::SetReceiveLimit(ULONGLONG maximum) noexcept
{
    if (!initialized_ || maximum > QuicVarIntMaximum || maximum < receivedBytes_)
    {
        return STATUS_INVALID_PARAMETER;
    }
    receiveLimit_ = maximum;
    return STATUS_SUCCESS;
}

bool QuicFlowController::TakeDataBlocked(ULONGLONG *limit) noexcept
{
    if (limit != nullptr)
    {
        *limit = 0;
    }
    if (!initialized_ || limit == nullptr || !dataBlockedPending_)
    {
        return false;
    }
    *limit = sendLimit_;
    dataBlockedPending_ = false;
    return true;
}
} // namespace wknet::quic
