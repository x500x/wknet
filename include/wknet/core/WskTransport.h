#pragma once

#include <wknet/core/ITransport.h>
#include <wknet/net/WskSocket.h>

namespace wknet
{
namespace core
{
    class WskTransport final : public ITransport
    {
    public:
        explicit WskTransport(_Inout_ net::WskSocket& socket) noexcept
            : socket_(socket)
        {
        }

        void SetCancellation(_In_opt_ const net::WskCancellationToken* cancellation) noexcept
        {
            cancellation_ = cancellation != nullptr ? *cancellation : net::WskCancellationToken{};
        }

        _Must_inspect_result_
        NTSTATUS Send(
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent) noexcept override
        {
            return socket_.Send(data, length, bytesSent, WSK_FLAG_NODELAY, CancellationOrNull());
        }

        _Must_inspect_result_
        NTSTATUS Receive(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept override
        {
            return socket_.Receive(buffer, length, bytesReceived, 0, WskOperationTimeoutMilliseconds, CancellationOrNull());
        }

        _Must_inspect_result_
        NTSTATUS ReceiveWithTimeout(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override
        {
            return socket_.Receive(buffer, length, bytesReceived, 0, timeoutMilliseconds, CancellationOrNull());
        }

        net::WskSocket& Socket() noexcept { return socket_; }

    private:
        _Ret_maybenull_
        const net::WskCancellationToken* CancellationOrNull() const noexcept
        {
            return cancellation_.IsCancellationRequested != nullptr ? &cancellation_ : nullptr;
        }

        net::WskSocket& socket_;
        net::WskCancellationToken cancellation_ = {};
    };
}
}
