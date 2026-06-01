#pragma once

#include <KernelHttp/core/ITransport.h>
#include <KernelHttp/net/WskSocket.h>

namespace KernelHttp
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

        _Must_inspect_result_
        NTSTATUS Send(
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent) noexcept override
        {
            return socket_.Send(data, length, bytesSent);
        }

        _Must_inspect_result_
        NTSTATUS Receive(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept override
        {
            return socket_.Receive(buffer, length, bytesReceived);
        }

        _Must_inspect_result_
        NTSTATUS ReceiveWithTimeout(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override
        {
            return socket_.Receive(buffer, length, bytesReceived, 0, timeoutMilliseconds);
        }

        net::WskSocket& Socket() noexcept { return socket_; }

    private:
        net::WskSocket& socket_;
    };
}
}
