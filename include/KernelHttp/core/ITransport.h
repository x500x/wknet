#pragma once

#include <KernelHttp/KernelHttpConfig.h>

namespace KernelHttp
{
namespace core
{
    class ITransport
    {
    public:
        virtual ~ITransport() noexcept = default;

        _Must_inspect_result_
        virtual NTSTATUS Send(
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent) noexcept = 0;

        _Must_inspect_result_
        virtual NTSTATUS Receive(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept = 0;

        _Must_inspect_result_
        virtual NTSTATUS ReceiveWithTimeout(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept = 0;
    };
}
}
