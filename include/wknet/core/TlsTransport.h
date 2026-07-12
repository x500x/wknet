#pragma once

#include <wknet/core/ITransport.h>

namespace wknet
{
namespace tls
{
    class TlsConnection;
}

namespace core
{
    class TlsTransport final : public ITransport
    {
    public:
        TlsTransport(
            _Inout_ ITransport& rawTransport,
            _Inout_ tls::TlsConnection& tls) noexcept
            : rawTransport_(rawTransport)
            , tls_(tls)
        {
        }

        _Must_inspect_result_
        NTSTATUS Send(
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent) noexcept override;

        _Must_inspect_result_
        NTSTATUS Receive(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept override;

        _Must_inspect_result_
        NTSTATUS ReceiveWithTimeout(
            _Out_writes_bytes_(length) void* buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override;

        ITransport& RawTransport() noexcept { return rawTransport_; }
        tls::TlsConnection& Tls() noexcept { return tls_; }

    private:
        ITransport& rawTransport_;
        tls::TlsConnection& tls_;
    };
}
}
