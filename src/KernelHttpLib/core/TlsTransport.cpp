#include <KernelHttp/core/TlsTransport.h>
#include <KernelHttp/tls/TlsConnection.h>

namespace KernelHttp
{
namespace core
{
    NTSTATUS TlsTransport::Send(
        _In_reads_bytes_(length) const void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesSent) noexcept
    {
        return tls_.Send(rawTransport_, data, length, bytesSent);
    }

    NTSTATUS TlsTransport::Receive(
        _Out_writes_bytes_(length) void* buffer,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived) noexcept
    {
        return tls_.Receive(rawTransport_, buffer, length, bytesReceived);
    }

    NTSTATUS TlsTransport::ReceiveWithTimeout(
        _Out_writes_bytes_(length) void* buffer,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived,
        ULONG timeoutMilliseconds) noexcept
    {
        return tls_.Receive(rawTransport_, buffer, length, bytesReceived, timeoutMilliseconds);
    }
}
}
