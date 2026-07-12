#pragma once

#include <wknet/WknetConfig.h>

namespace wknet {
namespace net {
    class WskSocket;
    struct WskCancellationToken;
}
namespace tls {
    class TlsConnection;
}
namespace transport {
    struct Transport;

    struct TransportCallbacks final
    {
        NTSTATUS (*Send)(void* context, const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept = nullptr;
        NTSTATUS (*Receive)(void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept = nullptr;
        NTSTATUS (*ReceiveWithTimeout)(
            void* context,
            void* buffer,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept = nullptr;
        void (*SetCancellation)(void* context, const net::WskCancellationToken* cancellation) noexcept = nullptr;
    };

    _Must_inspect_result_
    NTSTATUS TransportCreateWsk(_Inout_ net::WskSocket* socket, _Out_ Transport** transport) noexcept;
    _Must_inspect_result_
    NTSTATUS TransportCreateTls(
        _Inout_ Transport* rawTransport,
        _Inout_ tls::TlsConnection* tlsConnection,
        _Out_ Transport** transport) noexcept;
    _Must_inspect_result_
    NTSTATUS TransportCreateCallbacks(
        _In_ const TransportCallbacks* callbacks,
        _In_opt_ void* context,
        _Out_ Transport** transport) noexcept;
    void TransportClose(_In_opt_ Transport* transport) noexcept;

    _Must_inspect_result_
    NTSTATUS TransportSend(
        _Inout_ Transport* transport,
        _In_reads_bytes_(length) const void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesSent) noexcept;
    _Must_inspect_result_
    NTSTATUS TransportReceive(
        _Inout_ Transport* transport,
        _Out_writes_bytes_(length) void* buffer,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived) noexcept;
    _Must_inspect_result_
    NTSTATUS TransportReceiveWithTimeout(
        _Inout_ Transport* transport,
        _Out_writes_bytes_(length) void* buffer,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived,
        ULONG timeoutMilliseconds) noexcept;
    void TransportSetCancellation(
        _Inout_opt_ Transport* transport,
        _In_opt_ const net::WskCancellationToken* cancellation) noexcept;
    void TransportSetConnectionId(_Inout_opt_ Transport* transport, ULONGLONG connectionId) noexcept;
    ULONGLONG TransportConnectionId(_In_opt_ const Transport* transport) noexcept;
}
}
