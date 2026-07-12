#pragma once

#if defined(WKNET_USER_MODE_TEST)

#include <wknet/engine/Engine.h>
#include <wknet/http/Types.h>

namespace wknet::http {
namespace test
{
    typedef ::wknet::session::KhTestHttpTransportRequest HttpTransportRequest;
    typedef ::wknet::session::KhTestHttpTransportResponse HttpTransportResponse;
    typedef ::wknet::session::KhTestHttpTransportCallback HttpTransportCallback;

    typedef ::wknet::session::KhTestWebSocketConnectRequest WebSocketConnectRequest;
    typedef ::wknet::session::KhTestWebSocketMessage WebSocketMessage;
    typedef ::wknet::session::KhTestWebSocketConnectCallback WebSocketConnectCallback;
    typedef ::wknet::session::KhTestWebSocketSendCallback WebSocketSendCallback;
    typedef ::wknet::session::KhTestWebSocketReceiveCallback WebSocketReceiveCallback;
    typedef ::wknet::session::KhTestWebSocketCloseCallback WebSocketCloseCallback;

    void SetHttpTransport(HttpTransportCallback callback, void* context) noexcept;

    void SetWebSocketTransport(
        WebSocketConnectCallback connectCallback,
        WebSocketSendCallback sendCallback,
        WebSocketReceiveCallback receiveCallback,
        WebSocketCloseCallback closeCallback,
        void* context) noexcept;

    void SetCurrentIrql(ULONG irql) noexcept;
    void ResetCurrentIrql() noexcept;
    void SetAsyncAutoRun(bool enabled) noexcept;
    NTSTATUS RunAsyncOperation(_In_ AsyncOp* operation) noexcept;
    bool IsHttpTls12ConfirmationCandidate(
        ::wknet::session::KhTlsVersion minVersion,
        ::wknet::session::KhTlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept;
}
}
#endif
