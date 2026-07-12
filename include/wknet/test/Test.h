#pragma once

#if defined(WKNET_USER_MODE_TEST)

#include "session/Engine.h"
#include <wknet/http/Types.h>

namespace wknet::http {
namespace test
{
    typedef ::wknet::session::TestHttpTransportRequest HttpTransportRequest;
    typedef ::wknet::session::TestHttpTransportResponse HttpTransportResponse;
    typedef ::wknet::session::TestHttpTransportCallback HttpTransportCallback;

    typedef ::wknet::session::TestWebSocketConnectRequest WebSocketConnectRequest;
    typedef ::wknet::session::TestWebSocketMessage WebSocketMessage;
    typedef ::wknet::session::TestWebSocketConnectCallback WebSocketConnectCallback;
    typedef ::wknet::session::TestWebSocketSendCallback WebSocketSendCallback;
    typedef ::wknet::session::TestWebSocketReceiveCallback WebSocketReceiveCallback;
    typedef ::wknet::session::TestWebSocketCloseCallback WebSocketCloseCallback;

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
        ::wknet::session::TlsVersion minVersion,
        ::wknet::session::TlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept;
}
}
#endif
