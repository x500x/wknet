#pragma once

#if defined(KERNEL_HTTP_USER_MODE_TEST)

#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/khttp/Types.h>

namespace KernelHttp
{
namespace khttp
{
namespace test
{
    typedef engine::KhTestHttpTransportRequest HttpTransportRequest;
    typedef engine::KhTestHttpTransportResponse HttpTransportResponse;
    typedef engine::KhTestHttpTransportCallback HttpTransportCallback;

    typedef engine::KhTestWebSocketConnectRequest WebSocketConnectRequest;
    typedef engine::KhTestWebSocketMessage WebSocketMessage;
    typedef engine::KhTestWebSocketConnectCallback WebSocketConnectCallback;
    typedef engine::KhTestWebSocketSendCallback WebSocketSendCallback;
    typedef engine::KhTestWebSocketReceiveCallback WebSocketReceiveCallback;
    typedef engine::KhTestWebSocketCloseCallback WebSocketCloseCallback;

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
}
}
}

#endif
