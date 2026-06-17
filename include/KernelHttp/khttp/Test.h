#pragma once

#if defined(KERNEL_HTTP_USER_MODE_TEST)

#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/khttp/Types.h>

namespace khttp
{
namespace test
{
    typedef ::KernelHttp::engine::KhTestHttpTransportRequest HttpTransportRequest;
    typedef ::KernelHttp::engine::KhTestHttpTransportResponse HttpTransportResponse;
    typedef ::KernelHttp::engine::KhTestHttpTransportCallback HttpTransportCallback;

    typedef ::KernelHttp::engine::KhTestWebSocketConnectRequest WebSocketConnectRequest;
    typedef ::KernelHttp::engine::KhTestWebSocketMessage WebSocketMessage;
    typedef ::KernelHttp::engine::KhTestWebSocketConnectCallback WebSocketConnectCallback;
    typedef ::KernelHttp::engine::KhTestWebSocketSendCallback WebSocketSendCallback;
    typedef ::KernelHttp::engine::KhTestWebSocketReceiveCallback WebSocketReceiveCallback;
    typedef ::KernelHttp::engine::KhTestWebSocketCloseCallback WebSocketCloseCallback;

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
        ::KernelHttp::engine::KhTlsVersion minVersion,
        ::KernelHttp::engine::KhTlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept;
}
}
#endif
