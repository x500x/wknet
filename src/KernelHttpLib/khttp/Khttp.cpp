#include <KernelHttp/khttp/Test.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/http/HttpTypes.h>

namespace khttp
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
namespace test
{
    void SetHttpTransport(HttpTransportCallback callback, void* context) noexcept
    {
        ::KernelHttp::engine::KhTestSetHttpTransport(callback, context);
    }

    void SetWebSocketTransport(
        WebSocketConnectCallback connectCallback,
        WebSocketSendCallback sendCallback,
        WebSocketReceiveCallback receiveCallback,
        WebSocketCloseCallback closeCallback,
        void* context) noexcept
    {
        ::KernelHttp::engine::KhTestSetWebSocketTransport(
            connectCallback,
            sendCallback,
            receiveCallback,
            closeCallback,
            context);
    }

    void SetCurrentIrql(ULONG irql) noexcept
    {
        ::KernelHttp::engine::KhTestSetCurrentIrql(irql);
    }

    void ResetCurrentIrql() noexcept
    {
        ::KernelHttp::engine::KhTestResetCurrentIrql();
    }

    void SetAsyncAutoRun(bool enabled) noexcept
    {
        ::KernelHttp::engine::KhTestSetAsyncAutoRun(enabled);
    }

    NTSTATUS RunAsyncOperation(AsyncOp* operation) noexcept
    {
        return ::KernelHttp::engine::KhTestRunAsyncOperation(detail::ToApiAsyncOp(operation));
    }

    bool IsHttpTls12ConfirmationCandidate(
        ::KernelHttp::engine::KhTlsVersion minVersion,
        ::KernelHttp::engine::KhTlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept
    {
        return ::KernelHttp::engine::KhTestIsHttpTls12ConfirmationCandidate(
            minVersion,
            maxVersion,
            category,
            status,
            beforeTls13FirstServerHello);
    }
}
#endif

}
