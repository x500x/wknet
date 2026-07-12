#include <wknet/http/Test.h>
#include "Detail.h"
#include "session/Engine.h"
#include "http1/HttpTypes.h"

namespace wknet::http {
#if defined(WKNET_USER_MODE_TEST)
namespace test
{
    void SetHttpTransport(HttpTransportCallback callback, void* context) noexcept
    {
        ::wknet::session::KhTestSetHttpTransport(callback, context);
    }

    void SetWebSocketTransport(
        WebSocketConnectCallback connectCallback,
        WebSocketSendCallback sendCallback,
        WebSocketReceiveCallback receiveCallback,
        WebSocketCloseCallback closeCallback,
        void* context) noexcept
    {
        ::wknet::session::KhTestSetWebSocketTransport(
            connectCallback,
            sendCallback,
            receiveCallback,
            closeCallback,
            context);
    }

    void SetCurrentIrql(ULONG irql) noexcept
    {
        ::wknet::session::KhTestSetCurrentIrql(irql);
    }

    void ResetCurrentIrql() noexcept
    {
        ::wknet::session::KhTestResetCurrentIrql();
    }

    void SetAsyncAutoRun(bool enabled) noexcept
    {
        ::wknet::session::KhTestSetAsyncAutoRun(enabled);
    }

    NTSTATUS RunAsyncOperation(AsyncOp* operation) noexcept
    {
        return ::wknet::session::KhTestRunAsyncOperation(detail::ToApiAsyncOp(operation));
    }

    bool IsHttpTls12ConfirmationCandidate(
        ::wknet::session::KhTlsVersion minVersion,
        ::wknet::session::KhTlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept
    {
        return ::wknet::session::KhTestIsHttpTls12ConfirmationCandidate(
            minVersion,
            maxVersion,
            category,
            status,
            beforeTls13FirstServerHello);
    }
}
#endif

}
