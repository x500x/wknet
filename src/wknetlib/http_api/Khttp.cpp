#include <wknet/test/Test.h>
#include "session/detail/HttpHandles.h"
#include "session/Engine.h"
#include "http1/HttpTypes.h"

namespace wknet::http {
#if defined(WKNET_USER_MODE_TEST)
namespace test
{
    void SetHttpTransport(HttpTransportCallback callback, void* context) noexcept
    {
        ::wknet::session::TestSetHttpTransport(callback, context);
    }

    void SetWebSocketTransport(
        WebSocketConnectCallback connectCallback,
        WebSocketSendCallback sendCallback,
        WebSocketReceiveCallback receiveCallback,
        WebSocketCloseCallback closeCallback,
        void* context) noexcept
    {
        ::wknet::session::TestSetWebSocketTransport(
            connectCallback,
            sendCallback,
            receiveCallback,
            closeCallback,
            context);
    }

    void SetCurrentIrql(ULONG irql) noexcept
    {
        ::wknet::session::TestSetCurrentIrql(irql);
    }

    void ResetCurrentIrql() noexcept
    {
        ::wknet::session::TestResetCurrentIrql();
    }

    void SetAsyncAutoRun(bool enabled) noexcept
    {
        ::wknet::session::TestSetAsyncAutoRun(enabled);
    }

    NTSTATUS RunAsyncOperation(AsyncOp* operation) noexcept
    {
        return ::wknet::session::TestRunAsyncOperation(detail::ToApiAsyncOp(operation));
    }

    bool IsHttpTls12ConfirmationCandidate(
        ::wknet::session::TlsVersion minVersion,
        ::wknet::session::TlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept
    {
        return ::wknet::session::TestIsHttpTls12ConfirmationCandidate(
            minVersion,
            maxVersion,
            category,
            status,
            beforeTls13FirstServerHello);
    }
}
#endif

}
