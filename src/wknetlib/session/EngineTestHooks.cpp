#include "session/EnginePrivate.hpp"

namespace wknet
{
namespace session
{
#if defined(WKNET_USER_MODE_TEST)
    void TestSetHttpTransport(TestHttpTransportCallback callback, void* context) noexcept
    {
        g_testHttpTransport = callback;
        g_testHttpTransportContext = context;
    }

    void TestSetWebSocketTransport(
        TestWebSocketConnectCallback connectCallback,
        TestWebSocketSendCallback sendCallback,
        TestWebSocketReceiveCallback receiveCallback,
        TestWebSocketCloseCallback closeCallback,
        void* context) noexcept
    {
        g_testWebSocketConnect = connectCallback;
        g_testWebSocketSend = sendCallback;
        g_testWebSocketReceive = receiveCallback;
        g_testWebSocketClose = closeCallback;
        g_testWebSocketTransportContext = context;
    }

    NTSTATUS TestAsyncStatus(AsyncOperationHandle operation) noexcept
    {
        return AsyncOperationStatus(operation);
    }

    bool TestAsyncIsCompleted(AsyncOperationHandle operation) noexcept
    {
        return AsyncOperationIsCompleted(operation);
    }

    bool TestAsyncIsCanceled(AsyncOperationHandle operation) noexcept
    {
        return AsyncOperationIsCanceled(operation);
    }

    void TestSetCurrentIrql(ULONG irql) noexcept
    {
        g_testCurrentIrql = irql;
    }

    void TestResetCurrentIrql() noexcept
    {
        g_testCurrentIrql = PassiveLevel;
    }

    bool TestSessionHasWorkspace(SessionHandle session) noexcept
    {
        return IsSessionHandle(session) &&
            session->Workspace != nullptr &&
            session->Workspace->Request.Data != nullptr &&
            session->Workspace->Response.Data != nullptr &&
            session->Workspace->DecodedBody.Data != nullptr &&
            session->Workspace->Http2HeaderScratch.Data != nullptr &&
            session->Workspace->TlsHandshakeScratch.Data != nullptr &&
            session->Workspace->CertificateScratch.Data != nullptr &&
            session->Workspace->WebSocketFrameScratch.Data != nullptr &&
            session->Workspace->WebSocketSendFrameScratch.Data != nullptr;
    }

    bool TestSessionHasProviderCache(SessionHandle session) noexcept
    {
        return IsSessionHandle(session) &&
            session->ProviderCache != nullptr &&
            session->ProviderCache->IsInitialized();
    }
#endif

}
}
