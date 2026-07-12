#include "session/EnginePrivate.hpp"

namespace wknet
{
namespace session
{
    NTSTATUS SessionCreate(
        net::WskClient* wskClient,
        const SessionOptions* options,
        SessionHandle* session) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (wskClient == nullptr || session == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *session = nullptr;

        SessionOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        effectiveOptions.Http2KeepAlive =
            NormalizeHttp2KeepAliveOptions(effectiveOptions.Http2KeepAlive);
        if (!IsValidSessionOptions(effectiveOptions)) {
            return STATUS_INVALID_PARAMETER;
        }

        effectiveOptions.MaxResponseBytes = NormalizeMaxResponseBytes(effectiveOptions.MaxResponseBytes);

        SessionHandle newSession = AllocateSessionHandle();
        if (newSession == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newSession->Header = { HandleKind::Session, 0, nullptr };
        newSession->WskClient = wskClient;
        newSession->Options = effectiveOptions;
        newSession->Cache = effectiveOptions.Cache;
        newSession->InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeEvent(&newSession->DrainEvent, NotificationEvent, TRUE);
#endif

        status = newSession->WorkspaceLookaside.Initialize(sizeof(Workspace));
        if (!NT_SUCCESS(status)) {
            FreeHandle(newSession);
            return status;
        }

        WorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = effectiveOptions.ResponsePoolType;
        workspaceOptions.RequestBufferBytes = effectiveOptions.RequestBufferBytes;
        workspaceOptions.MaxResponseBytes = effectiveOptions.MaxResponseBytes;
        status = WorkspaceCreateFromLookaside(
            &workspaceOptions,
            &newSession->WorkspaceLookaside,
            &newSession->Workspace);
        if (!NT_SUCCESS(status)) {
            FreeHandle(newSession);
            return status;
        }

        newSession->ProviderCache = AllocateProviderCacheHandle();
        if (newSession->ProviderCache == nullptr) {
            WorkspaceReleaseToLookaside(newSession->Workspace, &newSession->WorkspaceLookaside);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = newSession->ProviderCache->Initialize();
        if (!NT_SUCCESS(status)) {
            FreeHandle(newSession->ProviderCache);
            newSession->ProviderCache = nullptr;
            WorkspaceReleaseToLookaside(newSession->Workspace, &newSession->WorkspaceLookaside);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return status;
        }

        status = ConnectionPoolInitialize(
            &newSession->ConnectionPool,
            effectiveOptions.ConnectionPoolCapacity,
            effectiveOptions.MaxConnectionsPerHost,
            effectiveOptions.IdleTimeoutMilliseconds,
            &effectiveOptions.Http2KeepAlive);
        if (!NT_SUCCESS(status)) {
            newSession->ProviderCache->Shutdown();
            FreeHandle(newSession->ProviderCache);
            newSession->ProviderCache = nullptr;
            WorkspaceReleaseToLookaside(newSession->Workspace, &newSession->WorkspaceLookaside);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return status;
        }

        status = ConnectionPoolStartHttp2KeepAlive(&newSession->ConnectionPool);
        if (!NT_SUCCESS(status)) {
            ConnectionPoolShutdown(&newSession->ConnectionPool);
            newSession->ProviderCache->Shutdown();
            FreeHandle(newSession->ProviderCache);
            newSession->ProviderCache = nullptr;
            WorkspaceReleaseToLookaside(newSession->Workspace, &newSession->WorkspaceLookaside);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return status;
        }

        status = RegisterActiveSessionHandle(newSession);
        if (!NT_SUCCESS(status)) {
            ConnectionPoolShutdown(&newSession->ConnectionPool);
            newSession->ProviderCache->Shutdown();
            FreeHandle(newSession->ProviderCache);
            newSession->ProviderCache = nullptr;
            WorkspaceReleaseToLookaside(newSession->Workspace, &newSession->WorkspaceLookaside);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return status;
        }

        *session = newSession;
        return STATUS_SUCCESS;
    }

    void SessionClose(SessionHandle session) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || session == nullptr) {
            return;
        }

        if (!TryCloseActiveSessionHandle(session)) {
            return;
        }

        WaitForSessionDrain(session);
        ConnectionPoolShutdown(&session->ConnectionPool);
        if (session->ProviderCache != nullptr) {
            session->ProviderCache->Shutdown();
            FreeHandle(session->ProviderCache);
            session->ProviderCache = nullptr;
        }
        Workspace* workspace = nullptr;
#if defined(WKNET_USER_MODE_TEST)
        workspace = session->Workspace;
        session->Workspace = nullptr;
#else
        workspace = static_cast<Workspace*>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&session->Workspace),
            nullptr));
#endif
        WorkspaceReleaseToLookaside(workspace, &session->WorkspaceLookaside);
        FreeHandle(session);
    }

    void EngineCloseActiveHandles() noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel())) {
            return;
        }

        for (;;) {
            WebSocketHandle websocket = FirstActiveWebSocketHandle();
            if (websocket == nullptr) {
                break;
            }

            const NTSTATUS status = WebSocketCloseSyncImpl(websocket);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Warning, "卸载扫尾关闭 WebSocket 失败: 0x%08X\r\n", static_cast<ULONG>(status));
                break;
            }
            if (FirstActiveWebSocketHandle() == websocket) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Warning, "卸载扫尾关闭 WebSocket 未推进\r\n");
                break;
            }
        }

        for (;;) {
            SessionHandle session = FirstActiveSessionHandle();
            if (session == nullptr) {
                break;
            }

            SessionClose(session);
            if (FirstActiveSessionHandle() == session) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Warning, "卸载扫尾关闭 session 未推进\r\n");
                break;
            }
        }
    }


}
}
