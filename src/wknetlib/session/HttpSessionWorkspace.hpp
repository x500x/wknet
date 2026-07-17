#pragma once

// Session workspace acquire/release helpers extracted from HttpEngineInternal
// so dispatch units can share a smaller include surface for workspace policy.

#include "session/HttpEngine.h"
#include "session/Workspace.h"
#include "session/HandleTypes.h"

namespace wknet
{
namespace session
{
    constexpr SIZE_T WorkspaceCacheMaxRetainedBytes = 256 * 1024;

    _Ret_maybenull_
    inline Workspace* ExchangeSessionWorkspace(_In_ SessionHandle session, _In_opt_ Workspace* workspace) noexcept
    {
        if (session == nullptr) {
            return nullptr;
        }

#if defined(WKNET_USER_MODE_TEST)
        Workspace* previous = session->Workspace;
        session->Workspace = workspace;
        return previous;
#else
        return static_cast<Workspace*>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&session->Workspace),
            workspace));
#endif
    }

    _Ret_maybenull_
    inline Workspace* CompareExchangeSessionWorkspace(
        _In_ SessionHandle session,
        _In_opt_ Workspace* workspace,
        _In_opt_ Workspace* expected) noexcept
    {
        if (session == nullptr) {
            return nullptr;
        }

#if defined(WKNET_USER_MODE_TEST)
        Workspace* previous = session->Workspace;
        if (previous == expected) {
            session->Workspace = workspace;
        }
        return previous;
#else
        return static_cast<Workspace*>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&session->Workspace),
            workspace,
            expected));
#endif
    }

    inline SIZE_T WorkspaceRetainedBytes(_In_ const Workspace& workspace) noexcept
    {
        return workspace.Request.Length +
            workspace.Response.Length +
            workspace.DecodedBody.Length +
            workspace.HttpHeaderScratch.Length +
            workspace.Http2HeaderScratch.Length +
            workspace.TlsHandshakeScratch.Length +
            workspace.CertificateScratch.Length +
            workspace.WebSocketFrameScratch.Length +
            workspace.WebSocketSendFrameScratch.Length +
            workspace.WebSocketPayloadScratch.Length;
    }

    inline bool CanCacheRequestWorkspace(
        _In_ const Workspace& workspace,
        SIZE_T requestBufferBytes) noexcept
    {
        return workspace.PoolType == PoolType::NonPaged &&
            workspace.Request.Length >= requestBufferBytes &&
            WorkspaceRetainedBytes(workspace) <= WorkspaceCacheMaxRetainedBytes;
    }

    inline NTSTATUS AcquireRequestWorkspace(
        _In_ SessionHandle session,
        SIZE_T maxResponseBytes,
        _Outptr_ Workspace** workspace) noexcept
    {
        if (session == nullptr || workspace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *workspace = nullptr;

        Workspace* cached = ExchangeSessionWorkspace(session, nullptr);
        if (cached != nullptr) {
            if (cached->Request.Length >= session->Options.RequestBufferBytes) {
                cached->MaxResponseBytes = maxResponseBytes;
                WorkspaceReset(cached);
                *workspace = cached;
                return STATUS_SUCCESS;
            }

            WorkspaceReleaseToLookaside(cached, &session->WorkspaceLookaside);
        }

        WorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = PoolType::NonPaged;
        workspaceOptions.RequestBufferBytes = session->Options.RequestBufferBytes;
        workspaceOptions.MaxResponseBytes = maxResponseBytes;
        return WorkspaceCreateFromLookaside(
            &workspaceOptions,
            &session->WorkspaceLookaside,
            workspace);
    }

    inline void ReleaseRequestWorkspace(_In_ SessionHandle session, _In_opt_ Workspace* workspace) noexcept
    {
        if (workspace == nullptr) {
            return;
        }

        if (session == nullptr ||
            !CanCacheRequestWorkspace(*workspace, session->Options.RequestBufferBytes)) {
            WorkspaceReleaseToLookaside(workspace, session != nullptr ? &session->WorkspaceLookaside : nullptr);
            return;
        }

        workspace->MaxResponseBytes = session->Options.MaxResponseBytes;
        WorkspaceReset(workspace);

        if (CompareExchangeSessionWorkspace(session, workspace, nullptr) != nullptr) {
            WorkspaceReleaseToLookaside(workspace, &session->WorkspaceLookaside);
        }
    }

    class WorkspaceGuard final
    {
    public:
        WorkspaceGuard() noexcept = default;

        ~WorkspaceGuard() noexcept
        {
            Reset();
        }

        WorkspaceGuard(const WorkspaceGuard&) = delete;
        WorkspaceGuard& operator=(const WorkspaceGuard&) = delete;

        _Must_inspect_result_
        NTSTATUS Create(SIZE_T maxResponseBytes, SIZE_T requestBufferBytes) noexcept
        {
            Reset();

            WorkspaceOptions workspaceOptions = {};
            workspaceOptions.PoolType = PoolType::NonPaged;
            workspaceOptions.RequestBufferBytes = requestBufferBytes;
            workspaceOptions.MaxResponseBytes = maxResponseBytes;
            return WorkspaceCreate(&workspaceOptions, &workspace_);
        }

        _Must_inspect_result_
        NTSTATUS CreateForSession(_In_ SessionHandle session, SIZE_T maxResponseBytes) noexcept
        {
            Reset();
            session_ = session;
            return AcquireRequestWorkspace(session, maxResponseBytes, &workspace_);
        }

        void Reset() noexcept
        {
            if (session_ != nullptr) {
                ReleaseRequestWorkspace(session_, workspace_);
            }
            else {
                WorkspaceRelease(workspace_);
            }
            workspace_ = nullptr;
            session_ = nullptr;
        }

        _Ret_maybenull_
        Workspace* Get() noexcept
        {
            return workspace_;
        }

        _Must_inspect_result_
        bool IsValid() const noexcept
        {
            return workspace_ != nullptr;
        }

    private:
        SessionHandle session_ = nullptr;
        Workspace* workspace_ = nullptr;
    };
} // namespace session
} // namespace wknet
