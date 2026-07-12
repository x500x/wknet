#pragma once

#include "session/Engine.h"

namespace wknet
{
namespace rtl
{
    class LookasideList;
}

namespace session
{
    constexpr SIZE_T WorkspaceRequestBufferBytes = DefaultRequestBufferBytes;
    constexpr SIZE_T WorkspaceResponseInitialBytes = 4 * 1024;
    constexpr SIZE_T WorkspaceDecodedBodyBytes = 16 * 1024;
    constexpr SIZE_T WorkspaceHttpHeaderScratchBytes = 24 * 1024;
    constexpr SIZE_T WorkspaceHttp2HeaderScratchBytes = 16 * 1024;
    constexpr SIZE_T WorkspaceTlsHandshakeScratchBytes = 32 * 1024;
    constexpr SIZE_T WorkspaceCertificateScratchBytes = 64 * 1024;
    constexpr SIZE_T WorkspaceWebSocketFrameScratchBytes = 16 * 1024;

    struct WorkspaceBuffer final
    {
        UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct WorkspaceOptions final
    {
        PoolType PoolType = PoolType::NonPaged;
        SIZE_T RequestBufferBytes = DefaultRequestBufferBytes;
        // 0 means the response buffer grows until allocation failure.
        SIZE_T MaxResponseBytes = DefaultMaxResponseBytes;
    };

    struct Workspace final
    {
        PoolType PoolType = PoolType::NonPaged;
        // 0 means no caller-imposed response byte limit.
        SIZE_T MaxResponseBytes = DefaultMaxResponseBytes;
        WorkspaceBuffer Request = {};
        WorkspaceBuffer Response = {};
        WorkspaceBuffer DecodedBody = {};
        WorkspaceBuffer HttpHeaderScratch = {};
        WorkspaceBuffer Http2HeaderScratch = {};
        WorkspaceBuffer TlsHandshakeScratch = {};
        WorkspaceBuffer CertificateScratch = {};
        WorkspaceBuffer WebSocketFrameScratch = {};
        WorkspaceBuffer WebSocketSendFrameScratch = {};
        WorkspaceBuffer WebSocketPayloadScratch = {};
        SIZE_T ResponseLength = 0;
    };

    _Must_inspect_result_
    NTSTATUS WorkspaceCreate(
        _In_opt_ const WorkspaceOptions* options,
        _Out_ Workspace** workspace) noexcept;

    _Must_inspect_result_
    NTSTATUS WorkspaceCreateFromLookaside(
        _In_opt_ const WorkspaceOptions* options,
        _In_opt_ rtl::LookasideList* lookaside,
        _Out_ Workspace** workspace) noexcept;

    void WorkspaceReset(_In_opt_ Workspace* workspace) noexcept;

    void WorkspaceRelease(_In_opt_ Workspace* workspace) noexcept;

    void WorkspaceReleaseToLookaside(
        _In_opt_ Workspace* workspace,
        _In_opt_ rtl::LookasideList* lookaside) noexcept;

    _Must_inspect_result_
    NTSTATUS WorkspaceEnsureResponseCapacity(
        _Inout_ Workspace* workspace,
        SIZE_T requiredCapacity) noexcept;

    _Must_inspect_result_
    NTSTATUS WorkspaceAppendResponse(
        _Inout_ Workspace* workspace,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WorkspaceEnsureDecodedBodyCapacity(
        _Inout_ Workspace* workspace,
        SIZE_T requiredCapacity) noexcept;

    _Must_inspect_result_
    NTSTATUS WorkspaceEnsureWebSocketPayloadCapacity(
        _Inout_ Workspace* workspace,
        SIZE_T requiredCapacity) noexcept;
}
}
