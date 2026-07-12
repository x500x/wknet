#pragma once

#include "session/Engine.h"

namespace wknet
{
namespace core
{
    class KhLookasideList;
}

namespace session
{
    constexpr SIZE_T KhWorkspaceRequestBufferBytes = KhDefaultRequestBufferBytes;
    constexpr SIZE_T KhWorkspaceResponseInitialBytes = 4 * 1024;
    constexpr SIZE_T KhWorkspaceDecodedBodyBytes = 16 * 1024;
    constexpr SIZE_T KhWorkspaceHttpHeaderScratchBytes = 24 * 1024;
    constexpr SIZE_T KhWorkspaceHttp2HeaderScratchBytes = 16 * 1024;
    constexpr SIZE_T KhWorkspaceTlsHandshakeScratchBytes = 32 * 1024;
    constexpr SIZE_T KhWorkspaceCertificateScratchBytes = 64 * 1024;
    constexpr SIZE_T KhWorkspaceWebSocketFrameScratchBytes = 16 * 1024;

    struct KhWorkspaceBuffer final
    {
        UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct KhWorkspaceOptions final
    {
        KhPoolType PoolType = KhPoolType::NonPaged;
        SIZE_T RequestBufferBytes = KhDefaultRequestBufferBytes;
        // 0 means the response buffer grows until allocation failure.
        SIZE_T MaxResponseBytes = KhDefaultMaxResponseBytes;
    };

    struct KhWorkspace final
    {
        KhPoolType PoolType = KhPoolType::NonPaged;
        // 0 means no caller-imposed response byte limit.
        SIZE_T MaxResponseBytes = KhDefaultMaxResponseBytes;
        KhWorkspaceBuffer Request = {};
        KhWorkspaceBuffer Response = {};
        KhWorkspaceBuffer DecodedBody = {};
        KhWorkspaceBuffer HttpHeaderScratch = {};
        KhWorkspaceBuffer Http2HeaderScratch = {};
        KhWorkspaceBuffer TlsHandshakeScratch = {};
        KhWorkspaceBuffer CertificateScratch = {};
        KhWorkspaceBuffer WebSocketFrameScratch = {};
        KhWorkspaceBuffer WebSocketSendFrameScratch = {};
        KhWorkspaceBuffer WebSocketPayloadScratch = {};
        SIZE_T ResponseLength = 0;
    };

    _Must_inspect_result_
    NTSTATUS KhWorkspaceCreate(
        _In_opt_ const KhWorkspaceOptions* options,
        _Out_ KhWorkspace** workspace) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWorkspaceCreateFromLookaside(
        _In_opt_ const KhWorkspaceOptions* options,
        _In_opt_ core::KhLookasideList* lookaside,
        _Out_ KhWorkspace** workspace) noexcept;

    void KhWorkspaceReset(_In_opt_ KhWorkspace* workspace) noexcept;

    void KhWorkspaceRelease(_In_opt_ KhWorkspace* workspace) noexcept;

    void KhWorkspaceReleaseToLookaside(
        _In_opt_ KhWorkspace* workspace,
        _In_opt_ core::KhLookasideList* lookaside) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWorkspaceEnsureResponseCapacity(
        _Inout_ KhWorkspace* workspace,
        SIZE_T requiredCapacity) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWorkspaceAppendResponse(
        _Inout_ KhWorkspace* workspace,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWorkspaceEnsureDecodedBodyCapacity(
        _Inout_ KhWorkspace* workspace,
        SIZE_T requiredCapacity) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWorkspaceEnsureWebSocketPayloadCapacity(
        _Inout_ KhWorkspace* workspace,
        SIZE_T requiredCapacity) noexcept;
}
}
