#include "session/Workspace.h"
#include "rtl/Lookaside.h"

namespace wknet
{
namespace session
{
namespace
{
    _Must_inspect_result_
    SIZE_T MinimumSize(SIZE_T left, SIZE_T right) noexcept
    {
        return left < right ? left : right;
    }

    _Must_inspect_result_
    bool HasResponseByteLimit(SIZE_T maxResponseBytes) noexcept
    {
        return maxResponseBytes != 0;
    }

    _Must_inspect_result_
    SIZE_T InitialResponseBytes(SIZE_T maxResponseBytes) noexcept
    {
        if (!HasResponseByteLimit(maxResponseBytes)) {
            return WorkspaceResponseInitialBytes;
        }

        return MinimumSize(WorkspaceResponseInitialBytes, maxResponseBytes);
    }

    _Must_inspect_result_
    bool AddWouldOverflow(SIZE_T left, SIZE_T right) noexcept
    {
        return left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right;
    }

    _Must_inspect_result_
    bool IsSupportedWorkspacePoolType(PoolType poolType) noexcept
    {
        return poolType == PoolType::NonPaged;
    }

    _Must_inspect_result_
    bool IsValidOptions(const WorkspaceOptions& options) noexcept
    {
        return IsSupportedWorkspacePoolType(options.PoolType) &&
            options.RequestBufferBytes != 0;
    }

    _Ret_maybenull_
    void* AllocateWorkspaceMemory(PoolType poolType, SIZE_T length) noexcept
    {
        if (!IsSupportedWorkspacePoolType(poolType)) {
            return nullptr;
        }
        return AllocateNonPagedPoolBytes(length);
    }

    void FreeWorkspaceMemory(void* data) noexcept
    {
        FreeNonPagedPoolBytes(data);
    }

    _Ret_maybenull_
    Workspace* AllocateWorkspaceObject(
        PoolType poolType,
        _In_opt_ rtl::LookasideList* lookaside) noexcept
    {
        if (!IsSupportedWorkspacePoolType(poolType)) {
            return nullptr;
        }

        if (lookaside != nullptr && lookaside->IsInitialized()) {
            return static_cast<Workspace*>(lookaside->Allocate());
        }

        return static_cast<Workspace*>(AllocateWorkspaceMemory(poolType, sizeof(Workspace)));
    }

    void FreeWorkspaceObject(
        _In_opt_ Workspace* workspace,
        _In_opt_ rtl::LookasideList* lookaside) noexcept
    {
        if (workspace == nullptr) {
            return;
        }

        if (lookaside != nullptr && lookaside->IsInitialized()) {
            lookaside->Free(workspace);
            return;
        }

        FreeWorkspaceMemory(workspace);
    }

    _Must_inspect_result_
    NTSTATUS AllocateBuffer(
        PoolType poolType,
        SIZE_T length,
        _Out_ WorkspaceBuffer* buffer) noexcept
    {
        if (buffer == nullptr || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        buffer->Data = static_cast<UCHAR*>(AllocateWorkspaceMemory(poolType, length));
        if (buffer->Data == nullptr) {
            buffer->Length = 0;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        buffer->Length = length;
        return STATUS_SUCCESS;
    }

    void ReleaseBuffer(_Inout_ WorkspaceBuffer* buffer) noexcept
    {
        if (buffer == nullptr) {
            return;
        }

        if (buffer->Data != nullptr && buffer->Length != 0) {
            RtlSecureZeroMemory(buffer->Data, buffer->Length);
        }
        FreeWorkspaceMemory(buffer->Data);
        buffer->Data = nullptr;
        buffer->Length = 0;
    }

    _Must_inspect_result_
    NTSTATUS GrowBuffer(
        PoolType poolType,
        _Inout_ WorkspaceBuffer* buffer,
        SIZE_T newLength) noexcept
    {
        if (buffer == nullptr || newLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (newLength <= buffer->Length) {
            return STATUS_SUCCESS;
        }

        UCHAR* replacement = static_cast<UCHAR*>(AllocateWorkspaceMemory(poolType, newLength));
        if (replacement == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (buffer->Data != nullptr && buffer->Length != 0) {
            RtlCopyMemory(replacement, buffer->Data, buffer->Length);
            RtlSecureZeroMemory(buffer->Data, buffer->Length);
        }

        FreeWorkspaceMemory(buffer->Data);
        buffer->Data = replacement;
        buffer->Length = newLength;
        return STATUS_SUCCESS;
    }
}

    NTSTATUS WorkspaceCreateFromLookaside(
        const WorkspaceOptions* options,
        rtl::LookasideList* lookaside,
        Workspace** workspace) noexcept
    {
        if (workspace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *workspace = nullptr;

        WorkspaceOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidOptions(effectiveOptions)) {
            return STATUS_INVALID_PARAMETER;
        }

        Workspace* newWorkspace = AllocateWorkspaceObject(effectiveOptions.PoolType, lookaside);
        if (newWorkspace == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(newWorkspace, sizeof(*newWorkspace));
        newWorkspace->PoolType = effectiveOptions.PoolType;
        newWorkspace->MaxResponseBytes = effectiveOptions.MaxResponseBytes;

        const SIZE_T initialResponseBytes = InitialResponseBytes(effectiveOptions.MaxResponseBytes);

        NTSTATUS status = AllocateBuffer(effectiveOptions.PoolType, effectiveOptions.RequestBufferBytes, &newWorkspace->Request);
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, initialResponseBytes, &newWorkspace->Response);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, WorkspaceDecodedBodyBytes, &newWorkspace->DecodedBody);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, WorkspaceHttpHeaderScratchBytes, &newWorkspace->HttpHeaderScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, WorkspaceHttp2HeaderScratchBytes, &newWorkspace->Http2HeaderScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, WorkspaceTlsHandshakeScratchBytes, &newWorkspace->TlsHandshakeScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, WorkspaceCertificateScratchBytes, &newWorkspace->CertificateScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, WorkspaceWebSocketFrameScratchBytes, &newWorkspace->WebSocketFrameScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, WorkspaceWebSocketFrameScratchBytes, &newWorkspace->WebSocketSendFrameScratch);
        }

        if (!NT_SUCCESS(status)) {
            WorkspaceRelease(newWorkspace);
            return status;
        }

        *workspace = newWorkspace;
        return STATUS_SUCCESS;
    }

    NTSTATUS WorkspaceCreate(const WorkspaceOptions* options, Workspace** workspace) noexcept
    {
        return WorkspaceCreateFromLookaside(options, nullptr, workspace);
    }

    void WorkspaceReset(Workspace* workspace) noexcept
    {
        if (workspace == nullptr) {
            return;
        }

        // Keep KB-scale temporary storage in this workspace instead of function
        // locals. New protocol scratch buffers should be added here, not on stack.
        if (workspace->Request.Data != nullptr) {
            RtlZeroMemory(workspace->Request.Data, workspace->Request.Length);
        }
        if (workspace->Response.Data != nullptr) {
            RtlZeroMemory(workspace->Response.Data, workspace->Response.Length);
        }
        if (workspace->DecodedBody.Data != nullptr) {
            RtlZeroMemory(workspace->DecodedBody.Data, workspace->DecodedBody.Length);
        }
        if (workspace->HttpHeaderScratch.Data != nullptr) {
            RtlZeroMemory(workspace->HttpHeaderScratch.Data, workspace->HttpHeaderScratch.Length);
        }
        if (workspace->Http2HeaderScratch.Data != nullptr) {
            RtlZeroMemory(workspace->Http2HeaderScratch.Data, workspace->Http2HeaderScratch.Length);
        }
        if (workspace->TlsHandshakeScratch.Data != nullptr) {
            RtlZeroMemory(workspace->TlsHandshakeScratch.Data, workspace->TlsHandshakeScratch.Length);
        }
        if (workspace->CertificateScratch.Data != nullptr) {
            RtlZeroMemory(workspace->CertificateScratch.Data, workspace->CertificateScratch.Length);
        }
        if (workspace->WebSocketFrameScratch.Data != nullptr) {
            RtlZeroMemory(workspace->WebSocketFrameScratch.Data, workspace->WebSocketFrameScratch.Length);
        }
        if (workspace->WebSocketSendFrameScratch.Data != nullptr) {
            RtlZeroMemory(workspace->WebSocketSendFrameScratch.Data, workspace->WebSocketSendFrameScratch.Length);
        }
        if (workspace->WebSocketPayloadScratch.Data != nullptr) {
            RtlZeroMemory(workspace->WebSocketPayloadScratch.Data, workspace->WebSocketPayloadScratch.Length);
        }

        workspace->ResponseLength = 0;
    }

    void WorkspaceReleaseToLookaside(Workspace* workspace, rtl::LookasideList* lookaside) noexcept
    {
        if (workspace == nullptr) {
            return;
        }

        ReleaseBuffer(&workspace->Request);
        ReleaseBuffer(&workspace->Response);
        ReleaseBuffer(&workspace->DecodedBody);
        ReleaseBuffer(&workspace->HttpHeaderScratch);
        ReleaseBuffer(&workspace->Http2HeaderScratch);
        ReleaseBuffer(&workspace->TlsHandshakeScratch);
        ReleaseBuffer(&workspace->CertificateScratch);
        ReleaseBuffer(&workspace->WebSocketFrameScratch);
        ReleaseBuffer(&workspace->WebSocketSendFrameScratch);
        ReleaseBuffer(&workspace->WebSocketPayloadScratch);
        RtlSecureZeroMemory(workspace, sizeof(*workspace));
        FreeWorkspaceObject(workspace, lookaside);
    }

    void WorkspaceRelease(Workspace* workspace) noexcept
    {
        WorkspaceReleaseToLookaside(workspace, nullptr);
    }

    NTSTATUS WorkspaceEnsureResponseCapacity(Workspace* workspace, SIZE_T requiredCapacity) noexcept
    {
        if (workspace == nullptr || requiredCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool hasLimit = HasResponseByteLimit(workspace->MaxResponseBytes);
        if (hasLimit && requiredCapacity > workspace->MaxResponseBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (requiredCapacity <= workspace->Response.Length) {
            return STATUS_SUCCESS;
        }

        SIZE_T newLength = workspace->Response.Length;
        if (newLength == 0) {
            newLength = InitialResponseBytes(workspace->MaxResponseBytes);
        }

        while (newLength < requiredCapacity) {
            if (hasLimit && newLength >= workspace->MaxResponseBytes) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            if (AddWouldOverflow(newLength, newLength)) {
                newLength = requiredCapacity;
            }
            else {
                newLength *= 2;
                if (hasLimit && newLength > workspace->MaxResponseBytes) {
                    newLength = workspace->MaxResponseBytes;
                }
            }
        }

        return GrowBuffer(workspace->PoolType, &workspace->Response, newLength);
    }

    NTSTATUS WorkspaceEnsureRequestCapacity(Workspace* workspace, SIZE_T requiredCapacity) noexcept
    {
        if (workspace == nullptr || requiredCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (requiredCapacity <= workspace->Request.Length) {
            return STATUS_SUCCESS;
        }

        SIZE_T newLength = workspace->Request.Length;
        if (newLength == 0) {
            newLength = DefaultRequestBufferBytes;
        }

        while (newLength < requiredCapacity) {
            if (AddWouldOverflow(newLength, newLength)) {
                newLength = requiredCapacity;
            }
            else {
                newLength *= 2;
            }
        }

        return GrowBuffer(workspace->PoolType, &workspace->Request, newLength);
    }

    NTSTATUS WorkspaceAppendResponse(Workspace* workspace, const UCHAR* data, SIZE_T dataLength) noexcept
    {
        if (workspace == nullptr || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength == 0) {
            return STATUS_SUCCESS;
        }

        if (AddWouldOverflow(workspace->ResponseLength, dataLength)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        const SIZE_T requiredCapacity = workspace->ResponseLength + dataLength;
        NTSTATUS status = WorkspaceEnsureResponseCapacity(workspace, requiredCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlCopyMemory(workspace->Response.Data + workspace->ResponseLength, data, dataLength);
        workspace->ResponseLength += dataLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS WorkspaceEnsureDecodedBodyCapacity(Workspace* workspace, SIZE_T requiredCapacity) noexcept
    {
        if (workspace == nullptr || requiredCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool hasLimit = HasResponseByteLimit(workspace->MaxResponseBytes);
        if (hasLimit && requiredCapacity > workspace->MaxResponseBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (requiredCapacity <= workspace->DecodedBody.Length) {
            return STATUS_SUCCESS;
        }

        SIZE_T newLength = workspace->DecodedBody.Length;
        if (newLength == 0) {
            newLength = hasLimit ?
                MinimumSize(WorkspaceDecodedBodyBytes, workspace->MaxResponseBytes) :
                WorkspaceDecodedBodyBytes;
        }

        while (newLength < requiredCapacity) {
            if (hasLimit && newLength >= workspace->MaxResponseBytes) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            if (AddWouldOverflow(newLength, newLength)) {
                newLength = requiredCapacity;
            }
            else {
                newLength *= 2;
                if (hasLimit && newLength > workspace->MaxResponseBytes) {
                    newLength = workspace->MaxResponseBytes;
                }
            }
        }

        return GrowBuffer(workspace->PoolType, &workspace->DecodedBody, newLength);
    }

    NTSTATUS WorkspaceEnsureWebSocketPayloadCapacity(
        Workspace* workspace,
        SIZE_T requiredCapacity) noexcept
    {
        if (workspace == nullptr || requiredCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (HasResponseByteLimit(workspace->MaxResponseBytes) &&
            requiredCapacity > workspace->MaxResponseBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return GrowBuffer(workspace->PoolType, &workspace->WebSocketPayloadScratch, requiredCapacity);
    }
}
}
