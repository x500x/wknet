#include <KernelHttp/engine/Workspace.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

namespace KernelHttp
{
namespace engine
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
        return HasResponseByteLimit(maxResponseBytes) ?
            MinimumSize(KhWorkspaceResponseInitialBytes, maxResponseBytes) :
            KhWorkspaceResponseInitialBytes;
    }

    _Must_inspect_result_
    bool AddWouldOverflow(SIZE_T left, SIZE_T right) noexcept
    {
        return left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right;
    }

    _Must_inspect_result_
    bool IsValidOptions(const KhWorkspaceOptions& options) noexcept
    {
        return options.PoolType == KhPoolType::NonPaged || options.PoolType == KhPoolType::Paged;
    }

    _Ret_maybenull_
    void* AllocateWorkspaceMemory(KhPoolType poolType, SIZE_T length) noexcept
    {
        UNREFERENCED_PARAMETER(poolType);
        if (length == 0) {
            return nullptr;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return calloc(1, length);
#else
        return ExAllocatePool2(POOL_FLAG_NON_PAGED, length, PoolTag);
#endif
    }

    void FreeWorkspaceMemory(void* data) noexcept
    {
        if (data == nullptr) {
            return;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(data);
#else
        ExFreePoolWithTag(data, PoolTag);
#endif
    }

    _Must_inspect_result_
    NTSTATUS AllocateBuffer(
        KhPoolType poolType,
        SIZE_T length,
        _Out_ KhWorkspaceBuffer* buffer) noexcept
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

    void ReleaseBuffer(_Inout_ KhWorkspaceBuffer* buffer) noexcept
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
        KhPoolType poolType,
        _Inout_ KhWorkspaceBuffer* buffer,
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

    NTSTATUS KhWorkspaceCreate(const KhWorkspaceOptions* options, KhWorkspace** workspace) noexcept
    {
        if (workspace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *workspace = nullptr;

        KhWorkspaceOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidOptions(effectiveOptions)) {
            return STATUS_INVALID_PARAMETER;
        }

        KhWorkspace* newWorkspace =
            static_cast<KhWorkspace*>(AllocateWorkspaceMemory(effectiveOptions.PoolType, sizeof(KhWorkspace)));
        if (newWorkspace == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(newWorkspace, sizeof(*newWorkspace));
        newWorkspace->PoolType = effectiveOptions.PoolType;
        newWorkspace->MaxResponseBytes = effectiveOptions.MaxResponseBytes;

        const SIZE_T initialResponseBytes = InitialResponseBytes(effectiveOptions.MaxResponseBytes);

        NTSTATUS status = AllocateBuffer(effectiveOptions.PoolType, KhWorkspaceRequestBufferBytes, &newWorkspace->Request);
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, initialResponseBytes, &newWorkspace->Response);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, KhWorkspaceDecodedBodyBytes, &newWorkspace->DecodedBody);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, KhWorkspaceHttpHeaderScratchBytes, &newWorkspace->HttpHeaderScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, KhWorkspaceHttp2HeaderScratchBytes, &newWorkspace->Http2HeaderScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, KhWorkspaceTlsHandshakeScratchBytes, &newWorkspace->TlsHandshakeScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, KhWorkspaceCertificateScratchBytes, &newWorkspace->CertificateScratch);
        }
        if (NT_SUCCESS(status)) {
            status = AllocateBuffer(effectiveOptions.PoolType, KhWorkspaceWebSocketFrameScratchBytes, &newWorkspace->WebSocketFrameScratch);
        }

        if (!NT_SUCCESS(status)) {
            KhWorkspaceRelease(newWorkspace);
            return status;
        }

        *workspace = newWorkspace;
        return STATUS_SUCCESS;
    }

    void KhWorkspaceReset(KhWorkspace* workspace) noexcept
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

        workspace->ResponseLength = 0;
    }

    void KhWorkspaceRelease(KhWorkspace* workspace) noexcept
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
        RtlSecureZeroMemory(workspace, sizeof(*workspace));
        FreeWorkspaceMemory(workspace);
    }

    NTSTATUS KhWorkspaceEnsureResponseCapacity(KhWorkspace* workspace, SIZE_T requiredCapacity) noexcept
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

    NTSTATUS KhWorkspaceAppendResponse(KhWorkspace* workspace, const UCHAR* data, SIZE_T dataLength) noexcept
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
        NTSTATUS status = KhWorkspaceEnsureResponseCapacity(workspace, requiredCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlCopyMemory(workspace->Response.Data + workspace->ResponseLength, data, dataLength);
        workspace->ResponseLength += dataLength;
        return STATUS_SUCCESS;
    }
}
}
