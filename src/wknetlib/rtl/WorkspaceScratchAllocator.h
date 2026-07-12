#pragma once

#include "rtl/IScratchAllocator.h"
#include "session/Workspace.h"

namespace wknet
{
namespace core
{
    class WorkspaceScratchAllocator final : public IScratchAllocator
    {
    public:
        enum class BufferKind : ULONG
        {
            TlsHandshake = 0,
            Certificate = 1,
            Http2Header = 2,
            WebSocketFrame = 3
        };

        WorkspaceScratchAllocator(
            _Inout_ session::Workspace& workspace,
            BufferKind kind) noexcept
            : workspace_(workspace)
            , kind_(kind)
        {
        }

        _Must_inspect_result_
        NTSTATUS Acquire(
            SIZE_T length,
            _Outptr_result_bytebuffer_(length) void** buffer) noexcept override
        {
            if (buffer == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            session::WorkspaceBuffer* wb = GetBuffer();
            if (wb == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            // This adapter never allocates on demand; callers get the bounded
            // NonPaged workspace buffer or a fixed capacity error.
            if (wb->Data != nullptr && wb->Length >= length) {
                *buffer = wb->Data;
                return STATUS_SUCCESS;
            }

            return STATUS_BUFFER_TOO_SMALL;
        }

        void Release(_In_opt_ void* buffer) noexcept override
        {
            (void)buffer;
        }

        _Must_inspect_result_
        NTSTATUS EnsureBuffer(
            SIZE_T length,
            _Outptr_result_bytebuffer_(length) void** buffer) noexcept override
        {
            return Acquire(length, buffer);
        }

    private:
        session::WorkspaceBuffer* GetBuffer() noexcept
        {
            switch (kind_)
            {
            case BufferKind::TlsHandshake:
                return &workspace_.TlsHandshakeScratch;
            case BufferKind::Certificate:
                return &workspace_.CertificateScratch;
            case BufferKind::Http2Header:
                return &workspace_.Http2HeaderScratch;
            case BufferKind::WebSocketFrame:
                return &workspace_.WebSocketFrameScratch;
            default:
                return nullptr;
            }
        }

        session::Workspace& workspace_;
        BufferKind kind_;
    };
}
}
