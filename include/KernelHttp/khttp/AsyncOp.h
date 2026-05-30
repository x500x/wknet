#pragma once

#include <KernelHttp/khttp/Types.h>

namespace KernelHttp
{
namespace khttp
{
    _Must_inspect_result_
    NTSTATUS AsyncWait(_In_ AsyncOp* operation, ULONG timeoutMs) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncCancel(_In_ AsyncOp* operation) noexcept;

    NTSTATUS AsyncGetStatus(_In_opt_ const AsyncOp* operation) noexcept;
    bool AsyncIsCompleted(_In_opt_ const AsyncOp* operation) noexcept;
    bool AsyncIsCanceled(_In_opt_ const AsyncOp* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGetResponse(_In_ AsyncOp* operation, _Out_ Response** response) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGetWebSocket(_In_ AsyncOp* operation, _Out_ WebSocket** websocket) noexcept;

    void AsyncRelease(_In_opt_ AsyncOp* operation) noexcept;
}
}
