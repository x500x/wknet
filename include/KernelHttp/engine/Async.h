#pragma once

#include <KernelHttp/engine/Engine.h>

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
#include <wdm.h>
#endif

namespace KernelHttp
{
namespace engine
{
    constexpr ULONG KhAsyncOperationMagic = 0x4B484131;

    enum class KhAsyncOperationKind : ULONG
    {
        HttpSend = 0,
        WebSocketConnect = 1
    };

    typedef NTSTATUS (*KhAsyncWorkerRoutine)(
        _In_ KH_ASYNC_OPERATION operation,
        _In_opt_ void* context);

    typedef void (*KhAsyncCleanupRoutine)(_In_opt_ void* context);

    enum class KhAsyncState : ULONG
    {
        Pending = 0,
        Running = 1,
        Completed = 2
    };

    struct KhAsyncOperation
    {
        ULONG Magic = KhAsyncOperationMagic;
        // User-visible handle state only. Internal worker references keep the
        // operation object alive and must still be able to observe cancellation.
        volatile LONG Closed = 0;
        KhAsyncOperationKind Kind = KhAsyncOperationKind::HttpSend;
        volatile LONG ReferenceCount = 1;
        volatile LONG Canceled = 0;
        volatile LONG Completed = 0;
        volatile LONG State = static_cast<LONG>(KhAsyncState::Pending);
        NTSTATUS Status = STATUS_PENDING;
        KhAsyncWorkerRoutine WorkerRoutine = nullptr;
        KhAsyncCleanupRoutine CleanupRoutine = nullptr;
        void* Context = nullptr;
        KhAsyncCompletionCallback CompletionCallback = nullptr;
        void* CompletionContext = nullptr;
        volatile LONG Queued = 0;
        KhAsyncOperation* QueueNext = nullptr;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        bool CompletionSignaled = false;
        bool TestWorkerReferenceHeld = false;
#else
        KEVENT CompletedEvent = {};
#endif
    };

    struct KhAsyncCreateOptions final
    {
        KhAsyncOperationKind Kind = KhAsyncOperationKind::HttpSend;
        KhAsyncWorkerRoutine WorkerRoutine = nullptr;
        KhAsyncCleanupRoutine CleanupRoutine = nullptr;
        void* Context = nullptr;
        KhAsyncCompletionCallback CompletionCallback = nullptr;
        void* CompletionContext = nullptr;
        bool StartSuspended = false;
    };

    _Must_inspect_result_
    NTSTATUS KhAsyncOperationCreate(
        _In_ const KhAsyncCreateOptions& options,
        _Out_ KH_ASYNC_OPERATION* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhAsyncOperationQueue(_In_ KH_ASYNC_OPERATION operation) noexcept;

    // Cancel completes pending operations immediately. Running HTTP/WebSocket workers
    // observe the flag and pass it to WSK-backed transport waits, which cancel the
    // active IRP where that lower layer supports cancellation.
    _Must_inspect_result_
    NTSTATUS KhAsyncOperationCancel(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhAsyncOperationWait(
        _In_ KH_ASYNC_OPERATION operation,
        ULONG timeoutMilliseconds) noexcept;

    void KhAsyncOperationRelease(_In_opt_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhAsyncOperationStatus(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    bool KhAsyncOperationIsCanceled(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    bool KhAsyncOperationIsCompleted(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    KhAsyncState KhAsyncOperationState(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    bool KhAsyncOperationIsValid(_In_opt_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    KhAsyncOperationKind KhAsyncOperationGetKind(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Ret_maybenull_
    void* KhAsyncOperationContext(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhEngineDrainAsync() noexcept;

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    void KhTestSetAsyncAutoRun(bool enabled) noexcept;
    NTSTATUS KhTestRunAsyncOperation(_In_ KH_ASYNC_OPERATION operation) noexcept;
#endif
}
}
