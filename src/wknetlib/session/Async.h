#pragma once

#include "session/Engine.h"

#if !defined(WKNET_USER_MODE_TEST)
#include <wdm.h>
#endif

namespace wknet
{
namespace session
{
    constexpr ULONG AsyncOperationMagic = 0x4B484131;

    enum class AsyncOperationKind : ULONG
    {
        HttpSend = 0,
        WebSocketConnect = 1
    };

    typedef NTSTATUS (*AsyncWorkerRoutine)(
        _In_ AsyncOperationHandle operation,
        _In_opt_ void* context);

    typedef void (*AsyncCleanupRoutine)(_In_opt_ void* context);

    enum class AsyncState : ULONG
    {
        Pending = 0,
        Running = 1,
        Completed = 2
    };

    struct AsyncOperation
    {
        ULONG Magic = AsyncOperationMagic;
        // User-visible handle state only. Internal worker references keep the
        // operation object alive and must still be able to observe cancellation.
        volatile LONG Closed = 0;
        AsyncOperationKind Kind = AsyncOperationKind::HttpSend;
        volatile LONG ReferenceCount = 1;
        volatile LONG Canceled = 0;
        volatile LONG Completed = 0;
        volatile LONG State = static_cast<LONG>(AsyncState::Pending);
        NTSTATUS Status = STATUS_PENDING;
        AsyncWorkerRoutine WorkerRoutine = nullptr;
        AsyncCleanupRoutine CleanupRoutine = nullptr;
        void* Context = nullptr;
        AsyncCompletionCallback CompletionCallback = nullptr;
        void* CompletionContext = nullptr;
        volatile LONG Queued = 0;
        AsyncOperation* QueueNext = nullptr;
#if defined(WKNET_USER_MODE_TEST)
        bool CompletionSignaled = false;
        bool TestWorkerReferenceHeld = false;
#else
        KEVENT CompletedEvent = {};
#endif
    };

    struct AsyncCreateOptions final
    {
        AsyncOperationKind Kind = AsyncOperationKind::HttpSend;
        AsyncWorkerRoutine WorkerRoutine = nullptr;
        AsyncCleanupRoutine CleanupRoutine = nullptr;
        void* Context = nullptr;
        AsyncCompletionCallback CompletionCallback = nullptr;
        void* CompletionContext = nullptr;
        bool StartSuspended = false;
    };

    _Must_inspect_result_
    NTSTATUS AsyncOperationCreate(
        _In_ const AsyncCreateOptions& options,
        _Out_ AsyncOperationHandle* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncOperationQueue(_In_ AsyncOperationHandle operation) noexcept;

    // Cancel completes pending operations immediately. Running HTTP/WebSocket workers
    // observe the flag and pass it to WSK-backed transport waits, which cancel the
    // active IRP where that lower layer supports cancellation.
    _Must_inspect_result_
    NTSTATUS AsyncOperationCancel(_In_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncOperationWait(
        _In_ AsyncOperationHandle operation,
        ULONG timeoutMilliseconds) noexcept;

    void AsyncOperationRelease(_In_opt_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncOperationStatus(_In_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    bool AsyncOperationIsCanceled(_In_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    bool AsyncOperationIsCompleted(_In_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    AsyncState AsyncOperationState(_In_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    bool AsyncOperationIsValid(_In_opt_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    AsyncOperationKind AsyncOperationGetKind(_In_ AsyncOperationHandle operation) noexcept;

    _Ret_maybenull_
    void* AsyncOperationContext(_In_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    NTSTATUS EngineDrainAsync() noexcept;

#if defined(WKNET_USER_MODE_TEST)
    void TestSetAsyncAutoRun(bool enabled) noexcept;
    NTSTATUS TestRunAsyncOperation(_In_ AsyncOperationHandle operation) noexcept;
#endif
}
}
