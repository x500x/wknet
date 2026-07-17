#include "session/Async.h"
#include "rtl/TraceInternal.h"

#if defined(WKNET_USER_MODE_TEST)
#include <stdlib.h>
#endif

#if !defined(WKNET_USER_MODE_TEST)
extern "C" NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);
#endif

namespace wknet
{
namespace session
{
namespace
{
#if defined(WKNET_USER_MODE_TEST)
    bool g_testAsyncAutoRun = true;
    volatile LONG g_asyncInFlight = 0;
#else
    volatile LONG g_asyncInFlight = 0;
    volatile LONG g_asyncRuntimeState = 0;
    KEVENT g_asyncDrainEvent = {};
    ULONG g_asyncWorkerCount = 4;
    ULONG g_asyncMaxQueueDepth = 256;
    constexpr ULONG AsyncWorkerCountMin = 1;
    constexpr ULONG AsyncWorkerCountMax = 16;
    constexpr ULONG AsyncQueueDepthMin = 16;
    constexpr ULONG AsyncQueueDepthMax = 4096;
    constexpr ULONG AsyncWorkerCountDefault = 4;
    constexpr ULONG AsyncQueueDepthDefault = 256;
    FAST_MUTEX g_asyncQueueLock = {};
    KSEMAPHORE g_asyncQueueSemaphore = {};
    KEVENT g_asyncWorkersExitedEvent = {};
    volatile LONG g_asyncQueueStopped = 0;
    volatile LONG g_asyncQueueDepth = 0;
    volatile LONG g_asyncWorkerExitCount = 0;
    AsyncOperation* g_asyncQueueHead = nullptr;
    AsyncOperation* g_asyncQueueTail = nullptr;
    PETHREAD g_asyncWorkers[AsyncWorkerCountMax] = {};
    AsyncOperation* g_asyncWorkerOperations[AsyncWorkerCountMax] = {};
#endif

    _Ret_maybenull_
    AsyncOperation* AllocateOperation() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return static_cast<AsyncOperation*>(calloc(1, sizeof(AsyncOperation)));
#else
        return AllocateNonPagedObject<AsyncOperation>();
#endif
    }

    void FreeOperation(_In_opt_ AsyncOperation* operation) noexcept
    {
        if (operation == nullptr) {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        free(operation);
#else
        FreeNonPagedObject(operation);
#endif
    }

    void AddRef(_In_ AsyncOperation* operation) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        ++operation->ReferenceCount;
#else
        InterlockedIncrement(&operation->ReferenceCount);
#endif
    }

    void ReleaseRef(_In_ AsyncOperation* operation) noexcept
    {
        LONG newCount = 0;
#if defined(WKNET_USER_MODE_TEST)
        --operation->ReferenceCount;
        newCount = operation->ReferenceCount;
#else
        newCount = InterlockedDecrement(&operation->ReferenceCount);
#endif
        if (newCount != 0) {
            return;
        }

        if (operation->CleanupRoutine != nullptr) {
            operation->CleanupRoutine(operation->Context);
            operation->CleanupRoutine = nullptr;
            operation->Context = nullptr;
        }

        FreeOperation(operation);
    }

    _Must_inspect_result_
    bool TryExchangeFlag(_Inout_ volatile LONG* target, LONG desired, LONG expected) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        if (*target != expected) {
            return false;
        }
        *target = desired;
        return true;
#else
        return InterlockedCompareExchange(target, desired, expected) == expected;
#endif
    }

    AsyncState ReadState(_In_ const AsyncOperation* operation) noexcept
    {
        if (operation == nullptr) {
            return AsyncState::Completed;
        }

#if defined(WKNET_USER_MODE_TEST)
        return static_cast<AsyncState>(operation->State);
#else
        return static_cast<AsyncState>(InterlockedCompareExchange(
            const_cast<volatile LONG*>(&operation->State),
            0,
            0));
#endif
    }

    void WriteState(_In_ AsyncOperation* operation, AsyncState state) noexcept
    {
        if (operation == nullptr) {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        operation->State = static_cast<LONG>(state);
#else
        InterlockedExchange(&operation->State, static_cast<LONG>(state));
#endif
    }

    void CompleteOperation(_In_ AsyncOperation* operation, NTSTATUS status) noexcept;
    NTSTATUS RunOperation(_In_ AsyncOperation* operation) noexcept;
    void EndAsyncOperation() noexcept;

#if !defined(WKNET_USER_MODE_TEST)
    void AcquireAsyncQueueLock() noexcept
    {
        ExAcquireFastMutex(&g_asyncQueueLock);
    }

    void ReleaseAsyncQueueLock() noexcept
    {
        ExReleaseFastMutex(&g_asyncQueueLock);
    }

    void UnlinkAllQueuedOperationsLocked(_Out_ AsyncOperation** head) noexcept
    {
        if (head != nullptr) {
            *head = g_asyncQueueHead;
        }
        g_asyncQueueHead = nullptr;
        g_asyncQueueTail = nullptr;
        InterlockedExchange(&g_asyncQueueDepth, 0);
    }

    _Must_inspect_result_
    NTSTATUS EnqueueAsyncOperation(_In_ AsyncOperation* operation) noexcept
    {
        if (operation == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        AcquireAsyncQueueLock();
        if (InterlockedCompareExchange(&g_asyncQueueStopped, 0, 0) != 0) {
            status = STATUS_DEVICE_NOT_READY;
        }
        else if (InterlockedCompareExchange(&g_asyncQueueDepth, 0, 0) >= static_cast<LONG>(g_asyncMaxQueueDepth)) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else {
            operation->QueueNext = nullptr;
            if (g_asyncQueueTail != nullptr) {
                g_asyncQueueTail->QueueNext = operation;
            }
            else {
                g_asyncQueueHead = operation;
            }
            g_asyncQueueTail = operation;
            InterlockedIncrement(&g_asyncQueueDepth);
        }
        ReleaseAsyncQueueLock();

        if (NT_SUCCESS(status)) {
            KeReleaseSemaphore(&g_asyncQueueSemaphore, IO_NO_INCREMENT, 1, FALSE);
        }
        return status;
    }

    _Ret_maybenull_
    AsyncOperation* DequeueAsyncOperation(ULONG workerIndex) noexcept
    {
        AsyncOperation* operation = nullptr;
        AcquireAsyncQueueLock();
        operation = g_asyncQueueHead;
        if (operation != nullptr) {
            g_asyncQueueHead = operation->QueueNext;
            if (g_asyncQueueHead == nullptr) {
                g_asyncQueueTail = nullptr;
            }
            operation->QueueNext = nullptr;
            InterlockedDecrement(&g_asyncQueueDepth);
            if (workerIndex < g_asyncWorkerCount) {
                g_asyncWorkerOperations[workerIndex] = operation;
            }
        }
        ReleaseAsyncQueueLock();
        return operation;
    }

    void CompleteQueuedOperationsForShutdown() noexcept
    {
        AsyncOperation* head = nullptr;
        AcquireAsyncQueueLock();
        UnlinkAllQueuedOperationsLocked(&head);
        ReleaseAsyncQueueLock();

        while (head != nullptr) {
            AsyncOperation* operation = head;
            head = head->QueueNext;
            operation->QueueNext = nullptr;
            CompleteOperation(operation, STATUS_CANCELLED);
            ReleaseRef(operation);
            EndAsyncOperation();
        }
    }

    void ClearWorkerOperation(ULONG workerIndex) noexcept
    {
        if (workerIndex >= g_asyncWorkerCount) {
            return;
        }

        AcquireAsyncQueueLock();
        g_asyncWorkerOperations[workerIndex] = nullptr;
        ReleaseAsyncQueueLock();
    }

    void CancelRunningOperationsForShutdown() noexcept
    {
        AcquireAsyncQueueLock();
        for (ULONG index = 0; index < g_asyncWorkerCount; ++index) {
            AsyncOperation* operation = g_asyncWorkerOperations[index];
            if (operation != nullptr) {
                InterlockedExchange(&operation->Canceled, 1);
            }
        }
        ReleaseAsyncQueueLock();
    }

    void WakeAsyncWorkers() noexcept
    {
        KeReleaseSemaphore(
            &g_asyncQueueSemaphore,
            IO_NO_INCREMENT,
            static_cast<LONG>(g_asyncWorkerCount),
            FALSE);
    }

    NTSTATUS WaitForAsyncInFlightToDrain(_In_opt_ LARGE_INTEGER* timeout) noexcept
    {
        if (InterlockedCompareExchange(&g_asyncInFlight, 0, 0) == 0) {
            return STATUS_SUCCESS;
        }

        const NTSTATUS status = KeWaitForSingleObject(
            &g_asyncDrainEvent,
            Executive,
            KernelMode,
            FALSE,
            timeout);
        if (status == STATUS_SUCCESS) {
            return STATUS_SUCCESS;
        }

        return status == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : status;
    }

    NTSTATUS JoinReferencedAsyncWorkers(_In_opt_ LARGE_INTEGER* timeout) noexcept
    {
        for (ULONG index = 0; index < g_asyncWorkerCount; ++index) {
            PETHREAD thread = g_asyncWorkers[index];
            if (thread == nullptr) {
                continue;
            }

            const NTSTATUS status = KeWaitForSingleObject(
                thread,
                Executive,
                KernelMode,
                FALSE,
                timeout);
            if (status != STATUS_SUCCESS) {
                return status == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : status;
            }

            ObDereferenceObject(thread);
            g_asyncWorkers[index] = nullptr;
        }

        RtlZeroMemory(g_asyncWorkerOperations, sizeof(g_asyncWorkerOperations));
        return STATUS_SUCCESS;
    }

    void AsyncWorkerRoutine(_In_ void* context)
    {
        const ULONG workerIndex = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(context));

        for (;;) {
            NTSTATUS waitStatus = KeWaitForSingleObject(
                &g_asyncQueueSemaphore,
                Executive,
                KernelMode,
                FALSE,
                nullptr);
            if (!NT_SUCCESS(waitStatus)) {
                break;
            }

            AsyncOperation* operation = DequeueAsyncOperation(workerIndex);
            if (operation == nullptr) {
                if (InterlockedCompareExchange(&g_asyncQueueStopped, 0, 0) != 0) {
                    break;
                }
                continue;
            }

            const NTSTATUS status = RunOperation(operation);
            UNREFERENCED_PARAMETER(status);
            ClearWorkerOperation(workerIndex);
            ReleaseRef(operation);
            EndAsyncOperation();
        }

        if (InterlockedIncrement(&g_asyncWorkerExitCount) == static_cast<LONG>(g_asyncWorkerCount)) {
            KeSetEvent(&g_asyncWorkersExitedEvent, IO_NO_INCREMENT, FALSE);
        }

        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    _Must_inspect_result_
    NTSTATUS StartAsyncWorkers() noexcept
    {
        for (ULONG index = 0; index < g_asyncWorkerCount; ++index) {
            if (g_asyncWorkers[index] != nullptr) {
                continue;
            }

            HANDLE threadHandle = nullptr;
            NTSTATUS status = PsCreateSystemThread(
                &threadHandle,
                THREAD_ALL_ACCESS,
                nullptr,
                nullptr,
                nullptr,
                AsyncWorkerRoutine,
                reinterpret_cast<void*>(static_cast<ULONG_PTR>(index)));
            if (!NT_SUCCESS(status)) {
                InterlockedExchange(&g_asyncQueueStopped, 1);
                WakeAsyncWorkers();
                return status;
            }

            PETHREAD threadObject = nullptr;
            status = ObReferenceObjectByHandle(
                threadHandle,
                THREAD_ALL_ACCESS,
                *PsThreadType,
                KernelMode,
                reinterpret_cast<PVOID*>(&threadObject),
                nullptr);
            if (!NT_SUCCESS(status)) {
                InterlockedExchange(&g_asyncQueueStopped, 1);
                WakeAsyncWorkers();
                LARGE_INTEGER timeout = {};
                timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
                const NTSTATUS waitStatus = ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
                UNREFERENCED_PARAMETER(waitStatus);
                ZwClose(threadHandle);
                return status;
            }

            ZwClose(threadHandle);
            g_asyncWorkers[index] = threadObject;
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS EnsureAsyncRuntimeInitialized() noexcept
    {
        if (InterlockedCompareExchange(&g_asyncRuntimeState, 0, 0) == 2) {
            return STATUS_SUCCESS;
        }

        if (InterlockedCompareExchange(&g_asyncRuntimeState, 1, 0) == 0) {
            ExInitializeFastMutex(&g_asyncQueueLock);
            KeInitializeSemaphore(
                &g_asyncQueueSemaphore,
                0,
                static_cast<LONG>(g_asyncMaxQueueDepth + g_asyncWorkerCount));
            KeInitializeEvent(&g_asyncDrainEvent, NotificationEvent, TRUE);
            KeInitializeEvent(&g_asyncWorkersExitedEvent, NotificationEvent, FALSE);
            InterlockedExchange(&g_asyncQueueStopped, 0);
            InterlockedExchange(&g_asyncQueueDepth, 0);
            InterlockedExchange(&g_asyncWorkerExitCount, 0);
            g_asyncQueueHead = nullptr;
            g_asyncQueueTail = nullptr;
            RtlZeroMemory(g_asyncWorkers, sizeof(g_asyncWorkers));
            RtlZeroMemory(g_asyncWorkerOperations, sizeof(g_asyncWorkerOperations));

            NTSTATUS status = StartAsyncWorkers();
            if (!NT_SUCCESS(status)) {
                WakeAsyncWorkers();
                LARGE_INTEGER timeout = {};
                timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
                const NTSTATUS joinStatus = JoinReferencedAsyncWorkers(&timeout);
                UNREFERENCED_PARAMETER(joinStatus);
                InterlockedExchange(&g_asyncRuntimeState, 3);
                return status;
            }

            InterlockedExchange(&g_asyncRuntimeState, 2);
            return STATUS_SUCCESS;
        }

        LARGE_INTEGER delay = {};
        delay.QuadPart = -10 * 1000;
        LONG state = InterlockedCompareExchange(&g_asyncRuntimeState, 0, 0);
        while (state == 1) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            state = InterlockedCompareExchange(&g_asyncRuntimeState, 0, 0);
        }

        return state == 2 ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
    }
#endif

    void BeginAsyncOperation() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        ++g_asyncInFlight;
#else
        InterlockedIncrement(&g_asyncInFlight);
        KeClearEvent(&g_asyncDrainEvent);
#endif
    }

    void EndAsyncOperation() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        if (g_asyncInFlight > 0) {
            --g_asyncInFlight;
        }
#else
        const LONG remaining = InterlockedDecrement(&g_asyncInFlight);
        if (remaining == 0) {
            KeSetEvent(&g_asyncDrainEvent, IO_NO_INCREMENT, FALSE);
        }
#endif
    }

    bool IsLiveOperation(AsyncOperationHandle operation) noexcept
    {
        return operation != nullptr && operation->Magic == AsyncOperationMagic;
    }

    bool IsOpenOperation(AsyncOperationHandle operation) noexcept
    {
        return operation != nullptr && operation->Magic == AsyncOperationMagic && operation->Closed == 0;
    }

    void CompleteOperation(_In_ AsyncOperation* operation, NTSTATUS status) noexcept
    {
        if (!TryExchangeFlag(&operation->Completed, 1, 0)) {
            return;
        }

        operation->Status = status;
        WriteState(operation, AsyncState::Completed);
        const TraceCorrelation correlation = { operation->TraceOperationId, 0, 0 };
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentSession,
            NT_SUCCESS(status) ? ::wknet::TraceLevel::Info : ::wknet::TraceLevel::Error,
            &correlation,
            NT_SUCCESS(status) ? "async.operation.complete kind=%u status=0x%08X" :
                "async.operation.failed kind=%u status=0x%08X",
            static_cast<ULONG>(operation->Kind),
            static_cast<ULONG>(status));

#if defined(WKNET_USER_MODE_TEST)
        operation->CompletionSignaled = true;
#else
        KeSetEvent(&operation->CompletedEvent, IO_NO_INCREMENT, FALSE);
#endif

        if (operation->CompletionCallback != nullptr) {
            operation->CompletionCallback(operation->CompletionContext, status);
        }
    }

    NTSTATUS RunOperation(_In_ AsyncOperation* operation) noexcept
    {
        if (!IsLiveOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (operation->Completed != 0) {
            return operation->Status;
        }

        if (operation->Canceled != 0) {
            CompleteOperation(operation, STATUS_CANCELLED);
            return STATUS_CANCELLED;
        }

        WriteState(operation, AsyncState::Running);
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        if (operation->WorkerRoutine != nullptr) {
            status = operation->WorkerRoutine(operation, operation->Context);
        }

        if (operation->Canceled != 0 && status == STATUS_PENDING) {
            status = STATUS_CANCELLED;
        }

        CompleteOperation(operation, status);

        return operation->Status;
    }

}

    NTSTATUS AsyncOperationCreate(
        const AsyncCreateOptions& options,
        AsyncOperationHandle* operation) noexcept
    {
        if (operation != nullptr) {
            *operation = nullptr;
        }

        if (operation == nullptr || options.WorkerRoutine == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        auto* newOperation = AllocateOperation();
        if (newOperation == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newOperation->Magic = AsyncOperationMagic;
        newOperation->Closed = 0;
        newOperation->Kind = options.Kind;
        newOperation->TraceOperationId = options.TraceOperationId != 0 ?
            options.TraceOperationId : rtl::TraceAllocateCorrelationId();
        newOperation->ReferenceCount = 1;
        newOperation->Canceled = 0;
        newOperation->Completed = 0;
        newOperation->State = static_cast<LONG>(AsyncState::Pending);
        newOperation->Status = STATUS_PENDING;
        newOperation->WorkerRoutine = options.WorkerRoutine;
        newOperation->CleanupRoutine = options.CleanupRoutine;
        newOperation->Context = options.Context;
        newOperation->CompletionCallback = options.CompletionCallback;
        newOperation->CompletionContext = options.CompletionContext;
        newOperation->Queued = 0;

#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeEvent(&newOperation->CompletedEvent, NotificationEvent, FALSE);
#else
        newOperation->CompletionSignaled = false;
#endif

        *operation = newOperation;
        const TraceCorrelation correlation = { newOperation->TraceOperationId, 0, 0 };
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentSession,
            ::wknet::TraceLevel::Info,
            &correlation,
            "async.operation.created kind=%u suspended=%u",
            static_cast<ULONG>(newOperation->Kind),
            options.StartSuspended ? 1u : 0u);

        if (!options.StartSuspended) {
            NTSTATUS status = AsyncOperationQueue(newOperation);
            if (!NT_SUCCESS(status)) {
                AsyncOperationRelease(newOperation);
                *operation = nullptr;
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS AsyncOperationQueue(AsyncOperationHandle operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        NTSTATUS status = EnsureAsyncRuntimeInitialized();
        if (!NT_SUCCESS(status)) {
            return status;
        }
#endif

        if (ReadState(operation) != AsyncState::Pending ||
            !TryExchangeFlag(&operation->Queued, 1, 0)) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (operation->Canceled != 0) {
            CompleteOperation(operation, STATUS_CANCELLED);
            return STATUS_SUCCESS;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (g_testAsyncAutoRun) {
            const NTSTATUS status = RunOperation(operation);
            UNREFERENCED_PARAMETER(status);
        }
        else {
            AddRef(operation);
            operation->TestWorkerReferenceHeld = true;
            BeginAsyncOperation();
        }
        return STATUS_SUCCESS;
#else
        AddRef(operation);
        BeginAsyncOperation();
        status = EnqueueAsyncOperation(operation);
        if (!NT_SUCCESS(status)) {
            EndAsyncOperation();
            ReleaseRef(operation);
            InterlockedExchange(&operation->Queued, 0);
            return status;
        }

        return STATUS_SUCCESS;
#endif
    }

    NTSTATUS AsyncOperationCancel(AsyncOperationHandle operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
#endif

#if defined(WKNET_USER_MODE_TEST)
        operation->Canceled = 1;
#else
        InterlockedExchange(&operation->Canceled, 1);
#endif
        if (ReadState(operation) == AsyncState::Pending) {
            CompleteOperation(operation, STATUS_CANCELLED);
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS AsyncOperationWait(
        AsyncOperationHandle operation,
        ULONG timeoutMilliseconds) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
#endif

#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(timeoutMilliseconds);
        return operation->Status;
#else
        LARGE_INTEGER timeout = {};
        LARGE_INTEGER* timeoutPointer = nullptr;
        if (timeoutMilliseconds != 0xffffffffUL) {
            timeout.QuadPart = -static_cast<LONGLONG>(timeoutMilliseconds) * 10000LL;
            timeoutPointer = &timeout;
        }

        NTSTATUS status = KeWaitForSingleObject(
            &operation->CompletedEvent,
            Executive,
            KernelMode,
            FALSE,
            timeoutPointer);
        if (status == STATUS_SUCCESS) {
            return operation->Status;
        }

        return status;
#endif
    }

    void AsyncOperationRelease(AsyncOperationHandle operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return;
        }
#endif

        if (!TryExchangeFlag(&operation->Closed, 1, 0)) {
            return;
        }
        ReleaseRef(operation);
    }

    NTSTATUS AsyncOperationStatus(AsyncOperationHandle operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        return operation->Status;
    }

    bool AsyncOperationIsCanceled(AsyncOperationHandle operation) noexcept
    {
        return IsLiveOperation(operation) && operation->Canceled != 0;
    }

    bool AsyncOperationIsCompleted(AsyncOperationHandle operation) noexcept
    {
        return IsLiveOperation(operation) && operation->Completed != 0;
    }

    AsyncState AsyncOperationState(AsyncOperationHandle operation) noexcept
    {
        if (!IsLiveOperation(operation)) {
            return AsyncState::Completed;
        }

        return ReadState(operation);
    }

    bool AsyncOperationIsValid(AsyncOperationHandle operation) noexcept
    {
        return IsOpenOperation(operation);
    }

    AsyncOperationKind AsyncOperationGetKind(AsyncOperationHandle operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return AsyncOperationKind::HttpSend;
        }

        return operation->Kind;
    }

    void* AsyncOperationContext(AsyncOperationHandle operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return nullptr;
        }

        return operation->Context;
    }

    NTSTATUS EngineDrainAsync() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return g_asyncInFlight == 0 ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
#else
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        LONG state = InterlockedCompareExchange(&g_asyncRuntimeState, 0, 0);
        while (state == 1) {
            LARGE_INTEGER delay = {};
            delay.QuadPart = -10 * 1000;
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            state = InterlockedCompareExchange(&g_asyncRuntimeState, 0, 0);
        }

        if (state == 0) {
            return InterlockedCompareExchange(&g_asyncInFlight, 0, 0) == 0
                ? STATUS_SUCCESS
                : STATUS_IO_TIMEOUT;
        }

        if (state != 2) {
            return InterlockedCompareExchange(&g_asyncInFlight, 0, 0) == 0
                ? STATUS_SUCCESS
                : STATUS_IO_TIMEOUT;
        }

        InterlockedExchange(&g_asyncQueueStopped, 1);
        CompleteQueuedOperationsForShutdown();
        CancelRunningOperationsForShutdown();
        WakeAsyncWorkers();

        LARGE_INTEGER timeout = {};
        timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
        const NTSTATUS drainStatus = WaitForAsyncInFlightToDrain(&timeout);
        if (!NT_SUCCESS(drainStatus)) {
            return drainStatus;
        }

        const NTSTATUS joinStatus = JoinReferencedAsyncWorkers(&timeout);
        if (!NT_SUCCESS(joinStatus)) {
            return joinStatus;
        }

        InterlockedExchange(&g_asyncRuntimeState, 3);
        InterlockedExchange(&g_asyncQueueDepth, 0);
        g_asyncQueueHead = nullptr;
        g_asyncQueueTail = nullptr;
        return STATUS_SUCCESS;
#endif
    }

#if defined(WKNET_USER_MODE_TEST)
    void TestSetAsyncAutoRun(bool enabled) noexcept
    {
        g_testAsyncAutoRun = enabled;
    }

    NTSTATUS TestRunAsyncOperation(AsyncOperationHandle operation) noexcept
    {
        if (!IsLiveOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool releaseWorkerReference = operation->TestWorkerReferenceHeld;
        operation->TestWorkerReferenceHeld = false;
        const NTSTATUS status = RunOperation(operation);
        if (releaseWorkerReference) {
            ReleaseRef(operation);
            EndAsyncOperation();
        }
        return status;
    }
#endif

    NTSTATUS AsyncRuntimeConfigure(const AsyncRuntimeConfig& config) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(config);
        return STATUS_SUCCESS;
#else
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        const ULONG workers = config.WorkerCount == 0 ? AsyncWorkerCountDefault : config.WorkerCount;
        const ULONG depth = config.QueueDepth == 0 ? AsyncQueueDepthDefault : config.QueueDepth;
        if (workers < AsyncWorkerCountMin || workers > AsyncWorkerCountMax ||
            depth < AsyncQueueDepthMin || depth > AsyncQueueDepthMax) {
            return STATUS_INVALID_PARAMETER;
        }
        // Busy if runtime started.
        if (InterlockedCompareExchange(&g_asyncRuntimeState, 0, 0) != 0 ||
            InterlockedCompareExchange(&g_asyncInFlight, 0, 0) != 0) {
            return STATUS_DEVICE_BUSY;
        }
        g_asyncWorkerCount = workers;
        g_asyncMaxQueueDepth = depth;
        return STATUS_SUCCESS;
#endif
    }
}
}
