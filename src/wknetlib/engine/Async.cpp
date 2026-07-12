#include <wknet/engine/Async.h>

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
    constexpr ULONG KhAsyncWorkerCount = 4;
    constexpr ULONG KhMaxAsyncQueueDepth = 256;
    FAST_MUTEX g_asyncQueueLock = {};
    KSEMAPHORE g_asyncQueueSemaphore = {};
    KEVENT g_asyncWorkersExitedEvent = {};
    volatile LONG g_asyncQueueStopped = 0;
    volatile LONG g_asyncQueueDepth = 0;
    volatile LONG g_asyncWorkerExitCount = 0;
    KhAsyncOperation* g_asyncQueueHead = nullptr;
    KhAsyncOperation* g_asyncQueueTail = nullptr;
    PETHREAD g_asyncWorkers[KhAsyncWorkerCount] = {};
    KhAsyncOperation* g_asyncWorkerOperations[KhAsyncWorkerCount] = {};
#endif

    _Ret_maybenull_
    KhAsyncOperation* AllocateOperation() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return static_cast<KhAsyncOperation*>(calloc(1, sizeof(KhAsyncOperation)));
#else
        return AllocateNonPagedObject<KhAsyncOperation>();
#endif
    }

    void FreeOperation(_In_opt_ KhAsyncOperation* operation) noexcept
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

    void AddRef(_In_ KhAsyncOperation* operation) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        ++operation->ReferenceCount;
#else
        InterlockedIncrement(&operation->ReferenceCount);
#endif
    }

    void ReleaseRef(_In_ KhAsyncOperation* operation) noexcept
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

    KhAsyncState ReadState(_In_ const KhAsyncOperation* operation) noexcept
    {
        if (operation == nullptr) {
            return KhAsyncState::Completed;
        }

#if defined(WKNET_USER_MODE_TEST)
        return static_cast<KhAsyncState>(operation->State);
#else
        return static_cast<KhAsyncState>(InterlockedCompareExchange(
            const_cast<volatile LONG*>(&operation->State),
            0,
            0));
#endif
    }

    void WriteState(_In_ KhAsyncOperation* operation, KhAsyncState state) noexcept
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

    void CompleteOperation(_In_ KhAsyncOperation* operation, NTSTATUS status) noexcept;
    NTSTATUS RunOperation(_In_ KhAsyncOperation* operation) noexcept;
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

    void UnlinkAllQueuedOperationsLocked(_Out_ KhAsyncOperation** head) noexcept
    {
        if (head != nullptr) {
            *head = g_asyncQueueHead;
        }
        g_asyncQueueHead = nullptr;
        g_asyncQueueTail = nullptr;
        InterlockedExchange(&g_asyncQueueDepth, 0);
    }

    _Must_inspect_result_
    NTSTATUS EnqueueAsyncOperation(_In_ KhAsyncOperation* operation) noexcept
    {
        if (operation == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        AcquireAsyncQueueLock();
        if (InterlockedCompareExchange(&g_asyncQueueStopped, 0, 0) != 0) {
            status = STATUS_DEVICE_NOT_READY;
        }
        else if (InterlockedCompareExchange(&g_asyncQueueDepth, 0, 0) >= static_cast<LONG>(KhMaxAsyncQueueDepth)) {
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
    KhAsyncOperation* DequeueAsyncOperation(ULONG workerIndex) noexcept
    {
        KhAsyncOperation* operation = nullptr;
        AcquireAsyncQueueLock();
        operation = g_asyncQueueHead;
        if (operation != nullptr) {
            g_asyncQueueHead = operation->QueueNext;
            if (g_asyncQueueHead == nullptr) {
                g_asyncQueueTail = nullptr;
            }
            operation->QueueNext = nullptr;
            InterlockedDecrement(&g_asyncQueueDepth);
            if (workerIndex < KhAsyncWorkerCount) {
                g_asyncWorkerOperations[workerIndex] = operation;
            }
        }
        ReleaseAsyncQueueLock();
        return operation;
    }

    void CompleteQueuedOperationsForShutdown() noexcept
    {
        KhAsyncOperation* head = nullptr;
        AcquireAsyncQueueLock();
        UnlinkAllQueuedOperationsLocked(&head);
        ReleaseAsyncQueueLock();

        while (head != nullptr) {
            KhAsyncOperation* operation = head;
            head = head->QueueNext;
            operation->QueueNext = nullptr;
            CompleteOperation(operation, STATUS_CANCELLED);
            ReleaseRef(operation);
            EndAsyncOperation();
        }
    }

    void ClearWorkerOperation(ULONG workerIndex) noexcept
    {
        if (workerIndex >= KhAsyncWorkerCount) {
            return;
        }

        AcquireAsyncQueueLock();
        g_asyncWorkerOperations[workerIndex] = nullptr;
        ReleaseAsyncQueueLock();
    }

    void CancelRunningOperationsForShutdown() noexcept
    {
        AcquireAsyncQueueLock();
        for (ULONG index = 0; index < KhAsyncWorkerCount; ++index) {
            KhAsyncOperation* operation = g_asyncWorkerOperations[index];
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
            static_cast<LONG>(KhAsyncWorkerCount),
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
        for (ULONG index = 0; index < KhAsyncWorkerCount; ++index) {
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

            KhAsyncOperation* operation = DequeueAsyncOperation(workerIndex);
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

        if (InterlockedIncrement(&g_asyncWorkerExitCount) == static_cast<LONG>(KhAsyncWorkerCount)) {
            KeSetEvent(&g_asyncWorkersExitedEvent, IO_NO_INCREMENT, FALSE);
        }

        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    _Must_inspect_result_
    NTSTATUS StartAsyncWorkers() noexcept
    {
        for (ULONG index = 0; index < KhAsyncWorkerCount; ++index) {
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
                static_cast<LONG>(KhMaxAsyncQueueDepth + KhAsyncWorkerCount));
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

    bool IsLiveOperation(KH_ASYNC_OPERATION operation) noexcept
    {
        return operation != nullptr && operation->Magic == KhAsyncOperationMagic;
    }

    bool IsOpenOperation(KH_ASYNC_OPERATION operation) noexcept
    {
        return operation != nullptr && operation->Magic == KhAsyncOperationMagic && operation->Closed == 0;
    }

    void CompleteOperation(_In_ KhAsyncOperation* operation, NTSTATUS status) noexcept
    {
        if (!TryExchangeFlag(&operation->Completed, 1, 0)) {
            return;
        }

        operation->Status = status;
        WriteState(operation, KhAsyncState::Completed);

#if defined(WKNET_USER_MODE_TEST)
        operation->CompletionSignaled = true;
#else
        KeSetEvent(&operation->CompletedEvent, IO_NO_INCREMENT, FALSE);
#endif

        if (operation->CompletionCallback != nullptr) {
            operation->CompletionCallback(operation->CompletionContext, status);
        }
    }

    NTSTATUS RunOperation(_In_ KhAsyncOperation* operation) noexcept
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

        WriteState(operation, KhAsyncState::Running);
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

    NTSTATUS KhAsyncOperationCreate(
        const KhAsyncCreateOptions& options,
        KH_ASYNC_OPERATION* operation) noexcept
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

        newOperation->Magic = KhAsyncOperationMagic;
        newOperation->Closed = 0;
        newOperation->Kind = options.Kind;
        newOperation->ReferenceCount = 1;
        newOperation->Canceled = 0;
        newOperation->Completed = 0;
        newOperation->State = static_cast<LONG>(KhAsyncState::Pending);
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

        if (!options.StartSuspended) {
            NTSTATUS status = KhAsyncOperationQueue(newOperation);
            if (!NT_SUCCESS(status)) {
                KhAsyncOperationRelease(newOperation);
                *operation = nullptr;
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS KhAsyncOperationQueue(KH_ASYNC_OPERATION operation) noexcept
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

        if (ReadState(operation) != KhAsyncState::Pending ||
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

    NTSTATUS KhAsyncOperationCancel(KH_ASYNC_OPERATION operation) noexcept
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
        if (ReadState(operation) == KhAsyncState::Pending) {
            CompleteOperation(operation, STATUS_CANCELLED);
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS KhAsyncOperationWait(
        KH_ASYNC_OPERATION operation,
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

    void KhAsyncOperationRelease(KH_ASYNC_OPERATION operation) noexcept
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

    NTSTATUS KhAsyncOperationStatus(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        return operation->Status;
    }

    bool KhAsyncOperationIsCanceled(KH_ASYNC_OPERATION operation) noexcept
    {
        return IsLiveOperation(operation) && operation->Canceled != 0;
    }

    bool KhAsyncOperationIsCompleted(KH_ASYNC_OPERATION operation) noexcept
    {
        return IsLiveOperation(operation) && operation->Completed != 0;
    }

    KhAsyncState KhAsyncOperationState(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsLiveOperation(operation)) {
            return KhAsyncState::Completed;
        }

        return ReadState(operation);
    }

    bool KhAsyncOperationIsValid(KH_ASYNC_OPERATION operation) noexcept
    {
        return IsOpenOperation(operation);
    }

    KhAsyncOperationKind KhAsyncOperationGetKind(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return KhAsyncOperationKind::HttpSend;
        }

        return operation->Kind;
    }

    void* KhAsyncOperationContext(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return nullptr;
        }

        return operation->Context;
    }

    NTSTATUS KhEngineDrainAsync() noexcept
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
    void KhTestSetAsyncAutoRun(bool enabled) noexcept
    {
        g_testAsyncAutoRun = enabled;
    }

    NTSTATUS KhTestRunAsyncOperation(KH_ASYNC_OPERATION operation) noexcept
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
}
}
