#include <KernelHttp/engine/Async.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
extern "C" NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);
#endif

namespace KernelHttp
{
namespace engine
{
namespace
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    bool g_testAsyncAutoRun = true;
    volatile LONG g_asyncInFlight = 0;
#else
    volatile LONG g_asyncInFlight = 0;
    volatile LONG g_asyncDrainState = 0;
    KEVENT g_asyncDrainEvent = {};
    constexpr ULONG KhMaxAsyncThreads = 256;
    FAST_MUTEX g_asyncThreadTableLock = {};
    volatile LONG g_asyncThreadTableLockState = 0;
    PETHREAD g_asyncThreads[KhMaxAsyncThreads] = {};
    bool g_asyncThreadReservations[KhMaxAsyncThreads] = {};
#endif

    _Ret_maybenull_
    KhAsyncOperation* AllocateOperation() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(operation);
#else
        FreeNonPagedObject(operation);
#endif
    }

    void AddRef(_In_ KhAsyncOperation* operation) noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        ++operation->ReferenceCount;
#else
        InterlockedIncrement(&operation->ReferenceCount);
#endif
    }

    void ReleaseRef(_In_ KhAsyncOperation* operation) noexcept
    {
        LONG newCount = 0;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
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
#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        operation->State = static_cast<LONG>(state);
#else
        InterlockedExchange(&operation->State, static_cast<LONG>(state));
#endif
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    void EnsureAsyncThreadTableLockInitialized() noexcept
    {
        if (InterlockedCompareExchange(&g_asyncThreadTableLockState, 0, 0) == 2) {
            return;
        }

        if (InterlockedCompareExchange(&g_asyncThreadTableLockState, 1, 0) == 0) {
            ExInitializeFastMutex(&g_asyncThreadTableLock);
            InterlockedExchange(&g_asyncThreadTableLockState, 2);
            return;
        }

        LARGE_INTEGER delay = {};
        delay.QuadPart = -10 * 1000;
        while (InterlockedCompareExchange(&g_asyncThreadTableLockState, 0, 0) != 2) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    void AcquireAsyncThreadTableLock() noexcept
    {
        EnsureAsyncThreadTableLockInitialized();
        ExAcquireFastMutex(&g_asyncThreadTableLock);
    }

    void ReleaseAsyncThreadTableLock() noexcept
    {
        ExReleaseFastMutex(&g_asyncThreadTableLock);
    }

    void ReclaimCompletedAsyncThreadsLocked() noexcept
    {
        LARGE_INTEGER zeroTimeout = {};
        for (ULONG index = 0; index < KhMaxAsyncThreads; ++index) {
            PETHREAD thread = g_asyncThreads[index];
            if (thread != nullptr &&
                KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, &zeroTimeout) == STATUS_SUCCESS) {
                g_asyncThreads[index] = nullptr;
                ObDereferenceObject(thread);
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS ReserveAsyncThreadSlot(_Out_ ULONG* slotIndex) noexcept
    {
        if (slotIndex == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *slotIndex = KhMaxAsyncThreads;
        NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
        AcquireAsyncThreadTableLock();
        ReclaimCompletedAsyncThreadsLocked();
        for (ULONG index = 0; index < KhMaxAsyncThreads; ++index) {
            if (g_asyncThreads[index] == nullptr && !g_asyncThreadReservations[index]) {
                g_asyncThreadReservations[index] = true;
                *slotIndex = index;
                status = STATUS_SUCCESS;
                break;
            }
        }
        ReleaseAsyncThreadTableLock();
        return status;
    }

    void CancelAsyncThreadSlotReservation(ULONG slotIndex) noexcept
    {
        if (slotIndex >= KhMaxAsyncThreads) {
            return;
        }

        AcquireAsyncThreadTableLock();
        g_asyncThreadReservations[slotIndex] = false;
        ReleaseAsyncThreadTableLock();
    }

    _Must_inspect_result_
    NTSTATUS CommitAsyncThreadSlot(ULONG slotIndex, _In_ PETHREAD thread) noexcept
    {
        if (slotIndex >= KhMaxAsyncThreads || thread == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
        AcquireAsyncThreadTableLock();
        if (g_asyncThreadReservations[slotIndex] &&
            g_asyncThreads[slotIndex] == nullptr) {
            g_asyncThreads[slotIndex] = thread;
            g_asyncThreadReservations[slotIndex] = false;
            status = STATUS_SUCCESS;
        }
        ReleaseAsyncThreadTableLock();
        return status;
    }

    _Ret_maybenull_
    PETHREAD TakeAsyncThreadForJoin() noexcept
    {
        PETHREAD thread = nullptr;
        AcquireAsyncThreadTableLock();
        for (ULONG index = 0; index < KhMaxAsyncThreads; ++index) {
            if (g_asyncThreads[index] != nullptr) {
                thread = g_asyncThreads[index];
                g_asyncThreads[index] = nullptr;
                break;
            }
        }
        ReleaseAsyncThreadTableLock();
        return thread;
    }

    void EnsureAsyncDrainInitialized() noexcept
    {
        if (InterlockedCompareExchange(&g_asyncDrainState, 0, 0) == 2) {
            return;
        }

        if (InterlockedCompareExchange(&g_asyncDrainState, 1, 0) == 0) {
            KeInitializeEvent(&g_asyncDrainEvent, NotificationEvent, TRUE);
            InterlockedExchange(&g_asyncDrainState, 2);
            return;
        }

        LARGE_INTEGER delay = {};
        delay.QuadPart = -10 * 1000;
        while (InterlockedCompareExchange(&g_asyncDrainState, 0, 0) != 2) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }
#endif

    void BeginAsyncThread() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        ++g_asyncInFlight;
#else
        EnsureAsyncDrainInitialized();
        InterlockedIncrement(&g_asyncInFlight);
        KeClearEvent(&g_asyncDrainEvent);
#endif
    }

    void EndAsyncThread() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    void AsyncThreadRoutine(_In_ void* context)
    {
        auto* operation = static_cast<KhAsyncOperation*>(context);
        if (operation != nullptr) {
            const NTSTATUS status = RunOperation(operation);
            UNREFERENCED_PARAMETER(status);
            ReleaseRef(operation);
            EndAsyncThread();
        }

        PsTerminateSystemThread(STATUS_SUCCESS);
    }
#endif
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

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
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

        if (ReadState(operation) != KhAsyncState::Pending ||
            !TryExchangeFlag(&operation->Queued, 1, 0)) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (operation->Canceled != 0) {
            CompleteOperation(operation, STATUS_CANCELLED);
            return STATUS_SUCCESS;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testAsyncAutoRun) {
            const NTSTATUS status = RunOperation(operation);
            UNREFERENCED_PARAMETER(status);
        }
        else {
            AddRef(operation);
            operation->TestWorkerReferenceHeld = true;
            BeginAsyncThread();
        }
        return STATUS_SUCCESS;
#else
        ULONG threadSlot = KhMaxAsyncThreads;
        NTSTATUS status = ReserveAsyncThreadSlot(&threadSlot);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&operation->Queued, 0);
            return status;
        }

        BeginAsyncThread();
        AddRef(operation);
        HANDLE threadHandle = nullptr;
        status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            AsyncThreadRoutine,
            operation);
        if (!NT_SUCCESS(status)) {
            ReleaseRef(operation);
            EndAsyncThread();
            CancelAsyncThreadSlotReservation(threadSlot);
            InterlockedExchange(&operation->Queued, 0);
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
            const NTSTATUS waitStatus = ZwWaitForSingleObject(threadHandle, FALSE, nullptr);
            UNREFERENCED_PARAMETER(waitStatus);
            CancelAsyncThreadSlotReservation(threadSlot);
            ZwClose(threadHandle);
            return status;
        }

        status = CommitAsyncThreadSlot(threadSlot, threadObject);
        if (!NT_SUCCESS(status)) {
            KeWaitForSingleObject(threadObject, Executive, KernelMode, FALSE, nullptr);
            ObDereferenceObject(threadObject);
            CancelAsyncThreadSlotReservation(threadSlot);
            ZwClose(threadHandle);
            return status;
        }

        ZwClose(threadHandle);
        return STATUS_SUCCESS;
#endif
    }

    NTSTATUS KhAsyncOperationCancel(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsOpenOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return g_asyncInFlight == 0 ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
#else
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        EnsureAsyncDrainInitialized();

        LARGE_INTEGER timeout = {};
        timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
        while (InterlockedCompareExchange(&g_asyncInFlight, 0, 0) != 0) {
            const NTSTATUS status = KeWaitForSingleObject(
                &g_asyncDrainEvent,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            if (status != STATUS_SUCCESS && status != STATUS_TIMEOUT) {
                return status;
            }
        }

        for (;;) {
            PETHREAD thread = TakeAsyncThreadForJoin();
            if (thread == nullptr) {
                break;
            }

            KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, nullptr);
            ObDereferenceObject(thread);
        }

        return STATUS_SUCCESS;
#endif
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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
            EndAsyncThread();
        }
        return status;
    }
#endif
}
}
