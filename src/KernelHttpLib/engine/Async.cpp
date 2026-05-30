#include <KernelHttp/engine/Async.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

namespace KernelHttp
{
namespace engine
{
namespace
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    bool g_testAsyncAutoRun = true;
#endif

    _Ret_maybenull_
    KhAsyncOperation* AllocateOperation() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhAsyncOperation*>(calloc(1, sizeof(KhAsyncOperation)));
#else
        return new KhAsyncOperation();
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
        delete operation;
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

    bool IsValidOperation(KH_ASYNC_OPERATION operation) noexcept
    {
        return operation != nullptr && operation->Magic == KhAsyncOperationMagic && !operation->Closed;
    }

    void CompleteOperation(_In_ KhAsyncOperation* operation, NTSTATUS status) noexcept
    {
        operation->Status = status;
        operation->State = KhAsyncState::Completed;

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
        if (!IsValidOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (operation->State == KhAsyncState::Completed) {
            return operation->Status;
        }

        if (operation->Canceled != 0) {
            CompleteOperation(operation, STATUS_CANCELLED);
            return STATUS_CANCELLED;
        }

        operation->State = KhAsyncState::Running;
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        if (operation->WorkerRoutine != nullptr) {
            status = operation->WorkerRoutine(operation, operation->Context);
        }

        if (operation->Canceled != 0 && status == STATUS_PENDING) {
            status = STATUS_CANCELLED;
        }

        if (operation->State != KhAsyncState::Completed) {
            CompleteOperation(operation, status);
        }

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
        newOperation->Closed = false;
        newOperation->Kind = options.Kind;
        newOperation->ReferenceCount = 1;
        newOperation->Canceled = 0;
        newOperation->State = KhAsyncState::Pending;
        newOperation->Status = STATUS_PENDING;
        newOperation->WorkerRoutine = options.WorkerRoutine;
        newOperation->CleanupRoutine = options.CleanupRoutine;
        newOperation->Context = options.Context;
        newOperation->CompletionCallback = options.CompletionCallback;
        newOperation->CompletionContext = options.CompletionContext;
        newOperation->Queued = false;

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
        if (!IsValidOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (operation->Queued || operation->State != KhAsyncState::Pending) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        operation->Queued = true;
        if (operation->Canceled != 0) {
            CompleteOperation(operation, STATUS_CANCELLED);
            return STATUS_SUCCESS;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testAsyncAutoRun) {
            const NTSTATUS status = RunOperation(operation);
            UNREFERENCED_PARAMETER(status);
        }
        return STATUS_SUCCESS;
#else
        AddRef(operation);
        HANDLE threadHandle = nullptr;
        NTSTATUS status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            AsyncThreadRoutine,
            operation);
        if (!NT_SUCCESS(status)) {
            ReleaseRef(operation);
            operation->Queued = false;
            return status;
        }

        ZwClose(threadHandle);
        return STATUS_SUCCESS;
#endif
    }

    NTSTATUS KhAsyncOperationCancel(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsValidOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        operation->Canceled = 1;
#else
        InterlockedExchange(&operation->Canceled, 1);
#endif
        if (operation->State == KhAsyncState::Pending) {
            CompleteOperation(operation, STATUS_CANCELLED);
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS KhAsyncOperationWait(
        KH_ASYNC_OPERATION operation,
        ULONG timeoutMilliseconds) noexcept
    {
        if (!IsValidOperation(operation)) {
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
        if (!IsValidOperation(operation)) {
            return;
        }

        operation->Closed = true;
        ReleaseRef(operation);
    }

    NTSTATUS KhAsyncOperationStatus(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsValidOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        return operation->Status;
    }

    bool KhAsyncOperationIsCanceled(KH_ASYNC_OPERATION operation) noexcept
    {
        return IsValidOperation(operation) && operation->Canceled != 0;
    }

    bool KhAsyncOperationIsCompleted(KH_ASYNC_OPERATION operation) noexcept
    {
        return IsValidOperation(operation) && operation->State == KhAsyncState::Completed;
    }

    bool KhAsyncOperationIsValid(KH_ASYNC_OPERATION operation) noexcept
    {
        return IsValidOperation(operation);
    }

    KhAsyncOperationKind KhAsyncOperationGetKind(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsValidOperation(operation)) {
            return KhAsyncOperationKind::HttpSend;
        }

        return operation->Kind;
    }

    void* KhAsyncOperationContext(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsValidOperation(operation)) {
            return nullptr;
        }

        return operation->Context;
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    void KhTestSetAsyncAutoRun(bool enabled) noexcept
    {
        g_testAsyncAutoRun = enabled;
    }

    NTSTATUS KhTestRunAsyncOperation(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!IsValidOperation(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        return RunOperation(operation);
    }
#endif
}
}
