#pragma once

#include <KernelHttp/KernelHttpConfig.h>

#include <wsk.h>

namespace KernelHttp
{
namespace net
{
    constexpr ULONG WskCancelCompletionTimeoutMilliseconds = 60000;
    static volatile LONG g_wskAbandonedIrpCount = 0;

    typedef void (*WskSyncCleanupRoutine)(_In_opt_ void* context);

    struct WskSyncIrpContext final
    {
        KEVENT Event = {};
        PIRP Irp = nullptr;
        volatile LONG ReferenceCount = 0;
        volatile LONG Completed = 0;
        NTSTATUS Status = STATUS_PENDING;
        SIZE_T Information = 0;
        WskSyncCleanupRoutine CleanupRoutine = nullptr;
        void* CleanupContext = nullptr;
    };

    inline void WskSyncReleaseContext(_In_opt_ WskSyncIrpContext* context) noexcept
    {
        if (context == nullptr) {
            return;
        }

        const LONG remaining = InterlockedDecrement(&context->ReferenceCount);
        if (remaining != 0) {
            return;
        }

        if (context->Irp != nullptr) {
            IoFreeIrp(context->Irp);
            context->Irp = nullptr;
        }

        if (context->CleanupRoutine != nullptr) {
            context->CleanupRoutine(context->CleanupContext);
            context->CleanupRoutine = nullptr;
            context->CleanupContext = nullptr;
        }

        delete context;
    }

    _Function_class_(IO_COMPLETION_ROUTINE)
    inline NTSTATUS WskSyncCompletionRoutine(
        _In_ PDEVICE_OBJECT deviceObject,
        _In_ PIRP irp,
        _In_opt_ PVOID context)
    {
        UNREFERENCED_PARAMETER(deviceObject);

        auto* sync = static_cast<WskSyncIrpContext*>(context);
        if (sync != nullptr) {
            sync->Status = irp->IoStatus.Status;
            sync->Information = static_cast<SIZE_T>(irp->IoStatus.Information);
            InterlockedExchange(&sync->Completed, 1);
            KeSetEvent(&sync->Event, IO_NO_INCREMENT, FALSE);
            WskSyncReleaseContext(sync);
        }

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    _Must_inspect_result_
    inline NTSTATUS WskSyncAllocateIrp(_Outptr_ WskSyncIrpContext** context) noexcept
    {
        if (context == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *context = nullptr;

        auto* sync = new WskSyncIrpContext();
        if (sync == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        sync->Irp = IoAllocateIrp(1, FALSE);
        if (sync->Irp == nullptr) {
            delete sync;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        sync->ReferenceCount = 2;
        KeInitializeEvent(&sync->Event, NotificationEvent, FALSE);
        IoSetCompletionRoutine(
            sync->Irp,
            WskSyncCompletionRoutine,
            sync,
            TRUE,
            TRUE,
            TRUE);

        *context = sync;
        return STATUS_SUCCESS;
    }

    inline void WskSyncDropCompletionReferenceIfNotCompleted(_In_ WskSyncIrpContext* context) noexcept
    {
        if (context == nullptr) {
            return;
        }

        if (InterlockedCompareExchange(&context->Completed, 0, 0) == 0) {
            WskSyncReleaseContext(context);
        }
    }

    inline void WskSyncReleaseUnsubmittedContext(_In_opt_ WskSyncIrpContext* context) noexcept
    {
        if (context == nullptr) {
            return;
        }

        WskSyncDropCompletionReferenceIfNotCompleted(context);
        WskSyncReleaseContext(context);
    }

    _Must_inspect_result_
    inline NTSTATUS WskSyncCompleteIrp(
        NTSTATUS requestStatus,
        _In_ WskSyncIrpContext* context,
        ULONG timeoutMilliseconds,
        _Out_opt_ SIZE_T* information) noexcept
    {
        if (information != nullptr) {
            *information = 0;
        }

        if (context == nullptr || context->Irp == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (requestStatus == STATUS_PENDING) {
            LARGE_INTEGER timeout = {};
            timeout.QuadPart = -static_cast<LONGLONG>(timeoutMilliseconds) * 10000LL;

            NTSTATUS waitStatus = KeWaitForSingleObject(
                &context->Event,
                Executive,
                KernelMode,
                FALSE,
                &timeout);

            if (waitStatus == STATUS_TIMEOUT) {
                IoCancelIrp(context->Irp);

                LARGE_INTEGER cancelTimeout = {};
                cancelTimeout.QuadPart = -static_cast<LONGLONG>(WskCancelCompletionTimeoutMilliseconds) * 10000LL;
                waitStatus = KeWaitForSingleObject(
                    &context->Event,
                    Executive,
                    KernelMode,
                    FALSE,
                    &cancelTimeout);

                if (waitStatus == STATUS_TIMEOUT) {
                    const LONG abandonedCount = InterlockedIncrement(&g_wskAbandonedIrpCount);
                    kprintf("WSK canceled IRP did not complete within %u ms; abandoned count=%ld\r\n",
                        WskCancelCompletionTimeoutMilliseconds,
                        abandonedCount);
                    UNREFERENCED_PARAMETER(abandonedCount);
                    return STATUS_IO_TIMEOUT;
                }
            }

            if (waitStatus != STATUS_SUCCESS) {
                return waitStatus;
            }

            requestStatus = context->Status;
        }
        else {
            if (InterlockedCompareExchange(&context->Completed, 0, 0) == 0) {
                context->Status = requestStatus;
                context->Information = static_cast<SIZE_T>(context->Irp->IoStatus.Information);
            }
            WskSyncDropCompletionReferenceIfNotCompleted(context);
            if (InterlockedCompareExchange(&context->Completed, 0, 0) != 0) {
                requestStatus = context->Status;
            }
        }

        if (information != nullptr) {
            *information = context->Information;
        }

        return requestStatus;
    }
}
}
