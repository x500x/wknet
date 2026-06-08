#pragma once

#include <KernelHttp/KernelHttpConfig.h>
#include <KernelHttp/net/WskSocket.h>

#include <wsk.h>

namespace KernelHttp
{
namespace net
{
    constexpr ULONG WskCancelCompletionTimeoutMilliseconds = 60000;
    constexpr ULONG WskCancellationPollMilliseconds = 50;
    static volatile LONG g_wskAbandonedIrpCount = 0;

    typedef void (*WskSyncCleanupRoutine)(_In_opt_ void* context);

    // Synchronous WSK operation ownership:
    // - pending: caller and completion routine each own one context reference.
    // - completed: completion stores IoStatus, signals Event, and releases its reference.
    // - timed out: caller requests IoCancelIrp and waits for the completion routine.
    // - caller canceled: async cancellation uses the same IoCancelIrp path and reports STATUS_CANCELLED.
    // - cancel completed: STATUS_CANCELLED caused by timeout is reported as STATUS_IO_TIMEOUT.
    // - late cleanup: if a canceled IRP does not complete within the bounded cancel wait,
    //   the completion reference intentionally owns IRP/buffer cleanup when it eventually arrives.
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
    inline bool WskSyncIsCancellationRequested(_In_opt_ const WskCancellationToken* cancellation) noexcept
    {
        return cancellation != nullptr &&
            cancellation->IsCancellationRequested != nullptr &&
            cancellation->IsCancellationRequested(cancellation->Context);
    }

    inline void WskSyncMakeRelativeTimeout(ULONG milliseconds, _Out_ LARGE_INTEGER* timeout) noexcept
    {
        if (timeout == nullptr) {
            return;
        }

        timeout->QuadPart = -static_cast<LONGLONG>(milliseconds) * 10000LL;
    }

    _Must_inspect_result_
    inline NTSTATUS WskSyncWaitForCompletion(
        _In_ WskSyncIrpContext* context,
        ULONG timeoutMilliseconds,
        _In_opt_ const WskCancellationToken* cancellation) noexcept
    {
        if (context == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (cancellation == nullptr || cancellation->IsCancellationRequested == nullptr) {
            LARGE_INTEGER timeout = {};
            WskSyncMakeRelativeTimeout(timeoutMilliseconds, &timeout);
            return KeWaitForSingleObject(
                &context->Event,
                Executive,
                KernelMode,
                FALSE,
                timeoutMilliseconds == 0xffffffffUL ? nullptr : &timeout);
        }

        ULONG elapsedMilliseconds = 0;
        for (;;) {
            if (WskSyncIsCancellationRequested(cancellation)) {
                return STATUS_CANCELLED;
            }

            ULONG waitMilliseconds = WskCancellationPollMilliseconds;
            if (timeoutMilliseconds != 0xffffffffUL) {
                if (elapsedMilliseconds >= timeoutMilliseconds) {
                    return STATUS_TIMEOUT;
                }

                const ULONG remainingMilliseconds = timeoutMilliseconds - elapsedMilliseconds;
                waitMilliseconds = remainingMilliseconds < waitMilliseconds ? remainingMilliseconds : waitMilliseconds;
            }

            LARGE_INTEGER timeout = {};
            WskSyncMakeRelativeTimeout(waitMilliseconds, &timeout);
            const NTSTATUS waitStatus = KeWaitForSingleObject(
                &context->Event,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            if (waitStatus != STATUS_TIMEOUT) {
                return waitStatus;
            }

            if (timeoutMilliseconds != 0xffffffffUL) {
                elapsedMilliseconds += waitMilliseconds;
            }
        }
    }

    _Must_inspect_result_
    inline NTSTATUS WskSyncCompleteIrp(
        NTSTATUS requestStatus,
        _In_ WskSyncIrpContext* context,
        ULONG timeoutMilliseconds,
        _Out_opt_ SIZE_T* information,
        _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept
    {
        if (information != nullptr) {
            *information = 0;
        }

        if (context == nullptr || context->Irp == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (requestStatus == STATUS_PENDING) {
            bool cancelIssuedForTimeout = false;
            bool cancelIssuedForCaller = false;

            NTSTATUS waitStatus = WskSyncWaitForCompletion(context, timeoutMilliseconds, cancellation);

            if (waitStatus == STATUS_TIMEOUT || waitStatus == STATUS_CANCELLED) {
                cancelIssuedForTimeout = waitStatus == STATUS_TIMEOUT;
                cancelIssuedForCaller = waitStatus == STATUS_CANCELLED;
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
            if (cancelIssuedForTimeout && requestStatus == STATUS_CANCELLED) {
                requestStatus = STATUS_IO_TIMEOUT;
            }
            else if (cancelIssuedForCaller) {
                requestStatus = STATUS_CANCELLED;
            }
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
