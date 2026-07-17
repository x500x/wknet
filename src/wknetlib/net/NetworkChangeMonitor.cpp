#include "net/NetworkChangeMonitor.h"

#if !defined(WKNET_USER_MODE_TEST)
#include <netioapi.h>
#endif

namespace wknet::net
{
namespace
{
#if !defined(WKNET_USER_MODE_TEST)
    void NTAPI InterfaceChanged(void *context, PMIB_IPINTERFACE_ROW row,
                                MIB_NOTIFICATION_TYPE notificationType) noexcept
    {
        UNREFERENCED_PARAMETER(row);
        UNREFERENCED_PARAMETER(notificationType);
        NetworkChangeMonitor *monitor = static_cast<NetworkChangeMonitor *>(context);
        if (monitor != nullptr)
        {
            // Notification context may be above PASSIVE. Only signal the worker.
            monitor->Notify();
        }
    }

    void WorkerThreadRoutine(void *context) noexcept
    {
        auto *monitor = static_cast<NetworkChangeMonitor *>(context);
        if (monitor == nullptr)
        {
            return;
        }

        for (;;)
        {
            const NTSTATUS waitStatus = KeWaitForSingleObject(
                &monitor->WorkEvent,
                Executive,
                KernelMode,
                FALSE,
                nullptr);
            UNREFERENCED_PARAMETER(waitStatus);

            if (InterlockedCompareExchange(&monitor->Stopping, 0, 0) != 0)
            {
                break;
            }

            monitor->ProcessPendingNotifications();
        }

        KeSetEvent(&monitor->WorkerStoppedEvent, IO_NO_INCREMENT, FALSE);
        PsTerminateSystemThread(STATUS_SUCCESS);
    }
#endif

    class MonitorLock final
    {
    public:
        explicit MonitorLock(NetworkChangeMonitor *monitor) noexcept : monitor_(monitor)
        {
#if defined(WKNET_USER_MODE_TEST)
            while (InterlockedCompareExchange(&monitor_->Lock, 1, 0) != 0)
            {
                YieldProcessor();
            }
#else
            ExAcquireFastMutex(&monitor_->Lock);
#endif
        }

        ~MonitorLock() noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            InterlockedExchange(&monitor_->Lock, 0);
#else
            ExReleaseFastMutex(&monitor_->Lock);
#endif
        }

        MonitorLock(const MonitorLock &) = delete;
        MonitorLock &operator=(const MonitorLock &) = delete;

    private:
        NetworkChangeMonitor *monitor_ = nullptr;
    };
}

    NetworkChangeMonitor::NetworkChangeMonitor() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        ExInitializeFastMutex(&Lock);
        KeInitializeEvent(&WorkEvent, SynchronizationEvent, FALSE);
        KeInitializeEvent(&WorkerStoppedEvent, NotificationEvent, FALSE);
#endif
    }

    NetworkChangeMonitor::~NetworkChangeMonitor() noexcept
    {
        Shutdown();
    }

    NTSTATUS NetworkChangeMonitor::Initialize() noexcept
    {
        if (Initialized)
        {
            return STATUS_SUCCESS;
        }

#if !defined(WKNET_USER_MODE_TEST)
        InterlockedExchange(&Stopping, 0);
        InterlockedExchange(&PendingNotifications, 0);
        KeClearEvent(&WorkEvent);
        KeClearEvent(&WorkerStoppedEvent);

        HANDLE threadHandle = nullptr;
        const NTSTATUS threadStatus = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            WorkerThreadRoutine,
            this);
        if (!NT_SUCCESS(threadStatus))
        {
            return threadStatus;
        }

        PETHREAD threadObject = nullptr;
        const NTSTATUS refStatus = ObReferenceObjectByHandle(
            threadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            reinterpret_cast<PVOID *>(&threadObject),
            nullptr);
        ZwClose(threadHandle);
        if (!NT_SUCCESS(refStatus))
        {
            InterlockedExchange(&Stopping, 1);
            KeSetEvent(&WorkEvent, IO_NO_INCREMENT, FALSE);
            return refStatus;
        }

        WorkerThread = threadObject;
        InterlockedExchange(&WorkerStarted, 1);

        const NETIO_STATUS status = NotifyIpInterfaceChange(
            AF_UNSPEC,
            InterfaceChanged,
            this,
            TRUE,
            &NotificationHandle);
        if (!NETIO_SUCCESS(status))
        {
            NotificationHandle = nullptr;
            InterlockedExchange(&Stopping, 1);
            KeSetEvent(&WorkEvent, IO_NO_INCREMENT, FALSE);
            KeWaitForSingleObject(WorkerThread, Executive, KernelMode, FALSE, nullptr);
            ObDereferenceObject(WorkerThread);
            WorkerThread = nullptr;
            InterlockedExchange(&WorkerStarted, 0);
            InterlockedExchange(&Stopping, 0);
            return static_cast<NTSTATUS>(status);
        }
#endif
        Initialized = true;
        return STATUS_SUCCESS;
    }

    void NetworkChangeMonitor::Shutdown() noexcept
    {
        if (!Initialized)
        {
            return;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (NotificationHandle != nullptr)
        {
            (void)CancelMibChangeNotify2(NotificationHandle);
            NotificationHandle = nullptr;
        }

        if (InterlockedCompareExchange(&WorkerStarted, 0, 0) != 0)
        {
            InterlockedExchange(&Stopping, 1);
            KeSetEvent(&WorkEvent, IO_NO_INCREMENT, FALSE);
            if (WorkerThread != nullptr)
            {
                KeWaitForSingleObject(WorkerThread, Executive, KernelMode, FALSE, nullptr);
                ObDereferenceObject(WorkerThread);
                WorkerThread = nullptr;
            }
            InterlockedExchange(&WorkerStarted, 0);
            InterlockedExchange(&Stopping, 0);
        }
#endif

        {
            MonitorLock lock(this);
            RtlZeroMemory(Subscribers, sizeof(Subscribers));
            InterlockedExchange(&PendingNotifications, 0);
            Initialized = false;
        }
    }

    NTSTATUS NetworkChangeMonitor::Subscribe(NetworkChangeSubscriber callback, void *context) noexcept
    {
        if (!Initialized || callback == nullptr || context == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        MonitorLock lock(this);
        for (ULONG index = 0; index < MaximumSubscribers; ++index)
        {
            if (Subscribers[index].Callback == callback && Subscribers[index].Context == context)
            {
                return STATUS_SUCCESS;
            }
            if (Subscribers[index].Callback == nullptr)
            {
                Subscribers[index].Callback = callback;
                Subscribers[index].Context = context;
                return STATUS_SUCCESS;
            }
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    void NetworkChangeMonitor::Unsubscribe(NetworkChangeSubscriber callback, void *context) noexcept
    {
        if (callback == nullptr || context == nullptr)
        {
            return;
        }
        MonitorLock lock(this);
        for (ULONG index = 0; index < MaximumSubscribers; ++index)
        {
            if (Subscribers[index].Callback == callback && Subscribers[index].Context == context)
            {
                Subscribers[index] = {};
                return;
            }
        }
    }

    void NetworkChangeMonitor::Notify() noexcept
    {
        InterlockedIncrement(&PendingNotifications);
#if !defined(WKNET_USER_MODE_TEST)
        KeSetEvent(&WorkEvent, IO_NO_INCREMENT, FALSE);
#endif
    }

    void NetworkChangeMonitor::ProcessPendingNotifications() noexcept
    {
        for (;;)
        {
            if (InterlockedCompareExchange(&PendingNotifications, 0, 0) == 0)
            {
                return;
            }

            // Coalesce: clear the counter before snapshot so concurrent Notify
            // after snapshot will re-arm another pass.
            InterlockedExchange(&PendingNotifications, 0);

            Subscriber snapshot[MaximumSubscribers] = {};
            {
                MonitorLock lock(this);
                if (!Initialized)
                {
                    return;
                }
                RtlCopyMemory(snapshot, Subscribers, sizeof(snapshot));
            }

            for (ULONG index = 0; index < MaximumSubscribers; ++index)
            {
                if (snapshot[index].Callback != nullptr)
                {
                    snapshot[index].Callback(snapshot[index].Context);
                }
            }
        }
    }

#if defined(WKNET_USER_MODE_TEST)
    void NetworkChangeMonitor::NotifyAndProcessForTest() noexcept
    {
        Notify();
        ProcessPendingNotifications();
    }
#endif

}
