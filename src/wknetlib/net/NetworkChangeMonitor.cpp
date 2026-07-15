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
            monitor->Notify();
        }
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
        const NETIO_STATUS status = NotifyIpInterfaceChange(
            AF_UNSPEC,
            InterfaceChanged,
            this,
            TRUE,
            &NotificationHandle);
        if (!NETIO_SUCCESS(status))
        {
            NotificationHandle = nullptr;
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
#endif
        {
            MonitorLock lock(this);
            RtlZeroMemory(Subscribers, sizeof(Subscribers));
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
        MonitorLock lock(this);
        for (ULONG index = 0; index < MaximumSubscribers; ++index)
        {
            if (Subscribers[index].Callback != nullptr)
            {
                Subscribers[index].Callback(Subscribers[index].Context);
            }
        }
    }

}
