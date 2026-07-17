#pragma once

#include "net/WskClient.h"

namespace wknet::net
{
    class NetworkChangeMonitor final
    {
    public:
        NetworkChangeMonitor() noexcept;
        ~NetworkChangeMonitor() noexcept;

        _Must_inspect_result_ NTSTATUS Initialize() noexcept;
        void Shutdown() noexcept;

        _Must_inspect_result_ NTSTATUS Subscribe(NetworkChangeSubscriber callback, void *context) noexcept;
        void Unsubscribe(NetworkChangeSubscriber callback, void *context) noexcept;

        // Safe from any IRQL used by NotifyIpInterfaceChange: only marks work and
        // wakes a PASSIVE worker. Never acquires FAST_MUTEX or invokes subscribers.
        void Notify() noexcept;

        // PASSIVE only. Drains pending notifications and invokes subscribers without
        // holding the monitor lock across callbacks.
        void ProcessPendingNotifications() noexcept;

#if defined(WKNET_USER_MODE_TEST)
        // Test hook: same as Notify + ProcessPendingNotifications on the calling thread.
        void NotifyAndProcessForTest() noexcept;
#endif

        NetworkChangeMonitor(const NetworkChangeMonitor &) = delete;
        NetworkChangeMonitor &operator=(const NetworkChangeMonitor &) = delete;

    public:
        struct Subscriber final
        {
            NetworkChangeSubscriber Callback = nullptr;
            void *Context = nullptr;
        };

        static constexpr ULONG MaximumSubscribers = WKNET_HARD_MAX_QUIC_CONNECTIONS_PER_SESSION * 8;

#if !defined(WKNET_USER_MODE_TEST)
        FAST_MUTEX Lock = {};
        HANDLE NotificationHandle = nullptr;
        KEVENT WorkEvent = {};
        KEVENT WorkerStoppedEvent = {};
        PETHREAD WorkerThread = nullptr;
        volatile LONG WorkerStarted = 0;
        volatile LONG Stopping = 0;
#else
        volatile LONG Lock = 0;
#endif
        Subscriber Subscribers[MaximumSubscribers] = {};
        volatile LONG PendingNotifications = 0;
        bool Initialized = false;
    };
}
