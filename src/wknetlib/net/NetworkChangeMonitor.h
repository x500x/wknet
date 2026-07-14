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
        void Notify() noexcept;

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
#else
        volatile LONG Lock = 0;
#endif
        Subscriber Subscribers[MaximumSubscribers] = {};
        bool Initialized = false;
    };
}
