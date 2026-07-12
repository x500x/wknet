#pragma once

#include "transport/Transport.h"

namespace wknet::transport {
    struct TransportOperations final
    {
        TransportCallbacks Callbacks = {};
        void (*CloseContext)(void* context) noexcept = nullptr;
    };

    struct Transport final
    {
        const TransportOperations* Operations = nullptr;
        void* Context = nullptr;
        ULONGLONG ConnectionId = 0;
        bool OwnsOperations = false;
    };
}
