#include <wknet/http/Lifecycle.h>
#include "TransientSessionPool.h"
#include "session/Async.h"
#include "session/Engine.h"

namespace wknet::http {
    void Destroy() noexcept
    {
        (void)::wknet::session::EngineDrainAsync();
        detail::TransientSessionPoolShutdown();
    }

    NTSTATUS AsyncRuntimeConfigure(const AsyncRuntimeConfig* config) noexcept
    {
        if (config == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ::wknet::session::AsyncRuntimeConfig api = {};
        api.WorkerCount = config->WorkerCount;
        api.QueueDepth = config->QueueDepth;
        return ::wknet::session::AsyncRuntimeConfigure(api);
    }
}
