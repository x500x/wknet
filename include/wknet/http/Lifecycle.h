#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    // IRQL: Destroy and AsyncRuntimeConfigure require PASSIVE_LEVEL in kernel builds.
    void Destroy() noexcept;

    struct AsyncRuntimeConfig final
    {
        ULONG WorkerCount = 4;
        ULONG QueueDepth = 256;
    };

    _Must_inspect_result_
    NTSTATUS AsyncRuntimeConfigure(_In_ const AsyncRuntimeConfig* config) noexcept;
}
