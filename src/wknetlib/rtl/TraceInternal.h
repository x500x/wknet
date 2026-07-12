#pragma once

#include <wknet/Trace.h>

namespace wknet
{
namespace rtl
{
    constexpr SIZE_T TraceSlotCount = 32;

#if defined(WKNET_USER_MODE_TEST)
    constexpr SIZE_T TracePageBytes = 4096;
#else
    constexpr SIZE_T TracePageBytes = PAGE_SIZE;
#endif

    ULONGLONG TraceAllocateCorrelationId() noexcept;

#if defined(WKNET_USER_MODE_TEST)
    SIZE_T TraceTestSlotSize() noexcept;
    SIZE_T TraceTestSlotAlignment() noexcept;
#endif
}
}
