#include "quic/QuicClock.h"
namespace wknet::quic
{
#if defined(WKNET_USER_MODE_TEST)
namespace
{
ULONGLONG g_now100ns = 1;
}
ULONGLONG QuicClockNow100ns() noexcept
{
    return g_now100ns;
}
void QuicTestClockSet(ULONGLONG now100ns) noexcept
{
    g_now100ns = now100ns == 0 ? 1 : now100ns;
}
void QuicTestClockAdvance(ULONGLONG delta100ns) noexcept
{
    g_now100ns += delta100ns;
}
#else
ULONGLONG QuicClockNow100ns() noexcept
{
    return KeQueryInterruptTime();
}
#endif
} // namespace wknet::quic
