#include "quic/QuicClock.h"
#if defined(WKNET_USER_MODE_TEST)
#include <chrono>
#endif
namespace wknet::quic
{
#if defined(WKNET_USER_MODE_TEST)
namespace
{
ULONGLONG g_now100ns = 1;
bool g_useSystemClock = false;
}
ULONGLONG QuicClockNow100ns() noexcept
{
    if (g_useSystemClock)
    {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100);
    }
    return g_now100ns;
}
void QuicTestClockUseSystem(bool enabled) noexcept
{
    g_useSystemClock = enabled;
}
void QuicTestClockSet(ULONGLONG now100ns) noexcept
{
    g_useSystemClock = false;
    g_now100ns = now100ns == 0 ? 1 : now100ns;
}
void QuicTestClockAdvance(ULONGLONG delta100ns) noexcept
{
    g_useSystemClock = false;
    g_now100ns += delta100ns;
}
#else
ULONGLONG QuicClockNow100ns() noexcept
{
    return KeQueryInterruptTime();
}
#endif
} // namespace wknet::quic
