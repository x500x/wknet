#include "session/AltSvcClock.h"

#if defined(WKNET_USER_MODE_TEST)
#include <chrono>
#endif

namespace wknet::session
{
#if defined(WKNET_USER_MODE_TEST)
namespace
{
    ULONGLONG g_testNowMilliseconds = 0;
    bool g_useTestClock = false;
}

    ULONGLONG AltSvcClockNowMilliseconds() noexcept
    {
        if (g_useTestClock)
        {
            return g_testNowMilliseconds;
        }
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<ULONGLONG>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
    }

    void AltSvcTestClockSet(ULONGLONG nowMilliseconds) noexcept
    {
        g_testNowMilliseconds = nowMilliseconds;
        g_useTestClock = true;
    }

    void AltSvcTestClockAdvance(ULONGLONG deltaMilliseconds) noexcept
    {
        g_testNowMilliseconds += deltaMilliseconds;
        g_useTestClock = true;
    }
#else
    ULONGLONG AltSvcClockNowMilliseconds() noexcept
    {
        return KeQueryInterruptTime() / 10000ULL;
    }
#endif
}
