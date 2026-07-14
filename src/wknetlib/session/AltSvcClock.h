#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::session
{
    ULONGLONG AltSvcClockNowMilliseconds() noexcept;

#if defined(WKNET_USER_MODE_TEST)
    void AltSvcTestClockSet(ULONGLONG nowMilliseconds) noexcept;
    void AltSvcTestClockAdvance(ULONGLONG deltaMilliseconds) noexcept;
#endif
}
