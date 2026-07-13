#pragma once
#include <wknet/WknetConfig.h>
namespace wknet::quic
{
ULONGLONG QuicClockNow100ns() noexcept;
#if defined(WKNET_USER_MODE_TEST)
void QuicTestClockSet(ULONGLONG now100ns) noexcept;
void QuicTestClockAdvance(ULONGLONG delta100ns) noexcept;
#endif
} // namespace wknet::quic
