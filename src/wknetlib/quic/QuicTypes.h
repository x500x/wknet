#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::quic {
    constexpr ULONG QuicVersionNegotiation = 0;
    constexpr ULONG QuicVersion1 = 0x00000001UL;
    constexpr SIZE_T QuicMaximumConnectionIdLength = 20;
    constexpr SIZE_T QuicRetryIntegrityTagLength = 16;
    constexpr ULONGLONG QuicVarIntMaximum = (1ULL << 62) - 1ULL;

    struct QuicBufferView final
    {
        const UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct QuicMutableBufferView final
    {
        UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    enum class QuicPacketType : UCHAR
    {
        Initial,
        ZeroRtt,
        Handshake,
        Retry,
        VersionNegotiation,
        OneRtt
    };
}
