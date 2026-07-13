#pragma once

#include "quic/QuicTypes.h"

namespace wknet::quic {
    enum class QuicTransportParameterPeerRole : UCHAR { Client, Server };
    constexpr SIZE_T QuicMaximumTransportParameterCount = 64;

    struct QuicPreferredAddress final
    {
        UCHAR Ipv4Address[4] = {};
        USHORT Ipv4Port = 0;
        UCHAR Ipv6Address[16] = {};
        USHORT Ipv6Port = 0;
        QuicBufferView ConnectionId = {};
        UCHAR StatelessResetToken[16] = {};
        bool Present = false;
    };

    struct QuicTransportParameters final
    {
        QuicBufferView OriginalDestinationConnectionId = {};
        ULONGLONG MaxIdleTimeout = 0;
        QuicBufferView StatelessResetToken = {};
        ULONGLONG MaxUdpPayloadSize = 65527;
        ULONGLONG InitialMaxData = 0;
        ULONGLONG InitialMaxStreamDataBidiLocal = 0;
        ULONGLONG InitialMaxStreamDataBidiRemote = 0;
        ULONGLONG InitialMaxStreamDataUni = 0;
        ULONGLONG InitialMaxStreamsBidi = 0;
        ULONGLONG InitialMaxStreamsUni = 0;
        ULONGLONG AckDelayExponent = 3;
        ULONGLONG MaxAckDelay = 25;
        ULONGLONG ActiveConnectionIdLimit = 2;
        QuicBufferView InitialSourceConnectionId = {};
        QuicBufferView RetrySourceConnectionId = {};
        QuicPreferredAddress PreferredAddress = {};
        bool DisableActiveMigration = false;
        ULONGLONG ObservedIds[QuicMaximumTransportParameterCount] = {};
        SIZE_T ObservedCount = 0;
    };

    NTSTATUS QuicParseTransportParameters(
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        QuicTransportParameterPeerRole peerRole,
        _Out_ QuicTransportParameters* parameters) noexcept;

    NTSTATUS QuicEncodeClientTransportParameters(
        _In_ QuicBufferView initialSourceConnectionId,
        _Out_writes_bytes_(capacity) UCHAR* output,
        SIZE_T capacity,
        _Out_ SIZE_T* bytesWritten) noexcept;
}
