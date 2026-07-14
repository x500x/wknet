#pragma once

#include <ntddk.h>

namespace wknettest::http3
{
    constexpr ULONG ProtocolVersion = 1;
    constexpr ULONG DeviceType = 0x8000;
    constexpr ULONG IoctlRun = CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
    constexpr ULONG AddressFamilyIpv4 = 2;
    constexpr ULONG AddressFamilyIpv6 = 23;

    enum class Scenario : ULONG
    {
        Handshake = 0,
        Ipv4 = 1,
        Ipv6 = 2,
        Concurrent = 3,
        Cancel = 4,
        SessionClose = 5,
        UnloadRundown = 6
    };

    struct Request final
    {
        ULONG Version = ProtocolVersion;
        ULONG Size = sizeof(Request);
        Scenario Test = Scenario::Handshake;
        ULONG AddressFamily = AddressFamilyIpv4;
        USHORT Port = 0;
        USHORT Reserved = 0;
        ULONG ConnectionCount = 1;
        ULONG StreamCount = 1;
        ULONG Iterations = 1;
        ULONG TimeoutMilliseconds = 30000;
    };

    struct Result final
    {
        ULONG Version = ProtocolVersion;
        ULONG Size = sizeof(Result);
        NTSTATUS Status = STATUS_PENDING;
        ULONG RequestCount = 0;
        ULONG CompletedCount = 0;
        ULONG CancelledCount = 0;
        ULONG OutstandingWorkers = 0;
        ULONG OutstandingIrps = 0;
        ULONG OutstandingTimers = 0;
        ULONG OutstandingRundown = 0;
    };
} // namespace wknettest::http3
