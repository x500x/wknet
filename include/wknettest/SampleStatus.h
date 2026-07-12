#pragma once

#include "http1/HttpTypes.h"

#ifndef STATUS_CONNECTION_REFUSED
#define STATUS_CONNECTION_REFUSED ((NTSTATUS)0xC0000236L)
#endif

#ifndef STATUS_NETWORK_UNREACHABLE
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xC000023CL)
#endif

#ifndef STATUS_HOST_UNREACHABLE
#define STATUS_HOST_UNREACHABLE ((NTSTATUS)0xC000023DL)
#endif

#ifndef STATUS_PROTOCOL_UNREACHABLE
#define STATUS_PROTOCOL_UNREACHABLE ((NTSTATUS)0xC000023EL)
#endif

#ifndef STATUS_NO_MATCH
#define STATUS_NO_MATCH ((NTSTATUS)0xC0000272L)
#endif

namespace wknet
{
namespace samples
{
    inline bool IsPublicNetworkEnvironmentStatus(NTSTATUS status) noexcept
    {
        return status == STATUS_CONNECTION_REFUSED ||
            status == STATUS_NETWORK_UNREACHABLE ||
            status == STATUS_HOST_UNREACHABLE ||
            status == STATUS_PROTOCOL_UNREACHABLE ||
            status == STATUS_NO_MATCH ||
            status == STATUS_IO_TIMEOUT ||
            status == STATUS_CONNECTION_DISCONNECTED ||
            status == STATUS_CONNECTION_RESET ||
            status == STATUS_CONNECTION_ABORTED ||
            status == STATUS_DEVICE_NOT_CONNECTED;
    }

    inline bool IsPublicEndpointDiagnosticStatus(NTSTATUS status) noexcept
    {
        return IsPublicNetworkEnvironmentStatus(status);
    }

    inline void MergeFatalSampleStatus(NTSTATUS& aggregate, NTSTATUS status) noexcept
    {
        if (NT_SUCCESS(aggregate) && !NT_SUCCESS(status)) {
            aggregate = status;
        }
    }

    inline void MergePublicDiagnosticSampleStatus(NTSTATUS& aggregate, NTSTATUS status) noexcept
    {
        if (NT_SUCCESS(status) || IsPublicEndpointDiagnosticStatus(status)) {
            return;
        }
        MergeFatalSampleStatus(aggregate, status);
    }
}
}
