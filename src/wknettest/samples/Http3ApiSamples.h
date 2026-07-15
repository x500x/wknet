#pragma once

#include "samples/HighLevelApiSamples.h"

namespace wknet
{
namespace net
{
    class WskClient;
}

namespace samples
{
    struct Http3ApiSampleResults final
    {
        HighLevelApiSampleResult Http3RequiredLoopback = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttp3ApiSamples(
        _In_ net::WskClient* wskClient,
        _Out_ Http3ApiSampleResults* results) noexcept;
}
}
