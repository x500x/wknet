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
        HighLevelApiSampleResult Http3RequiredExternal = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttp3ApiSamples(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ Http3ApiSampleResults* results) noexcept;
}
}
