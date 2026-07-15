#pragma once

#include "samples/AdvancedScenarioSamples.h"
#include "samples/HighLevelApiSamples.h"
#include "samples/Http3ApiSamples.h"

namespace wknet::http {
    struct Session;
}

namespace wknet
{
namespace samples
{
    struct DriverSampleResults final
    {
        HighLevelApiSampleResults HighLevel = {};
        AdvancedScenarioSampleResults Advanced = {};
        Http3ApiSampleResults Http3 = {};
    };

    _Must_inspect_result_
    NTSTATUS RunDriverSamples(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ DriverSampleResults* results) noexcept;
}
}
