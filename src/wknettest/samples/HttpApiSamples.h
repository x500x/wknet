#pragma once

#include "samples/AdvancedScenarioSamples.h"
#include "samples/HighLevelApiSamples.h"

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
    };

    _Must_inspect_result_
    NTSTATUS RunDriverSamples(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ DriverSampleResults* results) noexcept;
}
}
