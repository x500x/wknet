#pragma once

#include "samples/AdvancedScenarioSamples.h"
#include "samples/HighLevelApiSamples.h"
#include "samples/Http2VerbSamples.h"
#include "samples/HttpVerbSamples.h"

namespace wknet::http {
    struct Session;
}

namespace wknet
{
namespace samples
{
    struct wknettestSampleResults final
    {
        HighLevelApiSampleResults HighLevel = {};
        HttpVerbSampleResults Http = {};
        Http2VerbSampleResults Http2 = {};
        AdvancedScenarioSampleResults Advanced = {};
    };

    using KhttpSampleResults = wknettestSampleResults;

    _Must_inspect_result_
    NTSTATUS RunKhttpSamples(
        _In_ ::wknet::http::Session* session,
        _Out_ KhttpSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunwknettestSamples(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ wknettestSampleResults* results) noexcept;
}
}
