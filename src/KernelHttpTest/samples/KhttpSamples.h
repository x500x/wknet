#pragma once

#include "samples/AdvancedScenarioSamples.h"
#include "samples/HighLevelApiSamples.h"
#include "samples/Http2VerbSamples.h"
#include "samples/HttpVerbSamples.h"

namespace KernelHttp
{
namespace khttp
{
    struct Session;
}

namespace samples
{
    struct KernelHttpTestSampleResults final
    {
        HighLevelApiSampleResults HighLevel = {};
        HttpVerbSampleResults Http = {};
        Http2VerbSampleResults Http2 = {};
        AdvancedScenarioSampleResults Advanced = {};
    };

    using KhttpSampleResults = KernelHttpTestSampleResults;

    _Must_inspect_result_
    NTSTATUS RunKhttpSamples(
        _In_ khttp::Session* session,
        _Out_ KhttpSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunKernelHttpTestSamples(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ KernelHttpTestSampleResults* results) noexcept;
}
}
