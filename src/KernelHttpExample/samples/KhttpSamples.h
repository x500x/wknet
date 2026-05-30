#pragma once

#include "samples/HighLevelApiSamples.h"

namespace KernelHttp
{
namespace khttp
{
    struct Session;
}

namespace samples
{
    using KhttpSampleResult = HighLevelApiSampleResult;
    using KhttpSampleResults = HighLevelApiSampleResults;

    _Must_inspect_result_
    NTSTATUS RunKhttpSamples(
        _In_ khttp::Session* session,
        _Out_ KhttpSampleResults* results) noexcept;
}
}
