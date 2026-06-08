#pragma once

#include "samples/HighLevelApiSamples.h"

namespace KernelHttp
{
namespace net
{
    class WskClient;
}

namespace samples
{
    struct AdvancedScenarioSampleResults final
    {
        HighLevelApiSampleResult HttpRedirect = {};
        HighLevelApiSampleResult HttpRedirectDisabled = {};
        HighLevelApiSampleResult HttpNotFound = {};
        HighLevelApiSampleResult HttpServerError = {};
        HighLevelApiSampleResult HttpLargeResponse = {};
        HighLevelApiSampleResult HttpResponseLimit = {};
        HighLevelApiSampleResult HttpLargePost = {};
        HighLevelApiSampleResult HttpConcurrentAsync = {};
        HighLevelApiSampleResult HttpAsyncWaitTimeout = {};
        HighLevelApiSampleResult HttpsTrustFailure = {};
        HighLevelApiSampleResult HttpsAlpnMismatch = {};
        HighLevelApiSampleResult WebSocketClose = {};
        HighLevelApiSampleResult WebSocketFragmentSend = {};
    };

    _Must_inspect_result_
    NTSTATUS RunAdvancedScenarioSamples(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ AdvancedScenarioSampleResults* results) noexcept;
}
}
