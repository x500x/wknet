#pragma once

#include "api/KernelHttpApi.h"

namespace KernelHttp
{
namespace samples
{
    struct HighLevelApiSampleResult final
    {
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG StatusCode = 0;
        SIZE_T BodyLength = 0;
    };

    struct HighLevelApiSampleResults final
    {
        HighLevelApiSampleResult HttpGet = {};
        HighLevelApiSampleResult HttpPost = {};
        HighLevelApiSampleResult HttpsTlsOptions = {};
        HighLevelApiSampleResult HttpsPost = {};
        HighLevelApiSampleResult HttpsPut = {};
        HighLevelApiSampleResult HttpsPatch = {};
        HighLevelApiSampleResult HttpsDelete = {};
        HighLevelApiSampleResult Http2Alpn = {};
        HighLevelApiSampleResult WebSocketEcho = {};
        HighLevelApiSampleResult HttpPut = {};
        HighLevelApiSampleResult HttpPatch = {};
        HighLevelApiSampleResult HttpDelete = {};
        HighLevelApiSampleResult HttpHead = {};
        HighLevelApiSampleResult HttpOptions = {};
        HighLevelApiSampleResult HttpsNoVerify = {};
        HighLevelApiSampleResult HttpsPostNoVerify = {};
        HighLevelApiSampleResult HttpsPutNoVerify = {};
        HighLevelApiSampleResult HttpsPatchNoVerify = {};
        HighLevelApiSampleResult HttpsDeleteNoVerify = {};
        HighLevelApiSampleResult WebSocketEchoNoVerify = {};
        HighLevelApiSampleResult LocalHttpsSmoke = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiSamples(
        _In_ api::KH_SESSION session,
        _Out_ HighLevelApiSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiTestDriverSamples(
        _In_ api::KH_SESSION session,
        _Out_ HighLevelApiSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunHighLevelLocalHttpsSmokeSample(
        _In_ api::KH_SESSION session,
        _Out_ HighLevelApiSampleResult* result) noexcept;
}
}
