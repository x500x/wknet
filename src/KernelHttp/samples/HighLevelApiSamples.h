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
        HighLevelApiSampleResult HttpGetAsync = {};
        HighLevelApiSampleResult HttpPost = {};
        HighLevelApiSampleResult HttpPostAsync = {};
        HighLevelApiSampleResult HttpPut = {};
        HighLevelApiSampleResult HttpPutAsync = {};
        HighLevelApiSampleResult HttpPatch = {};
        HighLevelApiSampleResult HttpPatchAsync = {};
        HighLevelApiSampleResult HttpDelete = {};
        HighLevelApiSampleResult HttpDeleteAsync = {};
        HighLevelApiSampleResult HttpHead = {};
        HighLevelApiSampleResult HttpHeadAsync = {};
        HighLevelApiSampleResult HttpOptions = {};
        HighLevelApiSampleResult HttpOptionsAsync = {};
        HighLevelApiSampleResult HttpsTlsOptions = {};
        HighLevelApiSampleResult HttpsTlsOptionsAsync = {};
        HighLevelApiSampleResult HttpsPost = {};
        HighLevelApiSampleResult HttpsPostAsync = {};
        HighLevelApiSampleResult HttpsPut = {};
        HighLevelApiSampleResult HttpsPutAsync = {};
        HighLevelApiSampleResult HttpsPatch = {};
        HighLevelApiSampleResult HttpsPatchAsync = {};
        HighLevelApiSampleResult HttpsDelete = {};
        HighLevelApiSampleResult HttpsDeleteAsync = {};
        HighLevelApiSampleResult HttpsHead = {};
        HighLevelApiSampleResult HttpsHeadAsync = {};
        HighLevelApiSampleResult HttpsOptions = {};
        HighLevelApiSampleResult HttpsOptionsAsync = {};
        HighLevelApiSampleResult Http2Alpn = {};
        HighLevelApiSampleResult Http2AlpnAsync = {};
        HighLevelApiSampleResult WebSocketEcho = {};
        HighLevelApiSampleResult WebSocketEchoAsync = {};
        HighLevelApiSampleResult HttpsNoVerify = {};
        HighLevelApiSampleResult HttpsNoVerifyAsync = {};
        HighLevelApiSampleResult HttpsPostNoVerify = {};
        HighLevelApiSampleResult HttpsPostNoVerifyAsync = {};
        HighLevelApiSampleResult HttpsPutNoVerify = {};
        HighLevelApiSampleResult HttpsPutNoVerifyAsync = {};
        HighLevelApiSampleResult HttpsPatchNoVerify = {};
        HighLevelApiSampleResult HttpsPatchNoVerifyAsync = {};
        HighLevelApiSampleResult HttpsDeleteNoVerify = {};
        HighLevelApiSampleResult HttpsDeleteNoVerifyAsync = {};
        HighLevelApiSampleResult HttpsHeadNoVerify = {};
        HighLevelApiSampleResult HttpsHeadNoVerifyAsync = {};
        HighLevelApiSampleResult HttpsOptionsNoVerify = {};
        HighLevelApiSampleResult HttpsOptionsNoVerifyAsync = {};
        HighLevelApiSampleResult WebSocketEchoNoVerify = {};
        HighLevelApiSampleResult WebSocketEchoNoVerifyAsync = {};
        HighLevelApiSampleResult RemoteHttpsIpv4 = {};
        HighLevelApiSampleResult RemoteHttpsIpv4Async = {};
        HighLevelApiSampleResult RemoteHttpsIpv6 = {};
        HighLevelApiSampleResult RemoteHttpsIpv6Async = {};
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
    NTSTATUS RunHighLevelRemoteHttpsAddressFamilySample(
        _In_ api::KH_SESSION session,
        _Out_ HighLevelApiSampleResults* results) noexcept;
}
}
