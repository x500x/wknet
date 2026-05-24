#pragma once

#include "http/HttpResponse.h"
#include "net/WskClient.h"

namespace KernelHttp
{
namespace samples
{
    // Exhaustive legacy sample matrix for test-driver and regression coverage.
    // The normal load-time driver path uses HighLevelApiSamples instead.
    struct HttpVerbSampleResult final
    {
        NTSTATUS Status = STATUS_SUCCESS;
        USHORT StatusCode = 0;
        SIZE_T HeaderCount = 0;
        SIZE_T BodyLength = 0;
    };

    struct HttpVerbSampleResults final
    {
        HttpVerbSampleResult IdentityEncoding = {};
        HttpVerbSampleResult GzipEncoding = {};
        HttpVerbSampleResult DeflateEncoding = {};
        HttpVerbSampleResult BrotliEncoding = {};
        HttpVerbSampleResult GetHttpBin = {};
        HttpVerbSampleResult PostHttpBin = {};
        HttpVerbSampleResult PutHttpBin = {};
        HttpVerbSampleResult PatchHttpBin = {};
        HttpVerbSampleResult DeleteHttpBin = {};
        HttpVerbSampleResult HttpsGetHttpBin = {};
        HttpVerbSampleResult HttpsPostHttpBin = {};
        HttpVerbSampleResult HttpsPutHttpBin = {};
        HttpVerbSampleResult HttpsPatchHttpBin = {};
        HttpVerbSampleResult HttpsDeleteHttpBin = {};
        HttpVerbSampleResult HttpsGetHttpBinNoVerify = {};
        HttpVerbSampleResult HttpsPostHttpBinNoVerify = {};
        HttpVerbSampleResult HttpsPutHttpBinNoVerify = {};
        HttpVerbSampleResult HttpsPatchHttpBinNoVerify = {};
        HttpVerbSampleResult HttpsDeleteHttpBinNoVerify = {};
        HttpVerbSampleResult Tls13HttpsGet = {};
        HttpVerbSampleResult Tls13Http2Get = {};
        HttpVerbSampleResult Tls13HttpsGetNoVerify = {};
        HttpVerbSampleResult HeadHttpBin = {};
        HttpVerbSampleResult OptionsHttpBin = {};
        HttpVerbSampleResult LocalHttpsSmoke = {};
        HttpVerbSampleResult WebSocketEcho = {};
        HttpVerbSampleResult WebSocketEchoNoVerify = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttpVerbSamples(
        _Inout_ net::WskClient& wskClient,
        _Out_ HttpVerbSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunLocalHttpsSmokeSample(
        _Inout_ net::WskClient& wskClient,
        _Out_ HttpVerbSampleResult* result) noexcept;

    _Must_inspect_result_
    NTSTATUS RunWebSocketEchoSample(
        _Inout_ net::WskClient& wskClient,
        _Out_ HttpVerbSampleResult* result) noexcept;
}
}
