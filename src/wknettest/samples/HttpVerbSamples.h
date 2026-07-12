#pragma once

#include "http1/HttpResponse.h"
#include "net/WskClient.h"
#include <wknet/tls/CertificateStore.h>

namespace wknet
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
        HttpVerbSampleResult GetNgHttp2HttpBin = {};
        HttpVerbSampleResult PostNgHttp2HttpBin = {};
        HttpVerbSampleResult PutNgHttp2HttpBin = {};
        HttpVerbSampleResult PatchNgHttp2HttpBin = {};
        HttpVerbSampleResult DeleteNgHttp2HttpBin = {};
        HttpVerbSampleResult HttpsGetNgHttp2HttpBin = {};
        HttpVerbSampleResult HttpsPostNgHttp2HttpBin = {};
        HttpVerbSampleResult HttpsPutNgHttp2HttpBin = {};
        HttpVerbSampleResult HttpsPatchNgHttp2HttpBin = {};
        HttpVerbSampleResult HttpsDeleteNgHttp2HttpBin = {};
        HttpVerbSampleResult HttpsGetNgHttp2HttpBinNoVerify = {};
        HttpVerbSampleResult HttpsPostNgHttp2HttpBinNoVerify = {};
        HttpVerbSampleResult HttpsPutNgHttp2HttpBinNoVerify = {};
        HttpVerbSampleResult HttpsPatchNgHttp2HttpBinNoVerify = {};
        HttpVerbSampleResult HttpsDeleteNgHttp2HttpBinNoVerify = {};
        HttpVerbSampleResult Tls13HttpsGet = {};
        HttpVerbSampleResult Tls13Http2Get = {};
        HttpVerbSampleResult Tls13HttpsGetNoVerify = {};
        HttpVerbSampleResult HeadNgHttp2HttpBin = {};
        HttpVerbSampleResult OptionsNgHttp2HttpBin = {};
        HttpVerbSampleResult RemoteHttpsIpv4 = {};
        HttpVerbSampleResult RemoteHttpsIpv6 = {};
        HttpVerbSampleResult WebSocketEcho = {};
        HttpVerbSampleResult WebSocketEchoExternalTrust = {};
        HttpVerbSampleResult WebSocketEchoNoVerify = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttpVerbSamples(
        _Inout_ net::WskClient& wskClient,
        _In_opt_ const char* certificateBundlePath,
        _Out_ HttpVerbSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunRemoteHttpsAddressFamilySamples(
        _Inout_ net::WskClient& wskClient,
        _In_opt_ const tls::CertificateStore* certificateStore,
        _Out_ HttpVerbSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunWebSocketEchoSample(
        _Inout_ net::WskClient& wskClient,
        _Out_ HttpVerbSampleResult* result) noexcept;
}
}
