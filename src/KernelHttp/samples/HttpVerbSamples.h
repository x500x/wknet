#pragma once

#include "http/HttpResponse.h"
#include "net/WskClient.h"

namespace KernelHttp
{
namespace samples
{
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
        HttpVerbSampleResult HeadHttpBin = {};
        HttpVerbSampleResult OptionsHttpBin = {};
        HttpVerbSampleResult LocalHttpsSmoke = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttpVerbSamples(
        _Inout_ net::WskClient& wskClient,
        _Out_ HttpVerbSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunLocalHttpsSmokeSample(
        _Inout_ net::WskClient& wskClient,
        _Out_ HttpVerbSampleResult* result) noexcept;
}
}
