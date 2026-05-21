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
        HttpVerbSampleResult GetHttpBin = {};
        HttpVerbSampleResult PostHttpBin = {};
        HttpVerbSampleResult PutHttpBin = {};
        HttpVerbSampleResult PatchHttpBin = {};
        HttpVerbSampleResult DeleteHttpBin = {};
        HttpVerbSampleResult HeadHttpBin = {};
        HttpVerbSampleResult OptionsHttpBin = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttpVerbSamples(
        _Inout_ net::WskClient& wskClient,
        _Out_ HttpVerbSampleResults* results) noexcept;
}
}
