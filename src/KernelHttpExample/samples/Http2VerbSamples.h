#pragma once

#include <KernelHttp/http/HttpResponse.h>
#include <KernelHttp/net/WskClient.h>

namespace KernelHttp
{
namespace samples
{
    struct Http2VerbSampleResult final
    {
        NTSTATUS Status = STATUS_SUCCESS;
        USHORT StatusCode = 0;
        SIZE_T HeaderCount = 0;
        SIZE_T BodyLength = 0;
        char NegotiatedAlpn[16] = {};
    };

    struct Http2VerbSampleResults final
    {
        Http2VerbSampleResult Http2GetHttpBin = {};
        Http2VerbSampleResult Http2PostHttpBin = {};
        Http2VerbSampleResult H2cPriorKnowledgeGet = {};
        Http2VerbSampleResult H2cUpgradeGet = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttp2VerbSamples(
        _Inout_ net::WskClient& wskClient,
        _Out_ Http2VerbSampleResults* results) noexcept;
}
}
