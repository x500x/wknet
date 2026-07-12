#pragma once

#include <wknet/http1/HttpResponse.h>
#include <wknet/net/WskClient.h>

namespace wknet
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
        Http2VerbSampleResult Http2GetHttpBinExternalTrust = {};
        Http2VerbSampleResult Http2PostHttpBinExternalTrust = {};
        Http2VerbSampleResult H2cPriorKnowledgeGet = {};
        Http2VerbSampleResult H2cUpgradeGet = {};
        Http2VerbSampleResult GoAwayFrame = {};
        Http2VerbSampleResult RstStreamFrame = {};
        Http2VerbSampleResult WindowUpdateFrame = {};
        Http2VerbSampleResult ContinuationFrame = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHttp2VerbSamples(
        _Inout_ net::WskClient& wskClient,
        _Out_ Http2VerbSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunHttp2VerbSamples(
        _Inout_ net::WskClient& wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ Http2VerbSampleResults* results) noexcept;
}
}
