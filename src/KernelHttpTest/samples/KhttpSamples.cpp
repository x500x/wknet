#include "samples/KhttpSamples.h"

namespace KernelHttp
{
namespace samples
{
namespace
{
    void MergeSampleStatus(_Inout_ NTSTATUS& aggregate, NTSTATUS status) noexcept
    {
        if (NT_SUCCESS(aggregate) && !NT_SUCCESS(status)) {
            aggregate = status;
        }
    }
}

NTSTATUS RunKhttpSamples(khttp::Session* session, KhttpSampleResults* results) noexcept
{
    if (session == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};
    return RunHighLevelApiSamples(session, &results->HighLevel);
}

NTSTATUS RunKernelHttpTestSamples(
    net::WskClient* wskClient,
    const char* certificateBundlePath,
    KernelHttpTestSampleResults* results) noexcept
{
    if (wskClient == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};

    NTSTATUS aggregate = STATUS_SUCCESS;
    NTSTATUS status = RunHighLevelApiSamples(wskClient, certificateBundlePath, &results->HighLevel);
    MergeSampleStatus(aggregate, status);

    status = RunHttpVerbSamples(*wskClient, certificateBundlePath, &results->Http);
    MergeSampleStatus(aggregate, status);

    status = RunHttp2VerbSamples(*wskClient, &results->Http2);
    MergeSampleStatus(aggregate, status);

    status = RunAdvancedScenarioSamples(wskClient, certificateBundlePath, &results->Advanced);
    MergeSampleStatus(aggregate, status);

    return aggregate;
}
}
}
