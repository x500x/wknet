#include "samples/HttpApiSamples.h"

#include "WknetTestLog.h"

namespace wknet
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

NTSTATUS RunDriverSamples(
    net::WskClient* wskClient,
    const char* certificateBundlePath,
    DriverSampleResults* results) noexcept
{
    if (wskClient == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};

    NTSTATUS aggregate = STATUS_SUCCESS;
    NTSTATUS status = RunHighLevelApiSamples(wskClient, certificateBundlePath, &results->HighLevel);
    MergeSampleStatus(aggregate, status);

    status = RunAdvancedScenarioSamples(wskClient, certificateBundlePath, &results->Advanced);
    MergeSampleStatus(aggregate, status);

    status = RunHttp3ApiSamples(wskClient, certificateBundlePath, &results->Http3);
    MergeSampleStatus(aggregate, status);

    return aggregate;
}
}
}
