#include "samples/KhttpSamples.h"

namespace KernelHttp
{
namespace samples
{
NTSTATUS RunKhttpSamples(khttp::Session* session, KhttpSampleResults* results) noexcept
{
    return RunHighLevelApiSamples(session, results);
}
}
}
