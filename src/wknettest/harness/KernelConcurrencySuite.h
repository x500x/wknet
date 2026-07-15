#pragma once

#include "harness/KernelTestHarness.h"

namespace wknet::ktest
{
    // Kernel concurrency:
    //   - session-per-thread HTTPS GET
    //   - shared-session HTTPS GET with MaxConnsPerHost >= thread count
    _Must_inspect_result_
    NTSTATUS RunKernelConcurrencySuite(_Inout_ MatrixContext* context) noexcept;
}
