#pragma once

#include "harness/KernelTestHarness.h"

namespace wknet::ktest
{
    // Runs the existing high-level / advanced / H3 sample surface and maps each
    // result field into the Module×Property matrix (Functional / Reject / …).
    _Must_inspect_result_
    NTSTATUS RunFunctionalSampleSuite(_Inout_ MatrixContext* context) noexcept;
}
