#pragma once

#include "harness/KernelTestHarness.h"

namespace wknet::ktest
{
    // Product-path stress on real WSK (no fake transport):
    //   S0  serial HTTPS GET ×N
    //   S1  serial HTTPS GET ×M with raised pool
    //   POST serial HTTPS POST ×P (small body)
    // Defaults stay modest so DriverEntry remains bounded; registry knobs can come later.
    _Must_inspect_result_
    NTSTATUS RunKernelStressSuite(_Inout_ MatrixContext* context) noexcept;
}
