#pragma once

#include "harness/KernelTestTypes.h"

namespace wknet::net
{
    class WskClient;
}

namespace wknet::ktest
{
    // Capacity for one DriverEntry matrix run. Covers functional samples + stress + concurrency.
    constexpr SIZE_T MaxCaseResults = 256;

    struct MatrixReport final
    {
        CaseResult Cases[MaxCaseResults] = {};
        SIZE_T CaseCount = 0;
        SIZE_T PassCount = 0;
        SIZE_T FailCount = 0;
        SIZE_T EnvSkipCount = 0;
        SIZE_T NotRunCount = 0;
        // First hard failure (not environment). STATUS_SUCCESS if only env skips.
        NTSTATUS AggregateStatus = STATUS_SUCCESS;
    };

    struct MatrixContext final
    {
        net::WskClient* WskClient = nullptr;
        const char* CertificateBundlePath = nullptr;
        MatrixReport* Report = nullptr;
    };

    void ReportReset(_Out_ MatrixReport* report) noexcept;

    void ReportCase(
        _Inout_ MatrixReport* report,
        _In_z_ const char* name,
        Module mod,
        Property prop,
        CaseOutcome outcome,
        NTSTATUS status,
        ULONG httpStatusCode = 0,
        SIZE_T detail = 0) noexcept;

    // Classify a sample/API NTSTATUS for public-network kernel runs.
    CaseOutcome ClassifyPublicStatus(NTSTATUS status) noexcept;

    void ReportSampleField(
        _Inout_ MatrixReport* report,
        _In_z_ const char* name,
        Module mod,
        Property prop,
        NTSTATUS status,
        ULONG httpStatusCode,
        SIZE_T bodyLength) noexcept;

    void PrintMatrixReport(_In_ const MatrixReport* report) noexcept;

    // Full KM matrix: Functional (existing samples) + Stress + Concurrency.
    _Must_inspect_result_
    NTSTATUS RunKernelFullMatrix(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ MatrixReport* report) noexcept;
}
