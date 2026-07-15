#include "harness/KernelTestHarness.h"

#include "WknetTestLog.h"
#include "harness/KernelFunctionalSuite.h"
#include "harness/KernelStressSuite.h"
#include "harness/KernelConcurrencySuite.h"
#include <wknettest/SampleStatus.h>

namespace wknet::ktest
{
    void ReportReset(MatrixReport* report) noexcept
    {
        if (report == nullptr) {
            return;
        }
        *report = {};
        report->AggregateStatus = STATUS_SUCCESS;
    }

    void ReportCase(
        MatrixReport* report,
        const char* name,
        Module mod,
        Property prop,
        CaseOutcome outcome,
        NTSTATUS status,
        ULONG httpStatusCode,
        SIZE_T detail) noexcept
    {
        if (report == nullptr || name == nullptr) {
            return;
        }

        if (report->CaseCount >= MaxCaseResults) {
            WKNET_SAMPLE_LOG("[ktest] case table full; dropped %s\r\n", name);
            if (outcome == CaseOutcome::Fail && NT_SUCCESS(report->AggregateStatus)) {
                report->AggregateStatus = STATUS_INSUFFICIENT_RESOURCES;
            }
            return;
        }

        CaseResult& entry = report->Cases[report->CaseCount++];
        entry.Name = name;
        entry.Mod = mod;
        entry.Prop = prop;
        entry.Outcome = outcome;
        entry.Status = status;
        entry.HttpStatusCode = httpStatusCode;
        entry.Detail = detail;

        switch (outcome) {
        case CaseOutcome::Pass:
            ++report->PassCount;
            break;
        case CaseOutcome::Fail:
            ++report->FailCount;
            if (NT_SUCCESS(report->AggregateStatus)) {
                report->AggregateStatus = !NT_SUCCESS(status) ? status : STATUS_UNSUCCESSFUL;
            }
            break;
        case CaseOutcome::EnvironmentSkip:
            ++report->EnvSkipCount;
            break;
        case CaseOutcome::NotRun:
        default:
            ++report->NotRunCount;
            break;
        }

        WKNET_SAMPLE_LOG(
            "[ktest] %s  module=%s  prop=%s  status=0x%08X  http=%u  detail=%lu  %s\r\n",
            OutcomeName(outcome),
            ModuleName(mod),
            PropertyName(prop),
            static_cast<ULONG>(status),
            httpStatusCode,
            static_cast<ULONG>(detail),
            name);
    }

    CaseOutcome ClassifyPublicStatus(NTSTATUS status) noexcept
    {
        if (NT_SUCCESS(status)) {
            return CaseOutcome::Pass;
        }
        if (samples::IsPublicEndpointDiagnosticStatus(status)) {
            return CaseOutcome::EnvironmentSkip;
        }
        return CaseOutcome::Fail;
    }

    void ReportSampleField(
        MatrixReport* report,
        const char* name,
        Module mod,
        Property prop,
        NTSTATUS status,
        ULONG httpStatusCode,
        SIZE_T bodyLength) noexcept
    {
        ReportCase(
            report,
            name,
            mod,
            prop,
            ClassifyPublicStatus(status),
            status,
            httpStatusCode,
            bodyLength);
    }

    void PrintMatrixReport(const MatrixReport* report) noexcept
    {
        if (report == nullptr) {
            return;
        }

        WKNET_SAMPLE_LOG("\r\n========== wknettest KM matrix summary ==========\r\n");
        WKNET_SAMPLE_LOG(
            "cases=%lu  pass=%lu  fail=%lu  env=%lu  skip=%lu  aggregate=0x%08X\r\n",
            static_cast<ULONG>(report->CaseCount),
            static_cast<ULONG>(report->PassCount),
            static_cast<ULONG>(report->FailCount),
            static_cast<ULONG>(report->EnvSkipCount),
            static_cast<ULONG>(report->NotRunCount),
            static_cast<ULONG>(report->AggregateStatus));

        // Compact per-module coverage: which properties saw at least one PASS.
        for (ULONG modIndex = 0; modIndex < static_cast<ULONG>(Module::Count); ++modIndex) {
            const Module mod = static_cast<Module>(modIndex);
            bool saw[static_cast<ULONG>(Property::Count)] = {};
            bool any = false;
            for (SIZE_T i = 0; i < report->CaseCount; ++i) {
                if (report->Cases[i].Mod != mod) {
                    continue;
                }
                any = true;
                if (report->Cases[i].Outcome == CaseOutcome::Pass) {
                    saw[static_cast<ULONG>(report->Cases[i].Prop)] = true;
                }
            }
            if (!any) {
                continue;
            }
            WKNET_SAMPLE_LOG("module %-10s props:", ModuleName(mod));
            for (ULONG p = 0; p < static_cast<ULONG>(Property::Count); ++p) {
                if (saw[p]) {
                    WKNET_SAMPLE_LOG(" %s", PropertyName(static_cast<Property>(p)));
                }
            }
            WKNET_SAMPLE_LOG("\r\n");
        }

        if (report->FailCount != 0) {
            WKNET_SAMPLE_LOG("---------- failures ----------\r\n");
            for (SIZE_T i = 0; i < report->CaseCount; ++i) {
                if (report->Cases[i].Outcome != CaseOutcome::Fail) {
                    continue;
                }
                WKNET_SAMPLE_LOG(
                    "FAIL  %s/%s  0x%08X  %s\r\n",
                    ModuleName(report->Cases[i].Mod),
                    PropertyName(report->Cases[i].Prop),
                    static_cast<ULONG>(report->Cases[i].Status),
                    report->Cases[i].Name != nullptr ? report->Cases[i].Name : "?");
            }
        }

        WKNET_SAMPLE_LOG("================================================\r\n\r\n");
    }

    NTSTATUS RunKernelFullMatrix(
        net::WskClient* wskClient,
        const char* certificateBundlePath,
        MatrixReport* report) noexcept
    {
        if (wskClient == nullptr || report == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ReportReset(report);
        MatrixContext context = {};
        context.WskClient = wskClient;
        context.CertificateBundlePath = certificateBundlePath;
        context.Report = report;

        WKNET_SAMPLE_LOG("[ktest] === suite: Functional (legacy samples, integrated) ===\r\n");
        (void)RunFunctionalSampleSuite(&context);

        WKNET_SAMPLE_LOG("[ktest] === suite: Stress (KM product path) ===\r\n");
        (void)RunKernelStressSuite(&context);

        WKNET_SAMPLE_LOG("[ktest] === suite: Concurrency (KM multi-thread Get) ===\r\n");
        (void)RunKernelConcurrencySuite(&context);

        PrintMatrixReport(report);
        return report->AggregateStatus;
    }
}
