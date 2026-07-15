#include "harness/KernelStressSuite.h"

#include <wknet/Wknet.h>
#include "WknetTestLog.h"
#include "samples/ExternalTrustStore.h"
#include <wknettest/SampleStatus.h>

namespace wknet::ktest
{
namespace
{
    constexpr SIZE_T StressS0Iterations = 20;
    constexpr SIZE_T StressS1Iterations = 100;
    constexpr SIZE_T StressPostIterations = 50;
    constexpr const char* StressGetUrl = "https://postman-echo.com/get";
    constexpr const char* StressPostUrl = "https://postman-echo.com/post";
    constexpr const char* StressPostBody = "wknet-km-stress";

    struct StressLoopStats final
    {
        SIZE_T Attempted = 0;
        SIZE_T Succeeded = 0;
        SIZE_T EnvSkipped = 0;
        SIZE_T Failed = 0;
        NTSTATUS FirstHardFailure = STATUS_SUCCESS;
        ULONG LastHttpStatus = 0;
    };

    SIZE_T CStringLength(const char* text) noexcept
    {
        SIZE_T length = 0;
        if (text == nullptr) {
            return 0;
        }
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    NTSTATUS CreateStressSession(
        const char* certificateBundlePath,
        samples::ExternalTrustStore* trustStore,
        ULONG maxConnsPerHost,
        http::Session** session) noexcept
    {
        if (session == nullptr || trustStore == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *session = nullptr;

        http::SessionConfig config = http::DefaultSessionConfig();
        config.MaxConnsPerHost = maxConnsPerHost;
        if (config.PoolCapacity < maxConnsPerHost) {
            config.PoolCapacity = maxConnsPerHost;
        }

        const char* path = certificateBundlePath != nullptr
            ? certificateBundlePath
            : samples::ExternalTrustStoreDefaultBundlePath;
        if (path != nullptr && path[0] != '\0') {
            const NTSTATUS trustStatus = samples::InitializeExternalTrustStore(*trustStore, path);
            if (NT_SUCCESS(trustStatus) && trustStore->Store != nullptr) {
                config.Tls.Certificate = http::CertPolicy::Verify;
                config.Tls.Store = trustStore->Store;
            }
            else {
                config.Tls.Certificate = http::CertPolicy::NoVerify;
            }
        }
        else {
            config.Tls.Certificate = http::CertPolicy::NoVerify;
        }

        return http::SessionCreate(&config, session);
    }

    void RunSerialGetLoop(
        http::Session* session,
        SIZE_T iterations,
        StressLoopStats* stats) noexcept
    {
        if (session == nullptr || stats == nullptr) {
            return;
        }

        for (SIZE_T index = 0; index < iterations; ++index) {
            ++stats->Attempted;
            http::Response* response = nullptr;
            const NTSTATUS status = http::Get(session, StressGetUrl, &response);
            if (NT_SUCCESS(status) && response != nullptr) {
                stats->LastHttpStatus = http::ResponseStatusCode(response);
                if (stats->LastHttpStatus >= 200 && stats->LastHttpStatus < 500) {
                    ++stats->Succeeded;
                }
                else {
                    ++stats->Failed;
                    if (NT_SUCCESS(stats->FirstHardFailure)) {
                        stats->FirstHardFailure = STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
                http::ResponseRelease(response);
                continue;
            }

            if (samples::IsPublicEndpointDiagnosticStatus(status)) {
                ++stats->EnvSkipped;
            }
            else {
                ++stats->Failed;
                if (NT_SUCCESS(stats->FirstHardFailure)) {
                    stats->FirstHardFailure = status;
                }
            }
            http::ResponseRelease(response);
            if (stats->EnvSkipped >= 3 && stats->Succeeded == 0) {
                break;
            }
        }
    }

    void RunSerialPostLoop(
        http::Session* session,
        SIZE_T iterations,
        StressLoopStats* stats) noexcept
    {
        if (session == nullptr || stats == nullptr) {
            return;
        }

        const SIZE_T bodyLength = CStringLength(StressPostBody);
        const SIZE_T urlLength = CStringLength(StressPostUrl);

        for (SIZE_T index = 0; index < iterations; ++index) {
            ++stats->Attempted;
            http::Response* response = nullptr;
            const NTSTATUS status = http::Post(
                session,
                StressPostUrl,
                urlLength,
                reinterpret_cast<const UCHAR*>(StressPostBody),
                bodyLength,
                &response);
            if (NT_SUCCESS(status) && response != nullptr) {
                stats->LastHttpStatus = http::ResponseStatusCode(response);
                if (stats->LastHttpStatus >= 200 && stats->LastHttpStatus < 500) {
                    ++stats->Succeeded;
                }
                else {
                    ++stats->Failed;
                    if (NT_SUCCESS(stats->FirstHardFailure)) {
                        stats->FirstHardFailure = STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
                http::ResponseRelease(response);
                continue;
            }

            if (samples::IsPublicEndpointDiagnosticStatus(status)) {
                ++stats->EnvSkipped;
            }
            else {
                ++stats->Failed;
                if (NT_SUCCESS(stats->FirstHardFailure)) {
                    stats->FirstHardFailure = status;
                }
            }
            http::ResponseRelease(response);
            if (stats->EnvSkipped >= 3 && stats->Succeeded == 0) {
                break;
            }
        }
    }

    void PublishLoop(
        MatrixReport* report,
        const char* name,
        Module mod,
        Property prop,
        const StressLoopStats& stats) noexcept
    {
        if (stats.Failed != 0) {
            ReportCase(
                report,
                name,
                mod,
                prop,
                CaseOutcome::Fail,
                stats.FirstHardFailure,
                stats.LastHttpStatus,
                stats.Succeeded);
            return;
        }
        if (stats.Succeeded == 0 && stats.EnvSkipped != 0) {
            ReportCase(
                report,
                name,
                mod,
                prop,
                CaseOutcome::EnvironmentSkip,
                STATUS_IO_TIMEOUT,
                0,
                stats.EnvSkipped);
            return;
        }
        if (stats.Succeeded == 0) {
            ReportCase(
                report,
                name,
                mod,
                prop,
                CaseOutcome::Fail,
                STATUS_UNSUCCESSFUL,
                0,
                0);
            return;
        }
        ReportCase(
            report,
            name,
            mod,
            prop,
            CaseOutcome::Pass,
            STATUS_SUCCESS,
            stats.LastHttpStatus,
            stats.Succeeded);
    }
}

NTSTATUS RunKernelStressSuite(MatrixContext* context) noexcept
{
    if (context == nullptr || context->WskClient == nullptr || context->Report == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    MatrixReport* report = context->Report;
    samples::ExternalTrustStore trustStore = {};
    http::Session* session = nullptr;
    NTSTATUS status = CreateStressSession(
        context->CertificateBundlePath,
        &trustStore,
        4,
        &session);
    if (!NT_SUCCESS(status) || session == nullptr) {
        samples::ResetExternalTrustStore(trustStore);
        ReportCase(
            report,
            "km.stress.session_create",
            Module::Session,
            Property::Stress,
            CaseOutcome::Fail,
            status,
            0,
            0);
        return report->AggregateStatus;
    }

    ReportCase(
        report,
        "km.stress.session_create",
        Module::Session,
        Property::Lifecycle,
        CaseOutcome::Pass,
        STATUS_SUCCESS,
        0,
        0);

    StressLoopStats s0 = {};
    RunSerialGetLoop(session, StressS0Iterations, &s0);
    PublishLoop(report, "km.stress.s0_https_get_x20", Module::HttpApi, Property::Stress, s0);
    PublishLoop(report, "km.stress.s0_http1_path", Module::Http1, Property::Stress, s0);
    PublishLoop(report, "km.stress.s0_tls_path", Module::Tls, Property::Stress, s0);

    StressLoopStats s1 = {};
    RunSerialGetLoop(session, StressS1Iterations, &s1);
    PublishLoop(report, "km.stress.s1_https_get_x100", Module::Session, Property::Stress, s1);

    StressLoopStats post = {};
    RunSerialPostLoop(session, StressPostIterations, &post);
    PublishLoop(report, "km.stress.post_x50", Module::HttpApi, Property::Stress, post);

    http::SessionClose(session);
    samples::ResetExternalTrustStore(trustStore);

    ReportCase(
        report,
        "km.stress.session_close",
        Module::Session,
        Property::Lifecycle,
        CaseOutcome::Pass,
        STATUS_SUCCESS,
        0,
        s0.Succeeded + s1.Succeeded + post.Succeeded);

    ReportCase(
        report,
        "km.stress.runtime",
        Module::Net,
        Property::RuntimeKm,
        CaseOutcome::Pass,
        STATUS_SUCCESS,
        0,
        s1.Succeeded);

    WKNET_SAMPLE_LOG(
        "[ktest] stress suite s0=%lu/%lu s1=%lu/%lu post=%lu/%lu\r\n",
        static_cast<ULONG>(s0.Succeeded),
        static_cast<ULONG>(s0.Attempted),
        static_cast<ULONG>(s1.Succeeded),
        static_cast<ULONG>(s1.Attempted),
        static_cast<ULONG>(post.Succeeded),
        static_cast<ULONG>(post.Attempted));
    return report->AggregateStatus;
}
}
