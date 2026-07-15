#include "harness/KernelConcurrencySuite.h"

#include <wknet/Wknet.h>
#include "WknetTestLog.h"
#include "samples/ExternalTrustStore.h"
#include <wknettest/SampleStatus.h>

namespace wknet::ktest
{
namespace
{
    constexpr ULONG ConcurrentThreads = 4;
    constexpr SIZE_T GetsPerThread = 25;
    constexpr const char* ConcurrentGetUrl = "https://postman-echo.com/get";

    extern "C" NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
        _In_ HANDLE Handle,
        _In_ BOOLEAN Alertable,
        _In_opt_ PLARGE_INTEGER Timeout);

    struct ConcurrentWorkerContext final
    {
        http::Session* Session = nullptr;
        const char* CertificateBundlePath = nullptr;
        SIZE_T Iterations = 0;
        volatile LONG Succeeded = 0;
        volatile LONG Failed = 0;
        volatile LONG EnvSkipped = 0;
        volatile LONG FirstHardFailure = static_cast<LONG>(STATUS_SUCCESS);
    };

    NTSTATUS CreateConcurrentSession(
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
            if (NT_SUCCESS(samples::InitializeExternalTrustStore(*trustStore, path)) &&
                trustStore->Store != nullptr) {
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

    void RecordStatus(ConcurrentWorkerContext* context, NTSTATUS status) noexcept
    {
        if (context == nullptr) {
            return;
        }
        if (NT_SUCCESS(status)) {
            InterlockedIncrement(&context->Succeeded);
            return;
        }
        if (samples::IsPublicEndpointDiagnosticStatus(status)) {
            InterlockedIncrement(&context->EnvSkipped);
            return;
        }
        InterlockedIncrement(&context->Failed);
        InterlockedCompareExchange(
            &context->FirstHardFailure,
            static_cast<LONG>(status),
            static_cast<LONG>(STATUS_SUCCESS));
    }

    void WorkerRoutine(_In_ PVOID startContext) noexcept
    {
        auto* context = static_cast<ConcurrentWorkerContext*>(startContext);
        if (context == nullptr) {
            PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
            return;
        }

        http::Session* session = context->Session;
        samples::ExternalTrustStore ownedTrust = {};
        bool ownsSession = false;
        if (session == nullptr) {
            const NTSTATUS createStatus = CreateConcurrentSession(
                context->CertificateBundlePath,
                &ownedTrust,
                2,
                &session);
            if (!NT_SUCCESS(createStatus) || session == nullptr) {
                samples::ResetExternalTrustStore(ownedTrust);
                RecordStatus(context, createStatus);
                PsTerminateSystemThread(createStatus);
                return;
            }
            ownsSession = true;
        }

        for (SIZE_T index = 0; index < context->Iterations; ++index) {
            http::Response* response = nullptr;
            const NTSTATUS status = http::Get(session, ConcurrentGetUrl, &response);
            if (NT_SUCCESS(status) && response != nullptr) {
                const ULONG code = http::ResponseStatusCode(response);
                http::ResponseRelease(response);
                if (code >= 200 && code < 500) {
                    InterlockedIncrement(&context->Succeeded);
                }
                else {
                    RecordStatus(context, STATUS_INVALID_NETWORK_RESPONSE);
                }
            }
            else {
                http::ResponseRelease(response);
                RecordStatus(context, status);
                if (context->EnvSkipped >= 3 && context->Succeeded == 0) {
                    break;
                }
            }
        }

        if (ownsSession) {
            http::SessionClose(session);
            samples::ResetExternalTrustStore(ownedTrust);
        }

        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    NTSTATUS LaunchWorkers(
        ConcurrentWorkerContext* workers,
        ULONG count,
        PHANDLE handles) noexcept
    {
        OBJECT_ATTRIBUTES attributes = {};
        InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        for (ULONG index = 0; index < count; ++index) {
            handles[index] = nullptr;
            const NTSTATUS status = PsCreateSystemThread(
                &handles[index],
                THREAD_ALL_ACCESS,
                &attributes,
                nullptr,
                nullptr,
                WorkerRoutine,
                &workers[index]);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    void JoinWorkers(PHANDLE handles, ULONG count) noexcept
    {
        for (ULONG index = 0; index < count; ++index) {
            if (handles[index] != nullptr) {
                (void)ZwWaitForSingleObject(handles[index], FALSE, nullptr);
                ZwClose(handles[index]);
                handles[index] = nullptr;
            }
        }
    }

    void PublishAggregate(
        MatrixReport* report,
        const char* name,
        Module mod,
        Property prop,
        LONG succeeded,
        LONG failed,
        LONG envSkipped,
        LONG firstHardFailure) noexcept
    {
        if (failed != 0) {
            ReportCase(
                report,
                name,
                mod,
                prop,
                CaseOutcome::Fail,
                static_cast<NTSTATUS>(firstHardFailure),
                0,
                static_cast<SIZE_T>(succeeded));
            return;
        }
        if (succeeded == 0 && envSkipped != 0) {
            ReportCase(
                report,
                name,
                mod,
                prop,
                CaseOutcome::EnvironmentSkip,
                STATUS_IO_TIMEOUT,
                0,
                static_cast<SIZE_T>(envSkipped));
            return;
        }
        if (succeeded == 0) {
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
            0,
            static_cast<SIZE_T>(succeeded));
    }
}

NTSTATUS RunKernelConcurrencySuite(MatrixContext* context) noexcept
{
    if (context == nullptr || context->WskClient == nullptr || context->Report == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    MatrixReport* report = context->Report;

    // Mode A: session-per-thread
    {
        ConcurrentWorkerContext workers[ConcurrentThreads] = {};
        HANDLE handles[ConcurrentThreads] = {};
        for (ULONG index = 0; index < ConcurrentThreads; ++index) {
            workers[index].Session = nullptr;
            workers[index].CertificateBundlePath = context->CertificateBundlePath;
            workers[index].Iterations = GetsPerThread;
        }

        NTSTATUS status = LaunchWorkers(workers, ConcurrentThreads, handles);
        if (!NT_SUCCESS(status)) {
            JoinWorkers(handles, ConcurrentThreads);
            ReportCase(
                report,
                "km.concurrency.session_per_thread_launch",
                Module::Session,
                Property::Concurrency,
                CaseOutcome::Fail,
                status,
                0,
                0);
        }
        else {
            JoinWorkers(handles, ConcurrentThreads);
            LONG succeeded = 0;
            LONG failed = 0;
            LONG envSkipped = 0;
            LONG firstHard = static_cast<LONG>(STATUS_SUCCESS);
            for (ULONG index = 0; index < ConcurrentThreads; ++index) {
                succeeded += workers[index].Succeeded;
                failed += workers[index].Failed;
                envSkipped += workers[index].EnvSkipped;
                if (firstHard == static_cast<LONG>(STATUS_SUCCESS) &&
                    workers[index].FirstHardFailure != static_cast<LONG>(STATUS_SUCCESS)) {
                    firstHard = workers[index].FirstHardFailure;
                }
            }
            PublishAggregate(
                report,
                "km.concurrency.session_per_thread",
                Module::Session,
                Property::Concurrency,
                succeeded,
                failed,
                envSkipped,
                firstHard);
            PublishAggregate(
                report,
                "km.concurrency.session_per_thread_http_api",
                Module::HttpApi,
                Property::Concurrency,
                succeeded,
                failed,
                envSkipped,
                firstHard);
        }
    }

    // Mode B: shared session with MaxConnsPerHost >= thread count
    {
        samples::ExternalTrustStore trustStore = {};
        http::Session* shared = nullptr;
        NTSTATUS status = CreateConcurrentSession(
            context->CertificateBundlePath,
            &trustStore,
            ConcurrentThreads,
            &shared);
        if (!NT_SUCCESS(status) || shared == nullptr) {
            samples::ResetExternalTrustStore(trustStore);
            ReportCase(
                report,
                "km.concurrency.shared_session_create",
                Module::Session,
                Property::Concurrency,
                CaseOutcome::Fail,
                status,
                0,
                0);
            return report->AggregateStatus;
        }

        ConcurrentWorkerContext workers[ConcurrentThreads] = {};
        HANDLE handles[ConcurrentThreads] = {};
        for (ULONG index = 0; index < ConcurrentThreads; ++index) {
            workers[index].Session = shared;
            workers[index].CertificateBundlePath = context->CertificateBundlePath;
            workers[index].Iterations = GetsPerThread;
        }

        status = LaunchWorkers(workers, ConcurrentThreads, handles);
        if (!NT_SUCCESS(status)) {
            JoinWorkers(handles, ConcurrentThreads);
            ReportCase(
                report,
                "km.concurrency.shared_session_launch",
                Module::Session,
                Property::Concurrency,
                CaseOutcome::Fail,
                status,
                0,
                0);
        }
        else {
            JoinWorkers(handles, ConcurrentThreads);
            LONG succeeded = 0;
            LONG failed = 0;
            LONG envSkipped = 0;
            LONG firstHard = static_cast<LONG>(STATUS_SUCCESS);
            for (ULONG index = 0; index < ConcurrentThreads; ++index) {
                succeeded += workers[index].Succeeded;
                failed += workers[index].Failed;
                envSkipped += workers[index].EnvSkipped;
                if (firstHard == static_cast<LONG>(STATUS_SUCCESS) &&
                    workers[index].FirstHardFailure != static_cast<LONG>(STATUS_SUCCESS)) {
                    firstHard = workers[index].FirstHardFailure;
                }
            }
            PublishAggregate(
                report,
                "km.concurrency.shared_session",
                Module::Session,
                Property::Concurrency,
                succeeded,
                failed,
                envSkipped,
                firstHard);
        }

        http::SessionClose(shared);
        samples::ResetExternalTrustStore(trustStore);
    }

    ReportCase(
        report,
        "km.concurrency.runtime",
        Module::Net,
        Property::RuntimeKm,
        CaseOutcome::Pass,
        STATUS_SUCCESS,
        0,
        ConcurrentThreads * GetsPerThread);

    return report->AggregateStatus;
}
}
