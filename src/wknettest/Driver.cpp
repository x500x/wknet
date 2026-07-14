#include "tests/Http3KernelTestProtocol.h"

#include <ntstrsafe.h>

#include <wknet/http/AsyncOp.h>
#include <wknet/http/HttpAsync.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknet/http/Types.h>

#include "net/WskClient.h"

namespace wknettest::http3
{
    namespace net = wknet::net;
    namespace http = wknet::http;

    namespace
    {
        constexpr ULONG MinimumTimeoutMilliseconds = 1000;
        constexpr ULONG MaximumTimeoutMilliseconds = 180000;
        constexpr ULONG MaximumIterations = 100;

        PDEVICE_OBJECT g_deviceObject = nullptr;
        UNICODE_STRING g_deviceName = RTL_CONSTANT_STRING(L"\\Device\\wknettest");
        UNICODE_STRING g_symbolicName = RTL_CONSTANT_STRING(L"\\DosDevices\\wknettest");
        net::WskClient* g_wskClient = nullptr;
        volatile LONG g_outstandingIrps = 0;
        volatile LONG g_outstandingRundown = 0;

        bool IsValidRequest(const Request* request, ULONG inputLength) noexcept
        {
            return request != nullptr && inputLength >= sizeof(Request) && request->Version == ProtocolVersion &&
                   request->Size == sizeof(Request) && request->Port != 0 &&
                   (request->AddressFamily == AddressFamilyIpv4 || request->AddressFamily == AddressFamilyIpv6) &&
                   request->ConnectionCount != 0 && request->ConnectionCount <= 8 && request->StreamCount != 0 &&
                   request->StreamCount <= 64 && request->Iterations != 0 && request->Iterations <= MaximumIterations &&
                   request->TimeoutMilliseconds >= MinimumTimeoutMilliseconds &&
                   request->TimeoutMilliseconds <= MaximumTimeoutMilliseconds;
        }

        NTSTATUS BuildUrl(const Request* request, char* url, SIZE_T capacity) noexcept
        {
            const char* host = request->AddressFamily == AddressFamilyIpv6 ? "[::1]" : "127.0.0.1";
            const NTSTATUS status = RtlStringCchPrintfA(url, capacity, "https://%s:%hu/", host, request->Port);
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_NAME_TOO_LONG;
        }

        NTSTATUS RunOneRequest(http::Session* session, const char* url, ULONG timeoutMilliseconds, bool cancel,
                               Result* result) noexcept
        {
            http::AsyncOp* operation = nullptr;
            NTSTATUS status = http::AsyncGet(session, url, &operation);
            if (!NT_SUCCESS(status) || operation == nullptr)
            {
                return status;
            }
            ++result->RequestCount;
            if (cancel)
            {
                status = http::AsyncCancel(operation);
                if (NT_SUCCESS(status))
                {
                    ++result->CancelledCount;
                }
            }
            const NTSTATUS waitStatus = http::AsyncWait(operation, timeoutMilliseconds);
            const NTSTATUS operationStatus = http::AsyncGetStatus(operation);
            http::Response* response = nullptr;
            if (NT_SUCCESS(operationStatus))
            {
                (void)http::AsyncGetResponse(operation, &response);
                http::ResponseRelease(response);
            }
            http::AsyncRelease(operation);
            if (!NT_SUCCESS(waitStatus) && waitStatus != STATUS_CANCELLED)
            {
                return waitStatus;
            }
            if (cancel)
            {
                return operationStatus == STATUS_CANCELLED ? STATUS_SUCCESS : operationStatus;
            }
            if (NT_SUCCESS(operationStatus))
            {
                ++result->CompletedCount;
            }
            return operationStatus;
        }

        NTSTATUS RunConcurrentRequests(
            http::Session* session,
            const char* url,
            ULONG requestCount,
            ULONG timeoutMilliseconds,
            Result* result) noexcept
        {
            if (session == nullptr || url == nullptr || result == nullptr || requestCount == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            auto** operations = static_cast<http::AsyncOp**>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(http::AsyncOp*) * requestCount, '3HkW'));
            if (operations == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(operations, sizeof(http::AsyncOp*) * requestCount);

            NTSTATUS status = STATUS_SUCCESS;
            ULONG created = 0;
            for (; created < requestCount; ++created) {
                status = http::AsyncGet(session, url, &operations[created]);
                if (!NT_SUCCESS(status) || operations[created] == nullptr) {
                    break;
                }
                ++result->RequestCount;
            }

            if (NT_SUCCESS(status)) {
                for (ULONG index = 0; index < created; ++index) {
                    const NTSTATUS waitStatus = http::AsyncWait(operations[index], timeoutMilliseconds);
                    const NTSTATUS operationStatus = http::AsyncGetStatus(operations[index]);
                    if (!NT_SUCCESS(waitStatus) && waitStatus != STATUS_CANCELLED) {
                        status = waitStatus;
                    }
                    if (NT_SUCCESS(operationStatus)) {
                        ++result->CompletedCount;
                    }
                    else if (NT_SUCCESS(status)) {
                        status = operationStatus;
                    }
                }
            }

            for (ULONG index = 0; index < created; ++index) {
                if (operations[index] != nullptr) {
                    if (!NT_SUCCESS(status)) {
                        (void)http::AsyncCancel(operations[index]);
                    }
                    http::AsyncRelease(operations[index]);
                }
            }
            ExFreePoolWithTag(operations, '3HkW');
            return status;
        }

        NTSTATUS RunScenario(const Request* request, Result* result) noexcept
        {
            if (g_wskClient == nullptr || !net::WskClientIsInitialized(g_wskClient))
            {
                return STATUS_DEVICE_NOT_READY;
            }
            char url[64] = {};
            NTSTATUS status = BuildUrl(request, url, RTL_NUMBER_OF(url));
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            http::SessionConfig config = http::DefaultSessionConfig();
            config.PoolCapacity = request->ConnectionCount;
            config.MaxConnsPerHost = request->ConnectionCount;
            config.Http3.Mode = http::Http3ConnectMode::Required;
            config.Http3.Race = http::Http3RaceMode::SequentialPreferHttp3;
            config.Http3.QuicProbeTimeoutMs = request->TimeoutMilliseconds < 10000 ? request->TimeoutMilliseconds : 10000;
            config.Tls.Certificate = http::CertPolicy::NoVerify;
            config.Tls.MinVersion = http::TlsVersion::Tls13;
            config.Tls.MaxVersion = http::TlsVersion::Tls13;
            config.Tls.ServerName = "localhost";
            config.Tls.ServerNameLength = 9;
            config.Tls.PreferHttp2 = false;

            http::Session* session = nullptr;
            status = http::SessionCreate(&config, &session);
            if (!NT_SUCCESS(status))
            {
                return status;
            }

            const bool cancel = request->Test == Scenario::Cancel;
            if (request->Test == Scenario::Concurrent)
            {
                status = RunOneRequest(session, url, request->TimeoutMilliseconds, false, result);
                if (NT_SUCCESS(status))
                {
                    const ULONG count = request->ConnectionCount * request->StreamCount;
                    status = RunConcurrentRequests(session, url, count, request->TimeoutMilliseconds, result);
                }
            }
            else
            {
                const ULONG count = request->Iterations;
                for (ULONG index = 0; index < count && NT_SUCCESS(status); ++index)
                {
                    status = RunOneRequest(session, url, request->TimeoutMilliseconds, cancel, result);
                }
            }
            http::SessionClose(session);
            return status;
        }

        NTSTATUS CompleteIrp(PIRP irp, NTSTATUS status, ULONG information) noexcept
        {
            irp->IoStatus.Status = status;
            irp->IoStatus.Information = information;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return status;
        }

        NTSTATUS DispatchCreateClose(PDEVICE_OBJECT, PIRP irp) noexcept { return CompleteIrp(irp, STATUS_SUCCESS, 0); }

        NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT, PIRP irp) noexcept
        {
            auto* stack = IoGetCurrentIrpStackLocation(irp);
            const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
            const ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
            const ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
            if (code != IoctlRun || outputLength < sizeof(Result) ||
                !IsValidRequest(static_cast<const Request*>(irp->AssociatedIrp.SystemBuffer), inputLength))
            {
                return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
            }
            const auto* input = static_cast<const Request*>(irp->AssociatedIrp.SystemBuffer);
            const Request request = *input;
            auto* result = static_cast<Result*>(irp->AssociatedIrp.SystemBuffer);
            *result = {};
            result->Version = ProtocolVersion;
            result->Size = sizeof(Result);
            InterlockedIncrement(&g_outstandingIrps);
            InterlockedIncrement(&g_outstandingRundown);
            result->Status = RunScenario(&request, result);
            InterlockedDecrement(&g_outstandingRundown);
            InterlockedDecrement(&g_outstandingIrps);
            result->OutstandingIrps = static_cast<ULONG>(InterlockedCompareExchange(&g_outstandingIrps, 0, 0));
            result->OutstandingRundown = static_cast<ULONG>(InterlockedCompareExchange(&g_outstandingRundown, 0, 0));
            return CompleteIrp(irp, STATUS_SUCCESS, sizeof(Result));
        }
    } // namespace

    NTSTATUS Initialize(PDRIVER_OBJECT driverObject, net::WskClient* client) noexcept
    {
        if (driverObject == nullptr || client == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        g_wskClient = client;
        NTSTATUS status =
            IoCreateDevice(driverObject, 0, &g_deviceName, FILE_DEVICE_NETWORK, 0, FALSE, &g_deviceObject);
        if (!NT_SUCCESS(status))
        {
            g_wskClient = nullptr;
            return status;
        }
        status = IoCreateSymbolicLink(&g_symbolicName, &g_deviceName);
        if (!NT_SUCCESS(status))
        {
            IoDeleteDevice(g_deviceObject);
            g_deviceObject = nullptr;
            g_wskClient = nullptr;
            return status;
        }
        driverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
        driverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
        driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
        g_deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
        return STATUS_SUCCESS;
    }

    void Shutdown() noexcept
    {
        if (g_deviceObject != nullptr)
        {
            IoDeleteSymbolicLink(&g_symbolicName);
            IoDeleteDevice(g_deviceObject);
            g_deviceObject = nullptr;
        }
        g_wskClient = nullptr;
    }
} // namespace wknettest::http3
