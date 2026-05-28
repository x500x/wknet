#include "KernelHttpConfig.h"
#include "khttp/Session.h"
#include "net/WskClient.h"
#include "samples/HighLevelApiSamples.h"
#include "samples/KhttpSamples.h"

extern "C" NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

namespace KernelHttp
{
    namespace
    {
        net::WskClient* g_wskClient = nullptr;

        struct LoadHttpSamplesThreadContext
        {
            NTSTATUS Status;
        };

        void LoadHttpSamplesThread(_In_ PVOID startContext) noexcept;

        void ReleaseWskClient() noexcept
        {
            if (g_wskClient != nullptr) {
                g_wskClient->Shutdown();
                delete g_wskClient;
                g_wskClient = nullptr;
            }
        }

        bool IsLoadTimeWskProviderUnavailable(NTSTATUS status) noexcept
        {
            return status == STATUS_NOT_FOUND ||
                status == STATUS_OBJECT_NAME_NOT_FOUND ||
                status == STATUS_DEVICE_NOT_READY ||
                status == STATUS_IO_TIMEOUT;
        }
    }

    NTSTATUS RunHttpSamples(
        api::KH_SESSION session,
        samples::HighLevelApiSampleResults* results) noexcept
    {
        if (g_wskClient == nullptr || !g_wskClient->IsInitialized() || session == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }

#if defined(KERNEL_HTTP_REMOTE_HTTPS_ADDRESS_FAMILY_ONLY)
        if (results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};
        return samples::RunHighLevelRemoteHttpsAddressFamilySample(session, results);
#elif defined(KERNEL_HTTP_TEST_DRIVER_SCENARIOS)
        return samples::RunHighLevelApiTestDriverSamples(session, results);
#else
        return samples::RunHighLevelApiSamples(session, results);
#endif
    }

    NTSTATUS RunLoadHttpSamples() noexcept
    {
        NTSTATUS finalStatus = STATUS_SUCCESS;

        api::KH_SESSION session = nullptr;
        api::KhSessionOptions sessionOptions = {};
        NTSTATUS status = api::KhSessionCreate(g_wskClient, &sessionOptions, &session);
        if (!NT_SUCCESS(status)) {
            kprintf("High-level API session create failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        samples::HighLevelApiSampleResults results = {};
        status = RunHttpSamples(session, &results);
        api::KhSessionClose(session);

        if (!NT_SUCCESS(status)) {
            kprintf("High-level HTTP/WebSocket samples completed with failures: 0x%08X\r\n", static_cast<ULONG>(status));
            finalStatus = status;
        }
        else {
            kprintf("High-level HTTP/WebSocket samples completed successfully\r\n");
        }

        khttp::Session* khttpSession = nullptr;
        NTSTATUS khttpStatus = khttp::SessionCreate(g_wskClient, nullptr, &khttpSession);
        if (NT_SUCCESS(khttpStatus)) {
            samples::KhttpSampleResults khttpResults = {};
            khttpStatus = samples::RunKhttpSamples(khttpSession, &khttpResults);
            khttp::SessionClose(khttpSession);
            if (!NT_SUCCESS(khttpStatus)) {
                kprintf("khttp samples completed with failures: 0x%08X\r\n", static_cast<ULONG>(khttpStatus));
                if (NT_SUCCESS(finalStatus)) {
                    finalStatus = khttpStatus;
                }
            }
            else {
                kprintf("khttp samples completed successfully\r\n");
            }
        }
        else {
            kprintf("khttp session create failed: 0x%08X\r\n", static_cast<ULONG>(khttpStatus));
            if (NT_SUCCESS(finalStatus)) {
                finalStatus = khttpStatus;
            }
        }

        return finalStatus;
    }

    void LoadHttpSamplesThread(_In_ PVOID startContext) noexcept
    {
        LoadHttpSamplesThreadContext* context = static_cast<LoadHttpSamplesThreadContext*>(startContext);
        if (context == nullptr) {
            PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
            return;
        }

        context->Status = RunLoadHttpSamples();
        PsTerminateSystemThread(context->Status);
    }

    _Use_decl_annotations_
    extern "C" void DriverUnload(PDRIVER_OBJECT driverObject)
    {
        UNREFERENCED_PARAMETER(driverObject);

        if (g_wskClient != nullptr) {
            kprintf("DriverUnload begin\r\n");
            ReleaseWskClient();
            kprintf("DriverUnload complete\r\n");
        }
    }
}

_Use_decl_annotations_
extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    kprintf("DriverEntry begin\r\n");
    driverObject->DriverUnload = KernelHttp::DriverUnload;

    KernelHttp::g_wskClient = new KernelHttp::net::WskClient();
    if (KernelHttp::g_wskClient == nullptr) {
        kprintf("WskClient allocation failed\r\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = KernelHttp::g_wskClient->Initialize();
    if (!NT_SUCCESS(status)) {
        if (!KernelHttp::IsLoadTimeWskProviderUnavailable(status)) {
            kprintf("WSK initialize failed: 0x%08X\r\n", static_cast<ULONG>(status));
            KernelHttp::ReleaseWskClient();
            return status;
        }

        kprintf(
            "DriverEntry continuing without WSK after initialization failure: 0x%08X\r\n",
            static_cast<ULONG>(status));
        KernelHttp::ReleaseWskClient();
        kprintf("DriverEntry complete: 0x%08X\r\n", static_cast<ULONG>(STATUS_SUCCESS));
        return STATUS_SUCCESS;
    }

    kprintf("WSK initialized, running load-time high-level HTTP/WebSocket requests\r\n");

    KernelHttp::LoadHttpSamplesThreadContext sampleThreadContext = { STATUS_UNSUCCESSFUL };
    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(&objectAttributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE sampleThreadHandle = nullptr;
    status = PsCreateSystemThread(
        &sampleThreadHandle,
        THREAD_ALL_ACCESS,
        &objectAttributes,
        nullptr,
        nullptr,
        KernelHttp::LoadHttpSamplesThread,
        &sampleThreadContext);
    if (!NT_SUCCESS(status)) {
        kprintf("Failed to create load-time sample thread: 0x%08X\r\n", static_cast<ULONG>(status));
        KernelHttp::ReleaseWskClient();
        return status;
    }

    status = ZwWaitForSingleObject(sampleThreadHandle, FALSE, nullptr);
    ZwClose(sampleThreadHandle);
    if (!NT_SUCCESS(status)) {
        kprintf("Failed to wait for load-time sample thread: 0x%08X\r\n", static_cast<ULONG>(status));
        KernelHttp::ReleaseWskClient();
        return status;
    }

    const NTSTATUS sampleStatus = sampleThreadContext.Status;
    if (!NT_SUCCESS(sampleStatus)) {
        kprintf(
            "DriverEntry continuing after load-time sample failure: 0x%08X\r\n",
            static_cast<ULONG>(sampleStatus));
    }

    status = STATUS_SUCCESS;
    kprintf("DriverEntry complete: 0x%08X\r\n", static_cast<ULONG>(status));

    return status;
}

_Ret_maybenull_
void* __cdecl operator new(size_t size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, KernelHttp::PoolTag);
}

_Ret_maybenull_
void* __cdecl operator new[](size_t size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, KernelHttp::PoolTag);
}

void __cdecl operator delete(void* pointer) noexcept
{
    if (pointer != nullptr) {
        ExFreePoolWithTag(pointer, KernelHttp::PoolTag);
    }
}

void __cdecl operator delete[](void* pointer) noexcept
{
    if (pointer != nullptr) {
        ExFreePoolWithTag(pointer, KernelHttp::PoolTag);
    }
}

void __cdecl operator delete(void* pointer, size_t size) noexcept
{
    UNREFERENCED_PARAMETER(size);
    operator delete(pointer);
}

void __cdecl operator delete[](void* pointer, size_t size) noexcept
{
    UNREFERENCED_PARAMETER(size);
    operator delete[](pointer);
}
