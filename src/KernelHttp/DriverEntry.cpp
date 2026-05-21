#include "KernelHttpConfig.h"
#include "net/WskClient.h"
#include "samples/HttpVerbSamples.h"

namespace KernelHttp
{
    namespace
    {
        net::WskClient* g_wskClient = nullptr;
    }

    NTSTATUS RunHttpSamples(samples::HttpVerbSampleResults* results) noexcept
    {
        if (g_wskClient == nullptr || !g_wskClient->IsInitialized()) {
            return STATUS_DEVICE_NOT_READY;
        }

        return samples::RunHttpVerbSamples(*g_wskClient, results);
    }

    void RunLoadHttpSamples() noexcept
    {
        samples::HttpVerbSampleResults results = {};
        const NTSTATUS status = RunHttpSamples(&results);
        if (!NT_SUCCESS(status)) {
            kprintf("HTTP samples completed with failures: 0x%08X\r\n", static_cast<ULONG>(status));
        }
        else {
            kprintf("HTTP samples completed successfully\r\n");
        }
    }

    _Use_decl_annotations_
    extern "C" void DriverUnload(PDRIVER_OBJECT driverObject)
    {
        UNREFERENCED_PARAMETER(driverObject);

        if (g_wskClient != nullptr) {
            kprintf("DriverUnload begin\r\n");
            g_wskClient->Shutdown();
            delete g_wskClient;
            g_wskClient = nullptr;
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
        kprintf("WSK initialize failed: 0x%08X\r\n", static_cast<ULONG>(status));
        delete KernelHttp::g_wskClient;
        KernelHttp::g_wskClient = nullptr;
        return status;
    }

    kprintf("WSK initialized, running load-time HTTP requests\r\n");
    KernelHttp::RunLoadHttpSamples();
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
