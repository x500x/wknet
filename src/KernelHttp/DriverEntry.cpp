#include "KernelHttpConfig.h"
#include "net/WskClient.h"

namespace KernelHttp
{
    namespace
    {
        net::WskClient* g_wskClient = nullptr;
    }

    _Use_decl_annotations_
    extern "C" void DriverUnload(PDRIVER_OBJECT driverObject)
    {
        UNREFERENCED_PARAMETER(driverObject);

        if (g_wskClient != nullptr) {
            g_wskClient->Shutdown();
            delete g_wskClient;
            g_wskClient = nullptr;
        }
    }
}

_Use_decl_annotations_
extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    driverObject->DriverUnload = KernelHttp::DriverUnload;

    KernelHttp::g_wskClient = new KernelHttp::net::WskClient();
    if (KernelHttp::g_wskClient == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = KernelHttp::g_wskClient->Initialize();
    if (!NT_SUCCESS(status)) {
        delete KernelHttp::g_wskClient;
        KernelHttp::g_wskClient = nullptr;
    }

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
