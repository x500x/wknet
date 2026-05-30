#include <KernelHttp/KernelHttp.h>

#include "samples/HighLevelApiSamples.h"

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

    NTSTATUS RunLoadHttpSamples() noexcept
    {
        NTSTATUS finalStatus = STATUS_SUCCESS;

        if (g_wskClient == nullptr || !g_wskClient->IsInitialized()) {
            return STATUS_DEVICE_NOT_READY;
        }

        samples::HighLevelApiSampleResults khttpResults = {};
        NTSTATUS khttpStatus = samples::RunHighLevelApiSamples(g_wskClient, &khttpResults);
        if (!NT_SUCCESS(khttpStatus)) {
            kprintf("khttp 高层示例完成，但存在失败项: 0x%08X\r\n", static_cast<ULONG>(khttpStatus));
            finalStatus = khttpStatus;
        }
        else {
            kprintf("khttp 高层示例全部完成\r\n");
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
            kprintf("驱动卸载开始\r\n");
            ReleaseWskClient();
            kprintf("驱动卸载完成\r\n");
        }
    }
}

_Use_decl_annotations_
extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    kprintf("DriverEntry 开始\r\n");
    driverObject->DriverUnload = KernelHttp::DriverUnload;

    KernelHttp::g_wskClient = new KernelHttp::net::WskClient();
    if (KernelHttp::g_wskClient == nullptr) {
        kprintf("WskClient 分配失败\r\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = KernelHttp::g_wskClient->Initialize();
    if (!NT_SUCCESS(status)) {
        if (!KernelHttp::IsLoadTimeWskProviderUnavailable(status)) {
            kprintf("WSK 初始化失败: 0x%08X\r\n", static_cast<ULONG>(status));
            KernelHttp::ReleaseWskClient();
            return status;
        }

        kprintf(
            "WSK 初始化暂不可用，DriverEntry 继续完成: 0x%08X\r\n",
            static_cast<ULONG>(status));
        KernelHttp::ReleaseWskClient();
        kprintf("DriverEntry 完成: 0x%08X\r\n", static_cast<ULONG>(STATUS_SUCCESS));
        return STATUS_SUCCESS;
    }

    kprintf("WSK 已初始化，开始运行高层 HTTP/WebSocket 中文示例\r\n");

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
        kprintf("创建加载期示例线程失败: 0x%08X\r\n", static_cast<ULONG>(status));
        KernelHttp::ReleaseWskClient();
        return status;
    }

    status = ZwWaitForSingleObject(sampleThreadHandle, FALSE, nullptr);
    ZwClose(sampleThreadHandle);
    if (!NT_SUCCESS(status)) {
        kprintf("等待加载期示例线程失败: 0x%08X\r\n", static_cast<ULONG>(status));
        KernelHttp::ReleaseWskClient();
        return status;
    }

    const NTSTATUS sampleStatus = sampleThreadContext.Status;
    if (!NT_SUCCESS(sampleStatus)) {
        kprintf(
            "加载期示例存在失败项，DriverEntry 继续完成: 0x%08X\r\n",
            static_cast<ULONG>(sampleStatus));
    }

    status = STATUS_SUCCESS;
    kprintf("DriverEntry 完成: 0x%08X\r\n", static_cast<ULONG>(status));

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
