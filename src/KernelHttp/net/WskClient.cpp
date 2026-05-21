#include "net/WskClient.h"

namespace KernelHttp
{
namespace net
{
    namespace
    {
        const WSK_CLIENT_DISPATCH WskClientDispatch = {
            MAKE_WSK_VERSION(1, 0),
            0,
            nullptr
        };

        _Function_class_(IO_COMPLETION_ROUTINE)
        NTSTATUS WskClientCompletionRoutine(
            _In_ PDEVICE_OBJECT deviceObject,
            _In_ PIRP irp,
            _In_opt_ PVOID context)
        {
            UNREFERENCED_PARAMETER(deviceObject);
            UNREFERENCED_PARAMETER(irp);

            auto* event = static_cast<PKEVENT>(context);
            KeSetEvent(event, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        _Must_inspect_result_
        NTSTATUS AllocateSyncIrp(_Outptr_ PIRP* irp, _Out_ PKEVENT event) noexcept
        {
            if (irp == nullptr || event == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *irp = IoAllocateIrp(1, FALSE);
            if (*irp == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            KeInitializeEvent(event, NotificationEvent, FALSE);
            IoSetCompletionRoutine(
                *irp,
                WskClientCompletionRoutine,
                event,
                TRUE,
                TRUE,
                TRUE);

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS CompleteSyncIrp(
            NTSTATUS requestStatus,
            _In_ PIRP irp,
            _In_ PKEVENT event,
            ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds) noexcept
        {
            if (requestStatus == STATUS_PENDING) {
                LARGE_INTEGER timeout = {};
                timeout.QuadPart = -static_cast<LONGLONG>(timeoutMilliseconds) * 10 * 1000;

                const NTSTATUS waitStatus = KeWaitForSingleObject(
                    event,
                    Executive,
                    KernelMode,
                    FALSE,
                    &timeout);

                if (waitStatus == STATUS_TIMEOUT) {
                    IoCancelIrp(irp);
                    KeWaitForSingleObject(event, Executive, KernelMode, FALSE, nullptr);
                    return STATUS_IO_TIMEOUT;
                }

                requestStatus = irp->IoStatus.Status;
            }

            return requestStatus;
        }

        _Must_inspect_result_
        bool CopySocketAddress(
            _In_ const ADDRINFOEXW* addressInfo,
            _Out_ SOCKADDR_STORAGE* remoteAddress) noexcept
        {
            if (addressInfo == nullptr ||
                addressInfo->ai_addr == nullptr ||
                remoteAddress == nullptr ||
                addressInfo->ai_addrlen > sizeof(*remoteAddress)) {
                return false;
            }

            if (addressInfo->ai_family != AF_INET && addressInfo->ai_family != AF_INET6) {
                return false;
            }

            RtlZeroMemory(remoteAddress, sizeof(*remoteAddress));
            RtlCopyMemory(remoteAddress, addressInfo->ai_addr, addressInfo->ai_addrlen);
            return true;
        }
    }

    WskClient::WskClient() noexcept
    {
        clientNpi_.ClientContext = this;
        clientNpi_.Dispatch = &WskClientDispatch;
    }

    WskClient::~WskClient() noexcept
    {
        Shutdown();
    }

    NTSTATUS WskClient::Initialize(ULONG waitTimeoutMilliseconds) noexcept
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (providerCaptured_) {
            return STATUS_SUCCESS;
        }

        NTSTATUS status = STATUS_SUCCESS;

        if (!registered_) {
            RtlZeroMemory(&registration_, sizeof(registration_));

            status = WskRegister(&clientNpi_, &registration_);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            registered_ = true;
        }

        RtlZeroMemory(&providerNpi_, sizeof(providerNpi_));

        status = WskCaptureProviderNPI(
            &registration_,
            waitTimeoutMilliseconds,
            &providerNpi_);

        if (!NT_SUCCESS(status)) {
            Shutdown();
            return status;
        }

        providerCaptured_ = true;
        return STATUS_SUCCESS;
    }

    void WskClient::Shutdown() noexcept
    {
        NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

        if (providerCaptured_) {
            WskReleaseProviderNPI(&registration_);
            providerCaptured_ = false;
            RtlZeroMemory(&providerNpi_, sizeof(providerNpi_));
        }

        if (registered_) {
            WskDeregister(&registration_);
            registered_ = false;
            RtlZeroMemory(&registration_, sizeof(registration_));
        }
    }

    bool WskClient::IsInitialized() const noexcept
    {
        return providerCaptured_ &&
            providerNpi_.Client != nullptr &&
            providerNpi_.Dispatch != nullptr;
    }

    PWSK_CLIENT WskClient::ProviderClient() const noexcept
    {
        return IsInitialized() ? providerNpi_.Client : nullptr;
    }

    const WSK_PROVIDER_DISPATCH* WskClient::ProviderDispatch() const noexcept
    {
        return IsInitialized() ? providerNpi_.Dispatch : nullptr;
    }

    NTSTATUS WskClient::Resolve(
        const wchar_t* nodeName,
        const wchar_t* serviceName,
        SOCKADDR_STORAGE* remoteAddress) noexcept
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (nodeName == nullptr || nodeName[0] == L'\0' ||
            serviceName == nullptr || serviceName[0] == L'\0' ||
            remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        auto* providerClient = ProviderClient();
        const auto* providerDispatch = ProviderDispatch();
        if (providerClient == nullptr ||
            providerDispatch == nullptr ||
            providerDispatch->WskGetAddressInfo == nullptr ||
            providerDispatch->WskFreeAddressInfo == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }

        UNICODE_STRING node = {};
        UNICODE_STRING service = {};
        RtlInitUnicodeString(&node, nodeName);
        RtlInitUnicodeString(&service, serviceName);

        ADDRINFOEXW hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        PIRP irp = nullptr;
        KEVENT event = {};

        NTSTATUS status = AllocateSyncIrp(&irp, &event);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        PADDRINFOEXW result = nullptr;
        status = providerDispatch->WskGetAddressInfo(
            providerClient,
            &node,
            &service,
            NS_ALL,
            nullptr,
            &hints,
            &result,
            nullptr,
            nullptr,
            irp);

        status = CompleteSyncIrp(status, irp, &event);
        IoFreeIrp(irp);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (result == nullptr) {
            return STATUS_NO_MATCH;
        }

        status = STATUS_OBJECT_NAME_NOT_FOUND;
        for (const ADDRINFOEXW* current = result; current != nullptr; current = current->ai_next) {
            if (CopySocketAddress(current, remoteAddress)) {
                status = STATUS_SUCCESS;
                break;
            }
        }

        providerDispatch->WskFreeAddressInfo(providerClient, result);
        return status;
    }
}
}
