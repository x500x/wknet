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
}
}
