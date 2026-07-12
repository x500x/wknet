#pragma once

#include "net/WskClient.h"

namespace wknet::net {
    class WskClient final
    {
    public:
        WskClient() noexcept;
        WskClient(const WskClient&) = delete;
        WskClient& operator=(const WskClient&) = delete;
        ~WskClient() noexcept;
        NTSTATUS Initialize(ULONG waitTimeoutMilliseconds = WskProviderCaptureTimeoutMilliseconds) noexcept;
        void Shutdown() noexcept;
        bool IsInitialized() const noexcept;
        PWSK_CLIENT ProviderClient() const noexcept;
        const WSK_PROVIDER_DISPATCH* ProviderDispatch() const noexcept;
        NTSTATUS Resolve(
            const wchar_t* nodeName,
            const wchar_t* serviceName,
            SOCKADDR_STORAGE* remoteAddress,
            WskAddressFamily addressFamily = WskAddressFamily::Any) noexcept;
        NTSTATUS ResolveAll(
            const wchar_t* nodeName,
            const wchar_t* serviceName,
            SOCKADDR_STORAGE* remoteAddresses,
            SIZE_T addressCapacity,
            SIZE_T* addressCount,
            WskAddressFamily addressFamily = WskAddressFamily::Any) noexcept;

    private:
        WSK_CLIENT_NPI clientNpi_ = {};
        WSK_REGISTRATION registration_ = {};
        WSK_PROVIDER_NPI providerNpi_ = {};
        bool registered_ = false;
        bool providerCaptured_ = false;
    };
}
