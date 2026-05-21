#pragma once

#include "KernelHttpConfig.h"

#include <wsk.h>

namespace KernelHttp
{
namespace net
{
    class WskClient final
    {
    public:
        WskClient() noexcept;

        WskClient(const WskClient&) = delete;
        WskClient& operator=(const WskClient&) = delete;

        ~WskClient() noexcept;

        _Must_inspect_result_
        NTSTATUS Initialize(
            ULONG waitTimeoutMilliseconds = WskProviderCaptureTimeoutMilliseconds) noexcept;

        void Shutdown() noexcept;

        bool IsInitialized() const noexcept;

        _Ret_maybenull_
        PWSK_CLIENT ProviderClient() const noexcept;

        _Ret_maybenull_
        const WSK_PROVIDER_DISPATCH* ProviderDispatch() const noexcept;

        _Must_inspect_result_
        NTSTATUS Resolve(
            _In_z_ const wchar_t* nodeName,
            _In_z_ const wchar_t* serviceName,
            _Out_ SOCKADDR_STORAGE* remoteAddress) noexcept;

    private:
        WSK_CLIENT_NPI clientNpi_ = {};
        WSK_REGISTRATION registration_ = {};
        WSK_PROVIDER_NPI providerNpi_ = {};
        bool registered_ = false;
        bool providerCaptured_ = false;
    };
}
}
