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
        NTSTATUS Initialize(ULONG waitTimeoutMilliseconds = WSK_INFINITE_WAIT) noexcept;

        void Shutdown() noexcept;

        bool IsInitialized() const noexcept;

        _Ret_maybenull_
        PWSK_CLIENT ProviderClient() const noexcept;

        _Ret_maybenull_
        const WSK_PROVIDER_DISPATCH* ProviderDispatch() const noexcept;

    private:
        WSK_CLIENT_NPI clientNpi_ = {};
        WSK_REGISTRATION registration_ = {};
        WSK_PROVIDER_NPI providerNpi_ = {};
        bool registered_ = false;
        bool providerCaptured_ = false;
    };
}
}
