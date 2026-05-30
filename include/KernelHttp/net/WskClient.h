#pragma once

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <KernelHttp/KernelHttpConfig.h>

using PWSK_CLIENT = void*;
using SOCKADDR = struct SOCKADDR;

struct SOCKADDR
{
    USHORT sa_family = 0;
    char sa_data[14] = {};
};

struct SOCKADDR_STORAGE
{
    USHORT ss_family = 0;
};

struct WSK_CLIENT_NPI
{
    void* ClientContext = nullptr;
    const void* Dispatch = nullptr;
};

struct WSK_REGISTRATION
{
    int Dummy = 0;
};

struct WSK_PROVIDER_NPI
{
    PWSK_CLIENT Client = nullptr;
    const void* Dispatch = nullptr;
};

struct WSK_PROVIDER_DISPATCH
{
    int Dummy = 0;
};

#else
#include <KernelHttp/KernelHttpConfig.h>

#include <wsk.h>
#endif

namespace KernelHttp
{
namespace net
{
    constexpr SIZE_T WskMaxResolvedAddresses = 8;

    enum class WskAddressFamily : ULONG
    {
        Any = 0,
        Ipv4 = 4,
        Ipv6 = 6
    };

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
            _Out_ SOCKADDR_STORAGE* remoteAddress,
            WskAddressFamily addressFamily = WskAddressFamily::Any) noexcept;

        _Must_inspect_result_
        NTSTATUS ResolveAll(
            _In_z_ const wchar_t* nodeName,
            _In_z_ const wchar_t* serviceName,
            _Out_writes_(addressCapacity) SOCKADDR_STORAGE* remoteAddresses,
            SIZE_T addressCapacity,
            _Out_ SIZE_T* addressCount,
            WskAddressFamily addressFamily = WskAddressFamily::Any) noexcept;

    private:
        WSK_CLIENT_NPI clientNpi_ = {};
        WSK_REGISTRATION registration_ = {};
        WSK_PROVIDER_NPI providerNpi_ = {};
        bool registered_ = false;
        bool providerCaptured_ = false;
    };
}
}
