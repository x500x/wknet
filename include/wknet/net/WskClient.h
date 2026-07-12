#pragma once

#if defined(WKNET_USER_MODE_TEST)
#include <wknet/WknetConfig.h>

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
    UCHAR __ss_pad[126] = {};
};

struct SOCKADDR_IN
{
    USHORT sin_family = 0;
    USHORT sin_port = 0;
    ULONG sin_addr = 0;
    char sin_zero[8] = {};
};

struct SOCKADDR_IN6
{
    USHORT sin6_family = 0;
    USHORT sin6_port = 0;
    ULONG sin6_flowinfo = 0;
    UCHAR sin6_addr[16] = {};
    ULONG sin6_scope_id = 0;
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

struct WSK_PROVIDER_DISPATCH
{
    int Dummy = 0;
};

struct WSK_PROVIDER_NPI
{
    PWSK_CLIENT Client = nullptr;
    const WSK_PROVIDER_DISPATCH* Dispatch = nullptr;
};

#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 23
#endif

#else
#include <wknet/WknetConfig.h>

#include <wsk.h>
#endif

namespace wknet
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

#if defined(WKNET_USER_MODE_TEST)
    typedef NTSTATUS (*WskTestResolveAllCallback)(
        _In_opt_ void* context,
        _In_z_ const wchar_t* nodeName,
        _In_z_ const wchar_t* serviceName,
        _Out_writes_(addressCapacity) SOCKADDR_STORAGE* remoteAddresses,
        SIZE_T addressCapacity,
        _Out_ SIZE_T* addressCount,
        WskAddressFamily addressFamily);

    void WskTestSetResolveAll(
        _In_opt_ WskTestResolveAllCallback callback,
        _In_opt_ void* context) noexcept;

    void WskTestClearResolveCache() noexcept;

    void WskTestAdvanceResolveCacheTime(ULONGLONG delta100ns) noexcept;
#endif

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
