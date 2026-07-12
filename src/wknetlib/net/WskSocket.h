#pragma once

#include "net/WskBuffer.h"
#include "net/WskClient.h"

namespace wknet
{
namespace net
{
    typedef bool (*WskCancellationCheck)(_In_opt_ void* context);

    struct WskCancellationToken final
    {
        WskCancellationCheck IsCancellationRequested = nullptr;
        void* Context = nullptr;
    };

#if defined(WKNET_USER_MODE_TEST)
    using PWSK_SOCKET = void*;
    using PIRP = void*;

    struct WSK_PROVIDER_CONNECTION_DISPATCH
    {
        int Dummy = 0;
    };

    typedef NTSTATUS (*WskTestSocketConnectCallback)(
        _In_opt_ void* context,
        _In_ const SOCKADDR* remoteAddress,
        _In_opt_ const SOCKADDR* localAddress,
        _In_opt_ const WskCancellationToken* cancellation,
        _Out_ PWSK_SOCKET* socket);

    typedef NTSTATUS (*WskTestSocketSendCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket,
        _In_reads_bytes_(length) const void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesSent,
        ULONG flags,
        _In_opt_ const WskCancellationToken* cancellation);

    typedef NTSTATUS (*WskTestSocketReceiveCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket,
        _Out_writes_bytes_(length) void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        _In_opt_ const WskCancellationToken* cancellation);

    typedef NTSTATUS (*WskTestSocketDisconnectCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket,
        ULONG flags);

    typedef void (*WskTestSocketCloseCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket);

    struct WskTestSocketProvider final
    {
        WskTestSocketConnectCallback Connect = nullptr;
        WskTestSocketSendCallback Send = nullptr;
        WskTestSocketReceiveCallback Receive = nullptr;
        WskTestSocketDisconnectCallback Disconnect = nullptr;
        WskTestSocketCloseCallback Close = nullptr;
    };

    void WskTestSetSocketProvider(
        _In_opt_ const WskTestSocketProvider* provider,
        _In_opt_ void* context) noexcept;
#endif

    class WskSocket;

    NTSTATUS WskSocketCreate(_Out_ WskSocket** socket) noexcept;
    NTSTATUS WskSocketConnect(
        _Inout_ WskSocket* socket,
        _Inout_ WskClient* client,
        _In_ const SOCKADDR* remoteAddress,
        _In_opt_ const SOCKADDR* localAddress = nullptr,
        _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;
    NTSTATUS WskSocketSend(
        _Inout_ WskSocket* socket,
        _In_reads_bytes_(length) const void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesSent,
        ULONG flags = WSK_FLAG_NODELAY,
        _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;
    NTSTATUS WskSocketReceive(
        _Inout_ WskSocket* socket,
        _Out_writes_bytes_(length) void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived,
        ULONG flags = 0,
        ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds,
        _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;
    NTSTATUS WskSocketClose(_Inout_opt_ WskSocket* socket) noexcept;
    void WskSocketDestroy(_Inout_opt_ WskSocket* socket) noexcept;
    bool WskSocketIsConnected(_In_opt_ const WskSocket* socket) noexcept;
    void WskSocketSetConnectionId(_Inout_opt_ WskSocket* socket, ULONGLONG connectionId) noexcept;
    ULONGLONG WskSocketConnectionId(_In_opt_ const WskSocket* socket) noexcept;
}
}
