#pragma once

#include "net/WskClient.h"

namespace wknet::net
{
class WskDatagramSocket;
using WskDatagramReceiveNotification = void (*)(void *context) noexcept;

struct WskDatagramReceiveResult final
{
    NTSTATUS Status = STATUS_PENDING;
    SIZE_T BytesReceived = 0;
    SOCKADDR_STORAGE RemoteAddress = {};
    ULONG RemoteAddressLength = 0;
    ULONGLONG Generation = 0;
};

NTSTATUS WskDatagramSocketCreate(_Inout_ WskClient *client, USHORT addressFamily,
                                 _Out_ WskDatagramSocket **socket) noexcept;

NTSTATUS WskDatagramSocketBind(_Inout_ WskDatagramSocket *socket, _In_ const SOCKADDR *localAddress) noexcept;

NTSTATUS WskDatagramSocketConnectPeer(_Inout_ WskDatagramSocket *socket, _In_ const SOCKADDR *remoteAddress) noexcept;

NTSTATUS WskDatagramSocketStartReceive(_Inout_ WskDatagramSocket *socket, _Out_writes_bytes_(length) void *data,
                                       SIZE_T length) noexcept;

NTSTATUS WskDatagramSocketSetReceiveNotification(_Inout_ WskDatagramSocket *socket,
                                                 _In_opt_ WskDatagramReceiveNotification notification,
                                                 _In_opt_ void *context) noexcept;

NTSTATUS WskDatagramSocketCancelReceive(_Inout_ WskDatagramSocket *socket) noexcept;

NTSTATUS WskDatagramSocketCompleteReceive(_Inout_ WskDatagramSocket *socket, ULONG timeoutMilliseconds,
                                          _Out_ WskDatagramReceiveResult *result) noexcept;

NTSTATUS WskDatagramSocketSend(_Inout_ WskDatagramSocket *socket, _In_reads_bytes_(length) const void *data,
                               SIZE_T length, _Out_opt_ SIZE_T *bytesSent) noexcept;

NTSTATUS WskDatagramSocketSendTo(_Inout_ WskDatagramSocket *socket, _In_reads_bytes_(length) const void *data,
                                 SIZE_T length, _In_ const SOCKADDR *remoteAddress,
                                 _Out_opt_ SIZE_T *bytesSent) noexcept;

NTSTATUS WskDatagramSocketGetLocalAddress(_In_ const WskDatagramSocket *socket,
                                          _Out_ SOCKADDR_STORAGE *localAddress) noexcept;

NTSTATUS WskDatagramSocketGetRemoteAddress(_In_ const WskDatagramSocket *socket,
                                           _Out_ SOCKADDR_STORAGE *remoteAddress) noexcept;

void WskDatagramSocketSetConnectionId(_Inout_opt_ WskDatagramSocket *socket, ULONGLONG connectionId) noexcept;

ULONGLONG WskDatagramSocketConnectionId(_In_opt_ const WskDatagramSocket *socket) noexcept;

NTSTATUS WskDatagramSocketClose(_Inout_opt_ WskDatagramSocket *socket) noexcept;

void WskDatagramSocketDestroy(_Inout_opt_ WskDatagramSocket *socket) noexcept;
} // namespace wknet::net
