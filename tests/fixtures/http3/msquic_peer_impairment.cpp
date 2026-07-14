#include "msquic_peer.h"

#include <msquicp.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <string.h>

namespace
{
    constexpr uint32_t QuicVersion2HostOrder = 0x6b3343cfU;
    constexpr int MaximumDatagramBytes = 65536;

    struct MsQuicPeerUdpProxy final
    {
        MsQuicPeerOptions Options = {};
        SOCKET ExternalSocket = INVALID_SOCKET;
        SOCKET InternalSocket = INVALID_SOCKET;
        HANDLE Thread = nullptr;
        sockaddr_in ServerAddress = {};
        sockaddr_storage ClientAddress = {};
        int ClientAddressLength = 0;
        int HeldLength = 0;
        uint8_t HeldDatagram[MaximumDatagramBytes] = {};
    };

    MsQuicPeerUdpProxy g_proxy = {};
    volatile LONG g_stopRequested = 0;
    volatile LONG g_stage = 0;
    bool g_winsockStarted = false;

    bool SendDatagram(SOCKET socket, const uint8_t* data, int length, const sockaddr* address,
                      int addressLength) noexcept
    {
        return sendto(socket, reinterpret_cast<const char*>(data), length, 0, address, addressLength) == length;
    }

    void ForwardServerDatagram(const uint8_t* data, int length) noexcept
    {
        if (g_proxy.ClientAddressLength == 0)
        {
            return;
        }
        const LONG stage = InterlockedCompareExchange(&g_stage, 0, 0);
        if (stage == 1)
        {
            InterlockedExchange(&g_stage, 2);
            MsQuicPeerLog(g_proxy.Options, "loss-reorder dropped server datagram bytes=%d", length);
            return;
        }
        if (stage == 2)
        {
            memcpy(g_proxy.HeldDatagram, data, static_cast<size_t>(length));
            g_proxy.HeldLength = length;
            InterlockedExchange(&g_stage, 3);
            return;
        }
        const sockaddr* clientAddress = reinterpret_cast<const sockaddr*>(&g_proxy.ClientAddress);
        if (stage == 3)
        {
            const bool currentSent =
                SendDatagram(g_proxy.ExternalSocket, data, length, clientAddress, g_proxy.ClientAddressLength);
            const bool heldSent = SendDatagram(g_proxy.ExternalSocket, g_proxy.HeldDatagram, g_proxy.HeldLength,
                                               clientAddress, g_proxy.ClientAddressLength);
            MsQuicPeerLog(g_proxy.Options, "loss-reorder reversed server datagrams current=%d held=%d status=%u",
                          length, g_proxy.HeldLength, currentSent && heldSent ? 1U : 0U);
            g_proxy.HeldLength = 0;
            InterlockedExchange(&g_stage, 0);
            return;
        }
        (void)SendDatagram(g_proxy.ExternalSocket, data, length, clientAddress, g_proxy.ClientAddressLength);
    }

    DWORD WINAPI UdpProxyThread(void*) noexcept
    {
        uint8_t datagram[MaximumDatagramBytes] = {};
        while (InterlockedCompareExchange(&g_stopRequested, 0, 0) == 0)
        {
            fd_set readSet = {};
            FD_ZERO(&readSet);
            FD_SET(g_proxy.ExternalSocket, &readSet);
            FD_SET(g_proxy.InternalSocket, &readSet);
            timeval timeout = {};
            timeout.tv_usec = 100000;
            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR)
            {
                if (InterlockedCompareExchange(&g_stopRequested, 0, 0) == 0)
                {
                    MsQuicPeerLog(g_proxy.Options, "loss-reorder select failed error=%d", WSAGetLastError());
                }
                break;
            }
            if (ready == 0)
            {
                continue;
            }
            if (FD_ISSET(g_proxy.ExternalSocket, &readSet))
            {
                int addressLength = sizeof(g_proxy.ClientAddress);
                const int length = recvfrom(g_proxy.ExternalSocket, reinterpret_cast<char*>(datagram), sizeof(datagram),
                                            0, reinterpret_cast<sockaddr*>(&g_proxy.ClientAddress), &addressLength);
                if (length > 0)
                {
                    g_proxy.ClientAddressLength = addressLength;
                    (void)SendDatagram(g_proxy.InternalSocket, datagram, length,
                                       reinterpret_cast<const sockaddr*>(&g_proxy.ServerAddress),
                                       sizeof(g_proxy.ServerAddress));
                }
            }
            if (FD_ISSET(g_proxy.InternalSocket, &readSet))
            {
                sockaddr_storage sourceAddress = {};
                int sourceAddressLength = sizeof(sourceAddress);
                const int length = recvfrom(g_proxy.InternalSocket, reinterpret_cast<char*>(datagram), sizeof(datagram),
                                            0, reinterpret_cast<sockaddr*>(&sourceAddress), &sourceAddressLength);
                if (length > 0)
                {
                    ForwardServerDatagram(datagram, length);
                }
            }
        }
        return 0;
    }

    bool BindLoopbackSocket(SOCKET socket, uint16_t port) noexcept
    {
        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != SOCKET_ERROR;
    }
} // namespace

bool MsQuicPeerApplyScenarioGlobalSettings(const MsQuicPeerOptions& options) noexcept
{
    if (_stricmp(options.Scenario, "retry") == 0)
    {
        uint16_t retryMemoryPercent = 0;
        const QUIC_STATUS status = g_msquic->SetParam(nullptr, QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
                                                      sizeof(retryMemoryPercent), &retryMemoryPercent);
        return QUIC_SUCCEEDED(status);
    }
    if (_stricmp(options.Scenario, "vn") == 0)
    {
        const uint32_t version2 = QuicVersion2HostOrder;
        const QUIC_VERSION_SETTINGS settings = {&version2, &version2, &version2, 1, 1, 1};
        const QUIC_STATUS status =
            g_msquic->SetParam(nullptr, QUIC_PARAM_GLOBAL_VERSION_SETTINGS, sizeof(settings), &settings);
        return QUIC_SUCCEEDED(status);
    }
    return true;
}

bool MsQuicPeerForceKeyUpdate(HQUIC connection) noexcept
{
    return QUIC_SUCCEEDED(g_msquic->SetParam(connection, QUIC_PARAM_CONN_FORCE_KEY_UPDATE, 0, nullptr));
}

bool MsQuicPeerStartImpairment(const MsQuicPeerOptions& options, uint16_t listenerPort) noexcept
{
    if (_stricmp(options.Scenario, "loss-reorder") != 0)
    {
        return true;
    }
    WSADATA winsock = {};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0)
    {
        return false;
    }
    g_winsockStarted = true;
    InterlockedExchange(&g_stopRequested, 0);
    InterlockedExchange(&g_stage, 0);
    g_proxy.Options = options;
    g_proxy.ServerAddress.sin_family = AF_INET;
    g_proxy.ServerAddress.sin_port = htons(listenerPort);
    g_proxy.ServerAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_proxy.ExternalSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    g_proxy.InternalSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_proxy.ExternalSocket == INVALID_SOCKET || g_proxy.InternalSocket == INVALID_SOCKET ||
        !BindLoopbackSocket(g_proxy.ExternalSocket, options.Port) || !BindLoopbackSocket(g_proxy.InternalSocket, 0))
    {
        MsQuicPeerStopImpairment();
        return false;
    }
    g_proxy.Thread = CreateThread(nullptr, 0, UdpProxyThread, nullptr, 0, nullptr);
    if (g_proxy.Thread == nullptr)
    {
        MsQuicPeerStopImpairment();
        return false;
    }
    MsQuicPeerLog(options, "loss-reorder UDP proxy ready external=%u internal=%u", options.Port, listenerPort);
    return true;
}

void MsQuicPeerArmImpairment(const MsQuicPeerOptions& options) noexcept
{
    if (_stricmp(options.Scenario, "loss-reorder") == 0)
    {
        InterlockedCompareExchange(&g_stage, 1, 0);
    }
}

void MsQuicPeerStopImpairment() noexcept
{
    InterlockedExchange(&g_stopRequested, 1);
    if (g_proxy.ExternalSocket != INVALID_SOCKET)
    {
        closesocket(g_proxy.ExternalSocket);
        g_proxy.ExternalSocket = INVALID_SOCKET;
    }
    if (g_proxy.InternalSocket != INVALID_SOCKET)
    {
        closesocket(g_proxy.InternalSocket);
        g_proxy.InternalSocket = INVALID_SOCKET;
    }
    if (g_proxy.Thread != nullptr)
    {
        WaitForSingleObject(g_proxy.Thread, 5000);
        CloseHandle(g_proxy.Thread);
        g_proxy.Thread = nullptr;
    }
    if (g_winsockStarted)
    {
        WSACleanup();
        g_winsockStarted = false;
    }
}
