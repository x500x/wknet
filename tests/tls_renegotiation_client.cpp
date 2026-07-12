#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "transport/Transport.h"
#include "tls/TlsConnectionPrivate.hpp"
#include "tls/TlsPolicy.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace
{
    using HMODULE = void*;
    using FARPROC = void*;
    using SOCKET = uintptr_t;

    constexpr SOCKET InvalidSocket = static_cast<SOCKET>(~static_cast<uintptr_t>(0));
    constexpr int SocketError = -1;
    constexpr int AddressFamilyInet = 2;
    constexpr int SocketTypeStream = 1;
    constexpr int ProtocolTcp = 6;
    constexpr int SocketLevelSocket = 0xffff;
    constexpr int SocketReceiveTimeout = 0x1006;
    constexpr int WsaTimedOut = 10060;
    constexpr int WsaConnectionReset = 10054;
    constexpr int WsaConnectionAborted = 10053;
    constexpr int WsaShutdown = 10058;
    constexpr int WsaNotConnected = 10057;

    bool TextEquals(const char* left, SIZE_T leftLength, const char* right, SIZE_T rightLength) noexcept
    {
        if (leftLength != rightLength) {
            return false;
        }
        if (leftLength == 0) {
            return true;
        }

        return left != nullptr && right != nullptr && memcmp(left, right, leftLength) == 0;
    }

    struct SockAddr final
    {
        USHORT Family = 0;
        char Data[14] = {};
    };

    struct InAddr final
    {
        ULONG Address = 0;
    };

    struct SockAddrIn final
    {
        short Family = 0;
        USHORT Port = 0;
        InAddr Address = {};
        char Zero[8] = {};
    };

    extern "C" __declspec(dllimport) HMODULE __stdcall LoadLibraryA(const char* fileName);
    extern "C" __declspec(dllimport) FARPROC __stdcall GetProcAddress(HMODULE module, const char* procName);
    extern "C" __declspec(dllimport) int __stdcall FreeLibrary(HMODULE module);

    struct WinsockApi final
    {
        using WsaStartupFn = int (__stdcall*)(USHORT, void*);
        using WsaCleanupFn = int (__stdcall*)();
        using WsaGetLastErrorFn = int (__stdcall*)();
        using SocketFn = SOCKET (__stdcall*)(int, int, int);
        using CloseSocketFn = int (__stdcall*)(SOCKET);
        using ConnectFn = int (__stdcall*)(SOCKET, const SockAddr*, int);
        using SendFn = int (__stdcall*)(SOCKET, const char*, int, int);
        using RecvFn = int (__stdcall*)(SOCKET, char*, int, int);
        using SetSockOptFn = int (__stdcall*)(SOCKET, int, int, const char*, int);

        HMODULE Module = nullptr;
        WsaStartupFn WsaStartup = nullptr;
        WsaCleanupFn WsaCleanup = nullptr;
        WsaGetLastErrorFn WsaGetLastError = nullptr;
        SocketFn Socket = nullptr;
        CloseSocketFn CloseSocket = nullptr;
        ConnectFn Connect = nullptr;
        SendFn Send = nullptr;
        RecvFn Recv = nullptr;
        SetSockOptFn SetSockOpt = nullptr;
    };

    template<typename T>
    bool LoadWinsockProc(HMODULE module, const char* name, T* function) noexcept
    {
        if (module == nullptr || name == nullptr || function == nullptr) {
            return false;
        }

        *function = reinterpret_cast<T>(GetProcAddress(module, name));
        return *function != nullptr;
    }

    bool LoadWinsock(WinsockApi& api) noexcept
    {
        api = {};
        api.Module = LoadLibraryA("ws2_32.dll");
        if (api.Module == nullptr) {
            return false;
        }

        return
            LoadWinsockProc(api.Module, "WSAStartup", &api.WsaStartup) &&
            LoadWinsockProc(api.Module, "WSACleanup", &api.WsaCleanup) &&
            LoadWinsockProc(api.Module, "WSAGetLastError", &api.WsaGetLastError) &&
            LoadWinsockProc(api.Module, "socket", &api.Socket) &&
            LoadWinsockProc(api.Module, "closesocket", &api.CloseSocket) &&
            LoadWinsockProc(api.Module, "connect", &api.Connect) &&
            LoadWinsockProc(api.Module, "send", &api.Send) &&
            LoadWinsockProc(api.Module, "recv", &api.Recv) &&
            LoadWinsockProc(api.Module, "setsockopt", &api.SetSockOpt);
    }

    void UnloadWinsock(WinsockApi& api) noexcept
    {
        if (api.Module != nullptr) {
            FreeLibrary(api.Module);
        }
        api = {};
    }

    USHORT HostToNetwork16(USHORT value) noexcept
    {
        return static_cast<USHORT>((value >> 8) | (value << 8));
    }

    NTSTATUS SocketErrorToStatus(int error) noexcept
    {
        switch (error) {
        case WsaTimedOut:
            return STATUS_IO_TIMEOUT;
        case WsaConnectionReset:
            return STATUS_CONNECTION_RESET;
        case WsaConnectionAborted:
            return STATUS_CONNECTION_ABORTED;
        case WsaShutdown:
        case WsaNotConnected:
            return STATUS_CONNECTION_DISCONNECTED;
        default:
            return STATUS_UNSUCCESSFUL;
        }
    }

    class SocketTransport final
    {
    public:
        explicit SocketTransport(const WinsockApi& api) noexcept :
            api_(&api)
        {
            const wknet::transport::TransportCallbacks callbacks = {
                SendCallback,
                ReceiveCallback,
                ReceiveWithTimeoutCallback,
                nullptr
            };
            createStatus_ = wknet::transport::TransportCreateCallbacks(&callbacks, this, &handle_);
        }

        ~SocketTransport() noexcept
        {
            Close();
            wknet::transport::TransportClose(handle_);
        }

        SocketTransport(const SocketTransport&) = delete;
        SocketTransport& operator=(const SocketTransport&) = delete;

        wknet::transport::Transport* Handle() noexcept { return handle_; }
        NTSTATUS CreateStatus() const noexcept { return createStatus_; }

        NTSTATUS Connect(USHORT port) noexcept
        {
            Close();

            if (api_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            socket_ = api_->Socket(AddressFamilyInet, SocketTypeStream, ProtocolTcp);
            if (socket_ == InvalidSocket) {
                return SocketErrorToStatus(api_->WsaGetLastError());
            }

            SockAddrIn address = {};
            address.Family = AddressFamilyInet;
            address.Port = HostToNetwork16(port);
            address.Address.Address = 0x0100007fUL;

            if (api_->Connect(socket_, reinterpret_cast<const SockAddr*>(&address), sizeof(address)) != 0) {
                const NTSTATUS status = SocketErrorToStatus(api_->WsaGetLastError());
                Close();
                return status;
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS Send(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
        {
            if (bytesSent != nullptr) {
                *bytesSent = 0;
            }
            if (socket_ == InvalidSocket || data == nullptr || length == 0 || length > INT_MAX) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T totalSent = 0;
            while (totalSent < length) {
                const int chunkLength = static_cast<int>(length - totalSent);
                const int sent = api_->Send(socket_, static_cast<const char*>(data) + totalSent, chunkLength, 0);
                if (sent == SocketError) {
                    return SocketErrorToStatus(api_->WsaGetLastError());
                }
                if (sent == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }
                totalSent += static_cast<SIZE_T>(sent);
            }

            if (bytesSent != nullptr) {
                *bytesSent = totalSent;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS Receive(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
        {
            return ReceiveWithTimeout(buffer, length, bytesReceived, 15000);
        }

        NTSTATUS ReceiveWithTimeout(
            void* buffer,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept
        {
            if (bytesReceived != nullptr) {
                *bytesReceived = 0;
            }
            if (socket_ == InvalidSocket || buffer == nullptr || length == 0 || length > INT_MAX) {
                return STATUS_INVALID_PARAMETER;
            }

            const ULONG timeout = timeoutMilliseconds;
            if (api_->SetSockOpt(
                    socket_,
                    SocketLevelSocket,
                    SocketReceiveTimeout,
                    reinterpret_cast<const char*>(&timeout),
                    sizeof(timeout)) != 0) {
                return SocketErrorToStatus(api_->WsaGetLastError());
            }

            const int received = api_->Recv(socket_, static_cast<char*>(buffer), static_cast<int>(length), 0);
            if (received == SocketError) {
                return SocketErrorToStatus(api_->WsaGetLastError());
            }
            if (received == 0) {
                return STATUS_CONNECTION_DISCONNECTED;
            }

            if (bytesReceived != nullptr) {
                *bytesReceived = static_cast<SIZE_T>(received);
            }
            return STATUS_SUCCESS;
        }

    private:
        static NTSTATUS SendCallback(
            void* context, const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
        {
            auto* self = static_cast<SocketTransport*>(context);
            return self != nullptr ? self->Send(data, length, bytesSent) : STATUS_INVALID_PARAMETER;
        }

        static NTSTATUS ReceiveCallback(
            void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
        {
            auto* self = static_cast<SocketTransport*>(context);
            return self != nullptr ? self->Receive(buffer, length, bytesReceived) : STATUS_INVALID_PARAMETER;
        }

        static NTSTATUS ReceiveWithTimeoutCallback(
            void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept
        {
            auto* self = static_cast<SocketTransport*>(context);
            return self != nullptr
                ? self->ReceiveWithTimeout(buffer, length, bytesReceived, timeoutMilliseconds)
                : STATUS_INVALID_PARAMETER;
        }

        void Close() noexcept
        {
            if (api_ != nullptr && socket_ != InvalidSocket) {
                api_->CloseSocket(socket_);
                socket_ = InvalidSocket;
            }
        }

        const WinsockApi* api_ = nullptr;
        SOCKET socket_ = InvalidSocket;
        wknet::transport::Transport* handle_ = nullptr;
        NTSTATUS createStatus_ = STATUS_UNSUCCESSFUL;
    };

    bool ParsePort(const char* text, USHORT* port) noexcept
    {
        if (text == nullptr || port == nullptr || text[0] == '\0') {
            return false;
        }

        char* end = nullptr;
        const unsigned long value = strtoul(text, &end, 10);
        if (end == nullptr || *end != '\0' || value == 0 || value > 0xffff) {
            return false;
        }

        *port = static_cast<USHORT>(value);
        return true;
    }
}

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 3) {
        printf("usage: tls_renegotiation_client <port> [--client-renegotiate]\n");
        return 2;
    }

    USHORT port = 0;
    if (!ParsePort(argv[1], &port)) {
        printf("invalid port: %s\n", argv[1] != nullptr ? argv[1] : "(null)");
        return 2;
    }
    const bool clientInitiatedRenegotiation =
        argc == 3 && strcmp(argv[2], "--client-renegotiate") == 0;
    if (argc == 3 && !clientInitiatedRenegotiation) {
        printf("unknown option: %s\n", argv[2]);
        return 2;
    }

    WinsockApi winsock = {};
    if (!LoadWinsock(winsock)) {
        printf("failed to load ws2_32.dll\n");
        UnloadWinsock(winsock);
        return 1;
    }

    UCHAR wsaData[512] = {};
    if (winsock.WsaStartup(0x0202, wsaData) != 0) {
        printf("WSAStartup failed\n");
        UnloadWinsock(winsock);
        return 1;
    }

    int exitCode = 1;
    {
        SocketTransport transport(winsock);
        NTSTATUS status = transport.Connect(port);
        if (!NT_SUCCESS(status)) {
            printf("socket connect failed: 0x%08X\n", static_cast<unsigned>(status));
            goto Cleanup;
        }

        wknet::tls::TlsConnection connection;
        wknet::tls::TlsClientConnectionOptions options = {};
        options.ServerName = "localhost";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = wknet::tls::TlsProtocol::Tls12;
        options.MaximumProtocol = wknet::tls::TlsProtocol::Tls12;
        options.Policy.Profile = wknet::tls::TlsSecurityProfile::CompatibilityExplicit;
        options.Policy.EnableTls12Renegotiation = true;
        options.MaxTls12Renegotiations = 1;
        const wknet::tls::TlsAlpnProtocol alpnProtocols[] = {
            { "h2", sizeof("h2") - 1 },
            { "http/1.1", sizeof("http/1.1") - 1 }
        };
        if (clientInitiatedRenegotiation) {
            options.AlpnProtocols = alpnProtocols;
            options.AlpnProtocolCount = sizeof(alpnProtocols) / sizeof(alpnProtocols[0]);
        }

        status = connection.Connect(transport.Handle(), options);
        if (!NT_SUCCESS(status)) {
            const wknet::tls::TlsHandshakeFailure& failure = connection.LastHandshakeFailure();
            printf(
                "TLS connect failed: 0x%08X category=%lu detail=0x%08X\n",
                static_cast<unsigned>(status),
                static_cast<unsigned long>(failure.Category),
                static_cast<unsigned>(failure.Status));
            goto Cleanup;
        }

        const char* initialAlpn = connection.NegotiatedAlpn();
        const SIZE_T initialAlpnLength = connection.NegotiatedAlpnLength();
        const bool shouldObserveAlpnRenegotiation =
            TextEquals(initialAlpn, initialAlpnLength, "h2", sizeof("h2") - 1);

        if (clientInitiatedRenegotiation) {
            status = connection.RenegotiateTls12(transport.Handle());
            if (!NT_SUCCESS(status)) {
                const wknet::tls::TlsHandshakeFailure& failure = connection.LastHandshakeFailure();
                printf(
                    "TLS client-initiated renegotiation failed: 0x%08X category=%lu detail=0x%08X\n",
                    static_cast<unsigned>(status),
                    static_cast<unsigned long>(failure.Category),
                    static_cast<unsigned>(failure.Status));
                goto Cleanup;
            }

            const char* renegotiatedAlpn = connection.NegotiatedAlpn();
            const SIZE_T renegotiatedAlpnLength = connection.NegotiatedAlpnLength();
            if (shouldObserveAlpnRenegotiation &&
                renegotiatedAlpnLength != 0 &&
                !TextEquals(renegotiatedAlpn, renegotiatedAlpnLength, "http/1.1", sizeof("http/1.1") - 1)) {
                printf(
                    "TLS ALPN renegotiation produced unexpected protocol: %.*s\n",
                    static_cast<int>(renegotiatedAlpnLength),
                    renegotiatedAlpn != nullptr ? renegotiatedAlpn : "");
                goto Cleanup;
            }

            printf(
                "TLS 1.2 client-initiated renegotiation complete alpn=%.*s\n",
                static_cast<int>(renegotiatedAlpnLength),
                renegotiatedAlpn != nullptr ? renegotiatedAlpn : "");
        }

        static const char request[] =
            "GET /reneg HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "\r\n";
        SIZE_T bytesSent = 0;
        status = connection.Send(transport.Handle(), request, sizeof(request) - 1, &bytesSent);
        if (!NT_SUCCESS(status) || bytesSent != sizeof(request) - 1) {
            printf("TLS request send failed: 0x%08X sent=%Iu\n", static_cast<unsigned>(status), bytesSent);
            goto Cleanup;
        }

        char response[8192] = {};
        SIZE_T responseLength = 0;
        for (ULONG attempt = 0; attempt < 64 && responseLength < sizeof(response) - 1; ++attempt) {
            SIZE_T bytesReceived = 0;
            status = connection.Receive(
                transport,
                response + responseLength,
                (sizeof(response) - 1) - responseLength,
                &bytesReceived,
                15000);
            if (status == STATUS_CONNECTION_DISCONNECTED) {
                break;
            }
            if (!NT_SUCCESS(status)) {
                const wknet::tls::TlsHandshakeFailure& failure = connection.LastHandshakeFailure();
                printf(
                    "TLS response receive failed: 0x%08X after=%Iu category=%lu detail=0x%08X alert=%u/%u\n",
                    static_cast<unsigned>(status),
                    responseLength,
                    static_cast<unsigned long>(failure.Category),
                    static_cast<unsigned>(failure.Status),
                    failure.HasPeerAlert ? static_cast<unsigned>(failure.PeerAlert.Level) : 0,
                    failure.HasPeerAlert ? static_cast<unsigned>(failure.PeerAlert.Description) : 0);
                goto Cleanup;
            }
            if (bytesReceived == 0) {
                break;
            }
            responseLength += bytesReceived;
            response[responseLength] = '\0';
            if (strstr(response, "HTTP/1.0 200") != nullptr ||
                strstr(response, "HTTP/1.1 200") != nullptr ||
                strstr(response, "s_server") != nullptr) {
                exitCode = 0;
                break;
            }
        }

        if (exitCode != 0 && responseLength != 0) {
            exitCode = 0;
        }

        if (exitCode == 0) {
            printf("TLS 1.2 renegotiation client received %Iu bytes\n", responseLength);
        }
        else {
            printf("TLS 1.2 renegotiation client received no response\n");
        }
    }

Cleanup:
    winsock.WsaCleanup();
    UnloadWinsock(winsock);
    return exitCode;
}
