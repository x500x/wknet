#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace
{
    using UCHAR = unsigned char;
    using USHORT = unsigned short;
    using ULONG = unsigned long;
    using SIZE_T = size_t;
    using HMODULE = void*;
    using FARPROC = void*;
    using SOCKET = uintptr_t;

    constexpr SOCKET InvalidSocket = static_cast<SOCKET>(~static_cast<uintptr_t>(0));
    constexpr int SocketError = -1;
    constexpr int AddressFamilyInet = 2;
    constexpr int SocketTypeStream = 1;
    constexpr int ProtocolTcp = 6;
    constexpr int SocketLevelSocket = 0xffff;
    constexpr int SocketReuseAddress = 0x0004;
    constexpr int SocketSendTimeout = 0x1005;
    constexpr int SocketReceiveTimeout = 0x1006;
    constexpr int SocketShutdownBoth = 2;
    constexpr int SslFileTypePem = 1;

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

    struct SslMethod;
    struct SslCtx;
    struct Ssl;

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
        using BindFn = int (__stdcall*)(SOCKET, const SockAddr*, int);
        using ListenFn = int (__stdcall*)(SOCKET, int);
        using AcceptFn = SOCKET (__stdcall*)(SOCKET, SockAddr*, int*);
        using SetSockOptFn = int (__stdcall*)(SOCKET, int, int, const char*, int);
        using ShutdownFn = int (__stdcall*)(SOCKET, int);

        HMODULE Module = nullptr;
        WsaStartupFn WsaStartup = nullptr;
        WsaCleanupFn WsaCleanup = nullptr;
        WsaGetLastErrorFn WsaGetLastError = nullptr;
        SocketFn Socket = nullptr;
        CloseSocketFn CloseSocket = nullptr;
        BindFn Bind = nullptr;
        ListenFn Listen = nullptr;
        AcceptFn Accept = nullptr;
        SetSockOptFn SetSockOpt = nullptr;
        ShutdownFn Shutdown = nullptr;
    };

    struct OpenSslApi final
    {
        using OpensslInitSslFn = int (__cdecl*)(uint64_t, const void*);
        using TlsServerMethodFn = const SslMethod* (__cdecl*)();
        using SslCtxNewFn = SslCtx* (__cdecl*)(const SslMethod*);
        using SslCtxFreeFn = void (__cdecl*)(SslCtx*);
        using SslCtxUseCertificateFileFn = int (__cdecl*)(SslCtx*, const char*, int);
        using SslCtxUsePrivateKeyFileFn = int (__cdecl*)(SslCtx*, const char*, int);
        using SslCtxCheckPrivateKeyFn = int (__cdecl*)(const SslCtx*);
        using SslCtxSetCipherListFn = int (__cdecl*)(SslCtx*, const char*);
        using SslNewFn = Ssl* (__cdecl*)(SslCtx*);
        using SslFreeFn = void (__cdecl*)(Ssl*);
        using SslSetFdFn = int (__cdecl*)(Ssl*, int);
        using SslAcceptFn = int (__cdecl*)(Ssl*);
        using SslReadFn = int (__cdecl*)(Ssl*, void*, int);
        using SslWriteFn = int (__cdecl*)(Ssl*, const void*, int);
        using SslRenegotiateFn = int (__cdecl*)(Ssl*);
        using SslRenegotiatePendingFn = int (__cdecl*)(const Ssl*);
        using SslDoHandshakeFn = int (__cdecl*)(Ssl*);
        using SslGetErrorFn = int (__cdecl*)(const Ssl*, int);
        using SslShutdownFn = int (__cdecl*)(Ssl*);
        using SslGetVersionFn = const char* (__cdecl*)(const Ssl*);
        using ErrGetErrorFn = unsigned long (__cdecl*)();
        using ErrErrorStringNFn = void (__cdecl*)(unsigned long, char*, size_t);

        HMODULE CryptoModule = nullptr;
        HMODULE SslModule = nullptr;
        OpensslInitSslFn OpensslInitSsl = nullptr;
        TlsServerMethodFn TlsServerMethod = nullptr;
        SslCtxNewFn SslCtxNew = nullptr;
        SslCtxFreeFn SslCtxFree = nullptr;
        SslCtxUseCertificateFileFn SslCtxUseCertificateFile = nullptr;
        SslCtxUsePrivateKeyFileFn SslCtxUsePrivateKeyFile = nullptr;
        SslCtxCheckPrivateKeyFn SslCtxCheckPrivateKey = nullptr;
        SslCtxSetCipherListFn SslCtxSetCipherList = nullptr;
        SslNewFn SslNew = nullptr;
        SslFreeFn SslFree = nullptr;
        SslSetFdFn SslSetFd = nullptr;
        SslAcceptFn SslAccept = nullptr;
        SslReadFn SslRead = nullptr;
        SslWriteFn SslWrite = nullptr;
        SslRenegotiateFn SslRenegotiate = nullptr;
        SslRenegotiatePendingFn SslRenegotiatePending = nullptr;
        SslDoHandshakeFn SslDoHandshake = nullptr;
        SslGetErrorFn SslGetError = nullptr;
        SslShutdownFn SslShutdown = nullptr;
        SslGetVersionFn SslGetVersion = nullptr;
        ErrGetErrorFn ErrGetError = nullptr;
        ErrErrorStringNFn ErrErrorStringN = nullptr;
    };

    template<typename T>
    bool LoadProc(HMODULE module, const char* name, T* function) noexcept
    {
        if (module == nullptr || name == nullptr || function == nullptr) {
            return false;
        }

        *function = reinterpret_cast<T>(GetProcAddress(module, name));
        if (*function == nullptr) {
            printf("missing procedure: %s\n", name);
            return false;
        }

        return true;
    }

    bool LoadWinsock(WinsockApi& api) noexcept
    {
        api = {};
        api.Module = LoadLibraryA("ws2_32.dll");
        if (api.Module == nullptr) {
            return false;
        }

        return
            LoadProc(api.Module, "WSAStartup", &api.WsaStartup) &&
            LoadProc(api.Module, "WSACleanup", &api.WsaCleanup) &&
            LoadProc(api.Module, "WSAGetLastError", &api.WsaGetLastError) &&
            LoadProc(api.Module, "socket", &api.Socket) &&
            LoadProc(api.Module, "closesocket", &api.CloseSocket) &&
            LoadProc(api.Module, "bind", &api.Bind) &&
            LoadProc(api.Module, "listen", &api.Listen) &&
            LoadProc(api.Module, "accept", &api.Accept) &&
            LoadProc(api.Module, "setsockopt", &api.SetSockOpt) &&
            LoadProc(api.Module, "shutdown", &api.Shutdown);
    }

    void UnloadWinsock(WinsockApi& api) noexcept
    {
        if (api.Module != nullptr) {
            FreeLibrary(api.Module);
        }
        api = {};
    }

    bool LoadOpenSsl(const char* cryptoPath, const char* sslPath, OpenSslApi& api) noexcept
    {
        api = {};
        api.CryptoModule = LoadLibraryA(cryptoPath);
        if (api.CryptoModule == nullptr) {
            printf("failed to load libcrypto: %s\n", cryptoPath != nullptr ? cryptoPath : "(null)");
            return false;
        }

        api.SslModule = LoadLibraryA(sslPath);
        if (api.SslModule == nullptr) {
            printf("failed to load libssl: %s\n", sslPath != nullptr ? sslPath : "(null)");
            return false;
        }

        return
            LoadProc(api.SslModule, "OPENSSL_init_ssl", &api.OpensslInitSsl) &&
            LoadProc(api.SslModule, "TLS_server_method", &api.TlsServerMethod) &&
            LoadProc(api.SslModule, "SSL_CTX_new", &api.SslCtxNew) &&
            LoadProc(api.SslModule, "SSL_CTX_free", &api.SslCtxFree) &&
            LoadProc(api.SslModule, "SSL_CTX_use_certificate_file", &api.SslCtxUseCertificateFile) &&
            LoadProc(api.SslModule, "SSL_CTX_use_PrivateKey_file", &api.SslCtxUsePrivateKeyFile) &&
            LoadProc(api.SslModule, "SSL_CTX_check_private_key", &api.SslCtxCheckPrivateKey) &&
            LoadProc(api.SslModule, "SSL_CTX_set_cipher_list", &api.SslCtxSetCipherList) &&
            LoadProc(api.SslModule, "SSL_new", &api.SslNew) &&
            LoadProc(api.SslModule, "SSL_free", &api.SslFree) &&
            LoadProc(api.SslModule, "SSL_set_fd", &api.SslSetFd) &&
            LoadProc(api.SslModule, "SSL_accept", &api.SslAccept) &&
            LoadProc(api.SslModule, "SSL_read", &api.SslRead) &&
            LoadProc(api.SslModule, "SSL_write", &api.SslWrite) &&
            LoadProc(api.SslModule, "SSL_renegotiate", &api.SslRenegotiate) &&
            LoadProc(api.SslModule, "SSL_renegotiate_pending", &api.SslRenegotiatePending) &&
            LoadProc(api.SslModule, "SSL_do_handshake", &api.SslDoHandshake) &&
            LoadProc(api.SslModule, "SSL_get_error", &api.SslGetError) &&
            LoadProc(api.SslModule, "SSL_shutdown", &api.SslShutdown) &&
            LoadProc(api.SslModule, "SSL_get_version", &api.SslGetVersion) &&
            LoadProc(api.CryptoModule, "ERR_get_error", &api.ErrGetError) &&
            LoadProc(api.CryptoModule, "ERR_error_string_n", &api.ErrErrorStringN);
    }

    void UnloadOpenSsl(OpenSslApi& api) noexcept
    {
        if (api.SslModule != nullptr) {
            FreeLibrary(api.SslModule);
        }
        if (api.CryptoModule != nullptr) {
            FreeLibrary(api.CryptoModule);
        }
        api = {};
    }

    USHORT HostToNetwork16(USHORT value) noexcept
    {
        return static_cast<USHORT>((value >> 8) | (value << 8));
    }

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

    void CloseSocket(const WinsockApi& api, SOCKET* socket) noexcept
    {
        if (socket != nullptr && *socket != InvalidSocket) {
            if (api.Shutdown != nullptr) {
                api.Shutdown(*socket, SocketShutdownBoth);
            }
            api.CloseSocket(*socket);
            *socket = InvalidSocket;
        }
    }

    bool SetSocketTimeouts(const WinsockApi& api, SOCKET socket, ULONG timeout) noexcept
    {
        return
            api.SetSockOpt(
                socket,
                SocketLevelSocket,
                SocketReceiveTimeout,
                reinterpret_cast<const char*>(&timeout),
                static_cast<int>(sizeof(timeout))) == 0 &&
            api.SetSockOpt(
                socket,
                SocketLevelSocket,
                SocketSendTimeout,
                reinterpret_cast<const char*>(&timeout),
                static_cast<int>(sizeof(timeout))) == 0;
    }

    SOCKET ListenLocalhost(const WinsockApi& api, USHORT port) noexcept
    {
        SOCKET listenSocket = api.Socket(AddressFamilyInet, SocketTypeStream, ProtocolTcp);
        if (listenSocket == InvalidSocket) {
            printf("socket failed: %d\n", api.WsaGetLastError());
            return InvalidSocket;
        }

        const int reuseAddress = 1;
        api.SetSockOpt(
            listenSocket,
            SocketLevelSocket,
            SocketReuseAddress,
            reinterpret_cast<const char*>(&reuseAddress),
            static_cast<int>(sizeof(reuseAddress)));

        SockAddrIn address = {};
        address.Family = AddressFamilyInet;
        address.Port = HostToNetwork16(port);
        address.Address.Address = 0x0100007fUL;

        if (api.Bind(listenSocket, reinterpret_cast<const SockAddr*>(&address), sizeof(address)) != 0) {
            printf("bind failed: %d\n", api.WsaGetLastError());
            CloseSocket(api, &listenSocket);
            return InvalidSocket;
        }

        if (api.Listen(listenSocket, 1) != 0) {
            printf("listen failed: %d\n", api.WsaGetLastError());
            CloseSocket(api, &listenSocket);
            return InvalidSocket;
        }

        return listenSocket;
    }

    void PrintOpenSslError(const OpenSslApi& api, const char* operation, Ssl* ssl, int result) noexcept
    {
        int sslError = 0;
        if (ssl != nullptr && api.SslGetError != nullptr) {
            sslError = api.SslGetError(ssl, result);
        }
        printf("%s failed: result=%d ssl_error=%d\n", operation, result, sslError);

        for (;;) {
            const unsigned long error = api.ErrGetError != nullptr ? api.ErrGetError() : 0;
            if (error == 0) {
                break;
            }

            char text[256] = {};
            api.ErrErrorStringN(error, text, sizeof(text));
            printf("openssl error: %s\n", text);
        }
    }

    bool ConfigureContext(const OpenSslApi& api, SslCtx* ctx, const char* certPath, const char* keyPath) noexcept
    {
        if (api.SslCtxSetCipherList(ctx, "ECDHE-RSA-AES128-GCM-SHA256") != 1) {
            PrintOpenSslError(api, "SSL_CTX_set_cipher_list", nullptr, 0);
            return false;
        }

        if (api.SslCtxUseCertificateFile(ctx, certPath, SslFileTypePem) != 1) {
            PrintOpenSslError(api, "SSL_CTX_use_certificate_file", nullptr, 0);
            return false;
        }

        if (api.SslCtxUsePrivateKeyFile(ctx, keyPath, SslFileTypePem) != 1) {
            PrintOpenSslError(api, "SSL_CTX_use_PrivateKey_file", nullptr, 0);
            return false;
        }

        if (api.SslCtxCheckPrivateKey(ctx) != 1) {
            PrintOpenSslError(api, "SSL_CTX_check_private_key", nullptr, 0);
            return false;
        }

        return true;
    }

    bool ReadHttpRequest(const OpenSslApi& api, Ssl* ssl) noexcept
    {
        char request[2048] = {};
        SIZE_T total = 0;
        while (total < sizeof(request) - 1) {
            const int capacity = static_cast<int>((sizeof(request) - 1) - total);
            const int received = api.SslRead(ssl, request + total, capacity);
            if (received <= 0) {
                PrintOpenSslError(api, "SSL_read request", ssl, received);
                return false;
            }

            total += static_cast<SIZE_T>(received);
            request[total] = '\0';
            if (strstr(request, "\r\n\r\n") != nullptr) {
                printf("server received request bytes=%Iu\n", total);
                return true;
            }
        }

        printf("HTTP request exceeded test buffer\n");
        return false;
    }

    bool CompleteRenegotiation(const OpenSslApi& api, Ssl* ssl) noexcept
    {
        int result = api.SslRenegotiate(ssl);
        if (result != 1) {
            PrintOpenSslError(api, "SSL_renegotiate", ssl, result);
            return false;
        }

        result = api.SslDoHandshake(ssl);
        if (result != 1) {
            PrintOpenSslError(api, "SSL_do_handshake renegotiation request", ssl, result);
            return false;
        }

        int pending = api.SslRenegotiatePending(ssl);
        printf("server renegotiation request sent pending=%d\n", pending);
        if (pending == 0) {
            return true;
        }

        char applicationByte = 0;
        for (ULONG attempt = 0; attempt < 8 && pending != 0; ++attempt) {
            result = api.SslRead(ssl, &applicationByte, 1);
            pending = api.SslRenegotiatePending(ssl);
            printf(
                "server renegotiation read attempt=%lu result=%d pending=%d\n",
                static_cast<unsigned long>(attempt + 1),
                result,
                pending);
            if (pending == 0) {
                return true;
            }
            if (result <= 0) {
                PrintOpenSslError(api, "SSL_read renegotiation", ssl, result);
                return false;
            }
        }

        printf("server renegotiation did not complete pending=%d\n", pending);
        return false;
    }

    bool WriteAllSsl(const OpenSslApi& api, Ssl* ssl, const char* data, SIZE_T length) noexcept
    {
        SIZE_T offset = 0;
        while (offset < length) {
            SIZE_T chunk = length - offset;
            if (chunk > static_cast<SIZE_T>(INT_MAX)) {
                chunk = static_cast<SIZE_T>(INT_MAX);
            }

            const int written = api.SslWrite(ssl, data + offset, static_cast<int>(chunk));
            if (written <= 0) {
                PrintOpenSslError(api, "SSL_write response", ssl, written);
                return false;
            }

            offset += static_cast<SIZE_T>(written);
        }

        return true;
    }

    int RunServer(USHORT port, const char* cryptoPath, const char* sslPath, const char* certPath, const char* keyPath) noexcept
    {
        WinsockApi winsock = {};
        OpenSslApi openssl = {};
        SOCKET listenSocket = InvalidSocket;
        SOCKET clientSocket = InvalidSocket;
        SslCtx* ctx = nullptr;
        Ssl* ssl = nullptr;
        SockAddr acceptedAddress = {};
        int acceptedAddressLength = sizeof(acceptedAddress);
        bool acceptedTlsClient = false;
        int exitCode = 1;

        if (!LoadWinsock(winsock)) {
            printf("failed to load ws2_32.dll\n");
            goto Cleanup;
        }

        UCHAR wsaData[512] = {};
        if (winsock.WsaStartup(0x0202, wsaData) != 0) {
            printf("WSAStartup failed\n");
            goto Cleanup;
        }

        if (!LoadOpenSsl(cryptoPath, sslPath, openssl)) {
            goto Cleanup;
        }

        if (openssl.OpensslInitSsl(0, nullptr) != 1) {
            PrintOpenSslError(openssl, "OPENSSL_init_ssl", nullptr, 0);
            goto Cleanup;
        }

        listenSocket = ListenLocalhost(winsock, port);
        if (listenSocket == InvalidSocket) {
            goto Cleanup;
        }

        ctx = openssl.SslCtxNew(openssl.TlsServerMethod());
        if (ctx == nullptr) {
            PrintOpenSslError(openssl, "SSL_CTX_new", nullptr, 0);
            goto Cleanup;
        }

        if (!ConfigureContext(openssl, ctx, certPath, keyPath)) {
            goto Cleanup;
        }

        printf("tls_renegotiation_server listening on 127.0.0.1:%u\n", static_cast<unsigned>(port));
        for (ULONG acceptAttempt = 0; acceptAttempt < 4; ++acceptAttempt) {
            acceptedAddress = {};
            acceptedAddressLength = sizeof(acceptedAddress);
            clientSocket = winsock.Accept(listenSocket, &acceptedAddress, &acceptedAddressLength);
            if (clientSocket == InvalidSocket) {
                printf("accept failed: %d\n", winsock.WsaGetLastError());
                goto Cleanup;
            }

            if (clientSocket > static_cast<SOCKET>(INT_MAX)) {
                printf("accepted socket handle does not fit OpenSSL SSL_set_fd\n");
                goto Cleanup;
            }

            if (!SetSocketTimeouts(winsock, clientSocket, 15000)) {
                printf("setsockopt timeout failed: %d\n", winsock.WsaGetLastError());
                goto Cleanup;
            }

            ssl = openssl.SslNew(ctx);
            if (ssl == nullptr) {
                PrintOpenSslError(openssl, "SSL_new", nullptr, 0);
                goto Cleanup;
            }

            if (openssl.SslSetFd(ssl, static_cast<int>(clientSocket)) != 1) {
                PrintOpenSslError(openssl, "SSL_set_fd", ssl, 0);
                goto Cleanup;
            }

            const int acceptResult = openssl.SslAccept(ssl);
            if (acceptResult == 1) {
                acceptedTlsClient = true;
                break;
            }

            PrintOpenSslError(openssl, "SSL_accept initial", ssl, acceptResult);
            openssl.SslFree(ssl);
            ssl = nullptr;
            CloseSocket(winsock, &clientSocket);
        }

        if (!acceptedTlsClient) {
            printf("server did not receive a TLS client connection\n");
            goto Cleanup;
        }

        printf("server initial handshake complete: %s\n", openssl.SslGetVersion(ssl));
        if (!ReadHttpRequest(openssl, ssl)) {
            goto Cleanup;
        }

        if (!SetSocketTimeouts(winsock, clientSocket, 1000)) {
            printf("setsockopt renegotiation timeout failed: %d\n", winsock.WsaGetLastError());
            goto Cleanup;
        }

        if (!CompleteRenegotiation(openssl, ssl)) {
            goto Cleanup;
        }

        static const char response[] =
            "HTTP/1.0 200 ok\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n"
            "renegotiated\n";
        if (!WriteAllSsl(openssl, ssl, response, sizeof(response) - 1)) {
            goto Cleanup;
        }

        printf("server renegotiation complete and response sent\n");
        exitCode = 0;

    Cleanup:
        if (ssl != nullptr) {
            if (openssl.SslShutdown != nullptr) {
                openssl.SslShutdown(ssl);
            }
            openssl.SslFree(ssl);
        }
        if (ctx != nullptr) {
            openssl.SslCtxFree(ctx);
        }
        CloseSocket(winsock, &clientSocket);
        CloseSocket(winsock, &listenSocket);
        if (winsock.WsaCleanup != nullptr) {
            winsock.WsaCleanup();
        }
        UnloadOpenSsl(openssl);
        UnloadWinsock(winsock);
        return exitCode;
    }
}

int main(int argc, char** argv)
{
    if (argc != 6) {
        printf("usage: tls_renegotiation_server <port> <libcrypto.dll> <libssl.dll> <cert.pem> <key.pem>\n");
        return 2;
    }

    USHORT port = 0;
    if (!ParsePort(argv[1], &port)) {
        printf("invalid port: %s\n", argv[1] != nullptr ? argv[1] : "(null)");
        return 2;
    }

    return RunServer(port, argv[2], argv[3], argv[4], argv[5]);
}
