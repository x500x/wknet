#pragma once

#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/engine/Async.h>
#include <KernelHttp/engine/ConnectionPool.h>
#include <KernelHttp/engine/Workspace.h>
#include <KernelHttp/crypto/CngProviderCache.h>
#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/client/WebSocketClient.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

namespace KernelHttp
{
namespace engine
{
    constexpr SIZE_T KhMaxHeadersPerRequest = 16;
    constexpr SIZE_T KhMaxHeadersPerResponse = 32;
    constexpr SIZE_T KhMaxHeaderNameLength = 128;
    constexpr SIZE_T KhMaxHeaderValueLength = 512;
    constexpr SIZE_T KhMaxSchemeLength = 5;
    constexpr SIZE_T KhMaxHostLength = KhPoolMaxHostLength;
    constexpr SIZE_T KhMaxHostHeaderLength = KhMaxHostLength + 9;
    constexpr SIZE_T KhMaxPathLength = 2048;
    constexpr SIZE_T KhMaxServiceNameLength = 5;
    constexpr SIZE_T KhInitialOwnedBodyCapacity = 256;
    constexpr SIZE_T KhMultipartBoundaryStorageLength = 64;

    enum class KhHandleKind : ULONG
    {
        Session = 0x4B485331,
        Request = 0x4B485231,
        Response = 0x4B485031,
        WebSocket = 0x4B485731,
        AsyncOperation = 0x4B484131
    };

    struct KhHandleHeader
    {
        KhHandleKind Kind;
        bool Closed;
    };

    struct KhSession
    {
        KhHandleHeader Header = { KhHandleKind::Session, false };
        net::WskClient* WskClient = nullptr;
        KhSessionOptions Options = {};
        KhWorkspace* Workspace = nullptr;
        crypto::CngProviderCache* ProviderCache = nullptr;
        KhConnectionPool ConnectionPool = {};
    };

    struct KhStoredHeader
    {
        char* Name = nullptr;
        SIZE_T NameLength = 0;
        char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct KhRequest
    {
        KhHandleHeader Header = { KhHandleKind::Request, false };
        KH_SESSION Session = nullptr;
        KhHttpMethod Method = KhHttpMethod::Get;
        char* Url = nullptr;
        SIZE_T UrlLength = 0;
        char Scheme[KhMaxSchemeLength + 1] = {};
        SIZE_T SchemeLength = 0;
        char Host[KhMaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        char Path[KhMaxPathLength + 1] = {};
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool HasBody = false;
        UCHAR* OwnedBody = nullptr;
        SIZE_T OwnedBodyLength = 0;
        SIZE_T OwnedBodyCapacity = 0;
        ULONG BodyBuildCounter = 0;
        char MultipartBoundary[KhMultipartBoundaryStorageLength] = {};
        KhStoredHeader Headers[KhMaxHeadersPerRequest] = {};
        SIZE_T HeaderCount = 0;
        KhTlsOptions Tls = {};
        char* OwnedTlsServerName = nullptr;
        char* OwnedTlsAlpn = nullptr;
        bool HasTlsOverride = false;
        KhConnectionPolicy ConnectionPolicy = KhConnectionPolicy::ReuseOrCreate;
        KhAddressFamily AddressFamily = KhAddressFamily::Any;
    };

    struct KhResponse
    {
        KhHandleHeader Header = { KhHandleKind::Response, false };
        ULONG StatusCode = 0;
        UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        char* HeaderNameStorage = nullptr;
        SIZE_T HeaderNameStorageLength = 0;
        char* HeaderValueStorage = nullptr;
        SIZE_T HeaderValueStorageLength = 0;
    };

    struct KhWebSocket
    {
        KhHandleHeader Header = { KhHandleKind::WebSocket, false };
        KH_SESSION Session = nullptr;
        char* Url = nullptr;
        SIZE_T UrlLength = 0;
        char Scheme[KhMaxSchemeLength + 1] = {};
        SIZE_T SchemeLength = 0;
        char Host[KhMaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        char Path[KhMaxPathLength + 1] = {};
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        UCHAR* LastMessage = nullptr;
        SIZE_T LastMessageLength = 0;
        KhWebSocketMessageType LastMessageType = KhWebSocketMessageType::Binary;
        SIZE_T MaxMessageBytes = KhDefaultMaxResponseBytes;
        bool AutoReplyPing = true;
        bool Connected = false;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        client::WebSocketClient* Client = nullptr;
#endif
    };

    inline KhSession* AllocateSessionHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhSession*>(calloc(1, sizeof(KhSession)));
#else
        return new KhSession();
#endif
    }

    inline KhRequest* AllocateRequestHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhRequest*>(calloc(1, sizeof(KhRequest)));
#else
        return new KhRequest();
#endif
    }

    inline KhResponse* AllocateResponseHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhResponse*>(calloc(1, sizeof(KhResponse)));
#else
        return new KhResponse();
#endif
    }

    inline KhWebSocket* AllocateWebSocketHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhWebSocket*>(calloc(1, sizeof(KhWebSocket)));
#else
        return new KhWebSocket();
#endif
    }

    inline crypto::CngProviderCache* AllocateProviderCacheHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<crypto::CngProviderCache*>(calloc(1, sizeof(crypto::CngProviderCache)));
#else
        return new crypto::CngProviderCache();
#endif
    }

    inline void FreeHandle(_In_opt_ KhSession* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ KhRequest* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ KhResponse* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ KhWebSocket* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ crypto::CngProviderCache* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline bool IsHandleHeader(const KhHandleHeader* header, KhHandleKind expectedKind) noexcept
    {
        return header != nullptr && header->Kind == expectedKind && !header->Closed;
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    extern KhTestHttpTransportCallback g_testHttpTransport;
    extern void* g_testHttpTransportContext;
    extern KhTestWebSocketConnectCallback g_testWebSocketConnect;
    extern KhTestWebSocketSendCallback g_testWebSocketSend;
    extern KhTestWebSocketReceiveCallback g_testWebSocketReceive;
    extern KhTestWebSocketCloseCallback g_testWebSocketClose;
    extern void* g_testWebSocketTransportContext;
#endif

    bool IsPassiveLevel() noexcept;
    NTSTATUS CheckPassiveLevel() noexcept;
    SIZE_T EffectiveMaxResponseBytes(SIZE_T requestValue, SIZE_T sessionValue) noexcept;
    bool IsValidSendOptions(const KhHttpSendOptions& options, const KhSession& session) noexcept;
    bool IsValidWebSocketConnectOptions(const KhWebSocketConnectOptions& options) noexcept;
    bool IsValidReceiveOptions(const KhWebSocketReceiveOptions& options) noexcept;
    bool IsValidAddressFamily(KhAddressFamily addressFamily) noexcept;
    net::WskAddressFamily ToWskAddressFamily(KhAddressFamily addressFamily) noexcept;

    _Ret_maybenull_
    void* AllocateApiMemory(SIZE_T length) noexcept;

    void FreeApiMemory(_In_opt_ void* data) noexcept;

    _Ret_maybenull_
    char* AllocateTextCopy(const char* text, SIZE_T length) noexcept;

    _Ret_maybenull_
    UCHAR* AllocateBytesCopy(const UCHAR* data, SIZE_T length) noexcept;

    bool TextEqualsIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right,
        SIZE_T rightLength) noexcept;

    bool TextEqualsLiteralIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept;

    bool TextEqualsLiteral(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept;

    bool TextContainsChar(const char* text, SIZE_T textLength, char needle) noexcept;
    bool IsConnectionCloseStatus(NTSTATUS status) noexcept;
    bool IsDefaultPort(const char* scheme, SIZE_T schemeLength, USHORT port) noexcept;

    _Must_inspect_result_
    NTSTATUS CopyExactText(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;

    bool IsSessionHandle(KH_SESSION session) noexcept;
    bool IsRequestHandle(KH_REQUEST request) noexcept;
    bool IsResponseHandle(KH_RESPONSE response) noexcept;
    bool IsWebSocketHandle(KH_WEBSOCKET websocket) noexcept;

    void ReleaseRequestStorage(_Inout_ KhRequest& request) noexcept;

    _Must_inspect_result_
    NTSTATUS CloneRequestForAsync(_In_ const KhRequest& source, _Out_ KH_REQUEST* clonedRequest) noexcept;

    void ReleaseResponseStorage(_Inout_ KhResponse& response) noexcept;
    void ReleaseWebSocketStorage(_Inout_ KhWebSocket& websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS BuildHostHeaderValue(
        const KhRequest& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS CopyAsciiToWide(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept;

    _Must_inspect_result_
    NTSTATUS FormatServiceName(
        USHORT port,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept;

    tls::TlsProtocol ToTlsProtocol(KhTlsVersion version) noexcept;
#endif

    _Must_inspect_result_
    NTSTATUS KhHttpSendSyncImpl(
        _In_ KH_SESSION session,
        _In_ KH_REQUEST request,
        _In_opt_ const KhHttpSendOptions* options,
        _Out_opt_ KH_RESPONSE* response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpSendAsyncImpl(
        _In_ KH_SESSION session,
        _In_ KH_REQUEST request,
        _In_opt_ const KhHttpSendOptions* options,
        _Out_ KH_ASYNC_OPERATION* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketConnectSyncImpl(
        _In_ KH_SESSION session,
        _In_ const KhWebSocketConnectOptions* options,
        _Out_ KH_WEBSOCKET* websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketConnectAsyncImpl(
        _In_ KH_SESSION session,
        _In_ const KhWebSocketConnectOptions* options,
        _Out_ KH_ASYNC_OPERATION* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendTextSyncImpl(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        _In_opt_ const KhWebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendBinarySyncImpl(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const KhWebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketReceiveSyncImpl(
        _In_ KH_WEBSOCKET websocket,
        _In_opt_ const KhWebSocketReceiveOptions* options,
        _Out_opt_ KhWebSocketMessage* message) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketCloseSyncImpl(_In_opt_ KH_WEBSOCKET websocket) noexcept;
}
}
