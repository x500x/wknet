#pragma once

#include <KernelHttp/engine/Async.h>
#include <KernelHttp/engine/ConnectionPool.h>
#include <KernelHttp/engine/Workspace.h>
#include <KernelHttp/crypto/CngProviderCache.h>
#include <KernelHttp/client/WebSocketClient.h>

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
        volatile LONG Closed;
    };

    struct KhSession
    {
        KhHandleHeader Header = { KhHandleKind::Session, 0 };
        net::WskClient* WskClient = nullptr;
        KhSessionOptions Options = {};
        KhWorkspace* Workspace = nullptr;
        crypto::CngProviderCache* ProviderCache = nullptr;
        KhConnectionPool ConnectionPool = {};
        volatile LONG InFlight = 0;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        FAST_MUTEX OperationLock = {};
        KEVENT DrainEvent = {};
#endif
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
        KhHandleHeader Header = { KhHandleKind::Request, 0 };
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
        KhHandleHeader Header = { KhHandleKind::Response, 0 };
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
        KhHandleHeader Header = { KhHandleKind::WebSocket, 0 };
        KH_SESSION Session = nullptr;
        KhWorkspace* Workspace = nullptr;
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
}
}
