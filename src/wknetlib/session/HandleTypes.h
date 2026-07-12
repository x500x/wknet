#pragma once

#include "session/Async.h"
#include "session/ConnectionPool.h"
#include "session/Workspace.h"
#include "rtl/Lookaside.h"
#include <wknet/crypto/CngProviderCache.h>
#include "session/WsConnection.h"

namespace wknet
{
namespace session
{
    struct HttpCache;

    constexpr SIZE_T MaxHeadersPerRequest = 16;
    constexpr SIZE_T MaxHeadersPerResponse = MaxConfigurableResponseHeaders;
    constexpr SIZE_T MaxTrailersPerResponse = 16;
    constexpr SIZE_T MaxHeaderNameLength = 128;
    constexpr SIZE_T MaxHeaderValueLength = 512;
    constexpr SIZE_T MaxSchemeLength = 5;
    constexpr SIZE_T MaxHostLength = PoolMaxHostLength;
    constexpr SIZE_T MaxHostHeaderLength = MaxHostLength + 9;
    constexpr SIZE_T MaxPathLength = 8000;
    constexpr SIZE_T MaxServiceNameLength = 5;
    constexpr SIZE_T InitialOwnedBodyCapacity = 256;
    constexpr SIZE_T MultipartBoundaryStorageLength = 64;

    enum class HandleKind : ULONG
    {
        Session = 0x4B485331,
        Request = 0x4B485231,
        Response = 0x4B485031,
        HttpCache = 0x4B484331,
        WebSocket = 0x4B485731,
        AsyncOperation = 0x4B484131
    };

    struct HandleHeader
    {
        HandleKind Kind;
        volatile LONG Closed;
        HandleHeader* TableNext;
    };

    struct Session
    {
        HandleHeader Header = { HandleKind::Session, 0, nullptr };
        net::WskClient* WskClient = nullptr;
        SessionOptions Options = {};
        Workspace* Workspace = nullptr;
        HttpCache* Cache = nullptr;
        rtl::LookasideList WorkspaceLookaside = {};
        crypto::CngProviderCache* ProviderCache = nullptr;
        ConnectionPool ConnectionPool = {};
        volatile LONG InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KEVENT DrainEvent = {};
#endif
    };

    struct StoredHeader
    {
        char* Name = nullptr;
        SIZE_T NameLength = 0;
        char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct Request
    {
        HandleHeader Header = { HandleKind::Request, 0, nullptr };
        SessionHandle Session = nullptr;
        HttpMethod Method = HttpMethod::Get;
        char* Url = nullptr;
        SIZE_T UrlLength = 0;
        char Scheme[MaxSchemeLength + 1] = {};
        SIZE_T SchemeLength = 0;
        char Host[MaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        char Path[MaxPathLength + 1] = {};
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool HasBody = false;
        RequestBodyMode BodyMode = RequestBodyMode::ContentLength;
        RequestBodyReadCallback BodySourceCallback = nullptr;
        void* BodySourceContext = nullptr;
        SIZE_T BodySourceContentLength = 0;
        bool BodySourceContentLengthKnown = false;
        UCHAR* OwnedBody = nullptr;
        SIZE_T OwnedBodyLength = 0;
        SIZE_T OwnedBodyCapacity = 0;
        ULONG BodyBuildCounter = 0;
        char MultipartBoundary[MultipartBoundaryStorageLength] = {};
        StoredHeader Headers[MaxHeadersPerRequest] = {};
        SIZE_T HeaderCount = 0;
        StoredHeader Trailers[MaxHeadersPerRequest] = {};
        SIZE_T TrailerCount = 0;
        TlsOptions Tls = {};
        char* OwnedTlsServerName = nullptr;
        char* OwnedTlsAlpn = nullptr;
        bool HasTlsOverride = false;
        ConnectionPolicy ConnectionPolicy = ConnectionPolicy::ReuseOrCreate;
        AddressFamily AddressFamily = AddressFamily::Any;
        volatile LONG InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KEVENT DrainEvent = {};
#endif
    };

    struct Response
    {
        HandleHeader Header = { HandleKind::Response, 0, nullptr };
        ULONG StatusCode = 0;
        UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        http1::HttpHeader* Trailers = nullptr;
        SIZE_T TrailerCount = 0;
        char* HeaderNameStorage = nullptr;
        SIZE_T HeaderNameStorageLength = 0;
        char* HeaderValueStorage = nullptr;
        SIZE_T HeaderValueStorageLength = 0;
        char* TrailerNameStorage = nullptr;
        SIZE_T TrailerNameStorageLength = 0;
        char* TrailerValueStorage = nullptr;
        SIZE_T TrailerValueStorageLength = 0;
        volatile LONG InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KEVENT DrainEvent = {};
#endif
    };

    struct WebSocket
    {
        HandleHeader Header = { HandleKind::WebSocket, 0, nullptr };
        SessionHandle Session = nullptr;
        ULONGLONG TraceOperationId = 0;
        ULONGLONG TraceConnectionId = 0;
        Workspace* Workspace = nullptr;
        char* Url = nullptr;
        SIZE_T UrlLength = 0;
        char Scheme[MaxSchemeLength + 1] = {};
        SIZE_T SchemeLength = 0;
        char Host[MaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        char Path[MaxPathLength + 1] = {};
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        StoredHeader ExtraHeaders[MaxHeadersPerRequest] = {};
        SIZE_T ExtraHeaderCount = 0;
        UCHAR* LastMessage = nullptr;
        SIZE_T LastMessageLength = 0;
        WebSocketMessageType LastMessageType = WebSocketMessageType::Binary;
        SIZE_T MaxMessageBytes = DefaultMaxWebSocketMessageBytes;
        bool AutoReplyPing = true;
        ws::PerMessageDeflateOptions PerMessageDeflate = {};
        bool Connected = false;
        bool TransportClosed = true;
        bool SendFragmentOpen = false;
        WebSocketMessageType SendFragmentType = WebSocketMessageType::Binary;
        SIZE_T SendFragmentLength = 0;
        ULONG SendTextUtf8CodePoint = 0;
        UCHAR SendTextUtf8Remaining = 0;
        UCHAR SendTextUtf8Expected = 0;
        volatile LONG InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KMUTEX SendLock = {};
        KMUTEX ReceiveLock = {};
        KEVENT DrainEvent = {};
        session::WsConnection* Client = nullptr;
#endif
    };
}
}
