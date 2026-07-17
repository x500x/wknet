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
    struct AltSvcCache;

    // Growth ceilings for client-owned request headers. These are protocol-safety
    // bounds (same family as WKNET_HARD_*), not fixed array sizes: storage is a
    // pointer + count + capacity list that doubles until these limits.
    constexpr SIZE_T MaxHeadersPerRequest = WKNET_HARD_MAX_HEADERS;
    constexpr SIZE_T MaxHeadersPerResponse = MaxConfigurableResponseHeaders;
    constexpr SIZE_T MaxTrailersPerResponse = WKNET_HARD_MAX_HEADERS;
    // Names stay modest (token identifiers); values follow the H1 line budget so
    // Cookie / JWT / large Authorization headers are accepted.
    constexpr SIZE_T MaxHeaderNameLength = 128;
    constexpr SIZE_T MaxHeaderValueLength = 8 * 1024;
    // Cache validators keep a smaller inline copy until M5 heap conversion.
    constexpr SIZE_T HttpCacheValidatorFieldBytes = 512;
    constexpr SIZE_T MaxSchemeLength = 5;
    constexpr SIZE_T MaxHostLength = PoolMaxHostLength;
    constexpr SIZE_T MaxHostHeaderLength = MaxHostLength + 9;
    // Hard ceiling for request-target length (path + query). Storage is heap-owned.
    // Keep this within Workspace header-scratch budget (see HttpRequestTargetScratchBytes).
    constexpr SIZE_T MaxPathLength = 16 * 1024;
    constexpr SIZE_T MaxServiceNameLength = 5;
    constexpr SIZE_T InitialOwnedBodyCapacity = 256;
    constexpr SIZE_T InitialHeaderListCapacity = 8;
    constexpr SIZE_T MultipartBoundaryStorageLength = 64;

    // Numeric handle tags are stable ABI cookies (historical values retained).
    // Names are product-neutral; do not reintroduce legacy product-name literals.
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
        AltSvcCache* AltSvc = nullptr;
        rtl::LookasideList WorkspaceLookaside = {};
        crypto::CngProviderCache* ProviderCache = nullptr;
        ConnectionPool ConnectionPool = {};
        bool NetworkChangeSubscribed = false;
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

    // Growable NonPaged header table. Items is null when Capacity == 0.
    // Call EnsureStoredHeaderListCapacity before writing a new slot.
    struct StoredHeaderList
    {
        StoredHeader* Items = nullptr;
        SIZE_T Count = 0;
        SIZE_T Capacity = 0;

        _Ret_maybenull_
        StoredHeader* Data() noexcept
        {
            return Items;
        }

        _Ret_maybenull_
        const StoredHeader* Data() const noexcept
        {
            return Items;
        }

        StoredHeader& operator[](SIZE_T index) noexcept
        {
            return Items[index];
        }

        const StoredHeader& operator[](SIZE_T index) const noexcept
        {
            return Items[index];
        }
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
        char* Path = nullptr;
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
        StoredHeaderList Headers = {};
        SIZE_T HeaderCount = 0; // mirrors Headers.Count for call-site compatibility
        StoredHeaderList Trailers = {};
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
        char* Path = nullptr;
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        StoredHeaderList ExtraHeaders = {};
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
