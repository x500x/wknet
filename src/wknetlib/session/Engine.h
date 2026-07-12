#pragma once

#include "http1/HttpContentEncoding.h"
#include "http1/HttpTypes.h"
#include "http2/Http2Frame.h"
#include <wknet/WknetLimits.h>
#include "net/WskClient.h"
#include "tls/TlsPolicy.h"
#include "ws/WebSocketDeflate.h"

namespace wknet
{
namespace tls
{
    class CertificateStore;
    struct TlsClientCredential;
}
}

#if defined(WKNET_USER_MODE_TEST)
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#endif
#endif

namespace wknet
{
namespace session
{
    struct Session;
    struct Request;
    struct Response;
    struct HttpCache;
    struct WebSocket;
    struct AsyncOperation;

    typedef Session* SessionHandle;
    typedef Request* RequestHandle;
    typedef Response* ResponseHandle;
    typedef HttpCache* HttpCacheHandle;
    typedef WebSocket* WebSocketHandle;
    typedef AsyncOperation* AsyncOperationHandle;

    constexpr SIZE_T DefaultRequestBufferBytes = 16 * 1024;
    constexpr SIZE_T DefaultMaxResponseBytes = 0;
    constexpr SIZE_T DefaultMaxWebSocketMessageBytes = 1024 * 1024;
    constexpr SIZE_T DefaultMaxResponseHeaders = 64;
    constexpr SIZE_T MaxConfigurableResponseHeaders = WKNET_HARD_MAX_HEADERS;
    constexpr SIZE_T DefaultHttp2MaxHeaderBlockBytes = 32 * 1024;
    constexpr SIZE_T MaxHttp2HeaderBlockBytes = WKNET_HARD_MAX_HEADER_SECTION;
    constexpr ULONG DefaultConnectionPoolCapacity = 8;
    constexpr ULONG DefaultConnectionsPerHost = 2;
    constexpr ULONG DefaultIdleTimeoutMilliseconds = 30000;
    constexpr ULONG DefaultTlsHandshakeReceiveTimeoutMilliseconds = TlsHandshakeReceiveTimeoutMilliseconds;
    constexpr ULONG DefaultMaxRedirects = 10;
    constexpr ULONG DefaultExpectContinueTimeoutMilliseconds = 1000;
    constexpr ULONG MaxExpectContinueTimeoutMilliseconds = WskOperationTimeoutMilliseconds;
    constexpr ULONG DefaultMaxTls12Renegotiations = 1;
    constexpr ULONG HardMaxTls12Renegotiations = 4;
    constexpr ULONG DefaultHttp2KeepAliveIdleMilliseconds = 30000;
    constexpr ULONG DefaultHttp2KeepAliveIntervalMilliseconds = 30000;
    constexpr ULONG DefaultHttp2KeepAliveAckTimeoutMilliseconds = 5000;
    constexpr ULONG DefaultHttp11PipelineMaxDepth = 4;
    constexpr ULONG MaxHttp11PipelineDepth = 64;
    constexpr ULONG Http11PipelineMethodGet = 0x00000001;
    constexpr ULONG Http11PipelineMethodPost = 0x00000002;
    constexpr ULONG Http11PipelineMethodPut = 0x00000004;
    constexpr ULONG Http11PipelineMethodPatch = 0x00000008;
    constexpr ULONG Http11PipelineMethodDelete = 0x00000010;
    constexpr ULONG Http11PipelineMethodHead = 0x00000020;
    constexpr ULONG Http11PipelineMethodOptions = 0x00000040;
    constexpr ULONG Http11PipelineMethodConnect = 0x00000080;
    constexpr ULONG Http11PipelineMethodTrace = 0x00000100;
    constexpr ULONG Http11PipelineKnownMethodMask =
        Http11PipelineMethodGet |
        Http11PipelineMethodPost |
        Http11PipelineMethodPut |
        Http11PipelineMethodPatch |
        Http11PipelineMethodDelete |
        Http11PipelineMethodHead |
        Http11PipelineMethodOptions |
        Http11PipelineMethodConnect |
        Http11PipelineMethodTrace;
    constexpr ULONG DefaultHttp11PipelineMethodMask =
        Http11PipelineMethodGet |
        Http11PipelineMethodHead |
        Http11PipelineMethodOptions;

    enum class PoolType : ULONG
    {
        NonPaged = 0,
        // Reserved ABI value. Current kernel implementation is NonPaged-only
        // and rejects Paged with STATUS_INVALID_PARAMETER.
        Paged = 1
    };

    enum class HttpMethod : ULONG
    {
        Get = 0,
        Post = 1,
        Put = 2,
        Patch = 3,
        Delete = 4,
        Head = 5,
        Options = 6,
        Connect = 7,
        Trace = 8
    };

    enum class TlsVersion : ULONG
    {
        Tls12 = 0x0303,
        Tls13 = 0x0304
    };

    enum class CertificatePolicy : ULONG
    {
        Verify = 0,
        NoVerify = 1
    };

    enum class ConnectionPolicy : ULONG
    {
        ReuseOrCreate = 0,
        ForceNew = 1,
        NoPool = 2
    };

    enum class Http2CleartextMode : ULONG
    {
        Disabled = 0,
        PriorKnowledge = 1,
        Upgrade = 2
    };

    enum class AddressFamily : ULONG
    {
        Any = 0,
        Ipv4 = 4,
        Ipv6 = 6
    };

    enum class RequestBodyPartKind : ULONG
    {
        Field = 0,
        FileBytes = 1,
        FilePath = 2
    };

    enum class RequestBodyMode : ULONG
    {
        ContentLength = 0,
        Chunked = 1
    };

    enum class WebSocketTransportMode : ULONG
    {
        Auto = 0,
        Http11Only = 1,
        Http2Required = 2,
        LegacyBoolean = 3
    };

    enum HttpSendFlags : ULONG
    {
        HttpSendFlagNone = 0,
        HttpSendFlagAggregateWithCallbacks = 0x00000001,
        HttpSendFlagDisableAutoRedirect = 0x00000002,
        HttpSendFlagExpectContinue = 0x00000004,
        HttpSendFlagAllowTrace = 0x00000008,
        HttpSendFlagBypassCache = 0x00000010,
        HttpSendFlagNoCacheStore = 0x00000020,
        HttpSendFlagOnlyIfCached = 0x00000040
    };

    enum class HttpCacheMode : ULONG
    {
        Private = 0,
        Shared = 1
    };

    enum class WebSocketMessageType : ULONG
    {
        Text = 0,
        Binary = 1,
        Close = 2,
        Continuation = 3,
        Ping = 4,
        Pong = 5
    };

    typedef NTSTATUS (*HeaderCallback)(
        void* context,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength);

    typedef NTSTATUS (*BodyCallback)(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalChunk);

    typedef NTSTATUS (*RequestBodyReadCallback)(
        void* context,
        _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
        SIZE_T bufferCapacity,
        _Out_ SIZE_T* bytesRead,
        _Out_ bool* endOfBody);

    typedef void (*AsyncCompletionCallback)(
        void* context,
        NTSTATUS status);

    typedef NTSTATUS (*WebSocketMessageCallback)(
        void* context,
        WebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment);

    struct TlsOptions final
    {
        TlsVersion MinVersion = TlsVersion::Tls12;
        TlsVersion MaxVersion = TlsVersion::Tls13;
        CertificatePolicy CertificatePolicy = CertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
        bool PreferHttp2 = true;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        ULONG HandshakeReceiveTimeoutMilliseconds = DefaultTlsHandshakeReceiveTimeoutMilliseconds;
        ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations;
    };

    struct ProxyOptions final
    {
        bool Enabled = false;
        SOCKADDR_STORAGE Address = {};
        const char* Authority = nullptr;
        SIZE_T AuthorityLength = 0;
        const char* AuthHeader = nullptr;
        SIZE_T AuthHeaderLength = 0;
    };

    struct Http2KeepAliveOptions final
    {
        bool Enabled = false;
        ULONG IdleMilliseconds = DefaultHttp2KeepAliveIdleMilliseconds;
        ULONG IntervalMilliseconds = DefaultHttp2KeepAliveIntervalMilliseconds;
        ULONG AckTimeoutMilliseconds = DefaultHttp2KeepAliveAckTimeoutMilliseconds;
    };

    struct HttpCacheOptions final
    {
        SIZE_T MaxBytes = 16 * 1024 * 1024;
        SIZE_T MaxEntries = 256;
        HttpCacheMode Mode = HttpCacheMode::Private;
    };

    struct HttpCacheStats final
    {
        SIZE_T EntryCount = 0;
        SIZE_T BytesUsed = 0;
        ULONGLONG Hits = 0;
        ULONGLONG Misses = 0;
        ULONGLONG Revalidations = 0;
        ULONGLONG Stores = 0;
        ULONGLONG Invalidations = 0;
        ULONGLONG Evictions = 0;
    };

    struct SessionOptions final
    {
        PoolType ResponsePoolType = PoolType::NonPaged;
        SIZE_T RequestBufferBytes = DefaultRequestBufferBytes;
        // 0 means no caller-imposed buffered response byte limit.
        SIZE_T MaxResponseBytes = DefaultMaxResponseBytes;
        SIZE_T MaxResponseHeaders = DefaultMaxResponseHeaders;
        SIZE_T Http2MaxHeaderBlockBytes = DefaultHttp2MaxHeaderBlockBytes;
        ULONG ConnectionPoolCapacity = DefaultConnectionPoolCapacity;
        ULONG MaxConnectionsPerHost = DefaultConnectionsPerHost;
        ULONG IdleTimeoutMilliseconds = DefaultIdleTimeoutMilliseconds;
        bool EnableHttp11Pipeline = false;
        ULONG Http11PipelineMaxDepth = DefaultHttp11PipelineMaxDepth;
        ULONG Http11PipelineMethodMask = DefaultHttp11PipelineMethodMask;
        Http2KeepAliveOptions Http2KeepAlive = {};
        TlsOptions Tls = {};
        ProxyOptions Proxy = {};
        HttpCacheHandle Cache = nullptr;
    };

    struct HttpSendOptions final
    {
        // 0 means use the session response limit. Passing nullptr options does the same.
        SIZE_T MaxResponseBytes = 0;
        ULONG Flags = HttpSendFlagNone;
        // 0 means use the default redirect limit.
        ULONG MaxRedirects = 0;
        // 0 means use DefaultExpectContinueTimeoutMilliseconds.
        ULONG ExpectContinueTimeoutMilliseconds = 0;
        HeaderCallback HeaderCallback = nullptr;
        BodyCallback BodyCallback = nullptr;
        void* CallbackContext = nullptr;
        AsyncCompletionCallback CompletionCallback = nullptr;
        void* CompletionContext = nullptr;
        Http2CleartextMode Http2CleartextMode = Http2CleartextMode::Disabled;
        const http1::HttpAcceptEncodingPreference* AcceptEncodingPreferences = nullptr;
        SIZE_T AcceptEncodingPreferenceCount = 0;
        const http1::HttpCodingDecodeMaterials* ContentCodingMaterials = nullptr;
        const http2::Http2Priority* Http2Priority = nullptr;
        HttpCacheHandle Cache = nullptr;
    };

    struct NameValuePair final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct MultipartFormDataPart final
    {
        RequestBodyPartKind Kind = RequestBodyPartKind::Field;
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        const char* FilePath = nullptr;
        SIZE_T FilePathLength = 0;
        const char* FileName = nullptr;
        SIZE_T FileNameLength = 0;
        const char* ContentType = nullptr;
        SIZE_T ContentTypeLength = 0;
    };

    struct ResponseView final
    {
        ULONG StatusCode = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
    };

    struct WebSocketHeader final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct WebSocketHandshakeChallenge final
    {
        USHORT StatusCode = 0;
        const http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        bool Redirect = false;
        bool AuthenticationChallenge = false;
    };

    struct WebSocketHandshakeRetryAction final
    {
        const char* RedirectPath = nullptr;
        SIZE_T RedirectPathLength = 0;
        const http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
    };

    typedef NTSTATUS (*WebSocketHandshakeChallengeCallback)(
        void* context,
        const WebSocketHandshakeChallenge* challenge,
        WebSocketHandshakeRetryAction* action);

    struct WebSocketConnectOptions final
    {
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        const WebSocketHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        TlsOptions Tls = {};
        AddressFamily AddressFamily = AddressFamily::Any;
        SIZE_T MaxMessageBytes = DefaultMaxWebSocketMessageBytes;
        bool AutoReplyPing = true;
        bool AllowWebSocketOverHttp2 = false;
        WebSocketTransportMode TransportMode = WebSocketTransportMode::Auto;
        ws::PerMessageDeflateOptions PerMessageDeflate = {};
        WebSocketHandshakeChallengeCallback ChallengeCallback = nullptr;
        void* ChallengeContext = nullptr;
        ULONG MaxHandshakeRetries = 0;
    };

    struct WebSocketSendOptions final
    {
        bool FinalFragment = true;
    };

    struct WebSocketReceiveOptions final
    {
        SIZE_T MaxMessageBytes = 0;
        bool AutoAllocate = true;
        WebSocketMessageCallback MessageCallback = nullptr;
        void* CallbackContext = nullptr;
        bool DeliverFragments = false;
    };

    struct WebSocketMessage final
    {
        WebSocketMessageType Type = WebSocketMessageType::Binary;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        bool FinalFragment = true;
    };

    _Must_inspect_result_
    NTSTATUS SessionCreate(
        _In_ net::WskClient* wskClient,
        _In_opt_ const SessionOptions* options,
        _Out_ SessionHandle* session) noexcept;

    void SessionClose(_In_opt_ SessionHandle session) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpCacheCreate(
        _In_opt_ const HttpCacheOptions* options,
        _Out_ HttpCacheHandle* cache) noexcept;

    void HttpCacheClose(_In_opt_ HttpCacheHandle cache) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpCacheClear(_In_ HttpCacheHandle cache) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpCacheGetStats(
        _In_ HttpCacheHandle cache,
        _Out_ HttpCacheStats* stats) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestCreate(
        _In_ SessionHandle session,
        _Out_ RequestHandle* request) noexcept;

    void HttpRequestRelease(_In_opt_ RequestHandle request) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetUrl(
        _In_ RequestHandle request,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetMethod(
        _In_ RequestHandle request,
        HttpMethod method) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetHeader(
        _In_ RequestHandle request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetRangeBytes(
        _In_ RequestHandle request,
        ULONGLONG firstByte,
        ULONGLONG lastByte,
        bool hasLastByte) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetRangeSuffix(
        _In_ RequestHandle request,
        ULONGLONG suffixLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetIfMatch(
        _In_ RequestHandle request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetIfNoneMatch(
        _In_ RequestHandle request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetIfModifiedSince(
        _In_ RequestHandle request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetIfUnmodifiedSince(
        _In_ RequestHandle request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetBody(
        _In_ RequestHandle request,
        _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
        SIZE_T bodyLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetBodySource(
        _In_ RequestHandle request,
        _In_ RequestBodyReadCallback callback,
        _In_opt_ void* context,
        SIZE_T contentLength,
        bool contentLengthKnown) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetBodyMode(
        _In_ RequestHandle request,
        RequestBodyMode mode) noexcept;

    // Adds a trailer field emitted after the final chunk. Only honored when the
    // request uses RequestBodyMode::Chunked; the field name must be a valid token
    // and must not be a forbidden trailer field (framing/auth/cookie headers), or
    // the send fails. Order is preserved.
    _Must_inspect_result_
    NTSTATUS HttpRequestAddTrailer(
        _In_ RequestHandle request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestClearBody(_In_ RequestHandle request) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetTextBody(
        _In_ RequestHandle request,
        _In_reads_bytes_opt_(textLength) const char* text,
        SIZE_T textLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetRawBody(
        _In_ RequestHandle request,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetUrlEncodedBody(
        _In_ RequestHandle request,
        _In_reads_(pairCount) const NameValuePair* pairs,
        SIZE_T pairCount) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetMultipartFormDataBody(
        _In_ RequestHandle request,
        _In_reads_(partCount) const MultipartFormDataPart* parts,
        SIZE_T partCount) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetFileBody(
        _In_ RequestHandle request,
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetTlsOptions(
        _In_ RequestHandle request,
        _In_ const TlsOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetConnectionPolicy(
        _In_ RequestHandle request,
        ConnectionPolicy policy) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpRequestSetAddressFamily(
        _In_ RequestHandle request,
        AddressFamily addressFamily) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpSendSync(
        _In_ SessionHandle session,
        _In_ RequestHandle request,
        _In_opt_ const HttpSendOptions* options,
        _Out_opt_ ResponseHandle* response) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpSendAsync(
        _In_ SessionHandle session,
        _In_ RequestHandle request,
        _In_opt_ const HttpSendOptions* options,
        _Out_ AsyncOperationHandle* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS ResponseGetView(
        _In_ ResponseHandle response,
        _Out_ ResponseView* view) noexcept;

    _Must_inspect_result_
    NTSTATUS ResponseGetHeader(
        _In_ ResponseHandle response,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    SIZE_T ResponseHeaderCount(_In_opt_ ResponseHandle response) noexcept;

    _Must_inspect_result_
    NTSTATUS ResponseGetHeaderAt(
        _In_ ResponseHandle response,
        SIZE_T index,
        _Outptr_result_bytebuffer_(*nameLength) const char** name,
        _Out_ SIZE_T* nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    SIZE_T ResponseTrailerCount(_In_opt_ ResponseHandle response) noexcept;

    _Must_inspect_result_
    NTSTATUS ResponseGetTrailer(
        _In_ ResponseHandle response,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS ResponseGetTrailerAt(
        _In_ ResponseHandle response,
        SIZE_T index,
        _Outptr_result_bytebuffer_(*nameLength) const char** name,
        _Out_ SIZE_T* nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    void ResponseRelease(_In_opt_ ResponseHandle response) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketConnectSync(
        _In_ SessionHandle session,
        _In_ const WebSocketConnectOptions* options,
        _Out_ WebSocketHandle* websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketConnectAsync(
        _In_ SessionHandle session,
        _In_ const WebSocketConnectOptions* options,
        _Out_ AsyncOperationHandle* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendTextSync(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        _In_opt_ const WebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendBinarySync(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const WebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendContinuationSync(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const WebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendPingSync(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendPongSync(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketReceiveSync(
        _In_ WebSocketHandle websocket,
        _In_opt_ const WebSocketReceiveOptions* options,
        _Out_opt_ WebSocketMessage* message) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketCloseSync(_In_opt_ WebSocketHandle websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketCloseExSync(
        _In_opt_ WebSocketHandle websocket,
        USHORT statusCode,
        _In_reads_bytes_opt_(reasonLength) const UCHAR* reason,
        SIZE_T reasonLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSelectedSubprotocol(
        _In_ WebSocketHandle websocket,
        _Outptr_result_bytebuffer_(*subprotocolLength) const char** subprotocol,
        _Out_ SIZE_T* subprotocolLength) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncCancel(_In_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncWait(
        _In_ AsyncOperationHandle operation,
        ULONG timeoutMilliseconds) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGetHttpResponse(
        _In_ AsyncOperationHandle operation,
        _Out_ ResponseHandle* response) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGetWebSocket(
        _In_ AsyncOperationHandle operation,
        _Out_ WebSocketHandle* websocket) noexcept;

    void AsyncRelease(_In_opt_ AsyncOperationHandle operation) noexcept;

    _Must_inspect_result_
    NTSTATUS EngineDrainAsync() noexcept;

    void EngineCloseActiveHandles() noexcept;

#if defined(WKNET_USER_MODE_TEST)
    struct TestHttpTransportRequest final
    {
        const char* Scheme = nullptr;
        SIZE_T SchemeLength = 0;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        AddressFamily AddressFamily = AddressFamily::Any;
        const char* BuiltRequest = nullptr;
        SIZE_T BuiltRequestLength = 0;
        SIZE_T HeaderBytesLength = 0;
        SIZE_T BodyBytesLength = 0;
        bool ExpectContinueEnabled = false;
        bool ExpectContinueBodySent = false;
        ConnectionPolicy ConnectionPolicy = ConnectionPolicy::ReuseOrCreate;
        CertificatePolicy CertificatePolicy = CertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
        const char* OfferedAlpn = nullptr;
        SIZE_T OfferedAlpnLength = 0;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations;
        bool ProxyEnabled = false;
        SOCKADDR_STORAGE ProxyAddress = {};
        const char* ProxyAuthority = nullptr;
        SIZE_T ProxyAuthorityLength = 0;
        const char* ProxyAuthHeader = nullptr;
        SIZE_T ProxyAuthHeaderLength = 0;
        bool PoolableConnection = false;
        bool ReusedConnection = false;
        ULONG ConnectionId = 0;
        bool Http11PipelineEnabled = false;
        bool Http11PipelineLease = false;
        ULONG Http11PipelineSequence = 0;
        Http2CleartextMode Http2CleartextMode = Http2CleartextMode::Disabled;
        bool UsedHttp2 = false;
    };

    struct TestHttpTransportResponse final
    {
        const char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        const char* NegotiatedAlpn = nullptr;
        SIZE_T NegotiatedAlpnLength = 0;
        bool ConnectionReusable = true;
    };

    typedef NTSTATUS (*TestHttpTransportCallback)(
        void* context,
        const TestHttpTransportRequest* request,
        TestHttpTransportResponse* response);

    struct TestWebSocketConnectRequest final
    {
        const char* Scheme = nullptr;
        SIZE_T SchemeLength = 0;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        const char* Path = nullptr;
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        CertificatePolicy CertificatePolicy = CertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        TlsVersion MinTlsVersion = TlsVersion::Tls12;
        TlsVersion MaxTlsVersion = TlsVersion::Tls13;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        AddressFamily AddressFamily = AddressFamily::Any;
        bool AutoReplyPing = true;
        SIZE_T MaxMessageBytes = 0;
        ULONG HandshakeReceiveTimeoutMilliseconds = DefaultTlsHandshakeReceiveTimeoutMilliseconds;
        ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations;
        bool AllowWebSocketOverHttp2 = false;
        WebSocketTransportMode TransportMode = WebSocketTransportMode::Auto;
        ws::PerMessageDeflateOptions PerMessageDeflate = {};
    };

    struct TestWebSocketMessage final
    {
        WebSocketMessageType Type = WebSocketMessageType::Binary;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        bool FinalFragment = true;
    };

    typedef NTSTATUS (*TestWebSocketConnectCallback)(
        void* context,
        const TestWebSocketConnectRequest* request);

    typedef NTSTATUS (*TestWebSocketSendCallback)(
        void* context,
        WebSocketHandle websocket,
        WebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment);

    typedef NTSTATUS (*TestWebSocketReceiveCallback)(
        void* context,
        WebSocketHandle websocket,
        TestWebSocketMessage* message);

    typedef void (*TestWebSocketCloseCallback)(
        void* context,
        WebSocketHandle websocket);

    void TestSetHttpTransport(
        TestHttpTransportCallback callback,
        void* context) noexcept;

    void TestSetWebSocketTransport(
        TestWebSocketConnectCallback connectCallback,
        TestWebSocketSendCallback sendCallback,
        TestWebSocketReceiveCallback receiveCallback,
        TestWebSocketCloseCallback closeCallback,
        void* context) noexcept;

    void TestSetAsyncAutoRun(bool enabled) noexcept;

    NTSTATUS TestRunAsyncOperation(_In_ AsyncOperationHandle operation) noexcept;

    NTSTATUS TestAsyncStatus(_In_ AsyncOperationHandle operation) noexcept;

    bool TestAsyncIsCompleted(_In_ AsyncOperationHandle operation) noexcept;

    bool TestAsyncIsCanceled(_In_ AsyncOperationHandle operation) noexcept;

    void TestSetCurrentIrql(ULONG irql) noexcept;
    void TestResetCurrentIrql() noexcept;
    bool TestIsHttpTls12ConfirmationCandidate(
        TlsVersion minVersion,
        TlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept;
    bool TestSessionHasWorkspace(SessionHandle session) noexcept;
    bool TestSessionHasProviderCache(SessionHandle session) noexcept;
#endif
}
}
