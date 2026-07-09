#pragma once

#include <KernelHttp/http/HttpContentEncoding.h>
#include <KernelHttp/http/HttpTypes.h>
#include <KernelHttp/http2/Http2Frame.h>
#include <KernelHttp/KernelHttpLimits.h>
#include <KernelHttp/net/WskClient.h>
#include <KernelHttp/tls/TlsPolicy.h>
#include <KernelHttp/websocket/WebSocketDeflate.h>

namespace KernelHttp
{
namespace tls
{
    class CertificateStore;
    struct TlsClientCredential;
}
}

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#endif
#endif

namespace KernelHttp
{
namespace engine
{
    struct KhSession;
    struct KhRequest;
    struct KhResponse;
    struct KhWebSocket;
    struct KhAsyncOperation;

    typedef KhSession* KH_SESSION;
    typedef KhRequest* KH_REQUEST;
    typedef KhResponse* KH_RESPONSE;
    typedef KhWebSocket* KH_WEBSOCKET;
    typedef KhAsyncOperation* KH_ASYNC_OPERATION;

    constexpr SIZE_T KhDefaultRequestBufferBytes = 16 * 1024;
    constexpr SIZE_T KhDefaultMaxResponseBytes = 0;
    constexpr SIZE_T KhDefaultMaxWebSocketMessageBytes = 1024 * 1024;
    constexpr SIZE_T KhDefaultMaxResponseHeaders = 64;
    constexpr SIZE_T KhMaxConfigurableResponseHeaders = KH_HARD_MAX_HEADERS;
    constexpr SIZE_T KhDefaultHttp2MaxHeaderBlockBytes = 32 * 1024;
    constexpr SIZE_T KhMaxHttp2HeaderBlockBytes = KH_HARD_MAX_HEADER_SECTION;
    constexpr ULONG KhDefaultConnectionPoolCapacity = 8;
    constexpr ULONG KhDefaultConnectionsPerHost = 2;
    constexpr ULONG KhDefaultIdleTimeoutMilliseconds = 30000;
    constexpr ULONG KhDefaultTlsHandshakeReceiveTimeoutMilliseconds = TlsHandshakeReceiveTimeoutMilliseconds;
    constexpr ULONG KhDefaultMaxRedirects = 10;
    constexpr ULONG KhDefaultExpectContinueTimeoutMilliseconds = 1000;
    constexpr ULONG KhMaxExpectContinueTimeoutMilliseconds = WskOperationTimeoutMilliseconds;
    constexpr ULONG KhDefaultMaxTls12Renegotiations = 1;
    constexpr ULONG KhHardMaxTls12Renegotiations = 4;
    constexpr ULONG KhDefaultHttp2KeepAliveIdleMilliseconds = 30000;
    constexpr ULONG KhDefaultHttp2KeepAliveIntervalMilliseconds = 30000;
    constexpr ULONG KhDefaultHttp2KeepAliveAckTimeoutMilliseconds = 5000;
    constexpr ULONG KhDefaultHttp11PipelineMaxDepth = 4;
    constexpr ULONG KhMaxHttp11PipelineDepth = 64;
    constexpr ULONG KhHttp11PipelineMethodGet = 0x00000001;
    constexpr ULONG KhHttp11PipelineMethodPost = 0x00000002;
    constexpr ULONG KhHttp11PipelineMethodPut = 0x00000004;
    constexpr ULONG KhHttp11PipelineMethodPatch = 0x00000008;
    constexpr ULONG KhHttp11PipelineMethodDelete = 0x00000010;
    constexpr ULONG KhHttp11PipelineMethodHead = 0x00000020;
    constexpr ULONG KhHttp11PipelineMethodOptions = 0x00000040;
    constexpr ULONG KhHttp11PipelineMethodConnect = 0x00000080;
    constexpr ULONG KhHttp11PipelineMethodTrace = 0x00000100;
    constexpr ULONG KhHttp11PipelineKnownMethodMask =
        KhHttp11PipelineMethodGet |
        KhHttp11PipelineMethodPost |
        KhHttp11PipelineMethodPut |
        KhHttp11PipelineMethodPatch |
        KhHttp11PipelineMethodDelete |
        KhHttp11PipelineMethodHead |
        KhHttp11PipelineMethodOptions |
        KhHttp11PipelineMethodConnect |
        KhHttp11PipelineMethodTrace;
    constexpr ULONG KhDefaultHttp11PipelineMethodMask =
        KhHttp11PipelineMethodGet |
        KhHttp11PipelineMethodHead |
        KhHttp11PipelineMethodOptions;

    enum class KhPoolType : ULONG
    {
        NonPaged = 0,
        // Reserved ABI value. Current kernel implementation is NonPaged-only
        // and rejects Paged with STATUS_INVALID_PARAMETER.
        Paged = 1
    };

    enum class KhHttpMethod : ULONG
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

    enum class KhTlsVersion : ULONG
    {
        Tls12 = 0x0303,
        Tls13 = 0x0304
    };

    enum class KhCertificatePolicy : ULONG
    {
        Verify = 0,
        NoVerify = 1
    };

    enum class KhConnectionPolicy : ULONG
    {
        ReuseOrCreate = 0,
        ForceNew = 1,
        NoPool = 2
    };

    enum class KhHttp2CleartextMode : ULONG
    {
        Disabled = 0,
        PriorKnowledge = 1,
        Upgrade = 2
    };

    enum class KhAddressFamily : ULONG
    {
        Any = 0,
        Ipv4 = 4,
        Ipv6 = 6
    };

    enum class KhRequestBodyPartKind : ULONG
    {
        Field = 0,
        FileBytes = 1,
        FilePath = 2
    };

    enum class KhRequestBodyMode : ULONG
    {
        ContentLength = 0,
        Chunked = 1
    };

    enum class KhWebSocketTransportMode : ULONG
    {
        LegacyBoolean = 0,
        Http11Only = 1,
        Auto = 2,
        Http2Required = 3
    };

    enum KhHttpSendFlags : ULONG
    {
        KhHttpSendFlagNone = 0,
        KhHttpSendFlagAggregateWithCallbacks = 0x00000001,
        KhHttpSendFlagDisableAutoRedirect = 0x00000002,
        KhHttpSendFlagExpectContinue = 0x00000004,
        KhHttpSendFlagAllowTrace = 0x00000008
    };

    enum class KhWebSocketMessageType : ULONG
    {
        Text = 0,
        Binary = 1,
        Close = 2,
        Continuation = 3,
        Ping = 4,
        Pong = 5
    };

    typedef NTSTATUS (*KhHeaderCallback)(
        void* context,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength);

    typedef NTSTATUS (*KhBodyCallback)(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalChunk);

    typedef NTSTATUS (*KhRequestBodyReadCallback)(
        void* context,
        _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
        SIZE_T bufferCapacity,
        _Out_ SIZE_T* bytesRead,
        _Out_ bool* endOfBody);

    typedef void (*KhAsyncCompletionCallback)(
        void* context,
        NTSTATUS status);

    typedef NTSTATUS (*KhWebSocketMessageCallback)(
        void* context,
        KhWebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment);

    struct KhTlsOptions final
    {
        KhTlsVersion MinVersion = KhTlsVersion::Tls12;
        KhTlsVersion MaxVersion = KhTlsVersion::Tls13;
        KhCertificatePolicy CertificatePolicy = KhCertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
        bool PreferHttp2 = true;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        ULONG HandshakeReceiveTimeoutMilliseconds = KhDefaultTlsHandshakeReceiveTimeoutMilliseconds;
        ULONG MaxTls12Renegotiations = KhDefaultMaxTls12Renegotiations;
    };

    struct KhProxyOptions final
    {
        bool Enabled = false;
        SOCKADDR_STORAGE Address = {};
        const char* Authority = nullptr;
        SIZE_T AuthorityLength = 0;
        const char* AuthHeader = nullptr;
        SIZE_T AuthHeaderLength = 0;
    };

    struct KhHttp2KeepAliveOptions final
    {
        bool Enabled = false;
        ULONG IdleMilliseconds = KhDefaultHttp2KeepAliveIdleMilliseconds;
        ULONG IntervalMilliseconds = KhDefaultHttp2KeepAliveIntervalMilliseconds;
        ULONG AckTimeoutMilliseconds = KhDefaultHttp2KeepAliveAckTimeoutMilliseconds;
    };

    struct KhSessionOptions final
    {
        KhPoolType ResponsePoolType = KhPoolType::NonPaged;
        SIZE_T RequestBufferBytes = KhDefaultRequestBufferBytes;
        // 0 means no caller-imposed buffered response byte limit.
        SIZE_T MaxResponseBytes = KhDefaultMaxResponseBytes;
        SIZE_T MaxResponseHeaders = KhDefaultMaxResponseHeaders;
        SIZE_T Http2MaxHeaderBlockBytes = KhDefaultHttp2MaxHeaderBlockBytes;
        ULONG ConnectionPoolCapacity = KhDefaultConnectionPoolCapacity;
        ULONG MaxConnectionsPerHost = KhDefaultConnectionsPerHost;
        ULONG IdleTimeoutMilliseconds = KhDefaultIdleTimeoutMilliseconds;
        bool EnableHttp11Pipeline = false;
        ULONG Http11PipelineMaxDepth = KhDefaultHttp11PipelineMaxDepth;
        ULONG Http11PipelineMethodMask = KhDefaultHttp11PipelineMethodMask;
        KhHttp2KeepAliveOptions Http2KeepAlive = {};
        KhTlsOptions Tls = {};
        KhProxyOptions Proxy = {};
    };

    struct KhHttpSendOptions final
    {
        // 0 means use the session response limit. Passing nullptr options does the same.
        SIZE_T MaxResponseBytes = 0;
        ULONG Flags = KhHttpSendFlagNone;
        // 0 means use the default redirect limit.
        ULONG MaxRedirects = 0;
        // 0 means use KhDefaultExpectContinueTimeoutMilliseconds.
        ULONG ExpectContinueTimeoutMilliseconds = 0;
        KhHeaderCallback HeaderCallback = nullptr;
        KhBodyCallback BodyCallback = nullptr;
        void* CallbackContext = nullptr;
        KhAsyncCompletionCallback CompletionCallback = nullptr;
        void* CompletionContext = nullptr;
        KhHttp2CleartextMode Http2CleartextMode = KhHttp2CleartextMode::Disabled;
        const http::HttpAcceptEncodingPreference* AcceptEncodingPreferences = nullptr;
        SIZE_T AcceptEncodingPreferenceCount = 0;
        const http2::Http2Priority* Http2Priority = nullptr;
    };

    struct KhNameValuePair final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct KhMultipartFormDataPart final
    {
        KhRequestBodyPartKind Kind = KhRequestBodyPartKind::Field;
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

    struct KhResponseView final
    {
        ULONG StatusCode = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
    };

    struct KhWebSocketHeader final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct KhWebSocketHandshakeChallenge final
    {
        USHORT StatusCode = 0;
        const http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        bool Redirect = false;
        bool AuthenticationChallenge = false;
    };

    struct KhWebSocketHandshakeRetryAction final
    {
        const char* RedirectPath = nullptr;
        SIZE_T RedirectPathLength = 0;
        const http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
    };

    typedef NTSTATUS (*KhWebSocketHandshakeChallengeCallback)(
        void* context,
        const KhWebSocketHandshakeChallenge* challenge,
        KhWebSocketHandshakeRetryAction* action);

    struct KhWebSocketConnectOptions final
    {
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        const KhWebSocketHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        KhTlsOptions Tls = {};
        KhAddressFamily AddressFamily = KhAddressFamily::Any;
        SIZE_T MaxMessageBytes = KhDefaultMaxWebSocketMessageBytes;
        bool AutoReplyPing = true;
        bool AllowWebSocketOverHttp2 = false;
        KhWebSocketTransportMode TransportMode = KhWebSocketTransportMode::LegacyBoolean;
        websocket::PerMessageDeflateOptions PerMessageDeflate = {};
        KhWebSocketHandshakeChallengeCallback ChallengeCallback = nullptr;
        void* ChallengeContext = nullptr;
        ULONG MaxHandshakeRetries = 0;
    };

    struct KhWebSocketSendOptions final
    {
        bool FinalFragment = true;
    };

    struct KhWebSocketReceiveOptions final
    {
        SIZE_T MaxMessageBytes = 0;
        bool AutoAllocate = true;
        KhWebSocketMessageCallback MessageCallback = nullptr;
        void* CallbackContext = nullptr;
        bool DeliverFragments = false;
    };

    struct KhWebSocketMessage final
    {
        KhWebSocketMessageType Type = KhWebSocketMessageType::Binary;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        bool FinalFragment = true;
    };

    _Must_inspect_result_
    NTSTATUS KhSessionCreate(
        _In_ net::WskClient* wskClient,
        _In_opt_ const KhSessionOptions* options,
        _Out_ KH_SESSION* session) noexcept;

    void KhSessionClose(_In_opt_ KH_SESSION session) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestCreate(
        _In_ KH_SESSION session,
        _Out_ KH_REQUEST* request) noexcept;

    void KhHttpRequestRelease(_In_opt_ KH_REQUEST request) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetUrl(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetMethod(
        _In_ KH_REQUEST request,
        KhHttpMethod method) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetHeader(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetRangeBytes(
        _In_ KH_REQUEST request,
        ULONGLONG firstByte,
        ULONGLONG lastByte,
        bool hasLastByte) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetRangeSuffix(
        _In_ KH_REQUEST request,
        ULONGLONG suffixLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetIfMatch(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetIfNoneMatch(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetIfModifiedSince(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetIfUnmodifiedSince(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetBody(
        _In_ KH_REQUEST request,
        _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
        SIZE_T bodyLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetBodySource(
        _In_ KH_REQUEST request,
        _In_ KhRequestBodyReadCallback callback,
        _In_opt_ void* context,
        SIZE_T contentLength,
        bool contentLengthKnown) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetBodyMode(
        _In_ KH_REQUEST request,
        KhRequestBodyMode mode) noexcept;

    // Adds a trailer field emitted after the final chunk. Only honored when the
    // request uses KhRequestBodyMode::Chunked; the field name must be a valid token
    // and must not be a forbidden trailer field (framing/auth/cookie headers), or
    // the send fails. Order is preserved.
    _Must_inspect_result_
    NTSTATUS KhHttpRequestAddTrailer(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestClearBody(_In_ KH_REQUEST request) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetTextBody(
        _In_ KH_REQUEST request,
        _In_reads_bytes_opt_(textLength) const char* text,
        SIZE_T textLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetRawBody(
        _In_ KH_REQUEST request,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetUrlEncodedBody(
        _In_ KH_REQUEST request,
        _In_reads_(pairCount) const KhNameValuePair* pairs,
        SIZE_T pairCount) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetMultipartFormDataBody(
        _In_ KH_REQUEST request,
        _In_reads_(partCount) const KhMultipartFormDataPart* parts,
        SIZE_T partCount) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetFileBody(
        _In_ KH_REQUEST request,
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetTlsOptions(
        _In_ KH_REQUEST request,
        _In_ const KhTlsOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetConnectionPolicy(
        _In_ KH_REQUEST request,
        KhConnectionPolicy policy) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpRequestSetAddressFamily(
        _In_ KH_REQUEST request,
        KhAddressFamily addressFamily) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpSendSync(
        _In_ KH_SESSION session,
        _In_ KH_REQUEST request,
        _In_opt_ const KhHttpSendOptions* options,
        _Out_opt_ KH_RESPONSE* response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpSendAsync(
        _In_ KH_SESSION session,
        _In_ KH_REQUEST request,
        _In_opt_ const KhHttpSendOptions* options,
        _Out_ KH_ASYNC_OPERATION* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhResponseGetView(
        _In_ KH_RESPONSE response,
        _Out_ KhResponseView* view) noexcept;

    _Must_inspect_result_
    NTSTATUS KhResponseGetHeader(
        _In_ KH_RESPONSE response,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    SIZE_T KhResponseHeaderCount(_In_opt_ KH_RESPONSE response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhResponseGetHeaderAt(
        _In_ KH_RESPONSE response,
        SIZE_T index,
        _Outptr_result_bytebuffer_(*nameLength) const char** name,
        _Out_ SIZE_T* nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    SIZE_T KhResponseTrailerCount(_In_opt_ KH_RESPONSE response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhResponseGetTrailer(
        _In_ KH_RESPONSE response,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhResponseGetTrailerAt(
        _In_ KH_RESPONSE response,
        SIZE_T index,
        _Outptr_result_bytebuffer_(*nameLength) const char** name,
        _Out_ SIZE_T* nameLength,
        _Outptr_result_bytebuffer_(*valueLength) const char** value,
        _Out_ SIZE_T* valueLength) noexcept;

    void KhResponseRelease(_In_opt_ KH_RESPONSE response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketConnectSync(
        _In_ KH_SESSION session,
        _In_ const KhWebSocketConnectOptions* options,
        _Out_ KH_WEBSOCKET* websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketConnectAsync(
        _In_ KH_SESSION session,
        _In_ const KhWebSocketConnectOptions* options,
        _Out_ KH_ASYNC_OPERATION* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendTextSync(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        _In_opt_ const KhWebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendBinarySync(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const KhWebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendContinuationSync(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const KhWebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendPingSync(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendPongSync(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketReceiveSync(
        _In_ KH_WEBSOCKET websocket,
        _In_opt_ const KhWebSocketReceiveOptions* options,
        _Out_opt_ KhWebSocketMessage* message) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketCloseSync(_In_opt_ KH_WEBSOCKET websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketCloseExSync(
        _In_opt_ KH_WEBSOCKET websocket,
        USHORT statusCode,
        _In_reads_bytes_opt_(reasonLength) const UCHAR* reason,
        SIZE_T reasonLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSelectedSubprotocol(
        _In_ KH_WEBSOCKET websocket,
        _Outptr_result_bytebuffer_(*subprotocolLength) const char** subprotocol,
        _Out_ SIZE_T* subprotocolLength) noexcept;

    _Must_inspect_result_
    NTSTATUS KhAsyncCancel(_In_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhAsyncWait(
        _In_ KH_ASYNC_OPERATION operation,
        ULONG timeoutMilliseconds) noexcept;

    _Must_inspect_result_
    NTSTATUS KhAsyncGetHttpResponse(
        _In_ KH_ASYNC_OPERATION operation,
        _Out_ KH_RESPONSE* response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhAsyncGetWebSocket(
        _In_ KH_ASYNC_OPERATION operation,
        _Out_ KH_WEBSOCKET* websocket) noexcept;

    void KhAsyncRelease(_In_opt_ KH_ASYNC_OPERATION operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhEngineDrainAsync() noexcept;

    void KhEngineCloseActiveHandles() noexcept;

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    struct KhTestHttpTransportRequest final
    {
        const char* Scheme = nullptr;
        SIZE_T SchemeLength = 0;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        KhAddressFamily AddressFamily = KhAddressFamily::Any;
        const char* BuiltRequest = nullptr;
        SIZE_T BuiltRequestLength = 0;
        SIZE_T HeaderBytesLength = 0;
        SIZE_T BodyBytesLength = 0;
        bool ExpectContinueEnabled = false;
        bool ExpectContinueBodySent = false;
        KhConnectionPolicy ConnectionPolicy = KhConnectionPolicy::ReuseOrCreate;
        KhCertificatePolicy CertificatePolicy = KhCertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
        const char* OfferedAlpn = nullptr;
        SIZE_T OfferedAlpnLength = 0;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        ULONG MaxTls12Renegotiations = KhDefaultMaxTls12Renegotiations;
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
        KhHttp2CleartextMode Http2CleartextMode = KhHttp2CleartextMode::Disabled;
        bool UsedHttp2 = false;
    };

    struct KhTestHttpTransportResponse final
    {
        const char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        const char* NegotiatedAlpn = nullptr;
        SIZE_T NegotiatedAlpnLength = 0;
        bool ConnectionReusable = true;
    };

    typedef NTSTATUS (*KhTestHttpTransportCallback)(
        void* context,
        const KhTestHttpTransportRequest* request,
        KhTestHttpTransportResponse* response);

    struct KhTestWebSocketConnectRequest final
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
        KhCertificatePolicy CertificatePolicy = KhCertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        KhTlsVersion MinTlsVersion = KhTlsVersion::Tls12;
        KhTlsVersion MaxTlsVersion = KhTlsVersion::Tls13;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        KhAddressFamily AddressFamily = KhAddressFamily::Any;
        bool AutoReplyPing = true;
        SIZE_T MaxMessageBytes = 0;
        ULONG HandshakeReceiveTimeoutMilliseconds = KhDefaultTlsHandshakeReceiveTimeoutMilliseconds;
        ULONG MaxTls12Renegotiations = KhDefaultMaxTls12Renegotiations;
        bool AllowWebSocketOverHttp2 = false;
        KhWebSocketTransportMode TransportMode = KhWebSocketTransportMode::LegacyBoolean;
        websocket::PerMessageDeflateOptions PerMessageDeflate = {};
    };

    struct KhTestWebSocketMessage final
    {
        KhWebSocketMessageType Type = KhWebSocketMessageType::Binary;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        bool FinalFragment = true;
    };

    typedef NTSTATUS (*KhTestWebSocketConnectCallback)(
        void* context,
        const KhTestWebSocketConnectRequest* request);

    typedef NTSTATUS (*KhTestWebSocketSendCallback)(
        void* context,
        KH_WEBSOCKET websocket,
        KhWebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment);

    typedef NTSTATUS (*KhTestWebSocketReceiveCallback)(
        void* context,
        KH_WEBSOCKET websocket,
        KhTestWebSocketMessage* message);

    typedef void (*KhTestWebSocketCloseCallback)(
        void* context,
        KH_WEBSOCKET websocket);

    void KhTestSetHttpTransport(
        KhTestHttpTransportCallback callback,
        void* context) noexcept;

    void KhTestSetWebSocketTransport(
        KhTestWebSocketConnectCallback connectCallback,
        KhTestWebSocketSendCallback sendCallback,
        KhTestWebSocketReceiveCallback receiveCallback,
        KhTestWebSocketCloseCallback closeCallback,
        void* context) noexcept;

    void KhTestSetAsyncAutoRun(bool enabled) noexcept;

    NTSTATUS KhTestRunAsyncOperation(_In_ KH_ASYNC_OPERATION operation) noexcept;

    NTSTATUS KhTestAsyncStatus(_In_ KH_ASYNC_OPERATION operation) noexcept;

    bool KhTestAsyncIsCompleted(_In_ KH_ASYNC_OPERATION operation) noexcept;

    bool KhTestAsyncIsCanceled(_In_ KH_ASYNC_OPERATION operation) noexcept;

    void KhTestSetCurrentIrql(ULONG irql) noexcept;
    void KhTestResetCurrentIrql() noexcept;
    bool KhTestIsHttpTls12ConfirmationCandidate(
        KhTlsVersion minVersion,
        KhTlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept;
    bool KhTestSessionHasWorkspace(KH_SESSION session) noexcept;
    bool KhTestSessionHasProviderCache(KH_SESSION session) noexcept;
#endif
}
}
