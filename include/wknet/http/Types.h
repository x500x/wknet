#pragma once

#include <wknet/WknetConfig.h>
#include <wknet/http/Certificate.h>

namespace wknet::http {
    struct Session;
    struct Request;
    struct Response;
    struct AsyncOp;
    struct Headers;
    struct Body;
    struct Cache;

    enum class Method : ULONG
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

    enum class PoolType : ULONG
    {
        NonPaged = 0,
        // Reserved ABI value. Sessions currently reject this with
        // STATUS_INVALID_PARAMETER because protocol buffers are NonPaged-only.
        Paged = 1
    };

    enum class TlsVersion : ULONG
    {
        Tls12 = 0x0303,
        Tls13 = 0x0304
    };

    enum class CertPolicy : ULONG
    {
        Verify = 0,
        NoVerify = 1
    };

    enum class AddressFamily : ULONG
    {
        Any = 0,
        Ipv4 = 4,
        Ipv6 = 6
    };

    enum class ConnPolicy : ULONG
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

    enum class Http3ConnectMode : ULONG
    {
        Auto = 0,
        Disabled = 1,
        Required = 2
    };

    enum class Http3RaceMode : ULONG
    {
        DelayedTcpFallback = 0,
        SequentialPreferHttp3 = 1
    };

    enum class BodyPartKind : ULONG
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

    enum SendFlags : ULONG
    {
        SendFlagNone = 0,
        SendFlagAggregateWithCallbacks = 0x00000001,
        SendFlagDisableAutoRedirect = 0x00000002,
        SendFlagExpectContinue = 0x00000004,
        SendFlagAllowTrace = 0x00000008,
        SendFlagBypassCache = 0x00000010,
        SendFlagNoCacheStore = 0x00000020,
        SendFlagOnlyIfCached = 0x00000040
    };

    enum class CacheMode : ULONG
    {
        Private = 0,
        Shared = 1
    };

    // Public TLS policy surface (implementation lives in wknet::tls).
    enum class TlsSecurityProfile : UCHAR
    {
        ModernDefault,
        CompatibilityExplicit
    };

    struct TlsPolicy final
    {
        TlsSecurityProfile Profile = TlsSecurityProfile::ModernDefault;
        bool EnableTls12RsaKeyExchange = false;
        bool EnableTls12Cbc = false;
        bool EnableTls12Renegotiation = false;
        bool EnableTls12Sha1Signatures = false;
        bool EnablePostHandshakeClientAuth = false;
        bool RequireRevocationCheck = false;
    };

    // Public content-coding negotiation/material surface.
    enum class AcceptCoding : UCHAR
    {
        Identity = 0,
        Gzip = 1,
        Deflate = 2,
        Brotli = 3,
        Compress = 4,
        Zstd = 5,
        DictionaryCompressedBrotli = 6,
        DictionaryCompressedZstd = 7,
        Aes128Gcm = 8,
        Exi = 9,
        Pack200Gzip = 10,
        Any = 11,
        Extension = 12
    };

    constexpr USHORT AcceptEncodingQValueMax = 1000;

    struct AcceptEncodingPreference final
    {
        AcceptCoding Coding = AcceptCoding::Identity;
        USHORT QValue = AcceptEncodingQValueMax;
    };

    enum class ContentCoding : UCHAR
    {
        Identity,
        Gzip,
        Deflate,
        Brotli,
        Compress,
        Zstd,
        DictionaryCompressedBrotli,
        DictionaryCompressedZstd,
        Aes128Gcm,
        Exi,
        Pack200Gzip
    };

    struct CodingExternalMaterial final
    {
        ContentCoding Coding = ContentCoding::Identity;
        const UCHAR* Dictionary = nullptr;
        SIZE_T DictionaryLength = 0;
        const UCHAR* Aes128GcmKeyingMaterial = nullptr;
        SIZE_T Aes128GcmKeyingMaterialLength = 0;
    };

    using CodingMaterialCallback = NTSTATUS(*)(
        _In_opt_ void* context,
        ContentCoding coding,
        _Out_ CodingExternalMaterial* material);

    struct CodingDecodeMaterials final
    {
        const CodingExternalMaterial* Items = nullptr;
        SIZE_T ItemCount = 0;
        CodingMaterialCallback Callback = nullptr;
        void* CallbackContext = nullptr;
    };

    // Public HTTP/2 priority descriptor (RFC 7540 weight/dependency).
    struct Http2Priority final
    {
        ULONG StreamDependency = 0;
        USHORT Weight = 16;
        bool Exclusive = false;
    };

    constexpr SIZE_T DefaultRequestBufferBytes = 16 * 1024;
    constexpr SIZE_T DefaultMaxResponseBytes = 0;
    constexpr SIZE_T DefaultMaxWebSocketMessageBytes = 1024 * 1024;
    constexpr ULONG DefaultPoolCapacity = 8;
    constexpr ULONG DefaultMaxConnsPerHost = 2;
    constexpr ULONG DefaultIdleTimeoutMs = 30000;
    constexpr ULONG DefaultTlsHandshakeTimeoutMs = TlsHandshakeReceiveTimeoutMilliseconds;
    constexpr ULONG DefaultMaxTls12Renegotiations = 1;
    constexpr ULONG HardMaxTls12Renegotiations = 4;
    constexpr ULONG DefaultMaxRedirects = 10;
    constexpr ULONG DefaultExpectContinueTimeoutMs = 1000;
    constexpr ULONG MaxExpectContinueTimeoutMs = WskOperationTimeoutMilliseconds;
    constexpr ULONG DefaultHttp2KeepAliveIdleMs = 30000;
    constexpr ULONG DefaultHttp2KeepAliveIntervalMs = 30000;
    constexpr ULONG DefaultHttp2KeepAliveAckTimeoutMs = 5000;
    constexpr ULONG DefaultHttp11PipelineMaxDepth = 4;
    constexpr ULONG DefaultHttp3RaceWindowMs = 250;
    constexpr ULONG DefaultHttp3QuicProbeTimeoutMs = 1500;
    constexpr ULONG DefaultHttp3AltSvcMaxEntries = 64;
    constexpr ULONG DefaultHttp3AltSvcMaxAgeSec = 604800;
    constexpr ULONG MaxHttp3RaceWindowMs = 60000;
    constexpr ULONG MaxHttp3QuicProbeTimeoutMs = 120000;
    constexpr ULONG MaxHttp3AltSvcMaxAgeSec = static_cast<ULONG>(~static_cast<ULONG>(0)) / 1000;
    constexpr ULONG Http11PipelineMethodGet = 0x00000001;
    constexpr ULONG Http11PipelineMethodPost = 0x00000002;
    constexpr ULONG Http11PipelineMethodPut = 0x00000004;
    constexpr ULONG Http11PipelineMethodPatch = 0x00000008;
    constexpr ULONG Http11PipelineMethodDelete = 0x00000010;
    constexpr ULONG Http11PipelineMethodHead = 0x00000020;
    constexpr ULONG Http11PipelineMethodOptions = 0x00000040;
    constexpr ULONG Http11PipelineMethodConnect = 0x00000080;
    constexpr ULONG Http11PipelineMethodTrace = 0x00000100;
    constexpr ULONG DefaultHttp11PipelineMethodMask =
        Http11PipelineMethodGet |
        Http11PipelineMethodHead |
        Http11PipelineMethodOptions;

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

    typedef void (*CompletionCallback)(
        void* context,
        NTSTATUS status);

    struct TlsConfig final
    {
        // Defaults to Min=TLS 1.2 and Max=TLS 1.3: prefer TLS 1.3 and reconnect with TLS 1.2
        // only when the peer proves it cannot negotiate 1.3. Set MinVersion=MaxVersion=Tls13
        // to require TLS 1.3 only.
        TlsVersion MinVersion = TlsVersion::Tls12;
        TlsVersion MaxVersion = TlsVersion::Tls13;
        CertPolicy Certificate = CertPolicy::Verify;
        const CertificateStore* Store = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
        bool PreferHttp2 = true;
        TlsPolicy Policy = {};
        const TlsClientCredential* ClientCredential = nullptr;
        ULONG HandshakeTimeoutMs = DefaultTlsHandshakeTimeoutMs;
        ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations;
    };

    struct ProxyConfig final
    {
        bool Enabled = false;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        AddressFamily Family = AddressFamily::Any;
        const char* Authority = nullptr;
        SIZE_T AuthorityLength = 0;
        const char* AuthHeader = nullptr;
        SIZE_T AuthHeaderLength = 0;
    };

    struct Http2KeepAliveConfig final
    {
        bool Enabled = false;
        ULONG IdleMs = DefaultHttp2KeepAliveIdleMs;
        ULONG IntervalMs = DefaultHttp2KeepAliveIntervalMs;
        ULONG AckTimeoutMs = DefaultHttp2KeepAliveAckTimeoutMs;
    };

    struct Http3Config final
    {
        Http3ConnectMode Mode = Http3ConnectMode::Auto;
        Http3RaceMode Race = Http3RaceMode::DelayedTcpFallback;
        ULONG RaceWindowMs = DefaultHttp3RaceWindowMs;
        ULONG QuicProbeTimeoutMs = DefaultHttp3QuicProbeTimeoutMs;
        ULONG AltSvcMaxEntries = DefaultHttp3AltSvcMaxEntries;
        ULONG AltSvcMaxAgeSec = DefaultHttp3AltSvcMaxAgeSec;
    };

    struct CacheOptions final
    {
        SIZE_T MaxBytes = 16 * 1024 * 1024;
        SIZE_T MaxEntries = 256;
        CacheMode Mode = CacheMode::Private;
    };

    struct CacheStats final
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

    struct SessionConfig final
    {
        PoolType ResponsePool = PoolType::NonPaged;
        SIZE_T RequestBufferBytes = DefaultRequestBufferBytes;
        // 0 means no caller-imposed buffered response byte limit.
        SIZE_T MaxResponseBytes = DefaultMaxResponseBytes;
        ULONG PoolCapacity = DefaultPoolCapacity;
        ULONG MaxConnsPerHost = DefaultMaxConnsPerHost;
        ULONG IdleTimeoutMs = DefaultIdleTimeoutMs;
        bool EnableHttp11Pipeline = false;
        ULONG Http11PipelineMaxDepth = DefaultHttp11PipelineMaxDepth;
        ULONG Http11PipelineMethodMask = DefaultHttp11PipelineMethodMask;
        Http2KeepAliveConfig Http2KeepAlive = {};
        Http3Config Http3 = {};
        TlsConfig Tls = {};
        ProxyConfig Proxy = {};
        Cache* Cache = nullptr;
    };

    struct SendOptions final
    {
        SIZE_T MaxResponseBytes;
        ULONG Flags;
        ULONG MaxRedirects;
        ULONG ExpectContinueTimeoutMs;
        // 0 = use library default (WSK op timeout) for waiting on response headers.
        ULONG ResponseHeaderTimeoutMs;
        // 0 = use library default for each underlying body read.
        ULONG BodyReadTimeoutMs;
        // 0 = disabled; when set, idle gap between body bytes aborts the stream.
        ULONG BodyIdleTimeoutMs;
        HeaderCallback OnHeader;
        BodyCallback OnBody;
        void* CallbackContext;
        TlsConfig Tls;
        bool HasTlsOverride;
        ConnPolicy ConnectionPolicy;
        AddressFamily Family;
        Http2CleartextMode Http2CleartextMode;
        const AcceptEncodingPreference* AcceptEncodingPreferences;
        SIZE_T AcceptEncodingPreferenceCount;
        const CodingDecodeMaterials* ContentCodingMaterials;
        const Http2Priority* Http2Priority;
        Cache* Cache;
#if defined(WKNET_USER_MODE_TEST)
        CompletionCallback OnComplete;
        void* CompletionContext;
#endif

        ~SendOptions() noexcept = default;
        SendOptions(const SendOptions&) noexcept = default;
        SendOptions& operator=(const SendOptions&) noexcept = default;

    private:
        SendOptions() noexcept;

        template<typename T, typename... Args>
        friend T* ::wknet::AllocateNonPagedObject(Args&&... args) noexcept;
        template<typename T>
        friend void ::wknet::FreeNonPagedObject(_In_opt_ T* object) noexcept;
        friend SendOptions DefaultSendOptions() noexcept;
        friend NTSTATUS SendOptionsCreate(_Out_ SendOptions** options) noexcept;
    };

    struct AsyncOptions final
    {
        SendOptions Send;
        CompletionCallback OnComplete;
        void* CompletionContext;

        ~AsyncOptions() noexcept = default;
        AsyncOptions(const AsyncOptions&) noexcept = default;
        AsyncOptions& operator=(const AsyncOptions&) noexcept = default;

    private:
        AsyncOptions() noexcept;

        template<typename T, typename... Args>
        friend T* ::wknet::AllocateNonPagedObject(Args&&... args) noexcept;
        template<typename T>
        friend void ::wknet::FreeNonPagedObject(_In_opt_ T* object) noexcept;
        friend NTSTATUS AsyncOptionsCreate(_Out_ AsyncOptions** options) noexcept;
    };

    struct NameValuePair final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct MultipartPart final
    {
        BodyPartKind Kind = BodyPartKind::Field;
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

    TlsConfig DefaultTlsConfig() noexcept;
    SessionConfig DefaultSessionConfig() noexcept;
    SendOptions DefaultSendOptions() noexcept;
}

namespace wknet::websocket {
    struct WebSocket;

    enum class MsgType : ULONG
    {
        Text = 0,
        Binary = 1,
        Close = 2,
        Continuation = 3,
        Ping = 4,
        Pong = 5
    };

    typedef NTSTATUS (*MessageCallback)(
        void* context,
        MsgType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment);

    // A caller-supplied opening-handshake header (e.g. Origin, Authorization, Cookie).
    // Headers that the library controls (Upgrade, Connection, Host, Sec-WebSocket-*)
    // are rejected with STATUS_INVALID_PARAMETER to prevent handshake tampering.
    struct Header final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    // Response header view used only by handshake challenge callbacks.
    struct ResponseHeader final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct HandshakeChallenge final
    {
        USHORT StatusCode = 0;
        const ResponseHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        bool Redirect = false;
        bool AuthenticationChallenge = false;
    };

    struct HandshakeRetryAction final
    {
        const char* RedirectPath = nullptr;
        SIZE_T RedirectPathLength = 0;
        const Header* Headers = nullptr;
        SIZE_T HeaderCount = 0;
    };

    typedef NTSTATUS (*HandshakeChallengeCallback)(
        void* context,
        const HandshakeChallenge* challenge,
        HandshakeRetryAction* action);

    struct PerMessageDeflateOptions final
    {
        bool Enable = false;
        bool ClientNoContextTakeover = false;
        bool ServerNoContextTakeover = false;
        UCHAR ClientMaxWindowBits = 15;
        UCHAR ServerMaxWindowBits = 15;
    };

    struct ConnectConfig final
    {
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        const Header* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        wknet::http::TlsConfig Tls = {};
        wknet::http::AddressFamily Family = wknet::http::AddressFamily::Any;
        SIZE_T MaxMessageBytes = wknet::http::DefaultMaxWebSocketMessageBytes;
        bool AutoReplyPing = true;
        bool AllowWebSocketOverHttp2 = false;
        wknet::http::WebSocketTransportMode TransportMode = wknet::http::WebSocketTransportMode::Auto;
        PerMessageDeflateOptions PerMessageDeflate = {};
        HandshakeChallengeCallback ChallengeCallback = nullptr;
        void* ChallengeContext = nullptr;
        ULONG MaxHandshakeRetries = 0;
    };

    struct SendOptions final
    {
        bool FinalFragment = true;
    };

    struct ReceiveOptions final
    {
        SIZE_T MaxMessageBytes = 0;
        bool AutoAllocate = true;
        MessageCallback OnMessage = nullptr;
        void* CallbackContext = nullptr;
        bool DeliverFragments = false;
    };

    struct Message final
    {
        MsgType Type = MsgType::Binary;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        bool Final = true;
        bool FinalFragment = true;
    };

    ConnectConfig DefaultConnectConfig() noexcept;
}
