#pragma once

#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/http/HttpContentEncoding.h>
#include <KernelHttp/http/HttpTypes.h>
#include <KernelHttp/tls/TlsPolicy.h>

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
#include <ntddk.h>
#endif

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#ifndef _Must_inspect_result_
#define _Must_inspect_result_
#endif
#ifndef _In_
#define _In_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _In_z_
#define _In_z_
#endif
#ifndef _In_reads_
#define _In_reads_(s)
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(s)
#endif
#ifndef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(s)
#endif
#ifndef _Outptr_result_bytebuffer_
#define _Outptr_result_bytebuffer_(s)
#endif
#endif

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <KernelHttp/net/WskClient.h>
#else
#include <KernelHttp/KernelHttpConfig.h>
#include <KernelHttp/net/WskClient.h>
#endif

namespace KernelHttp
{
namespace net
{
    class WskClient;
}

namespace tls
{
    class CertificateStore;
    struct TlsClientCredential;
}
}

namespace khttp
{
    struct Session;
    struct Request;
    struct Response;
    struct AsyncOp;
    struct Headers;
    struct Body;

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
        LegacyBoolean = 0,
        Http11Only = 1,
        Auto = 2,
        Http2Required = 3
    };

    enum SendFlags : ULONG
    {
        SendFlagNone = 0,
        SendFlagAggregateWithCallbacks = 0x00000001,
        SendFlagDisableAutoRedirect = 0x00000002,
        SendFlagExpectContinue = 0x00000004,
        SendFlagAllowTrace = 0x00000008
    };

    constexpr SIZE_T DefaultRequestBufferBytes = 16 * 1024;
    constexpr SIZE_T DefaultMaxResponseBytes = 0;
    constexpr SIZE_T DefaultMaxWebSocketMessageBytes = 1024 * 1024;
    constexpr ULONG DefaultPoolCapacity = 8;
    constexpr ULONG DefaultMaxConnsPerHost = 2;
    constexpr ULONG DefaultIdleTimeoutMs = 30000;
    constexpr ULONG DefaultTlsHandshakeTimeoutMs = ::KernelHttp::TlsHandshakeReceiveTimeoutMilliseconds;
    constexpr ULONG DefaultMaxRedirects = 10;
    constexpr ULONG DefaultExpectContinueTimeoutMs = 1000;
    constexpr ULONG MaxExpectContinueTimeoutMs = ::KernelHttp::WskOperationTimeoutMilliseconds;
    constexpr ULONG DefaultHttp11PipelineMaxDepth = ::KernelHttp::engine::KhDefaultHttp11PipelineMaxDepth;
    constexpr ULONG Http11PipelineMethodGet = ::KernelHttp::engine::KhHttp11PipelineMethodGet;
    constexpr ULONG Http11PipelineMethodPost = ::KernelHttp::engine::KhHttp11PipelineMethodPost;
    constexpr ULONG Http11PipelineMethodPut = ::KernelHttp::engine::KhHttp11PipelineMethodPut;
    constexpr ULONG Http11PipelineMethodPatch = ::KernelHttp::engine::KhHttp11PipelineMethodPatch;
    constexpr ULONG Http11PipelineMethodDelete = ::KernelHttp::engine::KhHttp11PipelineMethodDelete;
    constexpr ULONG Http11PipelineMethodHead = ::KernelHttp::engine::KhHttp11PipelineMethodHead;
    constexpr ULONG Http11PipelineMethodOptions = ::KernelHttp::engine::KhHttp11PipelineMethodOptions;
    constexpr ULONG Http11PipelineMethodConnect = ::KernelHttp::engine::KhHttp11PipelineMethodConnect;
    constexpr ULONG Http11PipelineMethodTrace = ::KernelHttp::engine::KhHttp11PipelineMethodTrace;
    constexpr ULONG DefaultHttp11PipelineMethodMask = ::KernelHttp::engine::KhDefaultHttp11PipelineMethodMask;

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
        const ::KernelHttp::tls::CertificateStore* Store = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
        bool PreferHttp2 = true;
        ::KernelHttp::tls::TlsPolicy Policy = {};
        const ::KernelHttp::tls::TlsClientCredential* ClientCredential = nullptr;
        ULONG HandshakeTimeoutMs = DefaultTlsHandshakeTimeoutMs;
    };

    struct ProxyConfig final
    {
        bool Enabled = false;
        SOCKADDR_STORAGE Address = {};
        const char* Authority = nullptr;
        SIZE_T AuthorityLength = 0;
        const char* AuthHeader = nullptr;
        SIZE_T AuthHeaderLength = 0;
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
        TlsConfig Tls = {};
        ProxyConfig Proxy = {};
    };

    struct SendOptions final
    {
        SIZE_T MaxResponseBytes;
        ULONG Flags;
        ULONG MaxRedirects;
        ULONG ExpectContinueTimeoutMs;
        HeaderCallback OnHeader;
        BodyCallback OnBody;
        void* CallbackContext;
        TlsConfig Tls;
        bool HasTlsOverride;
        ConnPolicy ConnectionPolicy;
        AddressFamily Family;
        Http2CleartextMode Http2CleartextMode;
        const ::KernelHttp::http::HttpAcceptEncodingPreference* AcceptEncodingPreferences;
        SIZE_T AcceptEncodingPreferenceCount;
        const ::KernelHttp::http2::Http2Priority* Http2Priority;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        CompletionCallback OnComplete;
        void* CompletionContext;
#endif

        ~SendOptions() noexcept = default;

    private:
        SendOptions() noexcept;

        template<typename T, typename... Args>
        friend T* ::KernelHttp::AllocateNonPagedObject(Args&&... args) noexcept;
        template<typename T>
        friend void ::KernelHttp::FreeNonPagedObject(_In_opt_ T* object) noexcept;
        friend SendOptions DefaultSendOptions() noexcept;
        friend NTSTATUS SendOptionsCreate(_Out_ SendOptions** options) noexcept;
    };

    struct AsyncOptions final
    {
        SendOptions Send;
        CompletionCallback OnComplete;
        void* CompletionContext;

        ~AsyncOptions() noexcept = default;

    private:
        AsyncOptions() noexcept;

        template<typename T, typename... Args>
        friend T* ::KernelHttp::AllocateNonPagedObject(Args&&... args) noexcept;
        template<typename T>
        friend void ::KernelHttp::FreeNonPagedObject(_In_opt_ T* object) noexcept;
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

namespace kws
{
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

    using HandshakeChallenge = ::KernelHttp::engine::KhWebSocketHandshakeChallenge;
    using HandshakeRetryAction = ::KernelHttp::engine::KhWebSocketHandshakeRetryAction;
    using HandshakeChallengeCallback = ::KernelHttp::engine::KhWebSocketHandshakeChallengeCallback;

    struct ConnectConfig final
    {
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        const Header* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        khttp::TlsConfig Tls = {};
        khttp::AddressFamily Family = khttp::AddressFamily::Any;
        SIZE_T MaxMessageBytes = khttp::DefaultMaxWebSocketMessageBytes;
        bool AutoReplyPing = true;
        bool AllowWebSocketOverHttp2 = false;
        khttp::WebSocketTransportMode TransportMode = khttp::WebSocketTransportMode::LegacyBoolean;
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
