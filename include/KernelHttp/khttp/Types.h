#pragma once

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

    enum class Method : ULONG
    {
        Get = 0,
        Post = 1,
        Put = 2,
        Patch = 3,
        Delete = 4,
        Head = 5,
        Options = 6,
        Connect = 7
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

    enum SendFlags : ULONG
    {
        SendFlagNone = 0,
        SendFlagAggregateWithCallbacks = 0x00000001,
        SendFlagDisableAutoRedirect = 0x00000002
    };

    constexpr SIZE_T DefaultRequestBufferBytes = 16 * 1024;
    constexpr SIZE_T DefaultMaxResponseBytes = 1024 * 1024;
    constexpr ULONG DefaultPoolCapacity = 8;
    constexpr ULONG DefaultMaxConnsPerHost = 2;
    constexpr ULONG DefaultIdleTimeoutMs = 30000;
    constexpr ULONG DefaultTlsHandshakeTimeoutMs = ::KernelHttp::TlsHandshakeReceiveTimeoutMilliseconds;
    constexpr ULONG DefaultMaxRedirects = 10;

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

    struct SessionConfig final
    {
        PoolType ResponsePool = PoolType::NonPaged;
        SIZE_T RequestBufferBytes = DefaultRequestBufferBytes;
        // SIZE_T is unsigned; 0 means no response-size limit.
        SIZE_T MaxResponseBytes = DefaultMaxResponseBytes;
        ULONG PoolCapacity = DefaultPoolCapacity;
        ULONG MaxConnsPerHost = DefaultMaxConnsPerHost;
        ULONG IdleTimeoutMs = DefaultIdleTimeoutMs;
        TlsConfig Tls = {};
    };

    struct SendOptions final
    {
        // 0 means no response-size limit. Passing nullptr options is also unlimited.
        SIZE_T MaxResponseBytes = 0;
        ULONG Flags = SendFlagNone;
        // 0 means use the default redirect limit.
        ULONG MaxRedirects = 0;
        HeaderCallback OnHeader = nullptr;
        BodyCallback OnBody = nullptr;
        void* CallbackContext = nullptr;
        CompletionCallback OnComplete = nullptr;
        void* CompletionContext = nullptr;
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
        SIZE_T MaxMessageBytes = khttp::DefaultMaxResponseBytes;
        bool AutoReplyPing = true;
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
