#pragma once

#include <KernelHttp/http/HttpTypes.h>

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
}

namespace khttp
{
    struct Session;
    struct Request;
    struct Response;
    struct AsyncOp;
    struct WebSocket;

    enum class Method : ULONG
    {
        Get = 0,
        Post = 1,
        Put = 2,
        Patch = 3,
        Delete = 4,
        Head = 5,
        Options = 6
    };

    enum class PoolType : ULONG
    {
        NonPaged = 0,
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

    enum class WsMsgType : ULONG
    {
        Text = 0,
        Binary = 1,
        Close = 2
    };

    enum class BodyPartKind : ULONG
    {
        Field = 0,
        FileBytes = 1,
        FilePath = 2
    };

    enum SendFlags : ULONG
    {
        SendFlagNone = 0,
        SendFlagAggregateWithCallbacks = 0x00000001
    };

    constexpr SIZE_T DefaultRequestBufferBytes = 16 * 1024;
    constexpr SIZE_T DefaultMaxResponseBytes = 1024 * 1024;
    constexpr ULONG DefaultPoolCapacity = 8;
    constexpr ULONG DefaultMaxConnsPerHost = 2;
    constexpr ULONG DefaultIdleTimeoutMs = 30000;
    constexpr ULONG DefaultTlsHandshakeTimeoutMs = TlsHandshakeReceiveTimeoutMilliseconds;

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

    typedef NTSTATUS (*WsMessageCallback)(
        void* context,
        WsMsgType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment);

    struct TlsConfig final
    {
        TlsVersion MinVersion = TlsVersion::Tls12;
        TlsVersion MaxVersion = TlsVersion::Tls13;
        CertPolicy Certificate = CertPolicy::Verify;
        const tls::CertificateStore* Store = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
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

    struct WsConnectConfig final
    {
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        TlsConfig Tls = {};
        AddressFamily Family = AddressFamily::Any;
        SIZE_T MaxMessageBytes = DefaultMaxResponseBytes;
        bool AutoReplyPing = true;
    };

    struct WsSendOptions final
    {
        bool FinalFragment = true;
    };

    struct WsReceiveOptions final
    {
        SIZE_T MaxMessageBytes = 0;
        bool AutoAllocate = true;
        WsMessageCallback OnMessage = nullptr;
        void* CallbackContext = nullptr;
    };

    struct WsMessage final
    {
        WsMsgType Type = WsMsgType::Binary;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        bool Final = true;
        bool FinalFragment = true;
    };

    TlsConfig DefaultTlsConfig() noexcept;
    SessionConfig DefaultSessionConfig() noexcept;
    SendOptions DefaultSendOptions() noexcept;
    WsConnectConfig DefaultWsConnectConfig() noexcept;
}
}

namespace khttp = ::KernelHttp::khttp;
