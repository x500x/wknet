#pragma once

#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/engine/HandleTypes.h>
#include <KernelHttp/khttp/Types.h>
#include <KernelHttp/net/WskClient.h>

namespace khttp
{
namespace detail
{
    constexpr ULONG KhHighSessionMagic = 0x4B485331;
    constexpr ULONG KhHighRequestMagic = 0x4B485232;
    constexpr ULONG KhHighHeadersMagic = 0x4B484432;
    constexpr ULONG KhHighBodyMagic = 0x4B484232;

    enum class BodyStorageKind : ULONG
    {
        Empty = 0,
        Bytes = 1,
        Text = 2,
        Json = 3,
        Form = 4,
        Multipart = 5,
        File = 6,
        Stream = 7
    };

    struct StoredText final
    {
        char* Text = nullptr;
        SIZE_T Length = 0;
    };

    struct StoredBytes final
    {
        UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct StoredHeader final
    {
        char* Name = nullptr;
        SIZE_T NameLength = 0;
        char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };
}

struct Session final
{
    ULONG Magic = detail::KhHighSessionMagic;
    volatile LONG Closed = 0;
    volatile LONG RefCount = 1;
    ::KernelHttp::net::WskClient* Wsk = nullptr;
    ::KernelHttp::engine::KH_SESSION Engine = nullptr;
};

struct Request final
{
    ULONG Magic = detail::KhHighRequestMagic;
    volatile LONG Closed = 0;
    Session* Parent = nullptr;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    char* BuilderUrl = nullptr;
    SIZE_T BuilderUrlLength = 0;
    Method BuilderMethod = Method::Get;
    Headers* BuilderHeaders = nullptr;
    Body* BuilderBody = nullptr;
    SendOptions* BuilderOptions = nullptr;
#endif
};

struct Headers final
{
    ULONG Magic = detail::KhHighHeadersMagic;
    detail::StoredHeader Items[::KernelHttp::engine::KhMaxHeadersPerRequest] = {};
    SIZE_T Count = 0;
};

struct Body final
{
    ULONG Magic = detail::KhHighBodyMagic;
    detail::BodyStorageKind Kind = detail::BodyStorageKind::Empty;
    RequestBodyMode Mode = RequestBodyMode::ContentLength;
    bool OwnsData = false;
    const UCHAR* Data = nullptr;
    SIZE_T DataLength = 0;
    char* ContentType = nullptr;
    SIZE_T ContentTypeLength = 0;
    NameValuePair* FormPairs = nullptr;
    SIZE_T FormPairCount = 0;
    MultipartPart* MultipartParts = nullptr;
    SIZE_T MultipartPartCount = 0;
    char* FilePath = nullptr;
    SIZE_T FilePathLength = 0;
    RequestBodyReadCallback StreamCallback = nullptr;
    void* StreamContext = nullptr;
    SIZE_T StreamContentLength = 0;
    bool StreamContentLengthKnown = false;
    detail::StoredHeader Trailers[::KernelHttp::engine::KhMaxHeadersPerRequest] = {};
    SIZE_T TrailerCount = 0;
};

namespace detail
{
    inline ::KernelHttp::engine::KhSession* ToApiSession(Session* s) noexcept
    {
        if (s == nullptr || s->Magic != KhHighSessionMagic || s->Closed != 0) {
            return nullptr;
        }
        return s->Engine;
    }

    inline ::KernelHttp::engine::KhSession* ToApiSession(Request* request) noexcept
    {
        return request == nullptr ? nullptr : ToApiSession(request->Parent);
    }

    inline ::KernelHttp::engine::KhRequest* ToApiRequest(Request* r) noexcept
    {
        UNREFERENCED_PARAMETER(r);
        return nullptr;
    }

    inline ::KernelHttp::engine::KhResponse* ToApiResponse(Response* r) noexcept
    {
        return reinterpret_cast<::KernelHttp::engine::KhResponse*>(r);
    }

    inline const ::KernelHttp::engine::KhResponse* ToApiResponseConst(const Response* r) noexcept
    {
        return reinterpret_cast<const ::KernelHttp::engine::KhResponse*>(r);
    }

    inline ::KernelHttp::engine::KhWebSocket* ToApiWebSocket(kws::WebSocket* ws) noexcept
    {
        return reinterpret_cast<::KernelHttp::engine::KhWebSocket*>(ws);
    }

    inline ::KernelHttp::engine::KhAsyncOperation* ToApiAsyncOp(AsyncOp* op) noexcept
    {
        return reinterpret_cast<::KernelHttp::engine::KhAsyncOperation*>(op);
    }

    inline Response* FromApiResponse(::KernelHttp::engine::KhResponse* r) noexcept
    {
        return reinterpret_cast<Response*>(r);
    }

    inline kws::WebSocket* FromApiWebSocket(::KernelHttp::engine::KhWebSocket* ws) noexcept
    {
        return reinterpret_cast<kws::WebSocket*>(ws);
    }

    inline AsyncOp* FromApiAsyncOp(::KernelHttp::engine::KhAsyncOperation* op) noexcept
    {
        return reinterpret_cast<AsyncOp*>(op);
    }

    inline Session* FromApiSession(::KernelHttp::engine::KhSession* s) noexcept
    {
        UNREFERENCED_PARAMETER(s);
        return nullptr;
    }

    inline Request* FromApiRequest(::KernelHttp::engine::KhRequest* r) noexcept
    {
        UNREFERENCED_PARAMETER(r);
        return nullptr;
    }

    inline bool IsValidSession(const Session* session) noexcept
    {
        return session != nullptr &&
            session->Magic == KhHighSessionMagic &&
            session->Closed == 0 &&
            session->Engine != nullptr;
    }

    inline bool IsValidRequest(const Request* request) noexcept
    {
        return request != nullptr &&
            request->Magic == KhHighRequestMagic &&
            request->Closed == 0 &&
            IsValidSession(request->Parent);
    }

    inline bool AddSessionRef(Session* session) noexcept
    {
        if (!IsValidSession(session)) {
            return false;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        ++session->RefCount;
#else
        InterlockedIncrement(&session->RefCount);
#endif
        return true;
    }

    inline bool ReleaseSessionRef(Session* session) noexcept
    {
        if (session == nullptr || session->Magic != KhHighSessionMagic) {
            return false;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        --session->RefCount;
        return session->RefCount == 0 && session->Closed != 0;
#else
        return InterlockedDecrement(&session->RefCount) == 0 && session->Closed != 0;
#endif
    }

    inline void FreeClosedSession(Session* session) noexcept
    {
        if (session == nullptr) {
            return;
        }
        if (session->Engine != nullptr) {
            ::KernelHttp::engine::KhSessionClose(session->Engine);
            session->Engine = nullptr;
        }
        if (session->Wsk != nullptr) {
            session->Wsk->Shutdown();
            ::KernelHttp::FreeNonPagedObject(session->Wsk);
            session->Wsk = nullptr;
        }
        session->Magic = 0;
        ::KernelHttp::FreeNonPagedObject(session);
    }

    inline Session* SessionFromSendHandle(Session* session) noexcept
    {
        return IsValidSession(session) ? session : nullptr;
    }

    inline Session* SessionFromSendHandle(Request* request) noexcept
    {
        return IsValidRequest(request) ? request->Parent : nullptr;
    }

    inline ::KernelHttp::engine::KhPoolType ToApiPoolType(PoolType t) noexcept
    {
        return t == PoolType::Paged ? ::KernelHttp::engine::KhPoolType::Paged : ::KernelHttp::engine::KhPoolType::NonPaged;
    }

    inline ::KernelHttp::engine::KhTlsVersion ToApiTlsVersion(TlsVersion v) noexcept
    {
        return v == TlsVersion::Tls13 ? ::KernelHttp::engine::KhTlsVersion::Tls13 : ::KernelHttp::engine::KhTlsVersion::Tls12;
    }

    inline ::KernelHttp::engine::KhCertificatePolicy ToApiCertPolicy(CertPolicy p) noexcept
    {
        return p == CertPolicy::NoVerify ? ::KernelHttp::engine::KhCertificatePolicy::NoVerify : ::KernelHttp::engine::KhCertificatePolicy::Verify;
    }

    inline ::KernelHttp::engine::KhAddressFamily ToApiAddressFamily(AddressFamily f) noexcept
    {
        switch (f) {
        case AddressFamily::Ipv4: return ::KernelHttp::engine::KhAddressFamily::Ipv4;
        case AddressFamily::Ipv6: return ::KernelHttp::engine::KhAddressFamily::Ipv6;
        case AddressFamily::Any:
        default: return ::KernelHttp::engine::KhAddressFamily::Any;
        }
    }

    inline ::KernelHttp::engine::KhConnectionPolicy ToApiConnPolicy(ConnPolicy p) noexcept
    {
        switch (p) {
        case ConnPolicy::ForceNew: return ::KernelHttp::engine::KhConnectionPolicy::ForceNew;
        case ConnPolicy::NoPool: return ::KernelHttp::engine::KhConnectionPolicy::NoPool;
        case ConnPolicy::ReuseOrCreate:
        default: return ::KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate;
        }
    }

    inline ::KernelHttp::engine::KhHttpMethod ToApiMethod(Method m) noexcept
    {
        switch (m) {
        case Method::Post: return ::KernelHttp::engine::KhHttpMethod::Post;
        case Method::Put: return ::KernelHttp::engine::KhHttpMethod::Put;
        case Method::Patch: return ::KernelHttp::engine::KhHttpMethod::Patch;
        case Method::Delete: return ::KernelHttp::engine::KhHttpMethod::Delete;
        case Method::Head: return ::KernelHttp::engine::KhHttpMethod::Head;
        case Method::Options: return ::KernelHttp::engine::KhHttpMethod::Options;
        case Method::Connect: return ::KernelHttp::engine::KhHttpMethod::Connect;
        case Method::Trace: return ::KernelHttp::engine::KhHttpMethod::Trace;
        case Method::Get:
        default: return ::KernelHttp::engine::KhHttpMethod::Get;
        }
    }

    inline kws::MsgType FromApiWsMsgType(::KernelHttp::engine::KhWebSocketMessageType t) noexcept
    {
        switch (t) {
        case ::KernelHttp::engine::KhWebSocketMessageType::Text: return kws::MsgType::Text;
        case ::KernelHttp::engine::KhWebSocketMessageType::Close: return kws::MsgType::Close;
        case ::KernelHttp::engine::KhWebSocketMessageType::Continuation: return kws::MsgType::Continuation;
        case ::KernelHttp::engine::KhWebSocketMessageType::Ping: return kws::MsgType::Ping;
        case ::KernelHttp::engine::KhWebSocketMessageType::Pong: return kws::MsgType::Pong;
        case ::KernelHttp::engine::KhWebSocketMessageType::Binary:
        default: return kws::MsgType::Binary;
        }
    }

    inline ::KernelHttp::engine::KhWebSocketTransportMode ToApiWebSocketTransportMode(
        WebSocketTransportMode mode) noexcept
    {
        switch (mode) {
        case WebSocketTransportMode::Http11Only:
            return ::KernelHttp::engine::KhWebSocketTransportMode::Http11Only;
        case WebSocketTransportMode::Auto:
            return ::KernelHttp::engine::KhWebSocketTransportMode::Auto;
        case WebSocketTransportMode::Http2Required:
            return ::KernelHttp::engine::KhWebSocketTransportMode::Http2Required;
        case WebSocketTransportMode::LegacyBoolean:
        default:
            return ::KernelHttp::engine::KhWebSocketTransportMode::LegacyBoolean;
        }
    }

    inline ::KernelHttp::engine::KhWebSocketMessageType ToApiWsMsgType(kws::MsgType t) noexcept
    {
        switch (t) {
        case kws::MsgType::Text: return ::KernelHttp::engine::KhWebSocketMessageType::Text;
        case kws::MsgType::Close: return ::KernelHttp::engine::KhWebSocketMessageType::Close;
        case kws::MsgType::Continuation: return ::KernelHttp::engine::KhWebSocketMessageType::Continuation;
        case kws::MsgType::Ping: return ::KernelHttp::engine::KhWebSocketMessageType::Ping;
        case kws::MsgType::Pong: return ::KernelHttp::engine::KhWebSocketMessageType::Pong;
        case kws::MsgType::Binary:
        default: return ::KernelHttp::engine::KhWebSocketMessageType::Binary;
        }
    }

    inline ::KernelHttp::engine::KhRequestBodyPartKind ToApiBodyPartKind(BodyPartKind k) noexcept
    {
        switch (k) {
        case BodyPartKind::FileBytes: return ::KernelHttp::engine::KhRequestBodyPartKind::FileBytes;
        case BodyPartKind::FilePath: return ::KernelHttp::engine::KhRequestBodyPartKind::FilePath;
        case BodyPartKind::Field:
        default: return ::KernelHttp::engine::KhRequestBodyPartKind::Field;
        }
    }

    inline ::KernelHttp::engine::KhRequestBodyMode ToApiRequestBodyMode(RequestBodyMode mode) noexcept
    {
        return mode == RequestBodyMode::Chunked ?
            ::KernelHttp::engine::KhRequestBodyMode::Chunked :
            ::KernelHttp::engine::KhRequestBodyMode::ContentLength;
    }

    inline ::KernelHttp::engine::KhHttp2CleartextMode ToApiHttp2CleartextMode(
        Http2CleartextMode mode) noexcept
    {
        switch (mode) {
        case Http2CleartextMode::PriorKnowledge:
            return ::KernelHttp::engine::KhHttp2CleartextMode::PriorKnowledge;
        case Http2CleartextMode::Upgrade:
            return ::KernelHttp::engine::KhHttp2CleartextMode::Upgrade;
        case Http2CleartextMode::Disabled:
        default:
            return ::KernelHttp::engine::KhHttp2CleartextMode::Disabled;
        }
    }

    inline void FillApiTlsOptions(const TlsConfig& src, ::KernelHttp::engine::KhTlsOptions& dst) noexcept
    {
        dst.MinVersion = ToApiTlsVersion(src.MinVersion);
        dst.MaxVersion = ToApiTlsVersion(src.MaxVersion);
        dst.CertificatePolicy = ToApiCertPolicy(src.Certificate);
        dst.CertificateStore = src.Store;
        dst.ServerName = src.ServerName;
        dst.ServerNameLength = src.ServerNameLength;
        dst.Alpn = src.Alpn;
        dst.AlpnLength = src.AlpnLength;
        dst.PreferHttp2 = src.PreferHttp2;
        dst.Policy = src.Policy;
        dst.ClientCredential = src.ClientCredential;
        dst.HandshakeReceiveTimeoutMilliseconds = src.HandshakeTimeoutMs;
    }

    void FillApiSendOptions(
        const SendOptions& src,
        ::KernelHttp::engine::KhHttpSendOptions& dst) noexcept;

    _Must_inspect_result_
    NTSTATUS PrepareHttpRequest(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const Headers* headers,
        const Body* body,
        const SendOptions* options,
        ::KernelHttp::engine::KH_REQUEST* request) noexcept;
}
}
