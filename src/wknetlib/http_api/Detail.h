#pragma once

#include "session/Engine.h"
#include "session/HandleTypes.h"
#include <wknet/http/Types.h>
#include "net/WskClient.h"

namespace wknet::http {
namespace detail
{
    constexpr ULONG KhHighSessionMagic = 0x4B485331;
    constexpr ULONG KhHighRequestMagic = 0x4B485232;
    constexpr ULONG KhHighHeadersMagic = 0x4B484432;
    constexpr ULONG KhHighBodyMagic = 0x4B484232;
    constexpr ULONG KhHighCacheMagic = 0x4B484332;

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
    ::wknet::net::WskClient* Wsk = nullptr;
    ::wknet::session::KH_SESSION Engine = nullptr;
};

struct Request final
{
    ULONG Magic = detail::KhHighRequestMagic;
    volatile LONG Closed = 0;
    Session* Parent = nullptr;
#if defined(WKNET_USER_MODE_TEST)
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
    detail::StoredHeader Items[::wknet::session::KhMaxHeadersPerRequest] = {};
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
    detail::StoredHeader Trailers[::wknet::session::KhMaxHeadersPerRequest] = {};
    SIZE_T TrailerCount = 0;
};

struct Cache final
{
    ULONG Magic = detail::KhHighCacheMagic;
    ::wknet::session::KH_HTTP_CACHE Engine = nullptr;
};

namespace detail
{
    inline ::wknet::session::KhSession* ToApiSession(Session* s) noexcept
    {
        if (s == nullptr || s->Magic != KhHighSessionMagic || s->Closed != 0) {
            return nullptr;
        }
        return s->Engine;
    }

    inline ::wknet::session::KhSession* ToApiSession(Request* request) noexcept
    {
        return request == nullptr ? nullptr : ToApiSession(request->Parent);
    }

    inline ::wknet::session::KhRequest* ToApiRequest(Request* r) noexcept
    {
        UNREFERENCED_PARAMETER(r);
        return nullptr;
    }

    inline ::wknet::session::KhResponse* ToApiResponse(Response* r) noexcept
    {
        return reinterpret_cast<::wknet::session::KhResponse*>(r);
    }

    inline const ::wknet::session::KhResponse* ToApiResponseConst(const Response* r) noexcept
    {
        return reinterpret_cast<const ::wknet::session::KhResponse*>(r);
    }

    inline ::wknet::session::KhWebSocket* ToApiWebSocket(wknet::websocket::WebSocket* ws) noexcept
    {
        return reinterpret_cast<::wknet::session::KhWebSocket*>(ws);
    }

    inline ::wknet::session::KhAsyncOperation* ToApiAsyncOp(AsyncOp* op) noexcept
    {
        return reinterpret_cast<::wknet::session::KhAsyncOperation*>(op);
    }

    inline ::wknet::session::KhHttpCache* ToApiCache(Cache* cache) noexcept
    {
        if (cache == nullptr || cache->Magic != KhHighCacheMagic) {
            return nullptr;
        }
        return cache->Engine;
    }

    inline const ::wknet::session::KhHttpCache* ToApiCacheConst(const Cache* cache) noexcept
    {
        if (cache == nullptr || cache->Magic != KhHighCacheMagic) {
            return nullptr;
        }
        return cache->Engine;
    }

    inline Response* FromApiResponse(::wknet::session::KhResponse* r) noexcept
    {
        return reinterpret_cast<Response*>(r);
    }

    inline wknet::websocket::WebSocket* FromApiWebSocket(::wknet::session::KhWebSocket* ws) noexcept
    {
        return reinterpret_cast<wknet::websocket::WebSocket*>(ws);
    }

    inline AsyncOp* FromApiAsyncOp(::wknet::session::KhAsyncOperation* op) noexcept
    {
        return reinterpret_cast<AsyncOp*>(op);
    }

    inline Session* FromApiSession(::wknet::session::KhSession* s) noexcept
    {
        UNREFERENCED_PARAMETER(s);
        return nullptr;
    }

    inline Request* FromApiRequest(::wknet::session::KhRequest* r) noexcept
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
#if defined(WKNET_USER_MODE_TEST)
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
#if defined(WKNET_USER_MODE_TEST)
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
            ::wknet::session::KhSessionClose(session->Engine);
            session->Engine = nullptr;
        }
        if (session->Wsk != nullptr) {
            session->Wsk->Shutdown();
            ::wknet::FreeNonPagedObject(session->Wsk);
            session->Wsk = nullptr;
        }
        session->Magic = 0;
        ::wknet::FreeNonPagedObject(session);
    }

    inline Session* SessionFromSendHandle(Session* session) noexcept
    {
        return IsValidSession(session) ? session : nullptr;
    }

    inline Session* SessionFromSendHandle(Request* request) noexcept
    {
        return IsValidRequest(request) ? request->Parent : nullptr;
    }

    inline ::wknet::session::KhPoolType ToApiPoolType(PoolType t) noexcept
    {
        return t == PoolType::Paged ? ::wknet::session::KhPoolType::Paged : ::wknet::session::KhPoolType::NonPaged;
    }

    inline ::wknet::session::KhTlsVersion ToApiTlsVersion(TlsVersion v) noexcept
    {
        return v == TlsVersion::Tls13 ? ::wknet::session::KhTlsVersion::Tls13 : ::wknet::session::KhTlsVersion::Tls12;
    }

    inline ::wknet::session::KhCertificatePolicy ToApiCertPolicy(CertPolicy p) noexcept
    {
        return p == CertPolicy::NoVerify ? ::wknet::session::KhCertificatePolicy::NoVerify : ::wknet::session::KhCertificatePolicy::Verify;
    }

    inline ::wknet::session::KhAddressFamily ToApiAddressFamily(AddressFamily f) noexcept
    {
        switch (f) {
        case AddressFamily::Ipv4: return ::wknet::session::KhAddressFamily::Ipv4;
        case AddressFamily::Ipv6: return ::wknet::session::KhAddressFamily::Ipv6;
        case AddressFamily::Any:
        default: return ::wknet::session::KhAddressFamily::Any;
        }
    }

    inline ::wknet::session::KhConnectionPolicy ToApiConnPolicy(ConnPolicy p) noexcept
    {
        switch (p) {
        case ConnPolicy::ForceNew: return ::wknet::session::KhConnectionPolicy::ForceNew;
        case ConnPolicy::NoPool: return ::wknet::session::KhConnectionPolicy::NoPool;
        case ConnPolicy::ReuseOrCreate:
        default: return ::wknet::session::KhConnectionPolicy::ReuseOrCreate;
        }
    }

    inline ::wknet::session::KhHttpMethod ToApiMethod(Method m) noexcept
    {
        switch (m) {
        case Method::Post: return ::wknet::session::KhHttpMethod::Post;
        case Method::Put: return ::wknet::session::KhHttpMethod::Put;
        case Method::Patch: return ::wknet::session::KhHttpMethod::Patch;
        case Method::Delete: return ::wknet::session::KhHttpMethod::Delete;
        case Method::Head: return ::wknet::session::KhHttpMethod::Head;
        case Method::Options: return ::wknet::session::KhHttpMethod::Options;
        case Method::Connect: return ::wknet::session::KhHttpMethod::Connect;
        case Method::Trace: return ::wknet::session::KhHttpMethod::Trace;
        case Method::Get:
        default: return ::wknet::session::KhHttpMethod::Get;
        }
    }

    inline wknet::websocket::MsgType FromApiWsMsgType(::wknet::session::KhWebSocketMessageType t) noexcept
    {
        switch (t) {
        case ::wknet::session::KhWebSocketMessageType::Text: return wknet::websocket::MsgType::Text;
        case ::wknet::session::KhWebSocketMessageType::Close: return wknet::websocket::MsgType::Close;
        case ::wknet::session::KhWebSocketMessageType::Continuation: return wknet::websocket::MsgType::Continuation;
        case ::wknet::session::KhWebSocketMessageType::Ping: return wknet::websocket::MsgType::Ping;
        case ::wknet::session::KhWebSocketMessageType::Pong: return wknet::websocket::MsgType::Pong;
        case ::wknet::session::KhWebSocketMessageType::Binary:
        default: return wknet::websocket::MsgType::Binary;
        }
    }

    inline ::wknet::session::KhWebSocketTransportMode ToApiWebSocketTransportMode(
        WebSocketTransportMode mode) noexcept
    {
        switch (mode) {
        case WebSocketTransportMode::Http11Only:
            return ::wknet::session::KhWebSocketTransportMode::Http11Only;
        case WebSocketTransportMode::Auto:
            return ::wknet::session::KhWebSocketTransportMode::Auto;
        case WebSocketTransportMode::Http2Required:
            return ::wknet::session::KhWebSocketTransportMode::Http2Required;
        case WebSocketTransportMode::LegacyBoolean:
        default:
            return ::wknet::session::KhWebSocketTransportMode::LegacyBoolean;
        }
    }

    inline ::wknet::session::KhWebSocketMessageType ToApiWsMsgType(wknet::websocket::MsgType t) noexcept
    {
        switch (t) {
        case wknet::websocket::MsgType::Text: return ::wknet::session::KhWebSocketMessageType::Text;
        case wknet::websocket::MsgType::Close: return ::wknet::session::KhWebSocketMessageType::Close;
        case wknet::websocket::MsgType::Continuation: return ::wknet::session::KhWebSocketMessageType::Continuation;
        case wknet::websocket::MsgType::Ping: return ::wknet::session::KhWebSocketMessageType::Ping;
        case wknet::websocket::MsgType::Pong: return ::wknet::session::KhWebSocketMessageType::Pong;
        case wknet::websocket::MsgType::Binary:
        default: return ::wknet::session::KhWebSocketMessageType::Binary;
        }
    }

    inline ::wknet::session::KhRequestBodyPartKind ToApiBodyPartKind(BodyPartKind k) noexcept
    {
        switch (k) {
        case BodyPartKind::FileBytes: return ::wknet::session::KhRequestBodyPartKind::FileBytes;
        case BodyPartKind::FilePath: return ::wknet::session::KhRequestBodyPartKind::FilePath;
        case BodyPartKind::Field:
        default: return ::wknet::session::KhRequestBodyPartKind::Field;
        }
    }

    inline ::wknet::session::KhRequestBodyMode ToApiRequestBodyMode(RequestBodyMode mode) noexcept
    {
        return mode == RequestBodyMode::Chunked ?
            ::wknet::session::KhRequestBodyMode::Chunked :
            ::wknet::session::KhRequestBodyMode::ContentLength;
    }

    inline ::wknet::session::KhHttp2CleartextMode ToApiHttp2CleartextMode(
        Http2CleartextMode mode) noexcept
    {
        switch (mode) {
        case Http2CleartextMode::PriorKnowledge:
            return ::wknet::session::KhHttp2CleartextMode::PriorKnowledge;
        case Http2CleartextMode::Upgrade:
            return ::wknet::session::KhHttp2CleartextMode::Upgrade;
        case Http2CleartextMode::Disabled:
        default:
            return ::wknet::session::KhHttp2CleartextMode::Disabled;
        }
    }

    inline ::wknet::session::KhHttpCacheMode ToApiCacheMode(CacheMode mode) noexcept
    {
        return mode == CacheMode::Shared ?
            ::wknet::session::KhHttpCacheMode::Shared :
            ::wknet::session::KhHttpCacheMode::Private;
    }

    inline ::wknet::tls::TlsPolicy ToApiTlsPolicy(const TlsPolicy& src) noexcept
    {
        ::wknet::tls::TlsPolicy dst = {};
        dst.Profile = src.Profile == TlsSecurityProfile::CompatibilityExplicit
            ? ::wknet::tls::TlsSecurityProfile::CompatibilityExplicit
            : ::wknet::tls::TlsSecurityProfile::ModernDefault;
        dst.EnableTls12RsaKeyExchange = src.EnableTls12RsaKeyExchange;
        dst.EnableTls12Cbc = src.EnableTls12Cbc;
        dst.EnableTls12Renegotiation = src.EnableTls12Renegotiation;
        dst.EnableTls12Sha1Signatures = src.EnableTls12Sha1Signatures;
        dst.EnablePostHandshakeClientAuth = src.EnablePostHandshakeClientAuth;
        dst.RequireRevocationCheck = src.RequireRevocationCheck;
        return dst;
    }

    inline void FillApiTlsOptions(const TlsConfig& src, ::wknet::session::KhTlsOptions& dst) noexcept
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
        dst.Policy = ToApiTlsPolicy(src.Policy);
        dst.ClientCredential = src.ClientCredential;
        dst.HandshakeReceiveTimeoutMilliseconds = src.HandshakeTimeoutMs;
        dst.MaxTls12Renegotiations = src.MaxTls12Renegotiations;
    }

    // Public coding/priority views are layout-compatible with internal protocol types.
    inline const ::wknet::http1::HttpAcceptEncodingPreference* ToApiAcceptEncodingPreferences(
        const AcceptEncodingPreference* preferences) noexcept
    {
        return reinterpret_cast<const ::wknet::http1::HttpAcceptEncodingPreference*>(preferences);
    }

    inline const ::wknet::http1::HttpCodingDecodeMaterials* ToApiCodingMaterials(
        const CodingDecodeMaterials* materials) noexcept
    {
        return reinterpret_cast<const ::wknet::http1::HttpCodingDecodeMaterials*>(materials);
    }

    inline const ::wknet::http2::Http2Priority* ToApiHttp2Priority(
        const Http2Priority* priority) noexcept
    {
        return reinterpret_cast<const ::wknet::http2::Http2Priority*>(priority);
    }

    inline ::wknet::ws::PerMessageDeflateOptions ToApiPerMessageDeflate(
        const wknet::websocket::PerMessageDeflateOptions& src) noexcept
    {
        ::wknet::ws::PerMessageDeflateOptions dst = {};
        dst.Enable = src.Enable;
        dst.ClientNoContextTakeover = src.ClientNoContextTakeover;
        dst.ServerNoContextTakeover = src.ServerNoContextTakeover;
        dst.ClientMaxWindowBits = src.ClientMaxWindowBits;
        dst.ServerMaxWindowBits = src.ServerMaxWindowBits;
        return dst;
    }

    inline ::wknet::session::KhWebSocketHandshakeChallengeCallback ToApiHandshakeChallengeCallback(
        wknet::websocket::HandshakeChallengeCallback callback) noexcept
    {
        return reinterpret_cast<::wknet::session::KhWebSocketHandshakeChallengeCallback>(callback);
    }

    void FillApiSendOptions(
        const SendOptions& src,
        ::wknet::session::KhHttpSendOptions& dst) noexcept;

    _Must_inspect_result_
    NTSTATUS PrepareHttpRequest(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const Headers* headers,
        const Body* body,
        const SendOptions* options,
        ::wknet::session::KH_REQUEST* request) noexcept;
}
}
