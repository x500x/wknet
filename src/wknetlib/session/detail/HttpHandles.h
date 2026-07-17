#pragma once

#include "session/Engine.h"
#include "session/HandleTypes.h"
#include <wknet/http/Types.h>
#include <wknet/http/Headers.h>
#include "net/WskClient.h"
#include "tls/CertificateStore.h"
#include "session/CookieJar.h"

namespace wknet::http {
namespace detail
{
    constexpr ULONG HighSessionMagic = 0x4B485331;
    constexpr ULONG HighRequestMagic = 0x4B485232;
    constexpr ULONG HighHeadersMagic = 0x4B484432;
    constexpr ULONG HighBodyMagic = 0x4B484232;
    constexpr ULONG HighCacheMagic = 0x4B484332;
    constexpr ULONG HighCertificateStoreMagic = 0x4B484353;
    constexpr ULONG HighAsyncOpMagic = 0x4B484133;

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
    ULONG Magic = detail::HighSessionMagic;
    volatile LONG Closed = 0;
    volatile LONG RefCount = 1;
    ::wknet::net::WskClient* Wsk = nullptr;
    ::wknet::session::SessionHandle Engine = nullptr;
    Headers* DefaultHeaders = nullptr;
    ::wknet::session::CookieJar CookieJar = {};
    // Prebuilt Authorization header value without the field name; empty means no session-level Authorization.
    char* AuthHeaderValue = nullptr;
    SIZE_T AuthHeaderValueLength = 0;
};

struct Request final
{
    ULONG Magic = detail::HighRequestMagic;
    volatile LONG Closed = 0;
    // Optional associated Session; nullptr means Send/AsyncSend uses a library-managed Session.
    Session* Parent = nullptr;
    char* BuilderUrl = nullptr;
    SIZE_T BuilderUrlLength = 0;
    Method BuilderMethod = Method::Get;
    Headers* BuilderHeaders = nullptr;
    Body* BuilderBody = nullptr;
    SendOptions* BuilderOptions = nullptr;
};

struct AsyncOp final
{
    ULONG Magic = detail::HighAsyncOpMagic;
    ::wknet::session::AsyncOperation* Engine = nullptr;
    // Non-null when this op owns a library-managed Session from a session-less entry point.
    Session* OwnedSession = nullptr;
};

struct Headers final
{
    ULONG Magic = detail::HighHeadersMagic;
    detail::StoredHeader* Items = nullptr;
    SIZE_T Count = 0;
    SIZE_T Capacity = 0;
};

struct Body final
{
    ULONG Magic = detail::HighBodyMagic;
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
    detail::StoredHeader* Trailers = nullptr;
    SIZE_T TrailerCount = 0;
    SIZE_T TrailerCapacity = 0;
};

struct Cache final
{
    ULONG Magic = detail::HighCacheMagic;
    ::wknet::session::HttpCacheHandle Engine = nullptr;
};

struct CertificateStore final
{
    ULONG Magic = detail::HighCertificateStoreMagic;
    ::wknet::tls::CertificateStore* Engine = nullptr;
    CertificateRevocationProviderCallback RevocationProvider = nullptr;
    void* RevocationProviderContext = nullptr;
    ::wknet::tls::CertificateTrustAnchor* TrustAnchors = nullptr;
    SIZE_T TrustAnchorCount = 0;
    SIZE_T TrustAnchorCapacity = 0;
    ::wknet::tls::CertificateAuthorityBundle* AuthorityBundles = nullptr;
    SIZE_T AuthorityBundleCount = 0;
    SIZE_T AuthorityBundleCapacity = 0;
    UCHAR** OwnedAuthorityBundleData = nullptr;
    SIZE_T OwnedAuthorityBundleCapacity = 0;
    ::wknet::tls::CertificatePin* Pins = nullptr;
    SIZE_T PinCount = 0;
    SIZE_T PinCapacity = 0;
    ::wknet::tls::CertificateRevocationEntry* RevocationEntries = nullptr;
    SIZE_T RevocationEntryCount = 0;
    SIZE_T RevocationEntryCapacity = 0;
    ::wknet::tls::CertificateStoreOptions EngineOptions = {};
};

namespace detail
{
    inline ::wknet::session::Session* ToApiSession(Session* s) noexcept
    {
        if (s == nullptr || s->Magic != HighSessionMagic || s->Closed != 0) {
            return nullptr;
        }
        return s->Engine;
    }

    inline ::wknet::session::Session* ToApiSession(Request* request) noexcept
    {
        return request == nullptr ? nullptr : ToApiSession(request->Parent);
    }

    inline ::wknet::session::Request* ToApiRequest(Request* r) noexcept
    {
        UNREFERENCED_PARAMETER(r);
        return nullptr;
    }

    inline ::wknet::session::Response* ToApiResponse(Response* r) noexcept
    {
        return reinterpret_cast<::wknet::session::Response*>(r);
    }

    inline const ::wknet::session::Response* ToApiResponseConst(const Response* r) noexcept
    {
        return reinterpret_cast<const ::wknet::session::Response*>(r);
    }

    inline ::wknet::session::WebSocket* ToApiWebSocket(wknet::websocket::WebSocket* ws) noexcept
    {
        return reinterpret_cast<::wknet::session::WebSocket*>(ws);
    }

    inline ::wknet::session::AsyncOperation* ToApiAsyncOp(AsyncOp* op) noexcept
    {
        if (op == nullptr || op->Magic != HighAsyncOpMagic) {
            return nullptr;
        }
        return op->Engine;
    }

    inline ::wknet::session::HttpCache* ToApiCache(Cache* cache) noexcept
    {
        if (cache == nullptr || cache->Magic != HighCacheMagic) {
            return nullptr;
        }
        return cache->Engine;
    }

    inline ::wknet::tls::CertificateStore* ToInternalCertificateStore(
        const CertificateStore* store) noexcept
    {
        if (store == nullptr ||
            store->Magic != HighCertificateStoreMagic ||
            store->Engine == nullptr) {
            return nullptr;
        }
        return store->Engine;
    }

    inline const ::wknet::session::HttpCache* ToApiCacheConst(const Cache* cache) noexcept
    {
        if (cache == nullptr || cache->Magic != HighCacheMagic) {
            return nullptr;
        }
        return cache->Engine;
    }

    inline Response* FromApiResponse(::wknet::session::Response* r) noexcept
    {
        return reinterpret_cast<Response*>(r);
    }

    inline wknet::websocket::WebSocket* FromApiWebSocket(::wknet::session::WebSocket* ws) noexcept
    {
        return reinterpret_cast<wknet::websocket::WebSocket*>(ws);
    }

    // Wraps an engine async op. On failure returns nullptr and does NOT release `op`
    // (caller must AsyncRelease the engine op). ownedSession may be null.
    _Ret_maybenull_
    inline AsyncOp* WrapAsyncOp(
        ::wknet::session::AsyncOperation* op,
        Session* ownedSession) noexcept
    {
        if (op == nullptr) {
            return nullptr;
        }
        auto* wrapper = ::wknet::AllocateNonPagedObject<AsyncOp>();
        if (wrapper == nullptr) {
            return nullptr;
        }
        wrapper->Magic = HighAsyncOpMagic;
        wrapper->Engine = op;
        wrapper->OwnedSession = ownedSession;
        return wrapper;
    }

    inline AsyncOp* FromApiAsyncOp(::wknet::session::AsyncOperation* op) noexcept
    {
        return WrapAsyncOp(op, nullptr);
    }

    inline Session* FromApiSession(::wknet::session::Session* s) noexcept
    {
        UNREFERENCED_PARAMETER(s);
        return nullptr;
    }

    inline Request* FromApiRequest(::wknet::session::Request* r) noexcept
    {
        UNREFERENCED_PARAMETER(r);
        return nullptr;
    }

    inline bool IsValidSession(const Session* session) noexcept
    {
        return session != nullptr &&
            session->Magic == HighSessionMagic &&
            session->Closed == 0 &&
            session->Engine != nullptr;
    }

    inline bool IsValidRequest(const Request* request) noexcept
    {
        return request != nullptr &&
            request->Magic == HighRequestMagic &&
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
        if (session == nullptr || session->Magic != HighSessionMagic) {
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
            ::wknet::session::SessionClose(session->Engine);
            session->Engine = nullptr;
        }
        if (session->Wsk != nullptr) {
            ::wknet::net::WskClientClose(session->Wsk);
            session->Wsk = nullptr;
        }
        HeadersRelease(session->DefaultHeaders);
        session->DefaultHeaders = nullptr;
        ::wknet::session::CookieJarDestroy(&session->CookieJar);
        if (session->AuthHeaderValue != nullptr) {
            RtlSecureZeroMemory(session->AuthHeaderValue, session->AuthHeaderValueLength);
            ::wknet::FreeNonPagedArray(session->AuthHeaderValue);
            session->AuthHeaderValue = nullptr;
            session->AuthHeaderValueLength = 0;
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

    inline ::wknet::session::PoolType ToApiPoolType(PoolType t) noexcept
    {
        return t == PoolType::Paged ? ::wknet::session::PoolType::Paged : ::wknet::session::PoolType::NonPaged;
    }

    inline ::wknet::session::TlsVersion ToApiTlsVersion(TlsVersion v) noexcept
    {
        return v == TlsVersion::Tls13 ? ::wknet::session::TlsVersion::Tls13 : ::wknet::session::TlsVersion::Tls12;
    }

    inline ::wknet::session::CertificatePolicy ToApiCertPolicy(CertPolicy p) noexcept
    {
        return p == CertPolicy::NoVerify ? ::wknet::session::CertificatePolicy::NoVerify : ::wknet::session::CertificatePolicy::Verify;
    }

    inline ::wknet::session::AddressFamily ToApiAddressFamily(AddressFamily f) noexcept
    {
        switch (f) {
        case AddressFamily::Ipv4: return ::wknet::session::AddressFamily::Ipv4;
        case AddressFamily::Ipv6: return ::wknet::session::AddressFamily::Ipv6;
        case AddressFamily::Any:
        default: return ::wknet::session::AddressFamily::Any;
        }
    }

    inline ::wknet::session::ConnectionPolicy ToApiConnPolicy(ConnPolicy p) noexcept
    {
        switch (p) {
        case ConnPolicy::ForceNew: return ::wknet::session::ConnectionPolicy::ForceNew;
        case ConnPolicy::NoPool: return ::wknet::session::ConnectionPolicy::NoPool;
        case ConnPolicy::ReuseOrCreate:
        default: return ::wknet::session::ConnectionPolicy::ReuseOrCreate;
        }
    }

    inline ::wknet::session::HttpMethod ToApiMethod(Method m) noexcept
    {
        switch (m) {
        case Method::Post: return ::wknet::session::HttpMethod::Post;
        case Method::Put: return ::wknet::session::HttpMethod::Put;
        case Method::Patch: return ::wknet::session::HttpMethod::Patch;
        case Method::Delete: return ::wknet::session::HttpMethod::Delete;
        case Method::Head: return ::wknet::session::HttpMethod::Head;
        case Method::Options: return ::wknet::session::HttpMethod::Options;
        case Method::Connect: return ::wknet::session::HttpMethod::Connect;
        case Method::Trace: return ::wknet::session::HttpMethod::Trace;
        case Method::Get:
        default: return ::wknet::session::HttpMethod::Get;
        }
    }

    inline wknet::websocket::MsgType FromApiWsMsgType(::wknet::session::WebSocketMessageType t) noexcept
    {
        switch (t) {
        case ::wknet::session::WebSocketMessageType::Text: return wknet::websocket::MsgType::Text;
        case ::wknet::session::WebSocketMessageType::Close: return wknet::websocket::MsgType::Close;
        case ::wknet::session::WebSocketMessageType::Continuation: return wknet::websocket::MsgType::Continuation;
        case ::wknet::session::WebSocketMessageType::Ping: return wknet::websocket::MsgType::Ping;
        case ::wknet::session::WebSocketMessageType::Pong: return wknet::websocket::MsgType::Pong;
        case ::wknet::session::WebSocketMessageType::Binary:
        default: return wknet::websocket::MsgType::Binary;
        }
    }

    inline ::wknet::session::WebSocketTransportMode ToApiWebSocketTransportMode(
        WebSocketTransportMode mode) noexcept
    {
        switch (mode) {
        case WebSocketTransportMode::Http11Only:
            return ::wknet::session::WebSocketTransportMode::Http11Only;
        case WebSocketTransportMode::Auto:
            return ::wknet::session::WebSocketTransportMode::Auto;
        case WebSocketTransportMode::Http2Required:
            return ::wknet::session::WebSocketTransportMode::Http2Required;
        case WebSocketTransportMode::LegacyBoolean:
        default:
            return ::wknet::session::WebSocketTransportMode::LegacyBoolean;
        }
    }

    inline ::wknet::session::WebSocketMessageType ToApiWsMsgType(wknet::websocket::MsgType t) noexcept
    {
        switch (t) {
        case wknet::websocket::MsgType::Text: return ::wknet::session::WebSocketMessageType::Text;
        case wknet::websocket::MsgType::Close: return ::wknet::session::WebSocketMessageType::Close;
        case wknet::websocket::MsgType::Continuation: return ::wknet::session::WebSocketMessageType::Continuation;
        case wknet::websocket::MsgType::Ping: return ::wknet::session::WebSocketMessageType::Ping;
        case wknet::websocket::MsgType::Pong: return ::wknet::session::WebSocketMessageType::Pong;
        case wknet::websocket::MsgType::Binary:
        default: return ::wknet::session::WebSocketMessageType::Binary;
        }
    }

    inline ::wknet::session::RequestBodyPartKind ToApiBodyPartKind(BodyPartKind k) noexcept
    {
        switch (k) {
        case BodyPartKind::FileBytes: return ::wknet::session::RequestBodyPartKind::FileBytes;
        case BodyPartKind::FilePath: return ::wknet::session::RequestBodyPartKind::FilePath;
        case BodyPartKind::Field:
        default: return ::wknet::session::RequestBodyPartKind::Field;
        }
    }

    inline ::wknet::session::RequestBodyMode ToApiRequestBodyMode(RequestBodyMode mode) noexcept
    {
        return mode == RequestBodyMode::Chunked ?
            ::wknet::session::RequestBodyMode::Chunked :
            ::wknet::session::RequestBodyMode::ContentLength;
    }

    inline ::wknet::session::Http2CleartextMode ToApiHttp2CleartextMode(
        Http2CleartextMode mode) noexcept
    {
        switch (mode) {
        case Http2CleartextMode::PriorKnowledge:
            return ::wknet::session::Http2CleartextMode::PriorKnowledge;
        case Http2CleartextMode::Upgrade:
            return ::wknet::session::Http2CleartextMode::Upgrade;
        case Http2CleartextMode::Disabled:
        default:
            return ::wknet::session::Http2CleartextMode::Disabled;
        }
    }

    inline ::wknet::session::HttpCacheMode ToApiCacheMode(CacheMode mode) noexcept
    {
        return mode == CacheMode::Shared ?
            ::wknet::session::HttpCacheMode::Shared :
            ::wknet::session::HttpCacheMode::Private;
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

    inline void FillApiTlsOptions(const TlsConfig& src, ::wknet::session::TlsOptions& dst) noexcept
    {
        dst.MinVersion = ToApiTlsVersion(src.MinVersion);
        dst.MaxVersion = ToApiTlsVersion(src.MaxVersion);
        dst.CertificatePolicy = ToApiCertPolicy(src.Certificate);
        dst.CertificateStore = ToInternalCertificateStore(src.Store);
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

    inline const ::wknet::codec::DecodeMaterials* ToApiCodingMaterials(
        const CodingDecodeMaterials* materials) noexcept
    {
        return reinterpret_cast<const ::wknet::codec::DecodeMaterials*>(materials);
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

    inline ::wknet::session::WebSocketHandshakeChallengeCallback ToApiHandshakeChallengeCallback(
        wknet::websocket::HandshakeChallengeCallback callback) noexcept
    {
        return reinterpret_cast<::wknet::session::WebSocketHandshakeChallengeCallback>(callback);
    }

    void FillApiSendOptions(
        const SendOptions& src,
        ::wknet::session::HttpSendOptions& dst) noexcept;

    _Must_inspect_result_
    NTSTATUS PrepareHttpRequest(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const Headers* headers,
        const Body* body,
        const SendOptions* options,
        ::wknet::session::RequestHandle* request) noexcept;
}
}
