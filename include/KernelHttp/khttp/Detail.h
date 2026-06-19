#pragma once

#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/khttp/Types.h>

namespace khttp
{
namespace detail
{
    inline ::KernelHttp::engine::KhSession* ToApiSession(Session* s) noexcept
    {
        return reinterpret_cast<::KernelHttp::engine::KhSession*>(s);
    }

    inline ::KernelHttp::engine::KhRequest* ToApiRequest(Request* r) noexcept
    {
        return reinterpret_cast<::KernelHttp::engine::KhRequest*>(r);
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
        return reinterpret_cast<Session*>(s);
    }

    inline Request* FromApiRequest(::KernelHttp::engine::KhRequest* r) noexcept
    {
        return reinterpret_cast<Request*>(r);
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
}
}
