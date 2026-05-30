#pragma once

#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/khttp/Types.h>

namespace KernelHttp
{
namespace khttp
{
namespace detail
{
    inline engine::KhSession* ToApiSession(Session* s) noexcept
    {
        return reinterpret_cast<engine::KhSession*>(s);
    }

    inline engine::KhRequest* ToApiRequest(Request* r) noexcept
    {
        return reinterpret_cast<engine::KhRequest*>(r);
    }

    inline engine::KhResponse* ToApiResponse(Response* r) noexcept
    {
        return reinterpret_cast<engine::KhResponse*>(r);
    }

    inline const engine::KhResponse* ToApiResponseConst(const Response* r) noexcept
    {
        return reinterpret_cast<const engine::KhResponse*>(r);
    }

    inline engine::KhWebSocket* ToApiWebSocket(WebSocket* ws) noexcept
    {
        return reinterpret_cast<engine::KhWebSocket*>(ws);
    }

    inline engine::KhAsyncOperation* ToApiAsyncOp(AsyncOp* op) noexcept
    {
        return reinterpret_cast<engine::KhAsyncOperation*>(op);
    }

    inline Response* FromApiResponse(engine::KhResponse* r) noexcept
    {
        return reinterpret_cast<Response*>(r);
    }

    inline WebSocket* FromApiWebSocket(engine::KhWebSocket* ws) noexcept
    {
        return reinterpret_cast<WebSocket*>(ws);
    }

    inline AsyncOp* FromApiAsyncOp(engine::KhAsyncOperation* op) noexcept
    {
        return reinterpret_cast<AsyncOp*>(op);
    }

    inline Session* FromApiSession(engine::KhSession* s) noexcept
    {
        return reinterpret_cast<Session*>(s);
    }

    inline Request* FromApiRequest(engine::KhRequest* r) noexcept
    {
        return reinterpret_cast<Request*>(r);
    }

    inline engine::KhPoolType ToApiPoolType(PoolType t) noexcept
    {
        return t == PoolType::Paged ? engine::KhPoolType::Paged : engine::KhPoolType::NonPaged;
    }

    inline engine::KhTlsVersion ToApiTlsVersion(TlsVersion v) noexcept
    {
        return v == TlsVersion::Tls13 ? engine::KhTlsVersion::Tls13 : engine::KhTlsVersion::Tls12;
    }

    inline engine::KhCertificatePolicy ToApiCertPolicy(CertPolicy p) noexcept
    {
        return p == CertPolicy::NoVerify ? engine::KhCertificatePolicy::NoVerify : engine::KhCertificatePolicy::Verify;
    }

    inline engine::KhAddressFamily ToApiAddressFamily(AddressFamily f) noexcept
    {
        switch (f) {
        case AddressFamily::Ipv4: return engine::KhAddressFamily::Ipv4;
        case AddressFamily::Ipv6: return engine::KhAddressFamily::Ipv6;
        case AddressFamily::Any:
        default: return engine::KhAddressFamily::Any;
        }
    }

    inline engine::KhConnectionPolicy ToApiConnPolicy(ConnPolicy p) noexcept
    {
        switch (p) {
        case ConnPolicy::ForceNew: return engine::KhConnectionPolicy::ForceNew;
        case ConnPolicy::NoPool: return engine::KhConnectionPolicy::NoPool;
        case ConnPolicy::ReuseOrCreate:
        default: return engine::KhConnectionPolicy::ReuseOrCreate;
        }
    }

    inline engine::KhHttpMethod ToApiMethod(Method m) noexcept
    {
        switch (m) {
        case Method::Post: return engine::KhHttpMethod::Post;
        case Method::Put: return engine::KhHttpMethod::Put;
        case Method::Patch: return engine::KhHttpMethod::Patch;
        case Method::Delete: return engine::KhHttpMethod::Delete;
        case Method::Head: return engine::KhHttpMethod::Head;
        case Method::Options: return engine::KhHttpMethod::Options;
        case Method::Get:
        default: return engine::KhHttpMethod::Get;
        }
    }

    inline WsMsgType FromApiWsMsgType(engine::KhWebSocketMessageType t) noexcept
    {
        switch (t) {
        case engine::KhWebSocketMessageType::Text: return WsMsgType::Text;
        case engine::KhWebSocketMessageType::Close: return WsMsgType::Close;
        case engine::KhWebSocketMessageType::Binary:
        default: return WsMsgType::Binary;
        }
    }

    inline engine::KhWebSocketMessageType ToApiWsMsgType(WsMsgType t) noexcept
    {
        switch (t) {
        case WsMsgType::Text: return engine::KhWebSocketMessageType::Text;
        case WsMsgType::Close: return engine::KhWebSocketMessageType::Close;
        case WsMsgType::Binary:
        default: return engine::KhWebSocketMessageType::Binary;
        }
    }

    inline engine::KhRequestBodyPartKind ToApiBodyPartKind(BodyPartKind k) noexcept
    {
        switch (k) {
        case BodyPartKind::FileBytes: return engine::KhRequestBodyPartKind::FileBytes;
        case BodyPartKind::FilePath: return engine::KhRequestBodyPartKind::FilePath;
        case BodyPartKind::Field:
        default: return engine::KhRequestBodyPartKind::Field;
        }
    }

    inline void FillApiTlsOptions(const TlsConfig& src, engine::KhTlsOptions& dst) noexcept
    {
        dst.MinVersion = ToApiTlsVersion(src.MinVersion);
        dst.MaxVersion = ToApiTlsVersion(src.MaxVersion);
        dst.CertificatePolicy = ToApiCertPolicy(src.Certificate);
        dst.CertificateStore = src.Store;
        dst.ServerName = src.ServerName;
        dst.ServerNameLength = src.ServerNameLength;
        dst.Alpn = src.Alpn;
        dst.AlpnLength = src.AlpnLength;
        dst.HandshakeReceiveTimeoutMilliseconds = src.HandshakeTimeoutMs;
    }
}
}
}
