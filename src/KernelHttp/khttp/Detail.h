#pragma once

#include "../api/KernelHttpApi.h"
#include "Types.h"

namespace KernelHttp
{
namespace khttp
{
namespace detail
{
    inline api::KhSession* ToApiSession(Session* s) noexcept
    {
        return reinterpret_cast<api::KhSession*>(s);
    }

    inline api::KhRequest* ToApiRequest(Request* r) noexcept
    {
        return reinterpret_cast<api::KhRequest*>(r);
    }

    inline api::KhResponse* ToApiResponse(Response* r) noexcept
    {
        return reinterpret_cast<api::KhResponse*>(r);
    }

    inline const api::KhResponse* ToApiResponseConst(const Response* r) noexcept
    {
        return reinterpret_cast<const api::KhResponse*>(r);
    }

    inline api::KhWebSocket* ToApiWebSocket(WebSocket* ws) noexcept
    {
        return reinterpret_cast<api::KhWebSocket*>(ws);
    }

    inline api::KhAsyncOperation* ToApiAsyncOp(AsyncOp* op) noexcept
    {
        return reinterpret_cast<api::KhAsyncOperation*>(op);
    }

    inline Response* FromApiResponse(api::KhResponse* r) noexcept
    {
        return reinterpret_cast<Response*>(r);
    }

    inline WebSocket* FromApiWebSocket(api::KhWebSocket* ws) noexcept
    {
        return reinterpret_cast<WebSocket*>(ws);
    }

    inline AsyncOp* FromApiAsyncOp(api::KhAsyncOperation* op) noexcept
    {
        return reinterpret_cast<AsyncOp*>(op);
    }

    inline Session* FromApiSession(api::KhSession* s) noexcept
    {
        return reinterpret_cast<Session*>(s);
    }

    inline Request* FromApiRequest(api::KhRequest* r) noexcept
    {
        return reinterpret_cast<Request*>(r);
    }

    inline api::KhPoolType ToApiPoolType(PoolType t) noexcept
    {
        return t == PoolType::Paged ? api::KhPoolType::Paged : api::KhPoolType::NonPaged;
    }

    inline api::KhTlsVersion ToApiTlsVersion(TlsVersion v) noexcept
    {
        return v == TlsVersion::Tls13 ? api::KhTlsVersion::Tls13 : api::KhTlsVersion::Tls12;
    }

    inline api::KhCertificatePolicy ToApiCertPolicy(CertPolicy p) noexcept
    {
        return p == CertPolicy::NoVerify ? api::KhCertificatePolicy::NoVerify : api::KhCertificatePolicy::Verify;
    }

    inline api::KhAddressFamily ToApiAddressFamily(AddressFamily f) noexcept
    {
        switch (f) {
        case AddressFamily::Ipv4: return api::KhAddressFamily::Ipv4;
        case AddressFamily::Ipv6: return api::KhAddressFamily::Ipv6;
        case AddressFamily::Any:
        default: return api::KhAddressFamily::Any;
        }
    }

    inline api::KhConnectionPolicy ToApiConnPolicy(ConnPolicy p) noexcept
    {
        switch (p) {
        case ConnPolicy::ForceNew: return api::KhConnectionPolicy::ForceNew;
        case ConnPolicy::NoPool: return api::KhConnectionPolicy::NoPool;
        case ConnPolicy::ReuseOrCreate:
        default: return api::KhConnectionPolicy::ReuseOrCreate;
        }
    }

    inline api::KhHttpMethod ToApiMethod(Method m) noexcept
    {
        switch (m) {
        case Method::Post: return api::KhHttpMethod::Post;
        case Method::Put: return api::KhHttpMethod::Put;
        case Method::Patch: return api::KhHttpMethod::Patch;
        case Method::Delete: return api::KhHttpMethod::Delete;
        case Method::Head: return api::KhHttpMethod::Head;
        case Method::Options: return api::KhHttpMethod::Options;
        case Method::Get:
        default: return api::KhHttpMethod::Get;
        }
    }

    inline WsMsgType FromApiWsMsgType(api::KhWebSocketMessageType t) noexcept
    {
        switch (t) {
        case api::KhWebSocketMessageType::Text: return WsMsgType::Text;
        case api::KhWebSocketMessageType::Close: return WsMsgType::Close;
        case api::KhWebSocketMessageType::Binary:
        default: return WsMsgType::Binary;
        }
    }

    inline api::KhWebSocketMessageType ToApiWsMsgType(WsMsgType t) noexcept
    {
        switch (t) {
        case WsMsgType::Text: return api::KhWebSocketMessageType::Text;
        case WsMsgType::Close: return api::KhWebSocketMessageType::Close;
        case WsMsgType::Binary:
        default: return api::KhWebSocketMessageType::Binary;
        }
    }

    inline api::KhRequestBodyPartKind ToApiBodyPartKind(BodyPartKind k) noexcept
    {
        switch (k) {
        case BodyPartKind::FileBytes: return api::KhRequestBodyPartKind::FileBytes;
        case BodyPartKind::FilePath: return api::KhRequestBodyPartKind::FilePath;
        case BodyPartKind::Field:
        default: return api::KhRequestBodyPartKind::Field;
        }
    }

    inline void FillApiTlsOptions(const TlsConfig& src, api::KhTlsOptions& dst) noexcept
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
