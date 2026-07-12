#include <wknet/http/Session.h>
#include "Detail.h"
#include "session/Engine.h"

namespace wknet::http {
namespace
{
    void FillApiSessionOptions(
        const SessionConfig* config,
        ::wknet::session::KhSessionOptions& apiOptions) noexcept
    {
        apiOptions.ResponsePoolType = detail::ToApiPoolType(config != nullptr ? config->ResponsePool : PoolType::NonPaged);
        apiOptions.RequestBufferBytes = config != nullptr ? config->RequestBufferBytes : DefaultRequestBufferBytes;
        apiOptions.MaxResponseBytes = config != nullptr ? config->MaxResponseBytes : DefaultMaxResponseBytes;
        apiOptions.ConnectionPoolCapacity = config != nullptr ? config->PoolCapacity : DefaultPoolCapacity;
        apiOptions.MaxConnectionsPerHost = config != nullptr ? config->MaxConnsPerHost : DefaultMaxConnsPerHost;
        apiOptions.IdleTimeoutMilliseconds = config != nullptr ? config->IdleTimeoutMs : DefaultIdleTimeoutMs;
        apiOptions.EnableHttp11Pipeline = config != nullptr ? config->EnableHttp11Pipeline : false;
        apiOptions.Http11PipelineMaxDepth =
            config != nullptr ? config->Http11PipelineMaxDepth : DefaultHttp11PipelineMaxDepth;
        apiOptions.Http11PipelineMethodMask =
            config != nullptr ? config->Http11PipelineMethodMask : DefaultHttp11PipelineMethodMask;
        apiOptions.Http2KeepAlive.Enabled = config != nullptr ? config->Http2KeepAlive.Enabled : false;
        apiOptions.Http2KeepAlive.IdleMilliseconds =
            config != nullptr ? config->Http2KeepAlive.IdleMs : DefaultHttp2KeepAliveIdleMs;
        apiOptions.Http2KeepAlive.IntervalMilliseconds =
            config != nullptr ? config->Http2KeepAlive.IntervalMs : DefaultHttp2KeepAliveIntervalMs;
        apiOptions.Http2KeepAlive.AckTimeoutMilliseconds =
            config != nullptr ? config->Http2KeepAlive.AckTimeoutMs : DefaultHttp2KeepAliveAckTimeoutMs;

        TlsConfig tls = {};
        if (config != nullptr) {
            tls = config->Tls;
            apiOptions.Proxy.Enabled = config->Proxy.Enabled;
            apiOptions.Proxy.Address = config->Proxy.Address;
            apiOptions.Proxy.Authority = config->Proxy.Authority;
            apiOptions.Proxy.AuthorityLength = config->Proxy.AuthorityLength;
            apiOptions.Proxy.AuthHeader = config->Proxy.AuthHeader;
            apiOptions.Proxy.AuthHeaderLength = config->Proxy.AuthHeaderLength;
            apiOptions.Cache = detail::ToApiCache(config->Cache);
        }
        detail::FillApiTlsOptions(tls, apiOptions.Tls);
    }

}

TlsConfig DefaultTlsConfig() noexcept
{
    return TlsConfig{};
}

SessionConfig DefaultSessionConfig() noexcept
{
    return SessionConfig{};
}

SendOptions::SendOptions() noexcept :
    MaxResponseBytes(0),
    Flags(SendFlagNone),
    MaxRedirects(0),
    ExpectContinueTimeoutMs(0),
    OnHeader(nullptr),
    OnBody(nullptr),
    CallbackContext(nullptr),
    Tls(DefaultTlsConfig()),
    HasTlsOverride(false),
    ConnectionPolicy(ConnPolicy::ReuseOrCreate),
    Family(AddressFamily::Any),
    Http2CleartextMode(::wknet::http::Http2CleartextMode::Disabled),
    AcceptEncodingPreferences(nullptr),
    AcceptEncodingPreferenceCount(0),
    ContentCodingMaterials(nullptr),
    Http2Priority(nullptr),
    Cache(nullptr)
#if defined(WKNET_USER_MODE_TEST)
    ,
    OnComplete(nullptr),
    CompletionContext(nullptr)
#endif
{
}

SendOptions DefaultSendOptions() noexcept
{
    return SendOptions{};
}

AsyncOptions::AsyncOptions() noexcept :
    Send(DefaultSendOptions()),
    OnComplete(nullptr),
    CompletionContext(nullptr)
{
}

NTSTATUS SessionCreate(Session** session) noexcept
{
    return SessionCreate(nullptr, session);
}

NTSTATUS SessionCreate(const SessionConfig* config, Session** session) noexcept
{
    if (session != nullptr) {
        *session = nullptr;
    }
    if (session == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    auto* highSession = ::wknet::AllocateNonPagedObject<Session>();
    if (highSession == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    highSession->Wsk = ::wknet::AllocateNonPagedObject<::wknet::net::WskClient>();
    if (highSession->Wsk == nullptr) {
        detail::FreeClosedSession(highSession);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = highSession->Wsk->Initialize();
    if (!NT_SUCCESS(status)) {
        detail::FreeClosedSession(highSession);
        return status;
    }

    ::wknet::session::KhSessionOptions apiOptions = {};
    FillApiSessionOptions(config, apiOptions);

    status = ::wknet::session::KhSessionCreate(highSession->Wsk, &apiOptions, &highSession->Engine);
    if (!NT_SUCCESS(status)) {
        detail::FreeClosedSession(highSession);
        return status;
    }

    *session = highSession;
    return STATUS_SUCCESS;
}

void SessionClose(Session* session) noexcept
{
    if (session == nullptr || session->Magic != detail::KhHighSessionMagic) {
        return;
    }

#if defined(WKNET_USER_MODE_TEST)
    if (session->Closed != 0) {
        return;
    }
    session->Closed = 1;
#else
    if (InterlockedCompareExchange(&session->Closed, 1, 0) != 0) {
        return;
    }
#endif

    if (session->Engine != nullptr) {
        ::wknet::session::KhSessionClose(session->Engine);
        session->Engine = nullptr;
    }
    if (session->Wsk != nullptr) {
        session->Wsk->Shutdown();
        ::wknet::FreeNonPagedObject(session->Wsk);
        session->Wsk = nullptr;
    }

    if (detail::ReleaseSessionRef(session)) {
        detail::FreeClosedSession(session);
    }
}
}

namespace wknet::websocket {
ConnectConfig DefaultConnectConfig() noexcept
{
    ConnectConfig config = {};
    config.TransportMode = wknet::http::WebSocketTransportMode::Auto;
    return config;
}
}
