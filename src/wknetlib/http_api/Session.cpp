#include <wknet/http/Session.h>
#include "session/detail/HttpHandles.h"
#include "session/Engine.h"

namespace wknet::http {
namespace
{
    void FillApiSessionOptions(
        const SessionConfig* config,
        ::wknet::session::SessionOptions& apiOptions) noexcept
    {
        apiOptions.ResponsePoolType = detail::ToApiPoolType(config != nullptr ? config->ResponsePool : PoolType::NonPaged);
        apiOptions.RequestBufferBytes = config != nullptr ? config->RequestBufferBytes : DefaultRequestBufferBytes;
        apiOptions.MaxResponseBytes = config != nullptr ? config->MaxResponseBytes : DefaultMaxResponseBytes;
        apiOptions.MaxResponseHeaders =
            config != nullptr ? config->MaxResponseHeaders : DefaultMaxResponseHeaders;
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

        const Http3Config http3 = config != nullptr ? config->Http3 : Http3Config{};
        apiOptions.Http3.Mode = static_cast<::wknet::session::Http3ConnectMode>(http3.Mode);
        apiOptions.Http3.Race = static_cast<::wknet::session::Http3RaceMode>(http3.Race);
        apiOptions.Http3.RaceWindowMilliseconds = http3.RaceWindowMs;
        apiOptions.Http3.QuicProbeTimeoutMilliseconds = http3.QuicProbeTimeoutMs;
        apiOptions.Http3.AltSvcMaxEntries = http3.AltSvcMaxEntries;
        apiOptions.Http3.AltSvcMaxAgeSeconds = http3.AltSvcMaxAgeSec;

        TlsConfig tls = {};
        if (config != nullptr) {
            tls = config->Tls;
            apiOptions.Proxy.Enabled = config->Proxy.Enabled;
            apiOptions.Proxy.Host = config->Proxy.Host;
            apiOptions.Proxy.HostLength = config->Proxy.HostLength;
            apiOptions.Proxy.Port = config->Proxy.Port;
            apiOptions.Proxy.Family = detail::ToApiAddressFamily(config->Proxy.Family);
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
    ResponseHeaderTimeoutMs(0),
    BodyReadTimeoutMs(0),
    BodyIdleTimeoutMs(0),
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

    ::wknet::session::SessionOptions apiOptions = {};
    FillApiSessionOptions(config, apiOptions);
    ::wknet::session::Http3ConnectMode effectiveHttp3Mode = ::wknet::session::Http3ConnectMode::Disabled;
    NTSTATUS status = ::wknet::session::ResolveHttp3ConnectMode(
        apiOptions.Http3, apiOptions.Tls, apiOptions.Proxy.Enabled, nullptr, true, false, &effectiveHttp3Mode);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    auto* highSession = ::wknet::AllocateNonPagedObject<Session>();
    if (highSession == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ::wknet::net::WskClientCreate(&highSession->Wsk);
    if (!NT_SUCCESS(status)) {
        detail::FreeClosedSession(highSession);
        return status;
    }

    status = ::wknet::net::WskClientInitialize(highSession->Wsk);
    if (!NT_SUCCESS(status)) {
        detail::FreeClosedSession(highSession);
        return status;
    }

    status = ::wknet::session::SessionCreate(highSession->Wsk, &apiOptions, &highSession->Engine);
    if (!NT_SUCCESS(status)) {
        detail::FreeClosedSession(highSession);
        return status;
    }

    *session = highSession;
    return STATUS_SUCCESS;
}

void SessionClose(Session* session) noexcept
{
    if (session == nullptr || session->Magic != detail::HighSessionMagic) {
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
        ::wknet::session::SessionClose(session->Engine);
        session->Engine = nullptr;
    }
    if (session->Wsk != nullptr) {
        ::wknet::net::WskClientClose(session->Wsk);
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
