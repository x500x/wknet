#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace khttp
{
TlsConfig DefaultTlsConfig() noexcept
{
    return TlsConfig{};
}

SessionConfig DefaultSessionConfig() noexcept
{
    return SessionConfig{};
}

SendOptions DefaultSendOptions() noexcept
{
    return SendOptions{};
}

NTSTATUS SessionCreate(
    ::KernelHttp::net::WskClient* wskClient,
    const SessionConfig* config,
    Session** out) noexcept
{
    if (out != nullptr) {
        *out = nullptr;
    }

    ::KernelHttp::engine::KhSessionOptions apiOptions = {};
    apiOptions.ResponsePoolType = detail::ToApiPoolType(config != nullptr ? config->ResponsePool : PoolType::NonPaged);
    apiOptions.RequestBufferBytes = config != nullptr ? config->RequestBufferBytes : DefaultRequestBufferBytes;
    apiOptions.MaxResponseBytes = config != nullptr ? config->MaxResponseBytes : DefaultMaxResponseBytes;
    apiOptions.ConnectionPoolCapacity = config != nullptr ? config->PoolCapacity : DefaultPoolCapacity;
    apiOptions.MaxConnectionsPerHost = config != nullptr ? config->MaxConnsPerHost : DefaultMaxConnsPerHost;
    apiOptions.IdleTimeoutMilliseconds = config != nullptr ? config->IdleTimeoutMs : DefaultIdleTimeoutMs;

    if (config != nullptr) {
        detail::FillApiTlsOptions(config->Tls, apiOptions.Tls);
        apiOptions.Proxy.Enabled = config->Proxy.Enabled;
        apiOptions.Proxy.Address = config->Proxy.Address;
        apiOptions.Proxy.Authority = config->Proxy.Authority;
        apiOptions.Proxy.AuthorityLength = config->Proxy.AuthorityLength;
        apiOptions.Proxy.AuthHeader = config->Proxy.AuthHeader;
        apiOptions.Proxy.AuthHeaderLength = config->Proxy.AuthHeaderLength;
    }
    else {
        TlsConfig defaultTls = {};
        detail::FillApiTlsOptions(defaultTls, apiOptions.Tls);
    }

    ::KernelHttp::engine::KH_SESSION apiSession = nullptr;
    NTSTATUS status = ::KernelHttp::engine::KhSessionCreate(wskClient, &apiOptions, &apiSession);
    if (NT_SUCCESS(status) && out != nullptr) {
        *out = detail::FromApiSession(apiSession);
    }
    return status;
}

void SessionClose(Session* session) noexcept
{
    ::KernelHttp::engine::KhSessionClose(detail::ToApiSession(session));
}
}

namespace kws
{
ConnectConfig DefaultConnectConfig() noexcept
{
    return ConnectConfig{};
}
}
