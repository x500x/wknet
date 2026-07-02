#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace khttp
{
namespace
{
    void FillApiSessionOptions(
        const SessionConfig* config,
        ::KernelHttp::engine::KhSessionOptions& apiOptions) noexcept
    {
        apiOptions.ResponsePoolType = detail::ToApiPoolType(config != nullptr ? config->ResponsePool : PoolType::NonPaged);
        apiOptions.RequestBufferBytes = config != nullptr ? config->RequestBufferBytes : DefaultRequestBufferBytes;
        apiOptions.MaxResponseBytes = config != nullptr ? config->MaxResponseBytes : DefaultMaxResponseBytes;
        apiOptions.ConnectionPoolCapacity = config != nullptr ? config->PoolCapacity : DefaultPoolCapacity;
        apiOptions.MaxConnectionsPerHost = config != nullptr ? config->MaxConnsPerHost : DefaultMaxConnsPerHost;
        apiOptions.IdleTimeoutMilliseconds = config != nullptr ? config->IdleTimeoutMs : DefaultIdleTimeoutMs;

        TlsConfig tls = {};
        if (config != nullptr) {
            tls = config->Tls;
            apiOptions.Proxy.Enabled = config->Proxy.Enabled;
            apiOptions.Proxy.Address = config->Proxy.Address;
            apiOptions.Proxy.Authority = config->Proxy.Authority;
            apiOptions.Proxy.AuthorityLength = config->Proxy.AuthorityLength;
            apiOptions.Proxy.AuthHeader = config->Proxy.AuthHeader;
            apiOptions.Proxy.AuthHeaderLength = config->Proxy.AuthHeaderLength;
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
    Http2CleartextMode(::khttp::Http2CleartextMode::Disabled)
#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

    auto* highSession = ::KernelHttp::AllocateNonPagedObject<Session>();
    if (highSession == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    highSession->Wsk = ::KernelHttp::AllocateNonPagedObject<::KernelHttp::net::WskClient>();
    if (highSession->Wsk == nullptr) {
        detail::FreeClosedSession(highSession);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = highSession->Wsk->Initialize();
    if (!NT_SUCCESS(status)) {
        detail::FreeClosedSession(highSession);
        return status;
    }

    ::KernelHttp::engine::KhSessionOptions apiOptions = {};
    FillApiSessionOptions(config, apiOptions);

    status = ::KernelHttp::engine::KhSessionCreate(highSession->Wsk, &apiOptions, &highSession->Engine);
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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
        ::KernelHttp::engine::KhSessionClose(session->Engine);
        session->Engine = nullptr;
    }
    if (session->Wsk != nullptr) {
        session->Wsk->Shutdown();
        ::KernelHttp::FreeNonPagedObject(session->Wsk);
        session->Wsk = nullptr;
    }

    if (detail::ReleaseSessionRef(session)) {
        detail::FreeClosedSession(session);
    }
}
}

namespace kws
{
ConnectConfig DefaultConnectConfig() noexcept
{
    return ConnectConfig{};
}
}
