#include <wknet/http/Session.h>
#include <wknet/http/Headers.h>
#include "session/EngineUtils.h"
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

    (void)::wknet::session::CookieJarInitialize(&highSession->CookieJar);
#if !defined(WKNET_USER_MODE_TEST)
    KeInitializeMutex(&highSession->ConfigLock, 0);
    highSession->ConfigLockState = 2;
#endif
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

namespace {
    SIZE_T StrLen(const char* s) noexcept
    {
        if (s == nullptr) {
            return 0;
        }
        SIZE_T n = 0;
        while (s[n] != 0) {
            ++n;
        }
        return n;
    }

    void Base64Encode(
        const UCHAR* input,
        SIZE_T inputLength,
        char* output,
        SIZE_T outputCapacity,
        SIZE_T* outputLength) noexcept
    {
        static const char kTable[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if (outputLength != nullptr) {
            *outputLength = 0;
        }
        if (output == nullptr || outputCapacity == 0) {
            return;
        }
        SIZE_T out = 0;
        SIZE_T i = 0;
        while (i < inputLength) {
            const SIZE_T remain = inputLength - i;
            const ULONG b0 = input[i++];
            const ULONG b1 = remain > 1 ? input[i++] : 0;
            const ULONG b2 = remain > 2 ? input[i++] : 0;
            const ULONG triple = (b0 << 16) | (b1 << 8) | b2;
            if (out + 4 >= outputCapacity) {
                break;
            }
            output[out++] = kTable[(triple >> 18) & 63];
            output[out++] = kTable[(triple >> 12) & 63];
            output[out++] = remain > 1 ? kTable[(triple >> 6) & 63] : '=';
            output[out++] = remain > 2 ? kTable[triple & 63] : '=';
        }
        output[out] = 0;
        if (outputLength != nullptr) {
            *outputLength = out;
        }
    }
}

NTSTATUS SessionSetDefaultHeader(Session* session, const char* name, const char* value) noexcept
{
    return SessionSetDefaultHeaderEx(session, name, StrLen(name), value, StrLen(value));
}

NTSTATUS SessionSetDefaultHeaderEx(
    Session* session,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength) noexcept
{
    NTSTATUS status = ::wknet::session::CheckPassiveLevel();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!detail::IsValidSession(session) || name == nullptr || nameLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    detail::LockSessionConfig(session);
    if (session->DefaultHeaders == nullptr) {
        status = HeadersCreate(&session->DefaultHeaders);
        if (!NT_SUCCESS(status)) {
            detail::UnlockSessionConfig(session);
            return status;
        }
    }
    status = HeadersAddEx(session->DefaultHeaders, name, nameLength, value, valueLength);
    detail::UnlockSessionConfig(session);
    return status;
}

void SessionClearDefaultHeaders(Session* session) noexcept
{
    if (!detail::IsValidSession(session)) {
        return;
    }
    if (!NT_SUCCESS(::wknet::session::CheckPassiveLevel())) {
        return;
    }
    detail::LockSessionConfig(session);
    HeadersRelease(session->DefaultHeaders);
    session->DefaultHeaders = nullptr;
    detail::UnlockSessionConfig(session);
}

void SessionClearAuth(Session* session) noexcept
{
    if (session == nullptr || session->Magic != detail::HighSessionMagic) {
        return;
    }
    if (!NT_SUCCESS(::wknet::session::CheckPassiveLevel())) {
        return;
    }
    detail::LockSessionConfig(session);
    if (session->AuthHeaderValue != nullptr) {
        RtlSecureZeroMemory(session->AuthHeaderValue, session->AuthHeaderValueLength);
        ::wknet::FreeNonPagedArray(session->AuthHeaderValue);
        session->AuthHeaderValue = nullptr;
        session->AuthHeaderValueLength = 0;
    }
    detail::UnlockSessionConfig(session);
}

NTSTATUS SessionSetBasicAuth(
    Session* session,
    const char* user,
    SIZE_T userLength,
    const char* password,
    SIZE_T passwordLength) noexcept
{
    NTSTATUS status = ::wknet::session::CheckPassiveLevel();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!detail::IsValidSession(session) || user == nullptr || userLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (password == nullptr) {
        passwordLength = 0;
    }
    const SIZE_T rawLen = userLength + 1 + passwordLength;
    auto* raw = ::wknet::AllocateNonPagedArray<UCHAR>(rawLen);
    if (raw == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(raw, user, userLength);
    raw[userLength] = static_cast<UCHAR>(':');
    if (passwordLength != 0) {
        RtlCopyMemory(raw + userLength + 1, password, passwordLength);
    }
    const SIZE_T b64Cap = ((rawLen + 2) / 3) * 4 + 1;
    auto* b64 = ::wknet::AllocateNonPagedArray<char>(b64Cap);
    if (b64 == nullptr) {
        RtlSecureZeroMemory(raw, rawLen);
        ::wknet::FreeNonPagedArray(raw);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T b64Len = 0;
    Base64Encode(raw, rawLen, b64, b64Cap, &b64Len);
    RtlSecureZeroMemory(raw, rawLen);
    ::wknet::FreeNonPagedArray(raw);

    const SIZE_T valueLen = 6 + b64Len;
    auto* value = ::wknet::AllocateNonPagedArray<char>(valueLen + 1);
    if (value == nullptr) {
        ::wknet::FreeNonPagedArray(b64);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(value, "Basic ", 6);
    RtlCopyMemory(value + 6, b64, b64Len);
    value[valueLen] = 0;
    ::wknet::FreeNonPagedArray(b64);

    detail::LockSessionConfig(session);
    if (session->AuthHeaderValue != nullptr) {
        RtlSecureZeroMemory(session->AuthHeaderValue, session->AuthHeaderValueLength);
        ::wknet::FreeNonPagedArray(session->AuthHeaderValue);
        session->AuthHeaderValue = nullptr;
        session->AuthHeaderValueLength = 0;
    }
    session->AuthHeaderValue = value;
    session->AuthHeaderValueLength = valueLen;
    detail::UnlockSessionConfig(session);
    return STATUS_SUCCESS;
}

NTSTATUS SessionSetBearerAuth(Session* session, const char* token, SIZE_T tokenLength) noexcept
{
    NTSTATUS status = ::wknet::session::CheckPassiveLevel();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!detail::IsValidSession(session) || token == nullptr || tokenLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    const SIZE_T valueLen = 7 + tokenLength;
    auto* value = ::wknet::AllocateNonPagedArray<char>(valueLen + 1);
    if (value == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(value, "Bearer ", 7);
    RtlCopyMemory(value + 7, token, tokenLength);
    value[valueLen] = 0;
    detail::LockSessionConfig(session);
    if (session->AuthHeaderValue != nullptr) {
        RtlSecureZeroMemory(session->AuthHeaderValue, session->AuthHeaderValueLength);
        ::wknet::FreeNonPagedArray(session->AuthHeaderValue);
        session->AuthHeaderValue = nullptr;
        session->AuthHeaderValueLength = 0;
    }
    session->AuthHeaderValue = value;
    session->AuthHeaderValueLength = valueLen;
    detail::UnlockSessionConfig(session);
    return STATUS_SUCCESS;
}

void SessionClearCookies(Session* session) noexcept
{
    if (!detail::IsValidSession(session)) {
        return;
    }
    if (!NT_SUCCESS(::wknet::session::CheckPassiveLevel())) {
        return;
    }
    detail::LockSessionConfig(session);
    ::wknet::session::CookieJarClear(&session->CookieJar);
    detail::UnlockSessionConfig(session);
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
