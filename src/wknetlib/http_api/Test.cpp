#include <wknet/test/Test.h>
#include "session/detail/HttpHandles.h"
#include "session/Engine.h"

namespace wknet::http::test {
#if defined(WKNET_USER_MODE_TEST)
namespace
{
    HttpTransportCallback g_httpCallback = nullptr;
    WebSocketConnectCallback g_wsConnectCallback = nullptr;
    WebSocketSendCallback g_wsSendCallback = nullptr;
    WebSocketReceiveCallback g_wsReceiveCallback = nullptr;
    WebSocketCloseCallback g_wsCloseCallback = nullptr;
    void* g_callbackContext = nullptr;

    TlsPolicy ToPublicTlsPolicy(const tls::TlsPolicy& source) noexcept
    {
        TlsPolicy result = {};
        result.Profile = source.Profile == tls::TlsSecurityProfile::CompatibilityExplicit
            ? TlsSecurityProfile::CompatibilityExplicit
            : TlsSecurityProfile::ModernDefault;
        result.EnableTls12RsaKeyExchange = source.EnableTls12RsaKeyExchange;
        result.EnableTls12Cbc = source.EnableTls12Cbc;
        result.EnableTls12Renegotiation = source.EnableTls12Renegotiation;
        result.EnableTls12Sha1Signatures = source.EnableTls12Sha1Signatures;
        result.EnablePostHandshakeClientAuth = source.EnablePostHandshakeClientAuth;
        result.RequireRevocationCheck = source.RequireRevocationCheck;
        return result;
    }

    AddressFamily ToPublicAddressFamily(session::AddressFamily source) noexcept
    {
        switch (source) {
        case session::AddressFamily::Ipv4: return AddressFamily::Ipv4;
        case session::AddressFamily::Ipv6: return AddressFamily::Ipv6;
        case session::AddressFamily::Any:
        default: return AddressFamily::Any;
        }
    }

    ConnPolicy ToPublicConnectionPolicy(session::ConnectionPolicy source) noexcept
    {
        switch (source) {
        case session::ConnectionPolicy::ForceNew: return ConnPolicy::ForceNew;
        case session::ConnectionPolicy::NoPool: return ConnPolicy::NoPool;
        case session::ConnectionPolicy::ReuseOrCreate:
        default: return ConnPolicy::ReuseOrCreate;
        }
    }

    TlsVersion ToPublicTlsVersion(session::TlsVersion source) noexcept
    {
        return source == session::TlsVersion::Tls13 ? TlsVersion::Tls13 : TlsVersion::Tls12;
    }

    Http2CleartextMode ToPublicCleartextMode(session::Http2CleartextMode source) noexcept
    {
        switch (source) {
        case session::Http2CleartextMode::PriorKnowledge: return Http2CleartextMode::PriorKnowledge;
        case session::Http2CleartextMode::Upgrade: return Http2CleartextMode::Upgrade;
        case session::Http2CleartextMode::Disabled:
        default: return Http2CleartextMode::Disabled;
        }
    }

    WebSocketTransportMode ToPublicWebSocketTransportMode(session::WebSocketTransportMode source) noexcept
    {
        switch (source) {
        case session::WebSocketTransportMode::Http11Only: return WebSocketTransportMode::Http11Only;
        case session::WebSocketTransportMode::Http2Required: return WebSocketTransportMode::Http2Required;
        case session::WebSocketTransportMode::LegacyBoolean: return WebSocketTransportMode::LegacyBoolean;
        case session::WebSocketTransportMode::Auto:
        default: return WebSocketTransportMode::Auto;
        }
    }

    websocket::PerMessageDeflateOptions ToPublicPerMessageDeflate(
        const ws::PerMessageDeflateOptions& source) noexcept
    {
        websocket::PerMessageDeflateOptions result = {};
        result.Enable = source.Enable;
        result.ClientNoContextTakeover = source.ClientNoContextTakeover;
        result.ServerNoContextTakeover = source.ServerNoContextTakeover;
        result.ClientMaxWindowBits = source.ClientMaxWindowBits;
        result.ServerMaxWindowBits = source.ServerMaxWindowBits;
        return result;
    }

    NTSTATUS HttpBridge(
        void*,
        const session::TestHttpTransportRequest* source,
        session::TestHttpTransportResponse* destination) noexcept
    {
        if (g_httpCallback == nullptr || source == nullptr || destination == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        HttpTransportRequest request = {};
        request.Scheme = source->Scheme;
        request.SchemeLength = source->SchemeLength;
        request.Host = source->Host;
        request.HostLength = source->HostLength;
        request.Port = source->Port;
        request.AddressFamily = ToPublicAddressFamily(source->AddressFamily);
        request.BuiltRequest = source->BuiltRequest;
        request.BuiltRequestLength = source->BuiltRequestLength;
        request.HeaderBytesLength = source->HeaderBytesLength;
        request.BodyBytesLength = source->BodyBytesLength;
        request.ExpectContinueEnabled = source->ExpectContinueEnabled;
        request.ExpectContinueBodySent = source->ExpectContinueBodySent;
        request.ConnectionPolicy = ToPublicConnectionPolicy(source->ConnectionPolicy);
        request.CertificatePolicy = source->CertificatePolicy == session::CertificatePolicy::NoVerify
            ? CertPolicy::NoVerify : CertPolicy::Verify;
        request.CertificateStore = source->CertificateStore;
        request.Alpn = source->Alpn;
        request.AlpnLength = source->AlpnLength;
        request.OfferedAlpn = source->OfferedAlpn;
        request.OfferedAlpnLength = source->OfferedAlpnLength;
        request.Policy = ToPublicTlsPolicy(source->Policy);
        request.ClientCredential = source->ClientCredential;
        request.MaxTls12Renegotiations = source->MaxTls12Renegotiations;
        request.ProxyEnabled = source->ProxyEnabled;
        request.ProxyHost = source->ProxyHost;
        request.ProxyHostLength = source->ProxyHostLength;
        request.ProxyPort = source->ProxyPort;
        request.ProxyFamily = ToPublicAddressFamily(source->ProxyFamily);
        request.ProxyAuthority = source->ProxyAuthority;
        request.ProxyAuthorityLength = source->ProxyAuthorityLength;
        request.ProxyAuthHeader = source->ProxyAuthHeader;
        request.ProxyAuthHeaderLength = source->ProxyAuthHeaderLength;
        request.PoolableConnection = source->PoolableConnection;
        request.ReusedConnection = source->ReusedConnection;
        request.ConnectionId = source->ConnectionId;
        request.Http11PipelineEnabled = source->Http11PipelineEnabled;
        request.Http11PipelineLease = source->Http11PipelineLease;
        request.Http11PipelineSequence = source->Http11PipelineSequence;
        request.Http2CleartextMode = ToPublicCleartextMode(source->Http2CleartextMode);
        request.UsedHttp2 = source->UsedHttp2;

        HttpTransportResponse response = {};
        const NTSTATUS status = g_httpCallback(g_callbackContext, &request, &response);
        if (NT_SUCCESS(status)) {
            destination->RawResponse = response.RawResponse;
            destination->RawResponseLength = response.RawResponseLength;
            destination->NegotiatedAlpn = response.NegotiatedAlpn;
            destination->NegotiatedAlpnLength = response.NegotiatedAlpnLength;
            destination->ConnectionReusable = response.ConnectionReusable;
        }
        return status;
    }

    NTSTATUS WebSocketConnectBridge(void*, const session::TestWebSocketConnectRequest* source) noexcept
    {
        if (g_wsConnectCallback == nullptr || source == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        WebSocketConnectRequest request = {};
        request.Scheme = source->Scheme;
        request.SchemeLength = source->SchemeLength;
        request.Host = source->Host;
        request.HostLength = source->HostLength;
        request.Path = source->Path;
        request.PathLength = source->PathLength;
        request.Port = source->Port;
        request.Subprotocol = source->Subprotocol;
        request.SubprotocolLength = source->SubprotocolLength;
        request.CertificatePolicy = source->CertificatePolicy == session::CertificatePolicy::NoVerify
            ? CertPolicy::NoVerify : CertPolicy::Verify;
        request.CertificateStore = source->CertificateStore;
        request.MinTlsVersion = ToPublicTlsVersion(source->MinTlsVersion);
        request.MaxTlsVersion = ToPublicTlsVersion(source->MaxTlsVersion);
        request.Policy = ToPublicTlsPolicy(source->Policy);
        request.ClientCredential = source->ClientCredential;
        request.AddressFamily = ToPublicAddressFamily(source->AddressFamily);
        request.AutoReplyPing = source->AutoReplyPing;
        request.MaxMessageBytes = source->MaxMessageBytes;
        request.HandshakeReceiveTimeoutMilliseconds = source->HandshakeReceiveTimeoutMilliseconds;
        request.MaxTls12Renegotiations = source->MaxTls12Renegotiations;
        request.AllowWebSocketOverHttp2 = source->AllowWebSocketOverHttp2;
        request.TransportMode = ToPublicWebSocketTransportMode(source->TransportMode);
        request.PerMessageDeflate = ToPublicPerMessageDeflate(source->PerMessageDeflate);
        return g_wsConnectCallback(g_callbackContext, &request);
    }

    NTSTATUS WebSocketSendBridge(
        void*, session::WebSocketHandle websocket, session::WebSocketMessageType type,
        const UCHAR* data, SIZE_T dataLength, bool finalFragment) noexcept
    {
        return g_wsSendCallback == nullptr ? STATUS_INVALID_PARAMETER : g_wsSendCallback(
            g_callbackContext,
            reinterpret_cast<websocket::WebSocket*>(websocket),
            detail::FromApiWsMsgType(type),
            data,
            dataLength,
            finalFragment);
    }

    NTSTATUS WebSocketReceiveBridge(
        void*, session::WebSocketHandle websocket, session::TestWebSocketMessage* destination) noexcept
    {
        if (g_wsReceiveCallback == nullptr || destination == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        WebSocketMessage message = {};
        const NTSTATUS status = g_wsReceiveCallback(
            g_callbackContext,
            reinterpret_cast<websocket::WebSocket*>(websocket),
            &message);
        if (NT_SUCCESS(status)) {
            destination->Type = detail::ToApiWsMsgType(message.Type);
            destination->Data = message.Data;
            destination->DataLength = message.DataLength;
            destination->FinalFragment = message.FinalFragment;
        }
        return status;
    }

    void WebSocketCloseBridge(void*, session::WebSocketHandle websocket) noexcept
    {
        if (g_wsCloseCallback != nullptr) {
            g_wsCloseCallback(g_callbackContext, reinterpret_cast<websocket::WebSocket*>(websocket));
        }
    }
}

void SetHttpTransport(HttpTransportCallback callback, void* context) noexcept
{
    g_httpCallback = callback;
    g_callbackContext = context;
    session::TestSetHttpTransport(callback != nullptr ? HttpBridge : nullptr, nullptr);
}

void SetWebSocketTransport(
    WebSocketConnectCallback connectCallback,
    WebSocketSendCallback sendCallback,
    WebSocketReceiveCallback receiveCallback,
    WebSocketCloseCallback closeCallback,
    void* context) noexcept
{
    g_wsConnectCallback = connectCallback;
    g_wsSendCallback = sendCallback;
    g_wsReceiveCallback = receiveCallback;
    g_wsCloseCallback = closeCallback;
    g_callbackContext = context;
    session::TestSetWebSocketTransport(
        connectCallback != nullptr ? WebSocketConnectBridge : nullptr,
        sendCallback != nullptr ? WebSocketSendBridge : nullptr,
        receiveCallback != nullptr ? WebSocketReceiveBridge : nullptr,
        closeCallback != nullptr ? WebSocketCloseBridge : nullptr,
        nullptr);
}

void SetCurrentIrql(ULONG irql) noexcept { session::TestSetCurrentIrql(irql); }
void ResetCurrentIrql() noexcept { session::TestResetCurrentIrql(); }
void SetAsyncAutoRun(bool enabled) noexcept { session::TestSetAsyncAutoRun(enabled); }
NTSTATUS RunAsyncOperation(AsyncOp* operation) noexcept
{
    return session::TestRunAsyncOperation(detail::ToApiAsyncOp(operation));
}
bool IsHttpTls12ConfirmationCandidate(
    TlsVersion minVersion, TlsVersion maxVersion, ULONG category, NTSTATUS status,
    bool beforeTls13FirstServerHello) noexcept
{
    return session::TestIsHttpTls12ConfirmationCandidate(
        detail::ToApiTlsVersion(minVersion), detail::ToApiTlsVersion(maxVersion), category, status,
        beforeTls13FirstServerHello);
}
#endif
}
