#pragma once

#if defined(WKNET_USER_MODE_TEST)

#include <wknet/http/Types.h>

namespace wknet::http::test {
    struct HttpTransportRequest final
    {
        const char* Scheme = nullptr;
        SIZE_T SchemeLength = 0;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        http::AddressFamily AddressFamily = http::AddressFamily::Any;
        const char* BuiltRequest = nullptr;
        SIZE_T BuiltRequestLength = 0;
        SIZE_T HeaderBytesLength = 0;
        SIZE_T BodyBytesLength = 0;
        bool ExpectContinueEnabled = false;
        bool ExpectContinueBodySent = false;
        ConnPolicy ConnectionPolicy = ConnPolicy::ReuseOrCreate;
        CertPolicy CertificatePolicy = CertPolicy::Verify;
        const void* CertificateStore = nullptr;
        const char* Alpn = nullptr;
        SIZE_T AlpnLength = 0;
        const char* OfferedAlpn = nullptr;
        SIZE_T OfferedAlpnLength = 0;
        TlsPolicy Policy = {};
        const TlsClientCredential* ClientCredential = nullptr;
        ULONG MaxTls12Renegotiations = 0;
        bool ProxyEnabled = false;
        const char* ProxyHost = nullptr;
        SIZE_T ProxyHostLength = 0;
        USHORT ProxyPort = 0;
        http::AddressFamily ProxyFamily = http::AddressFamily::Any;
        const char* ProxyAuthority = nullptr;
        SIZE_T ProxyAuthorityLength = 0;
        const char* ProxyAuthHeader = nullptr;
        SIZE_T ProxyAuthHeaderLength = 0;
        bool PoolableConnection = false;
        bool ReusedConnection = false;
        ULONGLONG ConnectionId = 0;
        bool Http11PipelineEnabled = false;
        bool Http11PipelineLease = false;
        ULONG Http11PipelineSequence = 0;
        http::Http2CleartextMode Http2CleartextMode = http::Http2CleartextMode::Disabled;
        bool UsedHttp2 = false;
    };

    struct HttpTransportResponse final
    {
        const char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        const char* NegotiatedAlpn = nullptr;
        SIZE_T NegotiatedAlpnLength = 0;
        bool ConnectionReusable = true;
    };

    using HttpTransportCallback = NTSTATUS(*)(
        void* context,
        const HttpTransportRequest* request,
        HttpTransportResponse* response);

    struct WebSocketConnectRequest final
    {
        const char* Scheme = nullptr;
        SIZE_T SchemeLength = 0;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        const char* Path = nullptr;
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        CertPolicy CertificatePolicy = CertPolicy::Verify;
        const void* CertificateStore = nullptr;
        TlsVersion MinTlsVersion = TlsVersion::Tls12;
        TlsVersion MaxTlsVersion = TlsVersion::Tls13;
        TlsPolicy Policy = {};
        const TlsClientCredential* ClientCredential = nullptr;
        http::AddressFamily AddressFamily = http::AddressFamily::Any;
        bool AutoReplyPing = true;
        SIZE_T MaxMessageBytes = 0;
        ULONG HandshakeReceiveTimeoutMilliseconds = 0;
        ULONG MaxTls12Renegotiations = 0;
        bool AllowWebSocketOverHttp2 = false;
        http::WebSocketTransportMode TransportMode = http::WebSocketTransportMode::Auto;
        websocket::PerMessageDeflateOptions PerMessageDeflate = {};
    };

    struct WebSocketMessage final
    {
        websocket::MsgType Type = websocket::MsgType::Binary;
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        bool FinalFragment = true;
    };

    using WebSocketConnectCallback = NTSTATUS(*)(void* context, const WebSocketConnectRequest* request);
    using WebSocketSendCallback = NTSTATUS(*)(
        void* context,
        websocket::WebSocket* websocket,
        websocket::MsgType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment);
    using WebSocketReceiveCallback = NTSTATUS(*)(
        void* context,
        websocket::WebSocket* websocket,
        WebSocketMessage* message);
    using WebSocketCloseCallback = void(*)(void* context, websocket::WebSocket* websocket);

    void SetHttpTransport(HttpTransportCallback callback, void* context) noexcept;
    void SetWebSocketTransport(
        WebSocketConnectCallback connectCallback,
        WebSocketSendCallback sendCallback,
        WebSocketReceiveCallback receiveCallback,
        WebSocketCloseCallback closeCallback,
        void* context) noexcept;
    void SetCurrentIrql(ULONG irql) noexcept;
    void ResetCurrentIrql() noexcept;
    void SetAsyncAutoRun(bool enabled) noexcept;
    NTSTATUS RunAsyncOperation(_In_ AsyncOp* operation) noexcept;
    bool IsHttpTls12ConfirmationCandidate(
        TlsVersion minVersion,
        TlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept;
}
#endif
