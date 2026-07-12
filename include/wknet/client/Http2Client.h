#pragma once

#include <wknet/http1/HttpRequest.h>
#include <wknet/http1/HttpTypes.h>
#include <wknet/http2/Http2Connection.h>
#include <wknet/net/WskClient.h>
#include <wknet/tls/CertificateStore.h>
#include <wknet/tls/TlsConnection.h>
#include <wknet/tls/TlsPolicy.h>

namespace wknet
{
namespace client
{
    constexpr SIZE_T Http2MaxRequestHeaders = 16;
    constexpr SIZE_T Http2MaxRequestTrailers = 16;
    constexpr SIZE_T Http2MaxHeaderNameLength = 64;
    constexpr SIZE_T Http2ContentLengthBufferLength = 32;

    enum class Http2TransportMode : UCHAR
    {
        TlsAlpn,
        H2cPriorKnowledge,
        H2cUpgrade
    };

    struct Http2RequestOptions final
    {
        Http2TransportMode TransportMode = Http2TransportMode::TlsAlpn;
        const SOCKADDR* RemoteAddress = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        http1::HttpMethod Method = http1::HttpMethod::Get;
        http1::HttpText Path = {};
        http1::HttpText Authority = {};
        http1::HttpText UserAgent = {};
        http1::HttpText ContentType = {};
        http1::HttpText AcceptEncoding = {};
        http1::HttpText ConnectProtocol = {};
        const http1::HttpHeader* ExtraHeaders = nullptr;
        SIZE_T ExtraHeaderCount = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        const http2::Http2RequestBodySource* BodySource = nullptr;
        const http1::HttpHeader* Trailers = nullptr;
        SIZE_T TrailerCount = 0;
        const http2::Http2Priority* Priority = nullptr;
        bool IncludeContentLength = false;
        const tls::CertificateStore* CertificateStore = nullptr;
        bool VerifyCertificate = true;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        ULONG MaxTls12Renegotiations = tls::Tls12DefaultMaxRenegotiations;
    };

    _Must_inspect_result_
    NTSTATUS BuildHttp2RequestHeaders(
        _In_ const Http2RequestOptions& options,
        _Out_writes_(headerCapacity) http1::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        _Out_writes_all_(Http2MaxRequestHeaders) char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength],
        _Out_writes_(Http2ContentLengthBufferLength) char* contentLengthBuffer,
        _Out_ SIZE_T* headerCount) noexcept;

    struct Http2ResponseBuffers final
    {
        http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCapacity = 0;
        char* NameValueBuffer = nullptr;
        SIZE_T NameValueBufferLength = 0;
        char* BodyBuffer = nullptr;
        SIZE_T BodyBufferLength = 0;
    };

    struct Http2Response final
    {
        USHORT StatusCode = 0;
        const http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        char NegotiatedAlpn[16] = {};
        SIZE_T NegotiatedAlpnLength = 0;
    };

    class Http2Client final
    {
    public:
        Http2Client() noexcept = default;

        Http2Client(const Http2Client&) = delete;
        Http2Client& operator=(const Http2Client&) = delete;

        // Sends a single HTTP/2 request over a freshly negotiated TLS+ALPN connection.
        // Returns STATUS_NOT_SUPPORTED if peer does not negotiate "h2".
        _Must_inspect_result_
        NTSTATUS SendRequest(
            _Inout_ net::WskClient& wskClient,
            _In_ const Http2RequestOptions& options,
            _In_ const Http2ResponseBuffers& buffers,
            _Out_ Http2Response& response) noexcept;
    };
}
}
