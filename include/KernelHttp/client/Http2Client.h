#pragma once

#include <KernelHttp/http/HttpRequest.h>
#include <KernelHttp/http/HttpTypes.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskClient.h>
#include <KernelHttp/tls/CertificateStore.h>

namespace KernelHttp
{
namespace client
{
    constexpr SIZE_T Http2MaxRequestHeaders = 16;
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
        http::HttpMethod Method = http::HttpMethod::Get;
        http::HttpText Path = {};
        http::HttpText Authority = {};
        http::HttpText UserAgent = {};
        http::HttpText ContentType = {};
        http::HttpText AcceptEncoding = {};
        const http::HttpHeader* ExtraHeaders = nullptr;
        SIZE_T ExtraHeaderCount = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool IncludeContentLength = false;
        const tls::CertificateStore* CertificateStore = nullptr;
        bool VerifyCertificate = true;
    };

    _Must_inspect_result_
    NTSTATUS BuildHttp2RequestHeaders(
        _In_ const Http2RequestOptions& options,
        _Out_writes_(headerCapacity) http::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        _Out_writes_all_(Http2MaxRequestHeaders) char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength],
        _Out_writes_(Http2ContentLengthBufferLength) char* contentLengthBuffer,
        _Out_ SIZE_T* headerCount) noexcept;

    struct Http2ResponseBuffers final
    {
        http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCapacity = 0;
        char* NameValueBuffer = nullptr;
        SIZE_T NameValueBufferLength = 0;
        char* BodyBuffer = nullptr;
        SIZE_T BodyBufferLength = 0;
    };

    struct Http2Response final
    {
        USHORT StatusCode = 0;
        const http::HttpHeader* Headers = nullptr;
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
