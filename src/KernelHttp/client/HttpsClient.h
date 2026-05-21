#pragma once

#include "http/HttpParser.h"
#include "http/HttpRequest.h"
#include "tls/TlsConnection.h"

namespace KernelHttp
{
namespace client
{
    struct HttpsRequestOptions final
    {
        const SOCKADDR* RemoteAddress = nullptr;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        http::HttpRequestBuildOptions Request = {};
        bool ResponseBodyForbidden = false;
        const tls::CertificateStore* CertificateStore = nullptr;
    };

    struct HttpsResponseBuffers final
    {
        char* RequestBuffer = nullptr;
        SIZE_T RequestBufferLength = 0;
        char* ResponseBuffer = nullptr;
        SIZE_T ResponseBufferLength = 0;
        char* DecodedBodyBuffer = nullptr;
        SIZE_T DecodedBodyBufferLength = 0;
        http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCapacity = 0;
    };

    class HttpsClient final
    {
    public:
        HttpsClient() noexcept = default;

        HttpsClient(const HttpsClient&) = delete;
        HttpsClient& operator=(const HttpsClient&) = delete;

        _Must_inspect_result_
        NTSTATUS SendRequest(
            _Inout_ net::WskClient& wskClient,
            _In_ const HttpsRequestOptions& options,
            _In_ const HttpsResponseBuffers& buffers,
            _Out_ http::HttpResponse& response) noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS ReadHttpResponse(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls,
            bool responseBodyForbidden,
            _In_ const HttpsResponseBuffers& buffers,
            _Out_ http::HttpResponse& response) noexcept;
    };
}
}
