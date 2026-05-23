#pragma once

#include "http/HttpParser.h"
#include "http/HttpRequest.h"
#include "tls/TlsConnection.h"

namespace KernelHttp
{
namespace api
{
    struct KhWorkspace;
}

namespace crypto
{
    class CngProviderCache;
}

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
        bool VerifyCertificate = true;
        bool PreferHttp2 = true;
        tls::TlsProtocol MinimumTlsProtocol = tls::TlsProtocol::Tls12;
        tls::TlsProtocol MaximumTlsProtocol = tls::TlsProtocol::Tls13;
        tls::Tls13SessionCache* SessionCache = nullptr;
        api::KhWorkspace* Workspace = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        bool EnableSessionResumption = true;
        bool EnableEarlyData = false;
        bool EarlyDataAccepted = false;
    };

    struct HttpsResponseBuffers final
    {
        char* RequestBuffer = nullptr;
        SIZE_T RequestBufferLength = 0;
        char* ResponseBuffer = nullptr;
        SIZE_T ResponseBufferLength = 0;
        char* DecodedBodyBuffer = nullptr;
        SIZE_T DecodedBodyBufferLength = 0;
        char* ScratchBodyBuffer = nullptr;
        SIZE_T ScratchBodyBufferLength = 0;
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
