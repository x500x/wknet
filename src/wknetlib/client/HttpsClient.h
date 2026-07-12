#pragma once

#include "transport/ITransport.h"
#include "http1/HttpParser.h"
#include "http1/HttpRequest.h"
#include "net/WskClient.h"
#include "tls/TlsConnection.h"

namespace wknet
{
namespace session
{
    struct Workspace;
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
        const SOCKADDR* ProxyAddress = nullptr;
        const char* ProxyAuthority = nullptr;
        SIZE_T ProxyAuthorityLength = 0;
        const http1::HttpHeader* ProxyHeaders = nullptr;
        SIZE_T ProxyHeaderCount = 0;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        http1::HttpRequestBuildOptions Request = {};
        bool ResponseBodyForbidden = false;
        const tls::CertificateStore* CertificateStore = nullptr;
        bool VerifyCertificate = true;
        bool PreferHttp2 = true;
        tls::TlsProtocol MinimumTlsProtocol = tls::TlsProtocol::Tls12;
        tls::TlsProtocol MaximumTlsProtocol = tls::TlsProtocol::Tls13;
        tls::TlsPolicy Policy = {};
        tls::Tls13SessionCache* SessionCache = nullptr;
        tls::Tls12SessionCache* Tls12SessionCache = nullptr;
        const tls::TlsAlpnProtocol* AlpnProtocols = nullptr;
        SIZE_T AlpnProtocolCount = 0;
        const tls::TlsClientCredential* ClientCredential = nullptr;
        session::Workspace* Workspace = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        bool EnableSessionResumption = true;
        ULONG MaxTls12Renegotiations = tls::Tls12DefaultMaxRenegotiations;
        bool EnableEarlyData = false;
        bool EarlyDataReplaySafe = false;
        SIZE_T* EarlyDataBytesSent = nullptr;
        bool* EarlyDataAccepted = nullptr;
    };

    struct HttpsResponseBuffers final
    {
        char* RequestBuffer = nullptr;
        SIZE_T RequestBufferLength = 0;
        char* ResponseBuffer = nullptr;
        SIZE_T ResponseBufferLength = 0;
        char* DecodedBodyBuffer = nullptr;
        SIZE_T DecodedBodyBufferLength = 0;
        char* HeaderNameValueBuffer = nullptr;
        SIZE_T HeaderNameValueBufferLength = 0;
        char* ScratchBodyBuffer = nullptr;
        SIZE_T ScratchBodyBufferLength = 0;
        http1::HttpHeader* Headers = nullptr;
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
            _Out_ http1::HttpResponse& response) noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS SendRequestOnce(
            _Inout_ net::WskClient& wskClient,
            _In_ const HttpsRequestOptions& options,
            _In_ const HttpsResponseBuffers& buffers,
            _Out_ http1::HttpResponse& response,
            _Out_opt_ bool* tls12ConfirmationCandidate) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHttpResponse(
            _Inout_ core::ITransport& transport,
            bool responseBodyForbidden,
            _In_ const HttpsResponseBuffers& buffers,
            _Out_ http1::HttpResponse& response) noexcept;
    };
}
}
