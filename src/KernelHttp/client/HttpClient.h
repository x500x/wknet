#pragma once

#include "http/HttpParser.h"
#include "http/HttpRequest.h"
#include "net/WskSocket.h"

namespace KernelHttp
{
namespace client
{
    struct HttpRequestOptions final
    {
        const wchar_t* ServerName = nullptr;
        const wchar_t* ServiceName = L"80";
        http::HttpRequestBuildOptions Request = {};
        bool ResponseBodyForbidden = false;
    };

    struct HttpResponseBuffers final
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

    class HttpClient final
    {
    public:
        HttpClient() noexcept = default;

        HttpClient(const HttpClient&) = delete;
        HttpClient& operator=(const HttpClient&) = delete;

        _Must_inspect_result_
        NTSTATUS SendRequest(
            _Inout_ net::WskClient& wskClient,
            _In_ const HttpRequestOptions& options,
            _In_ const HttpResponseBuffers& buffers,
            _Out_ http::HttpResponse& response) noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS ReadHttpResponse(
            _Inout_ net::WskSocket& socket,
            bool responseBodyForbidden,
            _In_ const HttpResponseBuffers& buffers,
            _Out_ http::HttpResponse& response) noexcept;
    };
}
}
