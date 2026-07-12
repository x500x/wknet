#include <wknet/client/ProxyTunnel.h>

namespace wknet
{
namespace client
{
    NTSTATUS BuildProxyConnectRequest(
        const ProxyConnectRequestOptions& options,
        char* requestBuffer,
        SIZE_T requestCapacity,
        SIZE_T* requestLength) noexcept
    {
        if (requestBuffer == nullptr ||
            requestLength == nullptr ||
            options.Authority.Data == nullptr ||
            options.Authority.Length == 0 ||
            (options.Headers == nullptr && options.HeaderCount != 0) ||
            (options.Headers != nullptr && options.HeaderCount == 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        http1::HttpRequestBuildOptions connect = {};
        connect.Method = http1::HttpMethod::Connect;
        connect.Path = options.Authority;
        connect.Host = options.Authority;
        connect.UserAgent = options.UserAgent;
        connect.ExtraHeaders = options.Headers;
        connect.ExtraHeaderCount = options.HeaderCount;
        return http1::HttpRequestBuilder::Build(
            connect,
            requestBuffer,
            requestCapacity,
            requestLength);
    }

    bool IsSuccessfulProxyConnectResponse(const http1::HttpResponse& response) noexcept
    {
        return response.StatusCode >= 200 && response.StatusCode < 300;
    }
}
}
