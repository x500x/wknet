#pragma once

#include "http1/HttpRequest.h"
#include "http1/HttpResponse.h"

namespace wknet
{
namespace transport
{
    struct ProxyConnectRequestOptions final
    {
        http1::HttpText Authority = {};
        http1::HttpText UserAgent = {};
        const http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
    };

    _Must_inspect_result_
    NTSTATUS BuildProxyConnectRequest(
        _In_ const ProxyConnectRequestOptions& options,
        _Out_writes_bytes_(requestCapacity) char* requestBuffer,
        SIZE_T requestCapacity,
        _Out_ SIZE_T* requestLength) noexcept;

    _Must_inspect_result_
    bool IsSuccessfulProxyConnectResponse(_In_ const http1::HttpResponse& response) noexcept;
}
}
