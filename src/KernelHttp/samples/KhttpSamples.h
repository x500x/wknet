#pragma once

#include "../http/HttpTypes.h"

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
#include <ntddk.h>
#endif

namespace KernelHttp
{
namespace khttp
{
    struct Session;
}

namespace samples
{
    struct KhttpSampleResult final
    {
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG StatusCode = 0;
        SIZE_T BodyLength = 0;
    };

    struct KhttpSampleResults final
    {
        KhttpSampleResult HttpGet = {};
        KhttpSampleResult HttpGetAsync = {};
        KhttpSampleResult HttpPost = {};
        KhttpSampleResult HttpPostAsync = {};
        KhttpSampleResult HttpPut = {};
        KhttpSampleResult HttpPatch = {};
        KhttpSampleResult HttpDelete = {};
        KhttpSampleResult HttpHead = {};
        KhttpSampleResult HttpOptions = {};
        KhttpSampleResult HttpsVerifyGet = {};
        KhttpSampleResult HttpsNoVerifyGet = {};
        KhttpSampleResult HttpsRequestBuilder = {};
        KhttpSampleResult WebSocketEcho = {};
    };

    _Must_inspect_result_
    NTSTATUS RunKhttpSamples(
        _In_ khttp::Session* session,
        _Out_ KhttpSampleResults* results) noexcept;
}
}
