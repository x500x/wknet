#pragma once

#include <KernelHttp/http/HttpTypes.h>

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
#include <ntddk.h>
#endif

namespace KernelHttp
{
namespace net
{
    class WskClient;
}

namespace khttp
{
    struct Session;
}

namespace samples
{
    struct HighLevelApiSampleResult final
    {
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG StatusCode = 0;
        SIZE_T BodyLength = 0;
    };

    struct HighLevelApiSampleResults final
    {
        HighLevelApiSampleResult SessionDefaultConfig = {};
        HighLevelApiSampleResult SessionCustomConfig = {};
        HighLevelApiSampleResult HttpGet = {};
        HighLevelApiSampleResult HttpShortcutGet = {};
        HighLevelApiSampleResult HttpShortcutPost = {};
        HighLevelApiSampleResult HttpShortcutPut = {};
        HighLevelApiSampleResult HttpShortcutPatch = {};
        HighLevelApiSampleResult HttpShortcutDelete = {};
        HighLevelApiSampleResult HttpShortcutHead = {};
        HighLevelApiSampleResult HttpShortcutOptions = {};
        HighLevelApiSampleResult HttpGetAsync = {};
        HighLevelApiSampleResult HttpPost = {};
        HighLevelApiSampleResult HttpPostAsync = {};
        HighLevelApiSampleResult HttpPut = {};
        HighLevelApiSampleResult HttpPatch = {};
        HighLevelApiSampleResult HttpDelete = {};
        HighLevelApiSampleResult HttpHead = {};
        HighLevelApiSampleResult HttpOptions = {};
        HighLevelApiSampleResult HttpGetIpv4 = {};
        HighLevelApiSampleResult HttpGetIpv6 = {};
        HighLevelApiSampleResult HttpGetAny = {};
        HighLevelApiSampleResult HttpSendWithOptions = {};
        HighLevelApiSampleResult HttpSendEx = {};
        HighLevelApiSampleResult HttpResponseHeader = {};
        HighLevelApiSampleResult HttpTextBody = {};
        HighLevelApiSampleResult HttpJsonBody = {};
        HighLevelApiSampleResult HttpRawBody = {};
        HighLevelApiSampleResult HttpFormBody = {};
        HighLevelApiSampleResult HttpMultipartBody = {};
        HighLevelApiSampleResult HttpFileBody = {};
        HighLevelApiSampleResult HttpClearBody = {};
        HighLevelApiSampleResult HttpSendAsync = {};
        HighLevelApiSampleResult HttpSendAsyncWithOptions = {};
        HighLevelApiSampleResult HttpSendAsyncEx = {};
        HighLevelApiSampleResult HttpAsyncCancel = {};
        HighLevelApiSampleResult HttpsVerifyGet = {};
        HighLevelApiSampleResult HttpsNoVerifyGet = {};
        HighLevelApiSampleResult HttpsRequestBuilder = {};
        HighLevelApiSampleResult HttpsHttp11 = {};
        HighLevelApiSampleResult HttpsHttp2 = {};
        HighLevelApiSampleResult WebSocketEcho = {};
        HighLevelApiSampleResult WebSocketUrlConnect = {};
        HighLevelApiSampleResult WebSocketConfigConnect = {};
        HighLevelApiSampleResult WebSocketConnectEx = {};
        HighLevelApiSampleResult WebSocketTextEx = {};
        HighLevelApiSampleResult WebSocketBinary = {};
        HighLevelApiSampleResult WebSocketBinaryEx = {};
        HighLevelApiSampleResult WebSocketReceiveEx = {};
        HighLevelApiSampleResult WebSocketConnectAsync = {};
        HighLevelApiSampleResult WebSocketConfigConnectAsync = {};
        HighLevelApiSampleResult WebSocketConnectAsyncEx = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiSamples(
        _In_ khttp::Session* session,
        _Out_ HighLevelApiSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiSamples(
        _In_ net::WskClient* wskClient,
        _Out_ HighLevelApiSampleResults* results) noexcept;
}
}
