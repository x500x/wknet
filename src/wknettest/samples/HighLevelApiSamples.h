#pragma once

#include "http1/HttpTypes.h"

#if !defined(WKNET_USER_MODE_TEST)
#include <ntddk.h>
#endif

namespace wknet::http {
    struct Session;
}

namespace wknet
{
namespace net
{
    class WskClient;
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
        HighLevelApiSampleResult WebSocketTls13Only = {};
        HighLevelApiSampleResult WebSocketReceiveEx = {};
        HighLevelApiSampleResult WebSocketConnectAsync = {};
        HighLevelApiSampleResult WebSocketConfigConnectAsync = {};
        HighLevelApiSampleResult WebSocketConnectAsyncEx = {};
    };

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiSamples(
        _In_ ::wknet::http::Session* session,
        _Out_ HighLevelApiSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiSamples(
        _In_ ::wknet::http::Session* session,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ HighLevelApiSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiSamples(
        _In_ net::WskClient* wskClient,
        _Out_ HighLevelApiSampleResults* results) noexcept;

    _Must_inspect_result_
    NTSTATUS RunHighLevelApiSamples(
        _In_ net::WskClient* wskClient,
        _In_opt_z_ const char* certificateBundlePath,
        _Out_ HighLevelApiSampleResults* results) noexcept;
}
}
