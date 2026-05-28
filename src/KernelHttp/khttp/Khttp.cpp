#include "Session.h"
#include "Request.h"
#include "Response.h"
#include "Http.h"
#include "HttpAsync.h"
#include "AsyncOp.h"
#include "WebSocket.h"
#include "Detail.h"
#include "../api/KernelHttpApi.h"
#include "../api/KernelHttpAsync.h"
#include "../http/HttpTypes.h"

namespace KernelHttp
{
namespace khttp
{
namespace
{
    void FillApiSendOptions(
        const SendOptions& src,
        api::KhHttpSendOptions& dst) noexcept
    {
        dst.MaxResponseBytes = src.MaxResponseBytes;
        dst.Flags = src.Flags;
        dst.HeaderCallback = reinterpret_cast<api::KhHeaderCallback>(src.OnHeader);
        dst.BodyCallback = reinterpret_cast<api::KhBodyCallback>(src.OnBody);
        dst.CallbackContext = src.CallbackContext;
        dst.CompletionCallback = reinterpret_cast<api::KhAsyncCompletionCallback>(src.OnComplete);
        dst.CompletionContext = src.CompletionContext;
    }

    NTSTATUS DoSimpleSend(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const UCHAR* body,
        SIZE_T bodyLength,
        Response** response) noexcept
    {
        if (response != nullptr) {
            *response = nullptr;
        }
        if (session == nullptr || url == nullptr || urlLength == 0 || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        api::KH_REQUEST request = nullptr;
        NTSTATUS status = api::KhHttpRequestCreate(detail::ToApiSession(session), &request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = api::KhHttpRequestSetUrl(request, url, urlLength);
        if (NT_SUCCESS(status)) {
            status = api::KhHttpRequestSetMethod(request, detail::ToApiMethod(method));
        }
        if (NT_SUCCESS(status) && body != nullptr && bodyLength != 0) {
            status = api::KhHttpRequestSetBody(request, body, bodyLength);
        }

        api::KH_RESPONSE apiResp = nullptr;
        if (NT_SUCCESS(status)) {
            status = api::KhHttpSendSync(detail::ToApiSession(session), request, nullptr, &apiResp);
        }
        api::KhHttpRequestRelease(request);

        if (NT_SUCCESS(status)) {
            *response = detail::FromApiResponse(apiResp);
        }
        else if (apiResp != nullptr) {
            api::KhResponseRelease(apiResp);
        }
        return status;
    }

    NTSTATUS DoSimpleSendAsync(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const UCHAR* body,
        SIZE_T bodyLength,
        AsyncOp** operation) noexcept
    {
        if (operation != nullptr) {
            *operation = nullptr;
        }
        if (session == nullptr || url == nullptr || urlLength == 0 || operation == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        api::KH_REQUEST request = nullptr;
        NTSTATUS status = api::KhHttpRequestCreate(detail::ToApiSession(session), &request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = api::KhHttpRequestSetUrl(request, url, urlLength);
        if (NT_SUCCESS(status)) {
            status = api::KhHttpRequestSetMethod(request, detail::ToApiMethod(method));
        }
        if (NT_SUCCESS(status) && body != nullptr && bodyLength != 0) {
            status = api::KhHttpRequestSetBody(request, body, bodyLength);
        }

        api::KH_ASYNC_OPERATION apiOp = nullptr;
        if (NT_SUCCESS(status)) {
            status = api::KhHttpSendAsync(detail::ToApiSession(session), request, nullptr, &apiOp);
        }
        api::KhHttpRequestRelease(request);

        if (NT_SUCCESS(status)) {
            *operation = detail::FromApiAsyncOp(apiOp);
        }
        return status;
    }
}

NTSTATUS SessionCreate(
    net::WskClient* wskClient,
    const SessionConfig* config,
    Session** out) noexcept
{
    if (out != nullptr) {
        *out = nullptr;
    }

    api::KhSessionOptions apiOptions = {};
    apiOptions.ResponsePoolType = detail::ToApiPoolType(config != nullptr ? config->ResponsePool : PoolType::NonPaged);
    apiOptions.MaxResponseBytes = config != nullptr ? config->MaxResponseBytes : DefaultMaxResponseBytes;
    apiOptions.ConnectionPoolCapacity = config != nullptr ? config->PoolCapacity : DefaultPoolCapacity;
    apiOptions.MaxConnectionsPerHost = config != nullptr ? config->MaxConnsPerHost : DefaultMaxConnsPerHost;
    apiOptions.IdleTimeoutMilliseconds = config != nullptr ? config->IdleTimeoutMs : DefaultIdleTimeoutMs;

    if (config != nullptr) {
        detail::FillApiTlsOptions(config->Tls, apiOptions.Tls);
    }
    else {
        TlsConfig defaultTls = {};
        detail::FillApiTlsOptions(defaultTls, apiOptions.Tls);
    }

    api::KH_SESSION apiSession = nullptr;
    NTSTATUS status = api::KhSessionCreate(wskClient, &apiOptions, &apiSession);
    if (NT_SUCCESS(status) && out != nullptr) {
        *out = detail::FromApiSession(apiSession);
    }
    return status;
}

void SessionClose(Session* session) noexcept
{
    api::KhSessionClose(detail::ToApiSession(session));
}

NTSTATUS RequestCreate(Session* session, Request** out) noexcept
{
    if (out != nullptr) {
        *out = nullptr;
    }
    api::KH_REQUEST apiRequest = nullptr;
    NTSTATUS status = api::KhHttpRequestCreate(detail::ToApiSession(session), &apiRequest);
    if (NT_SUCCESS(status) && out != nullptr) {
        *out = detail::FromApiRequest(apiRequest);
    }
    return status;
}

void RequestRelease(Request* request) noexcept
{
    api::KhHttpRequestRelease(detail::ToApiRequest(request));
}

NTSTATUS RequestSetUrl(Request* request, const char* url, SIZE_T urlLength) noexcept
{
    return api::KhHttpRequestSetUrl(detail::ToApiRequest(request), url, urlLength);
}

NTSTATUS RequestSetMethod(Request* request, Method method) noexcept
{
    return api::KhHttpRequestSetMethod(detail::ToApiRequest(request), detail::ToApiMethod(method));
}

NTSTATUS RequestSetHeader(
    Request* request,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength) noexcept
{
    return api::KhHttpRequestSetHeader(detail::ToApiRequest(request), name, nameLength, value, valueLength);
}

NTSTATUS RequestSetBody(Request* request, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return api::KhHttpRequestSetBody(detail::ToApiRequest(request), data, dataLength);
}

NTSTATUS RequestClearBody(Request* request) noexcept
{
    return api::KhHttpRequestClearBody(detail::ToApiRequest(request));
}

NTSTATUS RequestSetTextBody(
    Request* request,
    const char* text,
    SIZE_T textLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return api::KhHttpRequestSetTextBody(
        detail::ToApiRequest(request),
        text,
        textLength,
        contentType,
        contentTypeLength);
}

NTSTATUS RequestSetJsonBody(Request* request, const char* json, SIZE_T jsonLength) noexcept
{
    static const char kJsonContentType[] = "application/json; charset=utf-8";
    constexpr SIZE_T kJsonContentTypeLength = sizeof(kJsonContentType) - 1;
    return api::KhHttpRequestSetRawBody(
        detail::ToApiRequest(request),
        reinterpret_cast<const UCHAR*>(json),
        jsonLength,
        kJsonContentType,
        kJsonContentTypeLength);
}

NTSTATUS RequestSetRawBody(
    Request* request,
    const UCHAR* data,
    SIZE_T dataLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return api::KhHttpRequestSetRawBody(
        detail::ToApiRequest(request),
        data,
        dataLength,
        contentType,
        contentTypeLength);
}

NTSTATUS RequestSetFormBody(Request* request, const NameValuePair* pairs, SIZE_T pairCount) noexcept
{
    if (pairs == nullptr || pairCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    api::KhNameValuePair stack[16] = {};
    api::KhNameValuePair* apiPairs = stack;
    if (pairCount > 16) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    for (SIZE_T index = 0; index < pairCount; ++index) {
        apiPairs[index].Name = pairs[index].Name;
        apiPairs[index].NameLength = pairs[index].NameLength;
        apiPairs[index].Value = pairs[index].Value;
        apiPairs[index].ValueLength = pairs[index].ValueLength;
    }
    return api::KhHttpRequestSetUrlEncodedBody(detail::ToApiRequest(request), apiPairs, pairCount);
}

NTSTATUS RequestSetMultipartBody(Request* request, const MultipartPart* parts, SIZE_T partCount) noexcept
{
    if (parts == nullptr || partCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (partCount > 16) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    api::KhMultipartFormDataPart stack[16] = {};
    for (SIZE_T index = 0; index < partCount; ++index) {
        stack[index].Kind = detail::ToApiBodyPartKind(parts[index].Kind);
        stack[index].Name = parts[index].Name;
        stack[index].NameLength = parts[index].NameLength;
        stack[index].Value = parts[index].Value;
        stack[index].ValueLength = parts[index].ValueLength;
        stack[index].Data = parts[index].Data;
        stack[index].DataLength = parts[index].DataLength;
        stack[index].FilePath = parts[index].FilePath;
        stack[index].FilePathLength = parts[index].FilePathLength;
        stack[index].FileName = parts[index].FileName;
        stack[index].FileNameLength = parts[index].FileNameLength;
        stack[index].ContentType = parts[index].ContentType;
        stack[index].ContentTypeLength = parts[index].ContentTypeLength;
    }
    return api::KhHttpRequestSetMultipartFormDataBody(detail::ToApiRequest(request), stack, partCount);
}

NTSTATUS RequestSetFileBody(
    Request* request,
    const char* filePath,
    SIZE_T filePathLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return api::KhHttpRequestSetFileBody(
        detail::ToApiRequest(request),
        filePath,
        filePathLength,
        contentType,
        contentTypeLength);
}

NTSTATUS RequestSetTls(Request* request, const TlsConfig* config) noexcept
{
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    api::KhTlsOptions options = {};
    detail::FillApiTlsOptions(*config, options);
    return api::KhHttpRequestSetTlsOptions(detail::ToApiRequest(request), &options);
}

NTSTATUS RequestSetConnPolicy(Request* request, ConnPolicy policy) noexcept
{
    return api::KhHttpRequestSetConnectionPolicy(detail::ToApiRequest(request), detail::ToApiConnPolicy(policy));
}

NTSTATUS RequestSetAddressFamily(Request* request, AddressFamily family) noexcept
{
    return api::KhHttpRequestSetAddressFamily(detail::ToApiRequest(request), detail::ToApiAddressFamily(family));
}

ULONG ResponseStatusCode(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    api::KhResponseView view = {};
    NTSTATUS status = api::KhResponseGetView(
        const_cast<api::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.StatusCode : 0;
}

const UCHAR* ResponseBody(const Response* response) noexcept
{
    if (response == nullptr) {
        return nullptr;
    }
    api::KhResponseView view = {};
    NTSTATUS status = api::KhResponseGetView(
        const_cast<api::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.Body : nullptr;
}

SIZE_T ResponseBodyLength(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    api::KhResponseView view = {};
    NTSTATUS status = api::KhResponseGetView(
        const_cast<api::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.BodyLength : 0;
}

NTSTATUS ResponseGetHeader(
    const Response* response,
    const char* name,
    SIZE_T nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept
{
    return api::KhResponseGetHeader(
        const_cast<api::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        name,
        nameLength,
        value,
        valueLength);
}

void ResponseRelease(Response* response) noexcept
{
    api::KhResponseRelease(detail::ToApiResponse(response));
}

NTSTATUS Get(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Get, url, urlLength, nullptr, 0, response);
}

NTSTATUS Post(Session* session, const char* url, SIZE_T urlLength, const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Post, url, urlLength, body, bodyLength, response);
}

NTSTATUS Put(Session* session, const char* url, SIZE_T urlLength, const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Put, url, urlLength, body, bodyLength, response);
}

NTSTATUS Patch(Session* session, const char* url, SIZE_T urlLength, const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Patch, url, urlLength, body, bodyLength, response);
}

NTSTATUS Delete(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Delete, url, urlLength, nullptr, 0, response);
}

NTSTATUS Head(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Head, url, urlLength, nullptr, 0, response);
}

NTSTATUS Options(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Options, url, urlLength, nullptr, 0, response);
}

NTSTATUS Send(Session* session, Request* request, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    api::KH_RESPONSE apiResp = nullptr;
    NTSTATUS status = api::KhHttpSendSync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        nullptr,
        &apiResp);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    else if (apiResp != nullptr) {
        api::KhResponseRelease(apiResp);
    }
    return status;
}

NTSTATUS SendEx(
    Session* session,
    Request* request,
    const SendOptions* options,
    Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }

    api::KhHttpSendOptions apiOptions = {};
    if (options != nullptr) {
        FillApiSendOptions(*options, apiOptions);
    }

    api::KH_RESPONSE apiResp = nullptr;
    NTSTATUS status = api::KhHttpSendSync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        options != nullptr ? &apiOptions : nullptr,
        response != nullptr ? &apiResp : nullptr);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    else if (apiResp != nullptr) {
        api::KhResponseRelease(apiResp);
    }
    return status;
}

NTSTATUS GetAsync(Session* session, const char* url, SIZE_T urlLength, AsyncOp** operation) noexcept
{
    return DoSimpleSendAsync(session, Method::Get, url, urlLength, nullptr, 0, operation);
}

NTSTATUS PostAsync(
    Session* session,
    const char* url,
    SIZE_T urlLength,
    const UCHAR* body,
    SIZE_T bodyLength,
    AsyncOp** operation) noexcept
{
    return DoSimpleSendAsync(session, Method::Post, url, urlLength, body, bodyLength, operation);
}

NTSTATUS SendAsync(Session* session, Request* request, AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    api::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = api::KhHttpSendAsync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        nullptr,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS SendAsyncEx(
    Session* session,
    Request* request,
    const SendOptions* options,
    AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }

    api::KhHttpSendOptions apiOptions = {};
    if (options != nullptr) {
        FillApiSendOptions(*options, apiOptions);
    }

    api::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = api::KhHttpSendAsync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        options != nullptr ? &apiOptions : nullptr,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS AsyncWait(AsyncOp* operation, ULONG timeoutMs) noexcept
{
    return api::KhAsyncWait(detail::ToApiAsyncOp(operation), timeoutMs);
}

NTSTATUS AsyncCancel(AsyncOp* operation) noexcept
{
    return api::KhAsyncCancel(detail::ToApiAsyncOp(operation));
}

NTSTATUS AsyncGetStatus(const AsyncOp* operation) noexcept
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    return api::KhTestAsyncStatus(const_cast<api::KH_ASYNC_OPERATION>(
        reinterpret_cast<const api::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return reinterpret_cast<const api::KhAsyncOperation*>(operation)->Status;
#endif
}

bool AsyncIsCompleted(const AsyncOp* operation) noexcept
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    return api::KhTestAsyncIsCompleted(const_cast<api::KH_ASYNC_OPERATION>(
        reinterpret_cast<const api::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return reinterpret_cast<const api::KhAsyncOperation*>(operation)->State == api::KhAsyncState::Completed;
#endif
}

bool AsyncIsCanceled(const AsyncOp* operation) noexcept
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    return api::KhTestAsyncIsCanceled(const_cast<api::KH_ASYNC_OPERATION>(
        reinterpret_cast<const api::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return reinterpret_cast<const api::KhAsyncOperation*>(operation)->Canceled != 0;
#endif
}

NTSTATUS AsyncGetResponse(AsyncOp* operation, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    api::KH_RESPONSE apiResp = nullptr;
    NTSTATUS status = api::KhAsyncGetHttpResponse(detail::ToApiAsyncOp(operation), &apiResp);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    return status;
}

NTSTATUS AsyncGetWebSocket(AsyncOp* operation, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    api::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = api::KhAsyncGetWebSocket(detail::ToApiAsyncOp(operation), &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = detail::FromApiWebSocket(apiWs);
    }
    return status;
}

void AsyncRelease(AsyncOp* operation) noexcept
{
    api::KhAsyncRelease(detail::ToApiAsyncOp(operation));
}

namespace
{
    void FillApiWsConnectOptions(
        const WsConnectConfig& src,
        api::KhWebSocketConnectOptions& dst) noexcept
    {
        dst.Url = src.Url;
        dst.UrlLength = src.UrlLength;
        dst.Subprotocol = src.Subprotocol;
        dst.SubprotocolLength = src.SubprotocolLength;
        detail::FillApiTlsOptions(src.Tls, dst.Tls);
        dst.AddressFamily = detail::ToApiAddressFamily(src.Family);
        dst.MaxMessageBytes = src.MaxMessageBytes;
        dst.AutoReplyPing = src.AutoReplyPing;
    }
}

NTSTATUS WsConnect(Session* session, const char* url, SIZE_T urlLength, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    if (url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    WsConnectConfig config = {};
    config.Url = url;
    config.UrlLength = urlLength;
    return WsConnectEx(session, &config, websocket);
}

NTSTATUS WsConnectEx(Session* session, const WsConnectConfig* config, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    api::KhWebSocketConnectOptions apiOptions = {};
    FillApiWsConnectOptions(*config, apiOptions);

    api::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = api::KhWebSocketConnectSync(
        detail::ToApiSession(session),
        &apiOptions,
        &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = detail::FromApiWebSocket(apiWs);
    }
    return status;
}

NTSTATUS WsConnectAsync(Session* session, const char* url, SIZE_T urlLength, AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    WsConnectConfig config = {};
    config.Url = url;
    config.UrlLength = urlLength;
    return WsConnectAsyncEx(session, &config, operation);
}

NTSTATUS WsConnectAsyncEx(Session* session, const WsConnectConfig* config, AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    api::KhWebSocketConnectOptions apiOptions = {};
    FillApiWsConnectOptions(*config, apiOptions);

    api::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = api::KhWebSocketConnectAsync(
        detail::ToApiSession(session),
        &apiOptions,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS WsSendText(WebSocket* websocket, const char* text, SIZE_T textLength) noexcept
{
    return api::KhWebSocketSendTextSync(detail::ToApiWebSocket(websocket), text, textLength, nullptr);
}

NTSTATUS WsSendTextEx(
    WebSocket* websocket,
    const char* text,
    SIZE_T textLength,
    const WsSendOptions* options) noexcept
{
    api::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return api::KhWebSocketSendTextSync(
        detail::ToApiWebSocket(websocket),
        text,
        textLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS WsSendBinary(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return api::KhWebSocketSendBinarySync(detail::ToApiWebSocket(websocket), data, dataLength, nullptr);
}

NTSTATUS WsSendBinaryEx(
    WebSocket* websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const WsSendOptions* options) noexcept
{
    api::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return api::KhWebSocketSendBinarySync(
        detail::ToApiWebSocket(websocket),
        data,
        dataLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS WsReceive(WebSocket* websocket, WsMessage* message) noexcept
{
    if (message != nullptr) {
        *message = {};
    }
    api::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = api::KhWebSocketReceiveSync(
        detail::ToApiWebSocket(websocket),
        nullptr,
        &apiMessage);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = detail::FromApiWsMsgType(apiMessage.Type);
        message->Data = apiMessage.Data;
        message->DataLength = apiMessage.DataLength;
        message->FinalFragment = apiMessage.FinalFragment;
    }
    return status;
}

NTSTATUS WsReceiveEx(
    WebSocket* websocket,
    const WsReceiveOptions* options,
    WsMessage* message) noexcept
{
    if (message != nullptr) {
        *message = {};
    }

    api::KhWebSocketReceiveOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.MaxMessageBytes = options->MaxMessageBytes;
        apiOptions.AutoAllocate = options->AutoAllocate;
        apiOptions.MessageCallback = reinterpret_cast<api::KhWebSocketMessageCallback>(options->OnMessage);
        apiOptions.CallbackContext = options->CallbackContext;
    }

    api::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = api::KhWebSocketReceiveSync(
        detail::ToApiWebSocket(websocket),
        options != nullptr ? &apiOptions : nullptr,
        message != nullptr ? &apiMessage : nullptr);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = detail::FromApiWsMsgType(apiMessage.Type);
        message->Data = apiMessage.Data;
        message->DataLength = apiMessage.DataLength;
        message->FinalFragment = apiMessage.FinalFragment;
    }
    return status;
}

NTSTATUS WsClose(WebSocket* websocket) noexcept
{
    return api::KhWebSocketCloseSync(detail::ToApiWebSocket(websocket));
}

}
}
