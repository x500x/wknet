#include "samples/KhttpSamples.h"

#include "khttp/AsyncOp.h"
#include "khttp/Http.h"
#include "khttp/HttpAsync.h"
#include "khttp/Request.h"
#include "khttp/Response.h"
#include "khttp/Session.h"
#include "khttp/WebSocket.h"

namespace KernelHttp
{
namespace samples
{
namespace
{
    constexpr ULONG AsyncWaitTimeoutMs = 60000;

    constexpr const char* HttpGetUrl = "http://nghttp2.org/httpbin/get";
    constexpr const char* HttpPostUrl = "http://nghttp2.org/httpbin/post";
    constexpr const char* HttpPutUrl = "http://nghttp2.org/httpbin/put";
    constexpr const char* HttpPatchUrl = "http://nghttp2.org/httpbin/patch";
    constexpr const char* HttpDeleteUrl = "http://nghttp2.org/httpbin/delete";
    constexpr const char* HttpHeadUrl = "http://nghttp2.org/httpbin/get";
    constexpr const char* HttpOptionsUrl = "http://nghttp2.org/httpbin/";
    constexpr const char* HttpsGetUrl = "https://nghttp2.org/httpbin/get";
    constexpr const char* HttpsBuilderUrl = "https://nghttp2.org/httpbin/anything";
    constexpr const char* WebSocketEchoUrl = "wss://ws.postman-echo.com/raw";

    constexpr const char* JsonBody = "{\"hello\":\"world\"}";
    constexpr const char* WsHelloMessage = "hello-from-khttp";

    SIZE_T LiteralLength(const char* value) noexcept
    {
        SIZE_T length = 0;
        if (value == nullptr) {
            return 0;
        }
        while (value[length] != '\0') {
            ++length;
        }
        return length;
    }

    void CaptureResponse(KhttpSampleResult& result, NTSTATUS status, khttp::Response* response) noexcept
    {
        result.Status = status;
        if (response == nullptr) {
            result.StatusCode = 0;
            result.BodyLength = 0;
            return;
        }
        result.StatusCode = khttp::ResponseStatusCode(response);
        result.BodyLength = khttp::ResponseBodyLength(response);
    }

    NTSTATUS RunSimpleSync(
        khttp::Session* session,
        khttp::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        KhttpSampleResult& result) noexcept
    {
        khttp::Response* response = nullptr;
        NTSTATUS status = STATUS_SUCCESS;
        const SIZE_T urlLength = LiteralLength(url);

        switch (method) {
        case khttp::Method::Get:
            status = khttp::Get(session, url, urlLength, &response);
            break;
        case khttp::Method::Post:
            status = khttp::Post(session, url, urlLength, body, bodyLength, &response);
            break;
        case khttp::Method::Put:
            status = khttp::Put(session, url, urlLength, body, bodyLength, &response);
            break;
        case khttp::Method::Patch:
            status = khttp::Patch(session, url, urlLength, body, bodyLength, &response);
            break;
        case khttp::Method::Delete:
            status = khttp::Delete(session, url, urlLength, &response);
            break;
        case khttp::Method::Head:
            status = khttp::Head(session, url, urlLength, &response);
            break;
        case khttp::Method::Options:
            status = khttp::Options(session, url, urlLength, &response);
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        CaptureResponse(result, status, response);
        khttp::ResponseRelease(response);
        return status;
    }

    NTSTATUS RunSimpleAsyncGet(
        khttp::Session* session,
        const char* url,
        KhttpSampleResult& result) noexcept
    {
        khttp::AsyncOp* op = nullptr;
        NTSTATUS status = khttp::GetAsync(session, url, LiteralLength(url), &op);
        if (!NT_SUCCESS(status)) {
            result.Status = status;
            return status;
        }

        status = khttp::AsyncWait(op, AsyncWaitTimeoutMs);
        khttp::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            status = khttp::AsyncGetResponse(op, &response);
        }
        CaptureResponse(result, status, response);
        khttp::ResponseRelease(response);
        khttp::AsyncRelease(op);
        return status;
    }

    NTSTATUS RunHttpsRequestBuilder(
        khttp::Session* session,
        KhttpSampleResult& result) noexcept
    {
        khttp::Request* request = nullptr;
        NTSTATUS status = khttp::RequestCreate(session, &request);
        if (!NT_SUCCESS(status)) {
            result.Status = status;
            return status;
        }

        const SIZE_T urlLength = LiteralLength(HttpsBuilderUrl);
        status = khttp::RequestSetUrl(request, HttpsBuilderUrl, urlLength);
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetMethod(request, khttp::Method::Post);
        }
        if (NT_SUCCESS(status)) {
            const char* userAgent = "KernelHttp/0.1";
            status = khttp::RequestSetHeader(
                request,
                "User-Agent",
                LiteralLength("User-Agent"),
                userAgent,
                LiteralLength(userAgent));
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetJsonBody(request, JsonBody, LiteralLength(JsonBody));
        }

        khttp::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            status = khttp::Send(session, request, &response);
        }
        CaptureResponse(result, status, response);
        khttp::ResponseRelease(response);
        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS RunWebSocketEcho(
        khttp::Session* session,
        KhttpSampleResult& result) noexcept
    {
        khttp::WebSocket* websocket = nullptr;
        NTSTATUS status = khttp::WsConnect(
            session,
            WebSocketEchoUrl,
            LiteralLength(WebSocketEchoUrl),
            &websocket);
        if (!NT_SUCCESS(status)) {
            result.Status = status;
            return status;
        }

        status = khttp::WsSendText(websocket, WsHelloMessage, LiteralLength(WsHelloMessage));

        khttp::WsMessage message = {};
        if (NT_SUCCESS(status)) {
            status = khttp::WsReceive(websocket, &message);
        }

        result.Status = status;
        result.StatusCode = NT_SUCCESS(status) ? 1 : 0;
        result.BodyLength = message.DataLength;

        const NTSTATUS closeStatus = khttp::WsClose(websocket);
        if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
            result.Status = closeStatus;
            return closeStatus;
        }
        return status;
    }
}

NTSTATUS RunKhttpSamples(khttp::Session* session, KhttpSampleResults* results) noexcept
{
    if (session == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *results = {};

    NTSTATUS aggregate = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    const UCHAR* jsonBytes = reinterpret_cast<const UCHAR*>(JsonBody);
    const SIZE_T jsonLen = LiteralLength(JsonBody);

    status = RunSimpleSync(session, khttp::Method::Get, HttpGetUrl, nullptr, 0, results->HttpGet);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleAsyncGet(session, HttpGetUrl, results->HttpGetAsync);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleSync(session, khttp::Method::Post, HttpPostUrl, jsonBytes, jsonLen, results->HttpPost);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    {
        khttp::AsyncOp* op = nullptr;
        status = khttp::PostAsync(session, HttpPostUrl, LiteralLength(HttpPostUrl), jsonBytes, jsonLen, &op);
        if (NT_SUCCESS(status)) {
            status = khttp::AsyncWait(op, AsyncWaitTimeoutMs);
            khttp::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = khttp::AsyncGetResponse(op, &response);
            }
            CaptureResponse(results->HttpPostAsync, status, response);
            khttp::ResponseRelease(response);
            khttp::AsyncRelease(op);
        }
        else {
            results->HttpPostAsync.Status = status;
        }
        if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;
    }

    status = RunSimpleSync(session, khttp::Method::Put, HttpPutUrl, jsonBytes, jsonLen, results->HttpPut);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleSync(session, khttp::Method::Patch, HttpPatchUrl, jsonBytes, jsonLen, results->HttpPatch);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleSync(session, khttp::Method::Delete, HttpDeleteUrl, nullptr, 0, results->HttpDelete);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleSync(session, khttp::Method::Head, HttpHeadUrl, nullptr, 0, results->HttpHead);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleSync(session, khttp::Method::Options, HttpOptionsUrl, nullptr, 0, results->HttpOptions);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleSync(session, khttp::Method::Get, HttpsGetUrl, nullptr, 0, results->HttpsVerifyGet);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    {
        khttp::Request* request = nullptr;
        status = khttp::RequestCreate(session, &request);
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetUrl(request, HttpsGetUrl, LiteralLength(HttpsGetUrl));
            if (NT_SUCCESS(status)) {
                khttp::TlsConfig tls = {};
                tls.Certificate = khttp::CertPolicy::NoVerify;
                status = khttp::RequestSetTls(request, &tls);
            }
            khttp::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = khttp::Send(session, request, &response);
            }
            CaptureResponse(results->HttpsNoVerifyGet, status, response);
            khttp::ResponseRelease(response);
            khttp::RequestRelease(request);
        }
        else {
            results->HttpsNoVerifyGet.Status = status;
        }
        if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;
    }

    status = RunHttpsRequestBuilder(session, results->HttpsRequestBuilder);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunWebSocketEcho(session, results->WebSocketEcho);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    return aggregate;
}
}
}
