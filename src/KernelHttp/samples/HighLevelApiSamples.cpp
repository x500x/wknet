#include "samples/HighLevelApiSamples.h"

#include "khttp/AsyncOp.h"
#include "khttp/Http.h"
#include "khttp/HttpAsync.h"
#include "khttp/Request.h"
#include "khttp/Response.h"
#include "khttp/Session.h"
#include "khttp/WebSocket.h"
#include "samples/ExternalTrustStore.h"

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
    constexpr khttp::AddressFamily DefaultSampleAddressFamily = khttp::AddressFamily::Ipv4;

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

    void CaptureResponse(HighLevelApiSampleResult& result, NTSTATUS status, khttp::Response* response) noexcept
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

    NTSTATUS CreateSampleRequest(
        khttp::Session* session,
        khttp::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        const khttp::TlsConfig* tlsConfig,
        khttp::Request** request) noexcept
    {
        if (session == nullptr || url == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *request = nullptr;
        khttp::Request* newRequest = nullptr;
        NTSTATUS status = khttp::RequestCreate(session, &newRequest);
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetUrl(newRequest, url, LiteralLength(url));
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetMethod(newRequest, method);
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetAddressFamily(newRequest, DefaultSampleAddressFamily);
        }
        if (NT_SUCCESS(status) && tlsConfig != nullptr) {
            status = khttp::RequestSetTls(newRequest, tlsConfig);
        }
        if (NT_SUCCESS(status) && bodyLength != 0) {
            status = khttp::RequestSetBody(newRequest, body, bodyLength);
        }

        if (!NT_SUCCESS(status)) {
            khttp::RequestRelease(newRequest);
            return status;
        }

        *request = newRequest;
        return STATUS_SUCCESS;
    }

    NTSTATUS RunSimpleSync(
        khttp::Session* session,
        khttp::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        HighLevelApiSampleResult& result,
        const khttp::TlsConfig* tlsConfig = nullptr) noexcept
    {
        khttp::Request* request = nullptr;
        khttp::Response* response = nullptr;
        NTSTATUS status = CreateSampleRequest(session, method, url, body, bodyLength, tlsConfig, &request);
        if (NT_SUCCESS(status)) {
            status = khttp::Send(session, request, &response);
        }

        CaptureResponse(result, status, response);
        khttp::ResponseRelease(response);
        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS RunSimpleAsyncGet(
        khttp::Session* session,
        const char* url,
        HighLevelApiSampleResult& result) noexcept
    {
        khttp::Request* request = nullptr;
        khttp::AsyncOp* op = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            khttp::Method::Get,
            url,
            nullptr,
            0,
            nullptr,
            &request);
        if (NT_SUCCESS(status)) {
            status = khttp::SendAsync(session, request, &op);
        }
        if (!NT_SUCCESS(status)) {
            result.Status = status;
            khttp::RequestRelease(request);
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
        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS RunHttpsRequestBuilder(
        khttp::Session* session,
        HighLevelApiSampleResult& result,
        const khttp::TlsConfig& tlsConfig) noexcept
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
            status = khttp::RequestSetAddressFamily(request, DefaultSampleAddressFamily);
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetTls(request, &tlsConfig);
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
        HighLevelApiSampleResult& result,
        const khttp::TlsConfig& tlsConfig) noexcept
    {
        khttp::WebSocket* websocket = nullptr;
        khttp::WsConnectConfig config = khttp::DefaultWsConnectConfig();
        config.Url = WebSocketEchoUrl;
        config.UrlLength = LiteralLength(WebSocketEchoUrl);
        config.Tls = tlsConfig;
        config.Family = DefaultSampleAddressFamily;

        NTSTATUS status = khttp::WsConnect(session, &config, &websocket);
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

NTSTATUS RunHighLevelApiSamples(khttp::Session* session, HighLevelApiSampleResults* results) noexcept
{
    if (session == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *results = {};

    NTSTATUS aggregate = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    const UCHAR* jsonBytes = reinterpret_cast<const UCHAR*>(JsonBody);
    const SIZE_T jsonLen = LiteralLength(JsonBody);

    ExternalTrustStore trustStore = {};
    status = InitializeExternalTrustStore(trustStore);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    khttp::TlsConfig ngHttp2Tls = khttp::DefaultTlsConfig();
    ngHttp2Tls.Store = &trustStore.Store;

    khttp::TlsConfig webSocketTls = khttp::DefaultTlsConfig();
    webSocketTls.Store = &trustStore.Store;
    webSocketTls.MaxVersion = khttp::TlsVersion::Tls12;

    status = RunSimpleSync(session, khttp::Method::Get, HttpGetUrl, nullptr, 0, results->HttpGet);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleAsyncGet(session, HttpGetUrl, results->HttpGetAsync);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunSimpleSync(session, khttp::Method::Post, HttpPostUrl, jsonBytes, jsonLen, results->HttpPost);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    {
        khttp::AsyncOp* op = nullptr;
        khttp::Request* request = nullptr;
        status = CreateSampleRequest(
            session,
            khttp::Method::Post,
            HttpPostUrl,
            jsonBytes,
            jsonLen,
            nullptr,
            &request);
        if (NT_SUCCESS(status)) {
            status = khttp::SendAsync(session, request, &op);
        }
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
        khttp::RequestRelease(request);
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

    status = RunSimpleSync(
        session,
        khttp::Method::Get,
        HttpsGetUrl,
        nullptr,
        0,
        results->HttpsVerifyGet,
        &ngHttp2Tls);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    {
        khttp::Request* request = nullptr;
        status = khttp::RequestCreate(session, &request);
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetUrl(request, HttpsGetUrl, LiteralLength(HttpsGetUrl));
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetAddressFamily(request, DefaultSampleAddressFamily);
            }
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

    status = RunHttpsRequestBuilder(session, results->HttpsRequestBuilder, ngHttp2Tls);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    status = RunWebSocketEcho(session, results->WebSocketEcho, webSocketTls);
    if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) aggregate = status;

    ResetExternalTrustStore(trustStore);
    return aggregate;
}
}
}
