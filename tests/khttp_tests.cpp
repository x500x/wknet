#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/api/KernelHttpApi.h"
#include "../src/KernelHttp/khttp/AsyncOp.h"
#include "../src/KernelHttp/khttp/Http.h"
#include "../src/KernelHttp/khttp/HttpAsync.h"
#include "../src/KernelHttp/khttp/Request.h"
#include "../src/KernelHttp/khttp/Response.h"
#include "../src/KernelHttp/khttp/Session.h"
#include "../src/KernelHttp/khttp/WebSocket.h"

#include <stdio.h>
#include <string.h>

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    SIZE_T Length(const char* literal) noexcept
    {
        SIZE_T length = 0;
        while (literal[length] != '\0') {
            ++length;
        }
        return length;
    }

    struct CapturedRequest
    {
        char Scheme[8] = {};
        SIZE_T SchemeLength = 0;
        char Host[64] = {};
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        char Body[256] = {};
        SIZE_T BodyLength = 0;
        SIZE_T CallCount = 0;
        const char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
    };

    NTSTATUS TestTransport(
        void* context,
        const KernelHttp::api::KhTestHttpTransportRequest* request,
        KernelHttp::api::KhTestHttpTransportResponse* response) noexcept
    {
        auto* captured = static_cast<CapturedRequest*>(context);
        if (captured == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++captured->CallCount;
        captured->Port = request->Port;
        captured->SchemeLength = request->SchemeLength < sizeof(captured->Scheme) - 1
            ? request->SchemeLength
            : sizeof(captured->Scheme) - 1;
        memcpy(captured->Scheme, request->Scheme, captured->SchemeLength);
        captured->Scheme[captured->SchemeLength] = '\0';
        captured->HostLength = request->HostLength < sizeof(captured->Host) - 1
            ? request->HostLength
            : sizeof(captured->Host) - 1;
        memcpy(captured->Host, request->Host, captured->HostLength);
        captured->Host[captured->HostLength] = '\0';

        const char* requestBytes = request->BuiltRequest;
        SIZE_T requestLength = request->BuiltRequestLength;
        const char* bodyMarker = "\r\n\r\n";
        const SIZE_T markerLength = 4;
        for (SIZE_T index = 0; index + markerLength <= requestLength; ++index) {
            if (memcmp(requestBytes + index, bodyMarker, markerLength) == 0) {
                const char* bodyStart = requestBytes + index + markerLength;
                SIZE_T bodyLength = requestLength - (index + markerLength);
                if (bodyLength >= sizeof(captured->Body)) {
                    bodyLength = sizeof(captured->Body) - 1;
                }
                memcpy(captured->Body, bodyStart, bodyLength);
                captured->Body[bodyLength] = '\0';
                captured->BodyLength = bodyLength;
                break;
            }
        }

        response->RawResponse = captured->RawResponse;
        response->RawResponseLength = captured->RawResponseLength;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    struct WsCapture
    {
        SIZE_T ConnectCount = 0;
        SIZE_T SendCount = 0;
        SIZE_T ReceiveCount = 0;
        SIZE_T CloseCount = 0;
        char LastScheme[8] = {};
        SIZE_T LastSchemeLength = 0;
        char LastHost[64] = {};
        SIZE_T LastHostLength = 0;
        char LastSendBuffer[64] = {};
        SIZE_T LastSendLength = 0;
        KernelHttp::api::KhWebSocketMessageType NextType = KernelHttp::api::KhWebSocketMessageType::Text;
        UCHAR NextData[64] = {};
        SIZE_T NextLength = 0;
    };

    NTSTATUS WsConnectCallback(
        void* context,
        const KernelHttp::api::KhTestWebSocketConnectRequest* request) noexcept
    {
        auto* capture = static_cast<WsCapture*>(context);
        if (capture == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ++capture->ConnectCount;
        capture->LastSchemeLength = request->SchemeLength < sizeof(capture->LastScheme) - 1
            ? request->SchemeLength
            : sizeof(capture->LastScheme) - 1;
        memcpy(capture->LastScheme, request->Scheme, capture->LastSchemeLength);
        capture->LastScheme[capture->LastSchemeLength] = '\0';
        capture->LastHostLength = request->HostLength < sizeof(capture->LastHost) - 1
            ? request->HostLength
            : sizeof(capture->LastHost) - 1;
        memcpy(capture->LastHost, request->Host, capture->LastHostLength);
        capture->LastHost[capture->LastHostLength] = '\0';
        return STATUS_SUCCESS;
    }

    NTSTATUS WsSendCallback(
        void* context,
        KernelHttp::api::KH_WEBSOCKET websocket,
        KernelHttp::api::KhWebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        UNREFERENCED_PARAMETER(type);
        UNREFERENCED_PARAMETER(finalFragment);
        auto* capture = static_cast<WsCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ++capture->SendCount;
        const SIZE_T copy = dataLength < sizeof(capture->LastSendBuffer) - 1
            ? dataLength
            : sizeof(capture->LastSendBuffer) - 1;
        memcpy(capture->LastSendBuffer, data, copy);
        capture->LastSendBuffer[copy] = '\0';
        capture->LastSendLength = copy;
        return STATUS_SUCCESS;
    }

    NTSTATUS WsReceiveCallback(
        void* context,
        KernelHttp::api::KH_WEBSOCKET websocket,
        KernelHttp::api::KhTestWebSocketMessage* message) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WsCapture*>(context);
        if (capture == nullptr || message == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ++capture->ReceiveCount;
        message->Type = capture->NextType;
        message->Data = capture->NextData;
        message->DataLength = capture->NextLength;
        message->FinalFragment = true;
        return STATUS_SUCCESS;
    }

    void WsCloseCallback(void* context, KernelHttp::api::KH_WEBSOCKET websocket) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WsCapture*>(context);
        if (capture != nullptr) {
            ++capture->CloseCount;
        }
    }

    void TestSessionCreateAndClose() noexcept
    {
        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");
        Expect(session != nullptr, "Session pointer non-null");
        KernelHttp::khttp::SessionClose(session);
    }

    void TestSimpleGet() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        KernelHttp::api::KhTestSetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://example.com/test";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds");
        Expect(captured.CallCount == 1, "transport called once");
        Expect(strcmp(captured.Host, "example.com") == 0, "host captured");
        Expect(captured.Port == 80, "port is 80");

        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "status code is 200");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == 5, "body length is 5");
        const UCHAR* body = KernelHttp::khttp::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, "hello", 5) == 0, "body content is hello");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::api::KhTestSetHttpTransport(nullptr, nullptr);
    }

    void TestPostWithBody() noexcept
    {
        const char* response =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        KernelHttp::api::KhTestSetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        const char* url = "http://example.com/api";
        const char* body = "payload-bytes";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Post(
            session,
            url,
            Length(url),
            reinterpret_cast<const UCHAR*>(body),
            Length(body),
            &resp);
        Expect(NT_SUCCESS(status), "Post succeeds");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 201, "status code is 201");
        Expect(captured.BodyLength == Length(body), "body length passed through");
        Expect(memcmp(captured.Body, body, Length(body)) == 0, "body content passed through");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::api::KhTestSetHttpTransport(nullptr, nullptr);
    }

    void TestRequestBuilder() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        KernelHttp::api::KhTestSetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds");

        const char* url = "http://example.com/v1/data";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds");

        status = KernelHttp::khttp::RequestSetMethod(request, KernelHttp::khttp::Method::Put);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds");

        const char* json = "{\"key\":\"value\"}";
        status = KernelHttp::khttp::RequestSetJsonBody(request, json, Length(json));
        Expect(NT_SUCCESS(status), "RequestSetJsonBody succeeds");

        const char* hdrName = "X-Custom";
        const char* hdrValue = "abc";
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            hdrName, Length(hdrName),
            hdrValue, Length(hdrValue));
        Expect(NT_SUCCESS(status), "RequestSetHeader succeeds");

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, &resp);
        Expect(NT_SUCCESS(status), "Send succeeds");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "status code is 200");
        Expect(captured.BodyLength == Length(json), "json body length");
        Expect(memcmp(captured.Body, json, Length(json)) == 0, "json body content");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::api::KhTestSetHttpTransport(nullptr, nullptr);
    }

    void TestAsyncGet() noexcept
    {
        const char* response =
            "HTTP/1.1 202 Accepted\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "done";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        KernelHttp::api::KhTestSetHttpTransport(TestTransport, &captured);
        KernelHttp::api::KhTestSetAsyncAutoRun(true);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        const char* url = "http://example.com/async";
        KernelHttp::khttp::AsyncOp* op = nullptr;
        status = KernelHttp::khttp::GetAsync(session, url, Length(url), &op);
        Expect(NT_SUCCESS(status), "GetAsync succeeds");
        Expect(op != nullptr, "async op non-null");

        Expect(KernelHttp::khttp::AsyncIsCompleted(op), "async op completed under auto-run");
        Expect(NT_SUCCESS(KernelHttp::khttp::AsyncWait(op, 0)), "async wait returns success");

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::AsyncGetResponse(op, &resp);
        Expect(NT_SUCCESS(status), "AsyncGetResponse succeeds");
        Expect(resp != nullptr, "async response non-null");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 202, "async status code");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::AsyncRelease(op);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::api::KhTestSetHttpTransport(nullptr, nullptr);
    }

    void TestIrqlCheck() noexcept
    {
        KernelHttp::api::KhTestSetCurrentIrql(2);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "SessionCreate fails at non-PASSIVE");
        Expect(session == nullptr, "session not allocated at non-PASSIVE");

        KernelHttp::api::KhTestResetCurrentIrql();
    }

    void TestWebSocketRoundTrip() noexcept
    {
        WsCapture capture = {};
        const char* echo = "world";
        capture.NextType = KernelHttp::api::KhWebSocketMessageType::Text;
        capture.NextLength = Length(echo);
        memcpy(capture.NextData, echo, capture.NextLength);

        KernelHttp::api::KhTestSetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws");

        const char* url = "ws://example.com/socket";
        KernelHttp::khttp::WebSocket* ws = nullptr;
        status = KernelHttp::khttp::WsConnect(session, url, Length(url), &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds");
        Expect(capture.ConnectCount == 1, "connect called once");
        Expect(strcmp(capture.LastScheme, "ws") == 0, "scheme captured");
        Expect(strcmp(capture.LastHost, "example.com") == 0, "host captured");

        const char* hello = "hello";
        status = KernelHttp::khttp::WsSendText(ws, hello, Length(hello));
        Expect(NT_SUCCESS(status), "WsSendText succeeds");
        Expect(capture.SendCount == 1, "send called once");
        Expect(strcmp(capture.LastSendBuffer, hello) == 0, "send payload captured");

        KernelHttp::khttp::WsMessage message = {};
        status = KernelHttp::khttp::WsReceive(ws, &message);
        Expect(NT_SUCCESS(status), "WsReceive succeeds");
        Expect(message.Type == KernelHttp::khttp::WsMsgType::Text, "received type Text");
        Expect(message.DataLength == Length(echo), "received length matches");
        Expect(message.Data != nullptr && memcmp(message.Data, echo, message.DataLength) == 0,
            "received payload matches");

        status = KernelHttp::khttp::WsClose(ws);
        Expect(NT_SUCCESS(status), "WsClose succeeds");
        Expect(capture.CloseCount == 1, "close called once");

        KernelHttp::khttp::SessionClose(session);
        KernelHttp::api::KhTestSetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }
}

int main() noexcept
{
    KernelHttp::api::KhTestResetCurrentIrql();
    KernelHttp::api::KhTestSetAsyncAutoRun(true);

    TestSessionCreateAndClose();
    TestSimpleGet();
    TestPostWithBody();
    TestRequestBuilder();
    TestAsyncGet();
    TestIrqlCheck();
    TestWebSocketRoundTrip();

    if (g_failed) {
        printf("khttp tests FAILED\n");
        return 1;
    }
    printf("khttp tests passed\n");
    return 0;
}
