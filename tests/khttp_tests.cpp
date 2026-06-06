#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/KernelHttp.h>
#include <KernelHttp/khttp/Test.h>

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

    SIZE_T BuildLargeHttpResponse(char* buffer, SIZE_T capacity) noexcept
    {
        const char* header =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5000\r\n"
            "\r\n";
        const SIZE_T headerLength = Length(header);
        const SIZE_T bodyLength = 5000;
        if (buffer == nullptr || capacity < headerLength + bodyLength) {
            return 0;
        }

        memcpy(buffer, header, headerLength);
        for (SIZE_T index = 0; index < bodyLength; ++index) {
            buffer[headerLength + index] = 'a';
        }
        return headerLength + bodyLength;
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

    struct ReusedFailureCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
        SIZE_T NewConnectionCallCount = 0;
        ULONG FirstConnectionId = 0;
        ULONG RetryConnectionId = 0;
    };

    struct CompletionCapture
    {
        SIZE_T CallCount = 0;
        NTSTATUS LastStatus = STATUS_PENDING;
    };

    void RecordCompletion(void* context, NTSTATUS status) noexcept
    {
        auto* capture = static_cast<CompletionCapture*>(context);
        if (capture == nullptr) {
            return;
        }

        ++capture->CallCount;
        capture->LastStatus = status;
    }

    NTSTATUS TestTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
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

    NTSTATUS ReusedFailureTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<ReusedFailureCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (request->ReusedConnection) {
            ++capture->ReusedCallCount;
            return STATUS_CONNECTION_RESET;
        }

        ++capture->NewConnectionCallCount;
        if (capture->FirstConnectionId == 0) {
            capture->FirstConnectionId = request->ConnectionId;
        }
        else {
            capture->RetryConnectionId = request->ConnectionId;
        }

        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        response->RawResponse = responseBytes;
        response->RawResponseLength = sizeof(responseBytes) - 1;
        response->ConnectionReusable = true;
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
        KernelHttp::engine::KhWebSocketMessageType NextType = KernelHttp::engine::KhWebSocketMessageType::Text;
        UCHAR NextData[64] = {};
        SIZE_T NextLength = 0;
    };

    NTSTATUS WsConnectCallback(
        void* context,
        const KernelHttp::engine::KhTestWebSocketConnectRequest* request) noexcept
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
        KernelHttp::engine::KH_WEBSOCKET websocket,
        KernelHttp::engine::KhWebSocketMessageType type,
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
        KernelHttp::engine::KH_WEBSOCKET websocket,
        KernelHttp::engine::KhTestWebSocketMessage* message) noexcept
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

    void WsCloseCallback(void* context, KernelHttp::engine::KH_WEBSOCKET websocket) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WsCapture*>(context);
        if (capture != nullptr) {
            ++capture->CloseCount;
        }
    }

    void TestSessionCreateAndClose() noexcept
    {
        KernelHttp::khttp::SessionConfig config = KernelHttp::khttp::DefaultSessionConfig();
        KernelHttp::khttp::TlsConfig tls = KernelHttp::khttp::DefaultTlsConfig();
        UNREFERENCED_PARAMETER(config);
        UNREFERENCED_PARAMETER(tls);

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
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

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
        Expect(KernelHttp::khttp::ResponseHeaderCount(resp) == 2, "response header count is 2");

        const char* headerName = nullptr;
        SIZE_T headerNameLength = 0;
        const char* headerValue = nullptr;
        SIZE_T headerValueLength = 0;
        status = KernelHttp::khttp::ResponseGetHeaderAt(
            resp,
            0,
            &headerName,
            &headerNameLength,
            &headerValue,
            &headerValueLength);
        Expect(NT_SUCCESS(status), "first response header is readable");
        Expect(headerNameLength == Length("Content-Type") &&
            memcmp(headerName, "Content-Type", headerNameLength) == 0,
            "first response header name matches");
        Expect(headerValueLength == Length("text/plain") &&
            memcmp(headerValue, "text/plain", headerValueLength) == 0,
            "first response header value matches");

        status = KernelHttp::khttp::ResponseGetHeaderAt(
            resp,
            1,
            &headerName,
            &headerNameLength,
            &headerValue,
            &headerValueLength);
        Expect(NT_SUCCESS(status), "second response header is readable");
        Expect(headerNameLength == Length("Content-Length") &&
            memcmp(headerName, "Content-Length", headerNameLength) == 0,
            "second response header name matches");
        Expect(headerValueLength == Length("5") &&
            memcmp(headerValue, "5", headerValueLength) == 0,
            "second response header value matches");

        status = KernelHttp::khttp::ResponseGetHeaderAt(
            resp,
            2,
            &headerName,
            &headerNameLength,
            &headerValue,
            &headerValueLength);
        Expect(!NT_SUCCESS(status), "out-of-range response header is rejected");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestMaxResponseBytesZeroIsUnlimited() noexcept
    {
        char response[5100] = {};
        const SIZE_T responseLength = BuildLargeHttpResponse(response, sizeof(response));
        Expect(responseLength != 0, "large response fixture is built");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::SessionConfig config = KernelHttp::khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 64;

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate accepts unsigned max response limit");

        const char* url = "http://example.com/large";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get without options is unlimited");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == 5000, "unlimited default returns large body");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for max response test");
        if (NT_SUCCESS(status)) {
            status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
            Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for max response test");
        }

        KernelHttp::khttp::SendOptions limitedOptions = KernelHttp::khttp::DefaultSendOptions();
        limitedOptions.MaxResponseBytes = 64;
        status = KernelHttp::khttp::Send(session, request, &limitedOptions, &resp);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "explicit nonzero MaxResponseBytes limits response");
        Expect(resp == nullptr, "limited response is not allocated");

        KernelHttp::khttp::SendOptions unlimitedOptions = KernelHttp::khttp::DefaultSendOptions();
        unlimitedOptions.MaxResponseBytes = 0;
        status = KernelHttp::khttp::Send(session, request, &unlimitedOptions, &resp);
        Expect(NT_SUCCESS(status), "explicit zero MaxResponseBytes is unlimited");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == 5000, "explicit unlimited returns large body");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestReusedConnectionFailureRetriesWithFreshConnection() noexcept
    {
        ReusedFailureCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(ReusedFailureTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reused connection retry");

        const char* url = "http://example.com/retry";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first pooled Get succeeds");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "stale pooled Get retries with fresh connection");
        Expect(capture.CallCount == 3, "transport sees initial, failed reuse, and retry calls");
        Expect(capture.ReusedCallCount == 1, "one reused connection attempt fails");
        Expect(capture.NewConnectionCallCount == 2, "retry uses a fresh connection");
        Expect(capture.FirstConnectionId != 0, "first connection id captured");
        Expect(capture.RetryConnectionId != 0, "retry connection id captured");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "retry uses a different pool connection id");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "retry status code is 200");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestIdleTimeoutSkipsExpiredConnection() noexcept
    {
        ReusedFailureCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(ReusedFailureTransport, &capture);

        KernelHttp::khttp::SessionConfig config = {};
        config.IdleTimeoutMs = 1;

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for idle timeout");

        const char* url = "http://example.com/idle";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first idle-timeout Get succeeds");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "expired pooled Get creates a new connection");
        Expect(capture.CallCount == 2, "idle timeout avoids stale reuse attempt");
        Expect(capture.ReusedCallCount == 0, "expired connection is not reported as reused");
        Expect(capture.NewConnectionCallCount == 2, "idle timeout uses two new connections");
        Expect(capture.FirstConnectionId != 0, "first idle connection id captured");
        Expect(capture.RetryConnectionId != 0, "second idle connection id captured");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "idle timeout uses a different connection id");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
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
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

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
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
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
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

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
        KernelHttp::khttp::SendOptions sendOptions = KernelHttp::khttp::DefaultSendOptions();
        status = KernelHttp::khttp::Send(session, request, &sendOptions, &resp);
        Expect(NT_SUCCESS(status), "Send succeeds");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "status code is 200");
        Expect(captured.BodyLength == Length(json), "json body length");
        Expect(memcmp(captured.Body, json, Length(json)) == 0, "json body content");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
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
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);
        KernelHttp::khttp::test::SetAsyncAutoRun(true);

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

        KernelHttp::khttp::Response* secondResp = nullptr;
        status = KernelHttp::khttp::AsyncGetResponse(op, &secondResp);
        Expect(!NT_SUCCESS(status), "AsyncGetResponse only returns the response once");
        Expect(secondResp == nullptr, "second async response output stays null");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::AsyncRelease(op);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAsyncRequestIsCopied() noexcept
    {
        const char* response =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);
        KernelHttp::khttp::test::SetAsyncAutoRun(false);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for copied async request");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for copied async request");

        const char* url = "http://example.com/copied";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for copied async request");

        const char* body = "async-body";
        status = KernelHttp::khttp::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for copied async request");

        KernelHttp::khttp::AsyncOp* op = nullptr;
        status = KernelHttp::khttp::SendAsync(session, request, nullptr, &op);
        Expect(NT_SUCCESS(status), "SendAsync with options overload succeeds");
        KernelHttp::khttp::RequestRelease(request);

        status = KernelHttp::khttp::test::RunAsyncOperation(op);
        Expect(NT_SUCCESS(status), "manual async run succeeds after releasing request");
        Expect(captured.CallCount == 1, "copied async request transport called once");
        Expect(captured.BodyLength == Length(body), "copied async request body length");
        Expect(memcmp(captured.Body, body, Length(body)) == 0, "copied async request body content");

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::AsyncGetResponse(op, &resp);
        Expect(NT_SUCCESS(status), "AsyncGetResponse succeeds for copied async request");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 204, "copied async status code");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::AsyncRelease(op);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetAsyncAutoRun(true);
    }

    void TestAsyncCancelCompletionOnce() noexcept
    {
        KernelHttp::khttp::test::SetAsyncAutoRun(false);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for async cancel");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for async cancel");

        const char* url = "http://example.com/cancel";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for async cancel");

        CompletionCapture completion = {};
        KernelHttp::khttp::SendOptions options = {};
        options.OnComplete = RecordCompletion;
        options.CompletionContext = &completion;

        KernelHttp::khttp::AsyncOp* op = nullptr;
        status = KernelHttp::khttp::SendAsync(session, request, &options, &op);
        Expect(NT_SUCCESS(status), "SendAsync succeeds for async cancel");

        status = KernelHttp::khttp::AsyncCancel(op);
        Expect(NT_SUCCESS(status), "AsyncCancel succeeds");
        status = KernelHttp::khttp::test::RunAsyncOperation(op);
        Expect(status == STATUS_CANCELLED, "manual run preserves canceled status");
        Expect(completion.CallCount == 1, "completion callback fires once");
        Expect(completion.LastStatus == STATUS_CANCELLED, "completion status is canceled");

        KernelHttp::khttp::AsyncRelease(op);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetAsyncAutoRun(true);
    }

    void TestIrqlCheck() noexcept
    {
        KernelHttp::khttp::test::SetCurrentIrql(2);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "SessionCreate fails at non-PASSIVE");
        Expect(session == nullptr, "session not allocated at non-PASSIVE");

        KernelHttp::khttp::test::ResetCurrentIrql();

        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds before raised IRQL checks");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds before raised IRQL checks");

        KernelHttp::khttp::test::SetCurrentIrql(2);

        KernelHttp::khttp::Request* raisedRequest = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &raisedRequest);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "RequestCreate fails at non-PASSIVE");
        Expect(raisedRequest == nullptr, "request not allocated at non-PASSIVE");

        const char* url = "http://example.com/raised";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "RequestSetUrl fails at non-PASSIVE");

        KernelHttp::khttp::Response* response = nullptr;
        status = KernelHttp::khttp::Send(session, request, &response);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "Send fails at non-PASSIVE");
        Expect(response == nullptr, "response not allocated at non-PASSIVE");

        KernelHttp::khttp::test::ResetCurrentIrql();
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
    }

    void TestWebSocketRoundTrip() noexcept
    {
        WsCapture capture = {};
        const char* echo = "world";
        capture.NextType = KernelHttp::engine::KhWebSocketMessageType::Text;
        capture.NextLength = Length(echo);
        memcpy(capture.NextData, echo, capture.NextLength);

        KernelHttp::khttp::test::SetWebSocketTransport(
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
        KernelHttp::khttp::WsConnectConfig wsConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        status = KernelHttp::khttp::WsConnect(session, &wsConfig, &ws);
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
        Expect(message.Final, "received final flag matches");
        Expect(message.Data != nullptr && memcmp(message.Data, echo, message.DataLength) == 0,
            "received payload matches");

        status = KernelHttp::khttp::WsClose(ws);
        Expect(NT_SUCCESS(status), "WsClose succeeds");
        Expect(capture.CloseCount == 1, "close called once");

        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }
}

int main() noexcept
{
    KernelHttp::khttp::test::ResetCurrentIrql();
    KernelHttp::khttp::test::SetAsyncAutoRun(true);

    TestSessionCreateAndClose();
    TestSimpleGet();
    TestMaxResponseBytesZeroIsUnlimited();
    TestReusedConnectionFailureRetriesWithFreshConnection();
    TestIdleTimeoutSkipsExpiredConnection();
    TestPostWithBody();
    TestRequestBuilder();
    TestAsyncGet();
    TestAsyncRequestIsCopied();
    TestAsyncCancelCompletionOnce();
    TestIrqlCheck();
    TestWebSocketRoundTrip();

    if (g_failed) {
        printf("khttp tests FAILED\n");
        return 1;
    }
    printf("khttp tests passed\n");
    return 0;
}
