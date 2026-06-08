#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/KernelHttp.h>
#include <KernelHttp/engine/ConnectionPool.h>
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

    bool BufferContainsLiteral(const char* value, SIZE_T valueLength, const char* literal) noexcept
    {
        if (value == nullptr || literal == nullptr) {
            return false;
        }

        const SIZE_T literalLength = Length(literal);
        if (literalLength == 0 || literalLength > valueLength) {
            return false;
        }

        for (SIZE_T offset = 0; offset + literalLength <= valueLength; ++offset) {
            if (memcmp(value + offset, literal, literalLength) == 0) {
                return true;
            }
        }
        return false;
    }

    constexpr const char* EncodedBodyLiteral = "encoded response body";

    const unsigned char GzipBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xff, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49,
        0x4d, 0x51, 0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf,
        0x2b, 0x4e, 0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04,
        0x00, 0xec, 0xa9, 0xb0, 0x05, 0x15, 0x00, 0x00,
        0x00
    };

    SIZE_T BuildTransferGzipChunkedResponse(char* buffer, SIZE_T capacity) noexcept
    {
        if (buffer == nullptr) {
            return 0;
        }

        const int headerLength = snprintf(
            buffer,
            capacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: gzip, chunked\r\n"
            "\r\n"
            "%zx\r\n",
            sizeof(GzipBody));
        if (headerLength <= 0 || static_cast<SIZE_T>(headerLength) > capacity) {
            return 0;
        }

        SIZE_T cursor = static_cast<SIZE_T>(headerLength);
        if (sizeof(GzipBody) > capacity - cursor) {
            return 0;
        }

        memcpy(buffer + cursor, GzipBody, sizeof(GzipBody));
        cursor += sizeof(GzipBody);

        const char trailer[] = "\r\n0\r\n\r\n";
        if (sizeof(trailer) - 1 > capacity - cursor) {
            return 0;
        }

        memcpy(buffer + cursor, trailer, sizeof(trailer) - 1);
        cursor += sizeof(trailer) - 1;
        return cursor;
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
        SIZE_T ObservedBodyLength = 0;
        char BuiltRequest[1024] = {};
        SIZE_T BuiltRequestLength = 0;
        SIZE_T CallCount = 0;
        const char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
    };

    struct RedirectCapture
    {
        SIZE_T CallCount = 0;
        char Requests[8][512] = {};
        SIZE_T RequestLengths[8] = {};
    };

    struct RedirectMethodCapture
    {
        USHORT RedirectStatus = 302;
        SIZE_T CallCount = 0;
        char Requests[2][512] = {};
        SIZE_T RequestLengths[2] = {};
    };

    struct ReusedFailureCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
        SIZE_T NewConnectionCallCount = 0;
        ULONG FirstConnectionId = 0;
        ULONG RetryConnectionId = 0;
    };

    struct FreshTimeoutCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
        SIZE_T NewConnectionCallCount = 0;
        ULONG FirstConnectionId = 0;
        ULONG RetryConnectionId = 0;
    };

    struct ReuseDecisionCapture
    {
        const char* FirstResponse = nullptr;
        SIZE_T FirstResponseLength = 0;
        const char* SecondResponse = nullptr;
        SIZE_T SecondResponseLength = 0;
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
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
        captured->BuiltRequestLength = requestLength < sizeof(captured->BuiltRequest) - 1
            ? requestLength
            : sizeof(captured->BuiltRequest) - 1;
        memcpy(captured->BuiltRequest, requestBytes, captured->BuiltRequestLength);
        captured->BuiltRequest[captured->BuiltRequestLength] = '\0';

        const char* bodyMarker = "\r\n\r\n";
        const SIZE_T markerLength = 4;
        for (SIZE_T index = 0; index + markerLength <= requestLength; ++index) {
            if (memcmp(requestBytes + index, bodyMarker, markerLength) == 0) {
                const char* bodyStart = requestBytes + index + markerLength;
                SIZE_T bodyLength = requestLength - (index + markerLength);
                captured->ObservedBodyLength = bodyLength;
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

    void CaptureRedirectRequest(
        RedirectCapture& capture,
        const KernelHttp::engine::KhTestHttpTransportRequest& request) noexcept
    {
        if (capture.CallCount >= sizeof(capture.Requests) / sizeof(capture.Requests[0])) {
            return;
        }

        const SIZE_T index = capture.CallCount;
        const SIZE_T copy = request.BuiltRequestLength < sizeof(capture.Requests[index]) - 1
            ? request.BuiltRequestLength
            : sizeof(capture.Requests[index]) - 1;
        memcpy(capture.Requests[index], request.BuiltRequest, copy);
        capture.Requests[index][copy] = '\0';
        capture.RequestLengths[index] = copy;
    }

    NTSTATUS RedirectTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        CaptureRedirectRequest(*capture, *request);
        ++capture->CallCount;

        static const char redirectToSecond[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: /redirect/2\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectToFinal[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: /final\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "done";

        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, " /redirect/1 ")) {
            response->RawResponse = redirectToSecond;
            response->RawResponseLength = sizeof(redirectToSecond) - 1;
        }
        else if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, " /redirect/2 ")) {
            response->RawResponse = redirectToFinal;
            response->RawResponseLength = sizeof(redirectToFinal) - 1;
        }
        else if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, " /final ")) {
            response->RawResponse = finalResponse;
            response->RawResponseLength = sizeof(finalResponse) - 1;
        }
        else {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS RelativeRedirectTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        CaptureRedirectRequest(*capture, *request);
        ++capture->CallCount;

        static const char redirectToSibling[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: next\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectToParent[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: ../other?x=1\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectQueryOnly[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: ?page=2\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectToOtherOrigin[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: //other.example/final\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "done";

        switch (capture->CallCount) {
        case 1:
            response->RawResponse = redirectToSibling;
            response->RawResponseLength = sizeof(redirectToSibling) - 1;
            break;
        case 2:
            response->RawResponse = redirectToParent;
            response->RawResponseLength = sizeof(redirectToParent) - 1;
            break;
        case 3:
            response->RawResponse = redirectQueryOnly;
            response->RawResponseLength = sizeof(redirectQueryOnly) - 1;
            break;
        case 4:
            response->RawResponse = redirectToOtherOrigin;
            response->RawResponseLength = sizeof(redirectToOtherOrigin) - 1;
            break;
        case 5:
            response->RawResponse = finalResponse;
            response->RawResponseLength = sizeof(finalResponse) - 1;
            break;
        default:
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpsDowngradeRedirectTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        CaptureRedirectRequest(*capture, *request);
        ++capture->CallCount;

        static const char downgradeRedirect[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: http://secure.example/final\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        response->RawResponse = downgradeRedirect;
        response->RawResponseLength = sizeof(downgradeRedirect) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS RedirectMethodTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectMethodCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (capture->CallCount < sizeof(capture->Requests) / sizeof(capture->Requests[0])) {
            const SIZE_T index = capture->CallCount;
            const SIZE_T copy = request->BuiltRequestLength < sizeof(capture->Requests[index]) - 1
                ? request->BuiltRequestLength
                : sizeof(capture->Requests[index]) - 1;
            memcpy(capture->Requests[index], request->BuiltRequest, copy);
            capture->Requests[index][copy] = '\0';
            capture->RequestLengths[index] = copy;
        }
        ++capture->CallCount;

        static char redirectResponse[160] = {};
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        if (capture->CallCount == 1) {
            const int written = snprintf(
                redirectResponse,
                sizeof(redirectResponse),
                "HTTP/1.1 %u Redirect\r\n"
                "Location: /target\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n",
                static_cast<unsigned>(capture->RedirectStatus));
            if (written <= 0 || static_cast<SIZE_T>(written) >= sizeof(redirectResponse)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            response->RawResponse = redirectResponse;
            response->RawResponseLength = static_cast<SIZE_T>(written);
        }
        else if (capture->CallCount == 2) {
            response->RawResponse = finalResponse;
            response->RawResponseLength = sizeof(finalResponse) - 1;
        }
        else {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

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

    NTSTATUS FreshTimeoutTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<FreshTimeoutCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (request->ReusedConnection) {
            ++capture->ReusedCallCount;
            return STATUS_INVALID_DEVICE_STATE;
        }

        ++capture->NewConnectionCallCount;
        if (capture->FirstConnectionId == 0) {
            capture->FirstConnectionId = request->ConnectionId;
            return STATUS_IO_TIMEOUT;
        }

        capture->RetryConnectionId = request->ConnectionId;

        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";
        response->RawResponse = responseBytes;
        response->RawResponseLength = sizeof(responseBytes) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS ReuseDecisionTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<ReuseDecisionCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (request->ReusedConnection) {
            ++capture->ReusedCallCount;
        }

        if (capture->CallCount == 1) {
            response->RawResponse = capture->FirstResponse;
            response->RawResponseLength = capture->FirstResponseLength;
        }
        else {
            response->RawResponse = capture->SecondResponse;
            response->RawResponseLength = capture->SecondResponseLength;
        }
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
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Accept-Encoding: gzip, deflate, br, identity\r\n"),
            "default Accept-Encoding is added");

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

    void TestResponseTransferEncodingDecoded() noexcept
    {
        char response[256] = {};
        const SIZE_T responseLength = BuildTransferGzipChunkedResponse(response, sizeof(response));
        Expect(responseLength != 0, "transfer-coded khttp response fixture builds");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for transfer-coded response");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://example.com/transfer";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds for transfer-coded response");
        Expect(captured.CallCount == 1, "transfer-coded response reaches transport once");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "transfer-coded response status code is 200");
        Expect(
            KernelHttp::khttp::ResponseBodyLength(resp) == Length(EncodedBodyLiteral),
            "transfer-coded response body length is decoded");
        const UCHAR* body = KernelHttp::khttp::ResponseBody(resp);
        Expect(
            body != nullptr &&
                memcmp(body, EncodedBodyLiteral, Length(EncodedBodyLiteral)) == 0,
            "transfer-coded response body is decoded");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSessionMaxResponseBytesLimitsSimpleApi() noexcept
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
        Expect(status == STATUS_BUFFER_TOO_SMALL, "simple Get honors session MaxResponseBytes");
        Expect(resp == nullptr, "session-limited simple Get does not allocate response");

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

        KernelHttp::khttp::SendOptions largeOptions = KernelHttp::khttp::DefaultSendOptions();
        largeOptions.MaxResponseBytes = 8192;
        status = KernelHttp::khttp::Send(session, request, &largeOptions, &resp);
        Expect(NT_SUCCESS(status), "explicit larger MaxResponseBytes overrides session limit");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == 5000, "explicit larger limit returns large body");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRequestRejectsHeaderAndUrlInjection() noexcept
    {
        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for injection test");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for injection test");

        const char* badHeaderName = "Bad\rName";
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            badHeaderName,
            Length(badHeaderName),
            "value",
            Length("value"));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetHeader rejects CR in header name");

        const char* badHeaderValue = "ok\r\nInjected: yes";
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            "X-Test",
            Length("X-Test"),
            badHeaderValue,
            Length(badHeaderValue));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetHeader rejects CRLF in header value");

        const char* badUrl = "http://example.com/path\r\nInjected: yes";
        status = KernelHttp::khttp::RequestSetUrl(request, badUrl, Length(badUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects CRLF in request target");

        const char* spacedUrl = "http://example.com/a b";
        status = KernelHttp::khttp::RequestSetUrl(request, spacedUrl, Length(spacedUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects spaces in request target");

        const char* userInfoUrl = "http://user@example.com/path";
        status = KernelHttp::khttp::RequestSetUrl(request, userInfoUrl, Length(userInfoUrl));
        Expect(status == STATUS_NOT_SUPPORTED, "RequestSetUrl rejects userinfo authority");

        const char* unsupportedAuthorityUrl = "http://example.com:80:90/path";
        status = KernelHttp::khttp::RequestSetUrl(
            request,
            unsupportedAuthorityUrl,
            Length(unsupportedAuthorityUrl));
        Expect(status == STATUS_NOT_SUPPORTED, "RequestSetUrl rejects unsupported authority form");

        const char* badContentType = "text/plain\r\nX-Test: yes";
        status = KernelHttp::khttp::RequestSetTextBody(
            request,
            "hello",
            Length("hello"),
            badContentType,
            Length(badContentType));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetTextBody rejects CRLF in Content-Type");

        KernelHttp::khttp::MultipartPart part = {};
        part.Kind = KernelHttp::khttp::BodyPartKind::Field;
        part.Name = "field";
        part.NameLength = Length(part.Name);
        part.Value = "value";
        part.ValueLength = Length(part.Value);
        part.ContentType = badContentType;
        part.ContentTypeLength = Length(badContentType);
        status = KernelHttp::khttp::RequestSetMultipartBody(request, &part, 1);
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetMultipartBody rejects CRLF in part Content-Type");

        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
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

    void TestReusedConnectionPostFailureDoesNotRetry() noexcept
    {
        ReusedFailureCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(ReusedFailureTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reused POST retry test");

        const char* url = "http://example.com/retry-post";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first pooled Get succeeds before reused POST");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for reused POST");
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for reused POST");
        status = KernelHttp::khttp::RequestSetMethod(request, KernelHttp::khttp::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for reused POST");
        const char* payload = "payload";
        status = KernelHttp::khttp::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(payload),
            Length(payload));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for reused POST");

        status = KernelHttp::khttp::Send(session, request, nullptr, &resp);
        Expect(status == STATUS_CONNECTION_RESET, "reused POST failure is not retried");
        Expect(capture.CallCount == 2, "reused POST sees initial and failed reuse only");
        Expect(capture.ReusedCallCount == 1, "reused POST attempts one stale connection");
        Expect(capture.NewConnectionCallCount == 1, "reused POST does not create retry connection");
        Expect(capture.RetryConnectionId == 0, "reused POST records no retry connection id");
        Expect(resp == nullptr, "reused POST failure returns no response");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestConnectionPoolHonorsMaxConnectionsPerHost() noexcept
    {
        KernelHttp::engine::KhConnectionPool pool = {};
        NTSTATUS status = KernelHttp::engine::KhConnectionPoolInitialize(&pool, 4, 1, 30000);
        Expect(NT_SUCCESS(status), "connection pool initializes with per-host limit");

        KernelHttp::engine::KhConnectionPoolKey firstKey = {};
        memcpy(firstKey.Scheme, "http", Length("http"));
        firstKey.SchemeLength = Length("http");
        memcpy(firstKey.Host, "example.com", Length("example.com"));
        firstKey.HostLength = Length("example.com");
        firstKey.Port = 80;

        KernelHttp::engine::KhConnectionPoolKey secondKey = firstKey;
        memcpy(secondKey.Host, "other.example", Length("other.example"));
        secondKey.HostLength = Length("other.example");

        KernelHttp::engine::KhPooledConnection* first = nullptr;
        bool reused = true;
        status = KernelHttp::engine::KhConnectionPoolAcquire(
            &pool,
            firstKey,
            KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate,
            &first,
            &reused);
        Expect(NT_SUCCESS(status), "first per-host connection acquires");
        Expect(first != nullptr && !reused, "first per-host acquire is fresh");

        KernelHttp::engine::KhPooledConnection* blocked = nullptr;
        reused = true;
        status = KernelHttp::engine::KhConnectionPoolAcquire(
            &pool,
            firstKey,
            KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate,
            &blocked,
            &reused);
        Expect(status == STATUS_INSUFFICIENT_RESOURCES, "same host is limited while first is active");
        Expect(blocked == nullptr, "blocked same-host acquire returns no connection");

        KernelHttp::engine::KhPooledConnection* other = nullptr;
        reused = true;
        status = KernelHttp::engine::KhConnectionPoolAcquire(
            &pool,
            secondKey,
            KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate,
            &other,
            &reused);
        Expect(NT_SUCCESS(status), "different host can acquire under same pool capacity");
        Expect(other != nullptr && !reused, "different host acquire is fresh");

        KernelHttp::engine::KhConnectionPoolRelease(&pool, other, false);
        KernelHttp::engine::KhConnectionPoolRelease(&pool, first, false);
        KernelHttp::engine::KhConnectionPoolShutdown(&pool);
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

    void TestCloseDelimitedResponseDoesNotEnterPool() noexcept
    {
        static const char closeDelimitedResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "close-body";
        static const char secondResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = closeDelimitedResponse;
        capture.FirstResponseLength = Length(closeDelimitedResponse);
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        KernelHttp::khttp::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for close-delimited reuse test");

        const char* url = "http://example.com/close-delimited";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "close-delimited Get succeeds");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == Length("close-body"), "close-delimited body is returned");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after close-delimited response succeeds");
        Expect(capture.CallCount == 2, "close-delimited test sends two requests");
        Expect(capture.ReusedCallCount == 0, "close-delimited response is not returned to the pool");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttp10ConnectionReuseRules() noexcept
    {
        static const char http10NoDirective[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        static const char http10KeepAlive[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "ok";
        static const char secondResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = http10NoDirective;
        capture.FirstResponseLength = Length(http10NoDirective);
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        KernelHttp::khttp::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTP/1.0 reuse test");

        const char* url = "http://example.com/http10";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "HTTP/1.0 default-close Get succeeds");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after HTTP/1.0 default-close succeeds");
        Expect(capture.ReusedCallCount == 0, "HTTP/1.0 without keep-alive is not reused");
        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);

        capture = {};
        capture.FirstResponse = http10KeepAlive;
        capture.FirstResponseLength = Length(http10KeepAlive);
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        KernelHttp::khttp::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTP/1.0 keep-alive reuse test");

        resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "HTTP/1.0 keep-alive Get succeeds");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after HTTP/1.0 keep-alive succeeds");
        Expect(capture.ReusedCallCount == 1, "HTTP/1.0 keep-alive response is reusable");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSwitchingProtocolsDoesNotEnterHttpPool() noexcept
    {
        static const char switchingResponse[] =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "\r\n";
        static const char secondResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = switchingResponse;
        capture.FirstResponseLength = Length(switchingResponse);
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        KernelHttp::khttp::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for 101 reuse test");

        const char* url = "http://example.com/upgrade";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "101 response Get succeeds");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 101, "101 status reaches caller");
        KernelHttp::khttp::ResponseRelease(resp);
        resp = nullptr;

        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after 101 response succeeds");
        Expect(capture.CallCount == 2, "101 test sends two requests");
        Expect(capture.ReusedCallCount == 0, "101 response is not returned to the HTTP pool");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestFreshSafeConnectionTimeoutRetriesWithFreshConnection() noexcept
    {
        FreshTimeoutCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(FreshTimeoutTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for fresh timeout retry");

        const char* url = "http://example.com/fresh-timeout";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "fresh GET timeout retries with a new connection");
        Expect(capture.CallCount == 2, "fresh timeout retry makes two transport calls");
        Expect(capture.ReusedCallCount == 0, "fresh timeout retry does not reuse a stale connection");
        Expect(capture.NewConnectionCallCount == 2, "fresh timeout retry opens two connections");
        Expect(capture.FirstConnectionId != 0, "fresh timeout first connection id captured");
        Expect(capture.RetryConnectionId != 0, "fresh timeout retry connection id captured");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "fresh timeout retry uses a different connection id");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "fresh timeout retry response status is 200");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestFreshPostTimeoutDoesNotRetry() noexcept
    {
        FreshTimeoutCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(FreshTimeoutTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for fresh POST timeout");

        const char* url = "http://example.com/fresh-post-timeout";
        const char* body = "payload";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Post(
            session,
            url,
            Length(url),
            reinterpret_cast<const UCHAR*>(body),
            Length(body),
            &resp);
        Expect(status == STATUS_IO_TIMEOUT, "fresh POST timeout is not retried");
        Expect(resp == nullptr, "fresh POST timeout does not allocate a response");
        Expect(capture.CallCount == 1, "fresh POST timeout makes one transport call");
        Expect(capture.NewConnectionCallCount == 1, "fresh POST timeout opens one connection");
        Expect(capture.RetryConnectionId == 0, "fresh POST timeout has no retry connection id");

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

    void TestSessionRequestBufferBytesLimitsRequestBody() noexcept
    {
        static UCHAR body[20 * 1024] = {};
        for (SIZE_T index = 0; index < sizeof(body); ++index) {
            body[index] = static_cast<UCHAR>('a' + (index % 26));
        }

        const char* response =
            "HTTP/1.1 200 OK\r\n"
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for default request buffer test");

        const char* url = "http://example.com/large-post";
        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Post(
            session,
            url,
            Length(url),
            body,
            sizeof(body),
            &resp);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "default request buffer rejects oversized request body");
        Expect(captured.CallCount == 0, "oversized request body does not reach transport");
        Expect(resp == nullptr, "oversized request body does not allocate response");
        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);

        KernelHttp::khttp::SessionConfig config = KernelHttp::khttp::DefaultSessionConfig();
        config.RequestBufferBytes = 32 * 1024;
        captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);

        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate accepts custom request buffer");

        resp = nullptr;
        status = KernelHttp::khttp::Post(
            session,
            url,
            Length(url),
            body,
            sizeof(body),
            &resp);
        Expect(NT_SUCCESS(status), "custom request buffer allows larger request body");
        Expect(captured.CallCount == 1, "larger request body reaches transport");
        Expect(captured.ObservedBodyLength == sizeof(body), "larger request body length reaches transport");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "larger request body response parses");

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

        const char* encodingName = "Accept-Encoding";
        const char* encodingValue = "identity";
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            encodingName, Length(encodingName),
            encodingValue, Length(encodingValue));
        Expect(NT_SUCCESS(status), "custom Accept-Encoding header succeeds");

        KernelHttp::khttp::Response* resp = nullptr;
        KernelHttp::khttp::SendOptions sendOptions = KernelHttp::khttp::DefaultSendOptions();
        status = KernelHttp::khttp::Send(session, request, &sendOptions, &resp);
        Expect(NT_SUCCESS(status), "Send succeeds");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "status code is 200");
        Expect(captured.BodyLength == Length(json), "json body length");
        Expect(memcmp(captured.Body, json, Length(json)) == 0, "json body content");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Accept-Encoding: identity\r\n"),
            "custom Accept-Encoding is preserved");
        Expect(
            !BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Accept-Encoding: gzip, deflate, br, identity\r\n"),
            "default Accept-Encoding is not duplicated over custom value");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRequestTransferEncodingRejected() noexcept
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for Transfer-Encoding rejection");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for Transfer-Encoding rejection");

        const char* url = "http://example.com/upload";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for Transfer-Encoding rejection");

        const char* body = "hello";
        status = KernelHttp::khttp::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for Transfer-Encoding rejection");

        const char* headerName = "Transfer-Encoding";
        const char* headerValue = "chunked";
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            headerName,
            Length(headerName),
            headerValue,
            Length(headerValue));
        Expect(NT_SUCCESS(status), "RequestSetHeader stores Transfer-Encoding until send validation");

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, nullptr, &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "khttp send rejects request Transfer-Encoding");
        Expect(resp == nullptr, "rejected Transfer-Encoding does not allocate a response");
        Expect(captured.CallCount == 0, "rejected Transfer-Encoding does not reach transport");

        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAutoRedirectFollowsToFinalResponse() noexcept
    {
        RedirectCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(RedirectTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for redirect");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://example.com/redirect/1";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "default redirect succeeds");
        Expect(capture.CallCount == 3, "default redirect follows two hops");
        Expect(
            BufferContainsLiteral(capture.Requests[0], capture.RequestLengths[0], "GET /redirect/1 "),
            "first redirect request path is captured");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /redirect/2 "),
            "second redirect request path is captured");
        Expect(
            BufferContainsLiteral(capture.Requests[2], capture.RequestLengths[2], "GET /final "),
            "final redirect request path is captured");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "redirect final status is 200");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == 4, "redirect final body length");
        const UCHAR* body = KernelHttp::khttp::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, "done", 4) == 0, "redirect final body");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAutoRedirectCanBeDisabled() noexcept
    {
        RedirectCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(RedirectTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for disabled redirect");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for disabled redirect");

        const char* url = "http://example.com/redirect/1";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for disabled redirect");

        KernelHttp::khttp::SendOptions options = KernelHttp::khttp::DefaultSendOptions();
        options.Flags = KernelHttp::khttp::SendFlagDisableAutoRedirect;

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, &options, &resp);
        Expect(NT_SUCCESS(status), "disabled redirect send succeeds");
        Expect(capture.CallCount == 1, "disabled redirect does not follow Location");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 302, "disabled redirect returns 302");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAutoRedirectHonorsCustomMaximum() noexcept
    {
        RedirectCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(RedirectTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for redirect limit");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for redirect limit");

        const char* url = "http://example.com/redirect/1";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for redirect limit");

        KernelHttp::khttp::SendOptions options = KernelHttp::khttp::DefaultSendOptions();
        options.MaxRedirects = 1;

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, &options, &resp);
        Expect(NT_SUCCESS(status), "limited redirect send succeeds");
        Expect(capture.CallCount == 2, "custom redirect limit follows once");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /redirect/2 "),
            "custom redirect limit stops after first follow");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 302, "custom redirect limit returns last 302");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestPostRedirectRewritesToGet() noexcept
    {
        RedirectCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(RedirectTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for POST redirect");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for POST redirect");

        const char* url = "http://example.com/redirect/1";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for POST redirect");
        status = KernelHttp::khttp::RequestSetMethod(request, KernelHttp::khttp::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for redirect");

        const char* payload = "payload";
        status = KernelHttp::khttp::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(payload),
            Length(payload));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for POST redirect");

        KernelHttp::khttp::SendOptions options = KernelHttp::khttp::DefaultSendOptions();
        options.MaxRedirects = 1;

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, &options, &resp);
        Expect(NT_SUCCESS(status), "POST redirect send succeeds");
        Expect(capture.CallCount == 2, "POST redirect follows once");
        Expect(
            BufferContainsLiteral(capture.Requests[0], capture.RequestLengths[0], "POST /redirect/1 "),
            "first POST redirect request uses POST");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /redirect/2 "),
            "302 POST redirect rewrites to GET");
        Expect(
            !BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], payload),
            "302 POST redirect clears body");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAutoRedirectResolvesRelativeReferencesAndSanitizesCrossOriginHeaders() noexcept
    {
        RedirectCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(RelativeRedirectTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for relative redirect");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for relative redirect");

        const char* url = "https://example.com/dir/page?keep=1#frag";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for relative redirect");

        status = KernelHttp::khttp::RequestSetHeader(
            request,
            "Authorization",
            Length("Authorization"),
            "Bearer secret",
            Length("Bearer secret"));
        Expect(NT_SUCCESS(status), "Authorization header is accepted before redirect");
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            "Cookie",
            Length("Cookie"),
            "sid=secret",
            Length("sid=secret"));
        Expect(NT_SUCCESS(status), "Cookie header is accepted before redirect");
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            "Proxy-Authorization",
            Length("Proxy-Authorization"),
            "Basic secret",
            Length("Basic secret"));
        Expect(NT_SUCCESS(status), "Proxy-Authorization header is accepted before redirect");

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "relative redirect chain succeeds");
        Expect(capture.CallCount == 5, "relative redirect follows all hops");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /dir/next "),
            "relative redirect resolves sibling path");
        Expect(
            BufferContainsLiteral(capture.Requests[2], capture.RequestLengths[2], "GET /other?x=1 "),
            "relative redirect resolves parent path");
        Expect(
            BufferContainsLiteral(capture.Requests[3], capture.RequestLengths[3], "GET /other?page=2 "),
            "query-only redirect inherits current path");
        Expect(
            BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Host: other.example\r\n"),
            "scheme-relative redirect switches authority");
        Expect(
            !BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Authorization:"),
            "cross-origin redirect strips Authorization");
        Expect(
            !BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Cookie:"),
            "cross-origin redirect strips Cookie");
        Expect(
            !BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Proxy-Authorization:"),
            "cross-origin redirect strips Proxy-Authorization");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "relative redirect final status is 200");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpsDowngradeRedirectIsRejected() noexcept
    {
        RedirectCapture capture = {};
        KernelHttp::khttp::test::SetHttpTransport(HttpsDowngradeRedirectTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for downgrade redirect");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "https://secure.example/redirect";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "HTTPS to HTTP redirect is rejected by default");
        Expect(capture.CallCount == 1, "downgrade redirect does not send target request");
        Expect(resp == nullptr, "downgrade redirect does not allocate final response");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void RunRedirectMethodCase(
        const char* label,
        KernelHttp::khttp::Method method,
        USHORT statusCode,
        const char* expectedFirstMethod,
        const char* expectedSecondMethod,
        bool expectBodyOnSecond) noexcept
    {
        RedirectMethodCapture capture = {};
        capture.RedirectStatus = statusCode;
        KernelHttp::khttp::test::SetHttpTransport(RedirectMethodTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), label);

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for redirect method case");
        status = KernelHttp::khttp::RequestSetUrl(request, "http://example.com/source", Length("http://example.com/source"));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for redirect method case");
        status = KernelHttp::khttp::RequestSetMethod(request, method);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds for redirect method case");

        const char* payload = "payload";
        status = KernelHttp::khttp::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(payload),
            Length(payload));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for redirect method case");

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "redirect method case send succeeds");
        Expect(capture.CallCount == 2, "redirect method case follows one hop");
        Expect(
            BufferContainsLiteral(capture.Requests[0], capture.RequestLengths[0], expectedFirstMethod),
            "redirect method first request method matches");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], expectedSecondMethod),
            "redirect method second request method matches");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], payload) == expectBodyOnSecond,
            "redirect method body rewrite matches");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRedirectMethodRewriteRules() noexcept
    {
        RunRedirectMethodCase(
            "SessionCreate succeeds for PUT 302 redirect method case",
            KernelHttp::khttp::Method::Put,
            302,
            "PUT /source ",
            "PUT /target ",
            true);
        RunRedirectMethodCase(
            "SessionCreate succeeds for POST 303 redirect method case",
            KernelHttp::khttp::Method::Post,
            303,
            "POST /source ",
            "GET /target ",
            false);
        RunRedirectMethodCase(
            "SessionCreate succeeds for POST 307 redirect method case",
            KernelHttp::khttp::Method::Post,
            307,
            "POST /source ",
            "POST /target ",
            true);
        RunRedirectMethodCase(
            "SessionCreate succeeds for POST 308 redirect method case",
            KernelHttp::khttp::Method::Post,
            308,
            "POST /source ",
            "POST /target ",
            true);
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
    TestResponseTransferEncodingDecoded();
    TestSessionMaxResponseBytesLimitsSimpleApi();
    TestRequestRejectsHeaderAndUrlInjection();
    TestReusedConnectionFailureRetriesWithFreshConnection();
    TestReusedConnectionPostFailureDoesNotRetry();
    TestConnectionPoolHonorsMaxConnectionsPerHost();
    TestIdleTimeoutSkipsExpiredConnection();
    TestCloseDelimitedResponseDoesNotEnterPool();
    TestHttp10ConnectionReuseRules();
    TestSwitchingProtocolsDoesNotEnterHttpPool();
    TestFreshSafeConnectionTimeoutRetriesWithFreshConnection();
    TestFreshPostTimeoutDoesNotRetry();
    TestPostWithBody();
    TestSessionRequestBufferBytesLimitsRequestBody();
    TestRequestBuilder();
    TestRequestTransferEncodingRejected();
    TestAutoRedirectFollowsToFinalResponse();
    TestAutoRedirectCanBeDisabled();
    TestAutoRedirectHonorsCustomMaximum();
    TestPostRedirectRewritesToGet();
    TestAutoRedirectResolvesRelativeReferencesAndSanitizesCrossOriginHeaders();
    TestHttpsDowngradeRedirectIsRejected();
    TestRedirectMethodRewriteRules();
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
