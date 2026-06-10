#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/KernelHttp.h>
#include <KernelHttp/engine/Async.h>
#include <KernelHttp/engine/ConnectionPool.h>
#include <KernelHttp/engine/Workspace.h>
#include <KernelHttp/khttp/Test.h>
#include <KernelHttp/net/WskSocket.h>

#include <stdio.h>
#include <stdint.h>
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

    SIZE_T BuildTransferGzipCloseDelimitedResponse(char* buffer, SIZE_T capacity) noexcept
    {
        if (buffer == nullptr) {
            return 0;
        }

        const int headerLength = snprintf(
            buffer,
            capacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: gzip\r\n"
            "\r\n");
        if (headerLength <= 0 || static_cast<SIZE_T>(headerLength) > capacity) {
            return 0;
        }

        SIZE_T cursor = static_cast<SIZE_T>(headerLength);
        if (sizeof(GzipBody) > capacity - cursor) {
            return 0;
        }

        memcpy(buffer + cursor, GzipBody, sizeof(GzipBody));
        cursor += sizeof(GzipBody);
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
        bool FirstConnectionReusable = true;
        const char* SecondResponse = nullptr;
        SIZE_T SecondResponseLength = 0;
        bool SecondConnectionReusable = true;
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
    };

    struct CompletionCapture
    {
        SIZE_T CallCount = 0;
        NTSTATUS LastStatus = STATUS_PENDING;
    };

    struct LongUrlCapture
    {
        SIZE_T CallCount = 0;
        bool SawLongOriginForm = false;
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

    NTSTATUS LongUrlTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<LongUrlCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        static const char marker[] = " HTTP/1.1\r\n";
        constexpr SIZE_T requestTargetLength = 8000;
        if (request->BuiltRequest != nullptr &&
            request->BuiltRequestLength > 4 + requestTargetLength + sizeof(marker) - 1 &&
            memcmp(request->BuiltRequest, "GET /", 5) == 0 &&
            request->BuiltRequest[4 + requestTargetLength - 1] == 'a' &&
            memcmp(
                request->BuiltRequest + 4 + requestTargetLength,
                marker,
                sizeof(marker) - 1) == 0) {
            capture->SawLongOriginForm = true;
        }

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

    void ExpectRejectedRequestHeader(
        const char* headerName,
        const char* headerValue,
        bool includeBody,
        NTSTATUS expectedStatus,
        const char* message) noexcept
    {
        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        CapturedRequest captured = {};
        captured.RawResponse = responseBytes;
        captured.RawResponseLength = sizeof(responseBytes) - 1;
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reserved header rejection");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for reserved header rejection");

        const char* url = "http://example.com/rejected-header";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for reserved header rejection");

        if (includeBody) {
            const char* body = "payload";
            status = KernelHttp::khttp::RequestSetBody(
                request,
                reinterpret_cast<const UCHAR*>(body),
                Length(body));
            Expect(NT_SUCCESS(status), "RequestSetBody succeeds for reserved header rejection");
        }

        status = KernelHttp::khttp::RequestSetHeader(
            request,
            headerName,
            Length(headerName),
            headerValue,
            Length(headerValue));
        Expect(NT_SUCCESS(status), "RequestSetHeader stores reserved header until send validation");

        KernelHttp::khttp::Response* response = nullptr;
        status = KernelHttp::khttp::Send(session, request, nullptr, &response);
        Expect(status == expectedStatus, message);
        Expect(response == nullptr, "reserved header rejection does not allocate response");
        Expect(captured.CallCount == 0, "reserved header rejection does not reach transport");

        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
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
            response->ConnectionReusable = capture->FirstConnectionReusable;
        }
        else {
            response->RawResponse = capture->SecondResponse;
            response->RawResponseLength = capture->SecondResponseLength;
            response->ConnectionReusable = capture->SecondConnectionReusable;
        }
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
        char LastSubprotocol[64] = {};
        SIZE_T LastSubprotocolLength = 0;
        char LastSendBuffer[64] = {};
        UCHAR LastSendData[128] = {};
        SIZE_T LastSendLength = 0;
        KernelHttp::engine::KhWebSocketMessageType LastSendType = KernelHttp::engine::KhWebSocketMessageType::Text;
        bool LastSendFinalFragment = false;
        KernelHttp::engine::KhWebSocketMessageType NextType = KernelHttp::engine::KhWebSocketMessageType::Text;
        UCHAR NextData[64] = {};
        SIZE_T NextLength = 0;
        NTSTATUS SendStatus = STATUS_SUCCESS;
        NTSTATUS ReceiveStatus = STATUS_SUCCESS;
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
        if (request->Subprotocol != nullptr && request->SubprotocolLength != 0) {
            capture->LastSubprotocolLength = request->SubprotocolLength < sizeof(capture->LastSubprotocol) - 1
                ? request->SubprotocolLength
                : sizeof(capture->LastSubprotocol) - 1;
            memcpy(capture->LastSubprotocol, request->Subprotocol, capture->LastSubprotocolLength);
            capture->LastSubprotocol[capture->LastSubprotocolLength] = '\0';
        }
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
        auto* capture = static_cast<WsCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(capture->SendStatus)) {
            return capture->SendStatus;
        }
        ++capture->SendCount;
        capture->LastSendType = type;
        capture->LastSendFinalFragment = finalFragment;
        const SIZE_T dataCopy = dataLength < sizeof(capture->LastSendData)
            ? dataLength
            : sizeof(capture->LastSendData);
        if (dataCopy != 0 && data != nullptr) {
            memcpy(capture->LastSendData, data, dataCopy);
        }
        const SIZE_T copy = dataLength < sizeof(capture->LastSendBuffer) - 1
            ? dataLength
            : sizeof(capture->LastSendBuffer) - 1;
        if (copy != 0 && data != nullptr) {
            memcpy(capture->LastSendBuffer, data, copy);
        }
        capture->LastSendBuffer[copy] = '\0';
        capture->LastSendLength = dataLength;
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
        if (!NT_SUCCESS(capture->ReceiveStatus)) {
            return capture->ReceiveStatus;
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

    void TestResponseDuplicateHeaderSemantics() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "X-Repeat: one\r\n"
            "Set-Cookie: a=1\r\n"
            "X-Repeat: two\r\n"
            "Set-Cookie: b=2\r\n"
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for duplicate header semantics");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://example.com/headers";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds for duplicate header semantics");
        Expect(KernelHttp::khttp::ResponseHeaderCount(resp) == 5, "duplicate headers remain enumerable");

        const char* value = nullptr;
        SIZE_T valueLength = 0;
        status = KernelHttp::khttp::ResponseGetHeader(
            resp,
            "X-Repeat",
            Length("X-Repeat"),
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "duplicate header is found by name");
        Expect(valueLength == Length("one") && memcmp(value, "one", valueLength) == 0, "header lookup returns first duplicate");

        status = KernelHttp::khttp::ResponseGetHeader(
            resp,
            "Set-Cookie",
            Length("Set-Cookie"),
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "Set-Cookie is found by name");
        Expect(valueLength == Length("a=1") && memcmp(value, "a=1", valueLength) == 0, "Set-Cookie lookup returns first field");

        const char* name = nullptr;
        SIZE_T nameLength = 0;
        status = KernelHttp::khttp::ResponseGetHeaderAt(
            resp,
            2,
            &name,
            &nameLength,
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "second X-Repeat is readable by index");
        Expect(nameLength == Length("X-Repeat") && memcmp(name, "X-Repeat", nameLength) == 0, "indexed duplicate header name matches");
        Expect(valueLength == Length("two") && memcmp(value, "two", valueLength) == 0, "indexed duplicate header value matches");

        status = KernelHttp::khttp::ResponseGetHeaderAt(
            resp,
            3,
            &name,
            &nameLength,
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "second Set-Cookie is readable by index");
        Expect(nameLength == Length("Set-Cookie") && memcmp(name, "Set-Cookie", nameLength) == 0, "indexed Set-Cookie header name matches");
        Expect(valueLength == Length("b=2") && memcmp(value, "b=2", valueLength) == 0, "indexed Set-Cookie value is not merged");

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

    void TestTransferCodingCloseDelimitedHonorsTestTransportEof() noexcept
    {
        char response[256] = {};
        const SIZE_T responseLength = BuildTransferGzipCloseDelimitedResponse(response, sizeof(response));
        Expect(responseLength != 0, "close-delimited gzip transfer fixture builds");

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = response;
        capture.FirstResponseLength = responseLength;
        capture.FirstConnectionReusable = true;
        KernelHttp::khttp::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reusable close-delimited test");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://example.com/te-gzip";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "test transport does not complete close-delimited transfer while reusable");
        Expect(resp == nullptr, "incomplete close-delimited transfer returns no response");
        Expect(capture.CallCount == 1, "reusable close-delimited attempt reaches transport once");
        KernelHttp::khttp::SessionClose(session);

        capture = {};
        capture.FirstResponse = response;
        capture.FirstResponseLength = responseLength;
        capture.FirstConnectionReusable = false;
        KernelHttp::khttp::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for EOF close-delimited test");

        resp = nullptr;
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "EOF close-delimited transfer succeeds");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == Length(EncodedBodyLiteral), "EOF close-delimited transfer body length is decoded");
        const UCHAR* body = KernelHttp::khttp::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, EncodedBodyLiteral, Length(EncodedBodyLiteral)) == 0, "EOF close-delimited transfer body is decoded");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestResponseTrailersAreExposed() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "hello\r\n"
            "0\r\n"
            "Digest: sha-256=abc\r\n"
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for trailer response");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://example.com/trailer";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds for trailer response");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == Length("hello"), "trailer response body length matches");
        Expect(KernelHttp::khttp::ResponseTrailerCount(resp) == 1, "response trailer count is exposed");

        const char* value = nullptr;
        SIZE_T valueLength = 0;
        status = KernelHttp::khttp::ResponseGetTrailer(
            resp,
            "Digest",
            Length("Digest"),
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "response trailer is found by name");
        Expect(valueLength == Length("sha-256=abc") &&
            memcmp(value, "sha-256=abc", valueLength) == 0,
            "response trailer value matches");

        const char* name = nullptr;
        SIZE_T nameLength = 0;
        status = KernelHttp::khttp::ResponseGetTrailerAt(
            resp,
            0,
            &name,
            &nameLength,
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "response trailer is readable by index");
        Expect(nameLength == Length("Digest") &&
            memcmp(name, "Digest", nameLength) == 0,
            "response trailer name matches");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestInformationalResponsesAreSkipped() noexcept
    {
        const char* response =
            "HTTP/1.1 103 Early Hints\r\n"
            "Link: </style.css>; rel=preload\r\n"
            "\r\n"
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "final";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for informational response test");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://example.com/informational";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds after informational responses");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 200, "informational responses are skipped before final status");
        Expect(KernelHttp::khttp::ResponseBodyLength(resp) == Length("final"), "final response body length is returned");
        const UCHAR* body = KernelHttp::khttp::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, "final", Length("final")) == 0, "final response body is returned");

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

    void TestUrlRequestTargetAndHostSemantics() noexcept
    {
        static const char response[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = sizeof(response) - 1;
        KernelHttp::khttp::test::SetHttpTransport(TestTransport, &captured);

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for URL semantics");

        KernelHttp::khttp::Response* resp = nullptr;
        const char* url = "http://[2001:db8::1]?q=1#fragment";
        status = KernelHttp::khttp::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "IPv6 query-only URL succeeds");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "GET /?q=1 HTTP/1.1\r\n"),
            "query-only URL is sent as origin-form with leading slash and no fragment");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Host: [2001:db8::1]\r\n"),
            "IPv6 Host header is bracketed");
        KernelHttp::khttp::ResponseRelease(resp);

        captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = sizeof(response) - 1;
        resp = nullptr;
        const char* percentUrl = "http://example.com/a%2Fb?q=x%2Fy#drop";
        status = KernelHttp::khttp::Get(session, percentUrl, Length(percentUrl), &resp);
        Expect(NT_SUCCESS(status), "percent-encoded URL succeeds");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "GET /a%2Fb?q=x%2Fy HTTP/1.1\r\n"),
            "percent-encoded path and query are passed through without normalization");
        KernelHttp::khttp::ResponseRelease(resp);

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for URL rejection cases");

        const char* badPercentUrl = "http://example.com/a%2G";
        status = KernelHttp::khttp::RequestSetUrl(request, badPercentUrl, Length(badPercentUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects invalid percent triplet");

        const char nonAsciiHostUrl[] = {
            'h', 't', 't', 'p', ':', '/', '/', 'e', 'x',
            static_cast<char>(0xC3), static_cast<char>(0xA4),
            'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '/', '\0'
        };
        status = KernelHttp::khttp::RequestSetUrl(request, nonAsciiHostUrl, Length(nonAsciiHostUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects non-ASCII host");

        const char* zoneIdUrl = "http://[fe80::1%25eth0]/";
        status = KernelHttp::khttp::RequestSetUrl(request, zoneIdUrl, Length(zoneIdUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects IPv6 zone id");

        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);

        static char longUrl[sizeof("http://example.com/") + 7999] = {};
        static char tooLongUrl[sizeof("http://example.com/") + 8000] = {};
        const char prefix[] = "http://example.com/";
        memcpy(longUrl, prefix, sizeof(prefix) - 1);
        for (SIZE_T index = sizeof(prefix) - 1; index < sizeof(longUrl) - 1; ++index) {
            longUrl[index] = 'a';
        }
        longUrl[sizeof(longUrl) - 1] = '\0';

        memcpy(tooLongUrl, prefix, sizeof(prefix) - 1);
        for (SIZE_T index = sizeof(prefix) - 1; index < sizeof(tooLongUrl) - 1; ++index) {
            tooLongUrl[index] = 'a';
        }
        tooLongUrl[sizeof(tooLongUrl) - 1] = '\0';

        LongUrlCapture longCapture = {};
        KernelHttp::khttp::test::SetHttpTransport(LongUrlTransport, &longCapture);
        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for long URL");

        resp = nullptr;
        status = KernelHttp::khttp::Get(session, longUrl, Length(longUrl), &resp);
        Expect(NT_SUCCESS(status), "8000-octet request-target succeeds");
        Expect(longCapture.CallCount == 1, "long URL reaches transport");
        Expect(longCapture.SawLongOriginForm, "long URL is sent as 8000-octet origin-form target");
        KernelHttp::khttp::ResponseRelease(resp);

        request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for too-long URL");
        status = KernelHttp::khttp::RequestSetUrl(request, tooLongUrl, Length(tooLongUrl));
        Expect(status == STATUS_BUFFER_TOO_SMALL, "RequestSetUrl rejects request-target above 8000 octets");

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

    void TestConnectionPoolHostQuotaSeparatesTlsReuseIdentity() noexcept
    {
        KernelHttp::engine::KhConnectionPool pool = {};
        NTSTATUS status = KernelHttp::engine::KhConnectionPoolInitialize(&pool, 2, 1, 30000);
        Expect(NT_SUCCESS(status), "connection pool initializes for TLS identity quota");

        KernelHttp::engine::KhConnectionPoolKey firstKey = {};
        memcpy(firstKey.Scheme, "https", Length("https"));
        firstKey.SchemeLength = Length("https");
        memcpy(firstKey.Host, "example.com", Length("example.com"));
        firstKey.HostLength = Length("example.com");
        firstKey.Port = 443;
        memcpy(firstKey.TlsServerName, "api.example.com", Length("api.example.com"));
        firstKey.TlsServerNameLength = Length("api.example.com");
        memcpy(firstKey.Alpn, "h2", Length("h2"));
        firstKey.AlpnLength = Length("h2");

        KernelHttp::engine::KhConnectionPoolKey secondIdentity = firstKey;
        memcpy(secondIdentity.TlsServerName, "other.example.com", Length("other.example.com"));
        secondIdentity.TlsServerNameLength = Length("other.example.com");

        KernelHttp::engine::KhPooledConnection* first = nullptr;
        bool reused = true;
        status = KernelHttp::engine::KhConnectionPoolAcquire(
            &pool,
            firstKey,
            KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate,
            &first,
            &reused);
        Expect(NT_SUCCESS(status), "first TLS identity connection acquires");
        Expect(first != nullptr && !reused, "first TLS identity acquire is fresh");

        KernelHttp::engine::KhPooledConnection* blocked = nullptr;
        reused = true;
        status = KernelHttp::engine::KhConnectionPoolAcquire(
            &pool,
            secondIdentity,
            KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate,
            &blocked,
            &reused);
        Expect(status == STATUS_INSUFFICIENT_RESOURCES, "active same-host different TLS identity counts toward host quota");
        Expect(blocked == nullptr, "blocked TLS identity acquire returns no connection");

        const ULONG firstId = first != nullptr ? first->Id : 0;
        KernelHttp::engine::KhConnectionPoolRelease(&pool, first, true);

        KernelHttp::engine::KhPooledConnection* second = nullptr;
        reused = true;
        status = KernelHttp::engine::KhConnectionPoolAcquire(
            &pool,
            secondIdentity,
            KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate,
            &second,
            &reused);
        Expect(NT_SUCCESS(status), "idle same-host different TLS identity can replace old idle slot");
        Expect(second != nullptr && !reused, "different TLS identity is not reused across identity key");
        Expect(second != nullptr && second->Id != firstId, "different TLS identity receives a fresh connection id");

        KernelHttp::engine::KhConnectionPoolRelease(&pool, second, false);
        KernelHttp::engine::KhConnectionPoolShutdown(&pool);
    }

    void TestConnectionPoolKeyIncludesTlsIdentity() noexcept
    {
        KernelHttp::engine::KhConnectionPoolKey base = {};
        memcpy(base.Scheme, "https", Length("https"));
        base.SchemeLength = Length("https");
        memcpy(base.Host, "example.com", Length("example.com"));
        base.HostLength = Length("example.com");
        base.Port = 443;
        base.MinTlsVersion = KernelHttp::engine::KhTlsVersion::Tls12;
        base.MaxTlsVersion = KernelHttp::engine::KhTlsVersion::Tls13;
        base.CertificatePolicy = KernelHttp::engine::KhCertificatePolicy::Verify;
        base.CertificateStore = reinterpret_cast<const KernelHttp::tls::CertificateStore*>(static_cast<uintptr_t>(0x1000));
        memcpy(base.TlsServerName, "api.example.com", Length("api.example.com"));
        base.TlsServerNameLength = Length("api.example.com");
        memcpy(base.Alpn, "h2", Length("h2"));
        base.AlpnLength = Length("h2");

        KernelHttp::engine::KhConnectionPoolKey same = base;
        Expect(
            KernelHttp::engine::KhConnectionPoolKeysEqual(base, same),
            "connection pool keys match when TLS identity is identical");

        KernelHttp::engine::KhConnectionPoolKey differentSni = base;
        memcpy(differentSni.TlsServerName, "other.example", Length("other.example"));
        differentSni.TlsServerNameLength = Length("other.example");
        Expect(
            !KernelHttp::engine::KhConnectionPoolKeysEqual(base, differentSni),
            "connection pool key includes TLS server name");

        KernelHttp::engine::KhConnectionPoolKey differentStore = base;
        differentStore.CertificateStore =
            reinterpret_cast<const KernelHttp::tls::CertificateStore*>(static_cast<uintptr_t>(0x2000));
        Expect(
            !KernelHttp::engine::KhConnectionPoolKeysEqual(base, differentStore),
            "connection pool key includes certificate store identity");
    }

    struct FakeResolveCapture
    {
        SIZE_T CallCount = 0;
        KernelHttp::net::WskAddressFamily LastFamily = KernelHttp::net::WskAddressFamily::Any;
        USHORT LastServicePort = 0;
    };

    USHORT HostToNetworkPort(const wchar_t* serviceName) noexcept
    {
        USHORT port = 0;
        if (serviceName == nullptr) {
            return 0;
        }

        for (const wchar_t* current = serviceName; *current != L'\0'; ++current) {
            if (*current < L'0' || *current > L'9') {
                return 0;
            }

            port = static_cast<USHORT>((port * 10) + static_cast<USHORT>(*current - L'0'));
        }

        return static_cast<USHORT>((port >> 8) | (port << 8));
    }

    ULONG WideChecksum(const wchar_t* text) noexcept
    {
        ULONG checksum = 0;
        if (text == nullptr) {
            return checksum;
        }

        for (const wchar_t* current = text; *current != L'\0'; ++current) {
            checksum = (checksum * 131U) + static_cast<ULONG>(*current);
        }
        return checksum;
    }

    NTSTATUS FakeResolveAll(
        void* context,
        const wchar_t* nodeName,
        const wchar_t* serviceName,
        SOCKADDR_STORAGE* remoteAddresses,
        SIZE_T addressCapacity,
        SIZE_T* addressCount,
        KernelHttp::net::WskAddressFamily addressFamily) noexcept
    {
        auto* capture = static_cast<FakeResolveCapture*>(context);
        if (capture == nullptr ||
            remoteAddresses == nullptr ||
            addressCapacity == 0 ||
            addressCount == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        capture->LastFamily = addressFamily;
        capture->LastServicePort = HostToNetworkPort(serviceName);
        *addressCount = 0;

        const ULONG checksum = WideChecksum(nodeName);
        if (addressFamily == KernelHttp::net::WskAddressFamily::Any ||
            addressFamily == KernelHttp::net::WskAddressFamily::Ipv4) {
            auto* ipv4 = reinterpret_cast<SOCKADDR_IN*>(&remoteAddresses[*addressCount]);
            RtlZeroMemory(ipv4, sizeof(*ipv4));
            ipv4->sin_family = AF_INET;
            ipv4->sin_port = capture->LastServicePort;
            ipv4->sin_addr = 0x0a000001UL + checksum + static_cast<ULONG>(capture->CallCount);
            ++(*addressCount);
        }

        if (*addressCount < addressCapacity &&
            (addressFamily == KernelHttp::net::WskAddressFamily::Any ||
                addressFamily == KernelHttp::net::WskAddressFamily::Ipv6)) {
            auto* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(&remoteAddresses[*addressCount]);
            RtlZeroMemory(ipv6, sizeof(*ipv6));
            ipv6->sin6_family = AF_INET6;
            ipv6->sin6_port = capture->LastServicePort;
            ipv6->sin6_addr[15] = static_cast<UCHAR>(checksum + capture->CallCount);
            ++(*addressCount);
        }

        return *addressCount != 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

    void TestResolveAllCacheBoundaries() noexcept
    {
        KernelHttp::net::WskTestClearResolveCache();
        FakeResolveCapture capture = {};
        KernelHttp::net::WskTestSetResolveAll(FakeResolveAll, &capture);

        KernelHttp::net::WskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "test WskClient initializes");

        SOCKADDR_STORAGE addresses[KernelHttp::net::WskMaxResolvedAddresses] = {};
        SIZE_T addressCount = 0;
        status = client.ResolveAll(
            L"Example.COM",
            L"443",
            addresses,
            KernelHttp::net::WskMaxResolvedAddresses,
            &addressCount,
            KernelHttp::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "first ResolveAll succeeds");
        Expect(addressCount == 2, "Any resolve returns IPv4 and IPv6 fixtures");
        Expect(capture.CallCount == 1, "first ResolveAll reaches resolver");

        RtlZeroMemory(addresses, sizeof(addresses));
        addressCount = 0;
        status = client.ResolveAll(
            L"example.com",
            L"443",
            addresses,
            KernelHttp::net::WskMaxResolvedAddresses,
            &addressCount,
            KernelHttp::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "cached ResolveAll succeeds case-insensitively");
        Expect(addressCount == 2, "cached ResolveAll preserves address count");
        Expect(capture.CallCount == 1, "cached ResolveAll does not call resolver");

        status = client.ResolveAll(
            L"example.com",
            L"443",
            addresses,
            KernelHttp::net::WskMaxResolvedAddresses,
            &addressCount,
            KernelHttp::net::WskAddressFamily::Ipv4);
        Expect(NT_SUCCESS(status), "family-isolated ResolveAll succeeds");
        Expect(addressCount == 1, "IPv4-only ResolveAll returns one address");
        Expect(capture.CallCount == 2, "address family is part of DNS cache key");
        Expect(capture.LastFamily == KernelHttp::net::WskAddressFamily::Ipv4, "resolver observes IPv4 family");

        constexpr ULONGLONG ResolveCacheTtl100ns = 5ULL * 60ULL * 1000ULL * 10000ULL;
        KernelHttp::net::WskTestAdvanceResolveCacheTime(ResolveCacheTtl100ns + 10000ULL);
        status = client.ResolveAll(
            L"example.com",
            L"443",
            addresses,
            KernelHttp::net::WskMaxResolvedAddresses,
            &addressCount,
            KernelHttp::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "expired ResolveAll succeeds");
        Expect(capture.CallCount == 3, "expired DNS cache entry is refreshed");

        KernelHttp::net::WskTestClearResolveCache();
        capture.CallCount = 0;
        status = client.ResolveAll(
            L"host00.example",
            L"443",
            addresses,
            KernelHttp::net::WskMaxResolvedAddresses,
            &addressCount,
            KernelHttp::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "initial capacity ResolveAll succeeds");

        for (SIZE_T index = 1; index <= 16; ++index) {
            wchar_t host[] = L"host00.example";
            host[4] = static_cast<wchar_t>(L'0' + (index / 10));
            host[5] = static_cast<wchar_t>(L'0' + (index % 10));
            status = client.ResolveAll(
                host,
                L"443",
                addresses,
                KernelHttp::net::WskMaxResolvedAddresses,
                &addressCount,
                KernelHttp::net::WskAddressFamily::Any);
            Expect(NT_SUCCESS(status), "capacity fill ResolveAll succeeds");
        }

        status = client.ResolveAll(
            L"host00.example",
            L"443",
            addresses,
            KernelHttp::net::WskMaxResolvedAddresses,
            &addressCount,
            KernelHttp::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "evicted ResolveAll succeeds");
        Expect(capture.CallCount == 18, "DNS cache capacity replacement evicts the oldest slot");

        KernelHttp::net::WskTestSetResolveAll(nullptr, nullptr);
        KernelHttp::net::WskTestClearResolveCache();
    }

    struct FakeWskSocketCapture
    {
        SIZE_T ConnectCount = 0;
        SIZE_T SendCount = 0;
        SIZE_T ReceiveCount = 0;
        SIZE_T CloseCount = 0;
        NTSTATUS NextConnectStatus = STATUS_SUCCESS;
        NTSTATUS ConnectStatuses[4] = {};
        SIZE_T ConnectStatusCount = 0;
        NTSTATUS NextSendStatus = STATUS_SUCCESS;
        NTSTATUS NextReceiveStatus = STATUS_SUCCESS;
        bool ReturnSocketOnFailedConnect = false;
        KernelHttp::net::PWSK_SOCKET LastClosedSocket = nullptr;
        USHORT ConnectFamilies[4] = {};
        USHORT ConnectPorts[4] = {};
        char LastSend[32] = {};
        SIZE_T LastSendLength = 0;
    };

    bool AlwaysCancel(void* context) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        return true;
    }

    NTSTATUS FakeWskConnect(
        void* context,
        const SOCKADDR* remoteAddress,
        const SOCKADDR* localAddress,
        const KernelHttp::net::WskCancellationToken* cancellation,
        KernelHttp::net::PWSK_SOCKET* socket) noexcept
    {
        UNREFERENCED_PARAMETER(localAddress);
        UNREFERENCED_PARAMETER(cancellation);

        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr || remoteAddress == nullptr || socket == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T connectIndex = capture->ConnectCount;
        ++capture->ConnectCount;
        if (connectIndex < 4) {
            capture->ConnectFamilies[connectIndex] = remoteAddress->sa_family;
            if (remoteAddress->sa_family == AF_INET) {
                capture->ConnectPorts[connectIndex] =
                    reinterpret_cast<const SOCKADDR_IN*>(remoteAddress)->sin_port;
            }
            else if (remoteAddress->sa_family == AF_INET6) {
                capture->ConnectPorts[connectIndex] =
                    reinterpret_cast<const SOCKADDR_IN6*>(remoteAddress)->sin6_port;
            }
        }

        NTSTATUS status = capture->NextConnectStatus;
        if (connectIndex < capture->ConnectStatusCount) {
            status = capture->ConnectStatuses[connectIndex];
        }

        *socket = nullptr;
        if (NT_SUCCESS(status) || capture->ReturnSocketOnFailedConnect) {
            *socket = reinterpret_cast<KernelHttp::net::PWSK_SOCKET>(
                static_cast<uintptr_t>(0x1000U + static_cast<ULONG>(capture->ConnectCount)));
        }

        return status;
    }

    NTSTATUS FakeWskSend(
        void* context,
        KernelHttp::net::PWSK_SOCKET socket,
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags,
        const KernelHttp::net::WskCancellationToken* cancellation) noexcept
    {
        UNREFERENCED_PARAMETER(socket);
        UNREFERENCED_PARAMETER(flags);
        UNREFERENCED_PARAMETER(cancellation);

        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr || data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->SendCount;
        capture->LastSendLength = length < sizeof(capture->LastSend) ? length : sizeof(capture->LastSend);
        memcpy(capture->LastSend, data, capture->LastSendLength);
        if (bytesSent != nullptr) {
            *bytesSent = NT_SUCCESS(capture->NextSendStatus) ? length : 0;
        }
        return capture->NextSendStatus;
    }

    NTSTATUS FakeWskReceive(
        void* context,
        KernelHttp::net::PWSK_SOCKET socket,
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        const KernelHttp::net::WskCancellationToken* cancellation) noexcept
    {
        UNREFERENCED_PARAMETER(socket);
        UNREFERENCED_PARAMETER(flags);
        UNREFERENCED_PARAMETER(timeoutMilliseconds);
        UNREFERENCED_PARAMETER(cancellation);

        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr || data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->ReceiveCount;
        if (NT_SUCCESS(capture->NextReceiveStatus) && length != 0) {
            static const char payload[] = "rx";
            const SIZE_T copy = sizeof(payload) - 1 < length ? sizeof(payload) - 1 : length;
            memcpy(data, payload, copy);
            if (bytesReceived != nullptr) {
                *bytesReceived = copy;
            }
        }
        else if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }
        return capture->NextReceiveStatus;
    }

    void FakeWskClose(void* context, KernelHttp::net::PWSK_SOCKET socket) noexcept
    {
        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr) {
            return;
        }

        ++capture->CloseCount;
        capture->LastClosedSocket = socket;
    }

    void TestWskFakeProviderCancellationAndCleanup() noexcept
    {
        FakeWskSocketCapture capture = {};
        KernelHttp::net::WskTestSocketProvider provider = {};
        provider.Connect = FakeWskConnect;
        provider.Send = FakeWskSend;
        provider.Receive = FakeWskReceive;
        provider.Close = FakeWskClose;
        KernelHttp::net::WskTestSetSocketProvider(&provider, &capture);

        KernelHttp::net::WskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "fake WSK client initializes");

        SOCKADDR_IN remote = {};
        remote.sin_family = AF_INET;
        remote.sin_port = HostToNetworkPort(L"443");

        capture.NextConnectStatus = STATUS_IO_TIMEOUT;
        capture.ReturnSocketOnFailedConnect = true;
        KernelHttp::net::WskSocket timeoutSocket;
        status = timeoutSocket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(status == STATUS_IO_TIMEOUT, "fake connect timeout is returned");
        Expect(capture.CloseCount == 1, "late connected socket is closed after failed connect");
        Expect(!timeoutSocket.IsConnected(), "timeout socket is not connected");

        capture.NextConnectStatus = STATUS_SUCCESS;
        capture.ReturnSocketOnFailedConnect = false;
        KernelHttp::net::WskSocket sendSocket;
        status = sendSocket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(NT_SUCCESS(status), "fake connect succeeds before send cancel");
        Expect(sendSocket.IsConnected(), "send socket is connected");

        KernelHttp::net::WskCancellationToken cancellation = {};
        cancellation.IsCancellationRequested = AlwaysCancel;
        SIZE_T sent = 99;
        status = sendSocket.Send("abc", Length("abc"), &sent, 0, &cancellation);
        Expect(status == STATUS_CANCELLED, "send observes caller cancellation");
        Expect(sent == 0, "canceled send reports zero bytes");
        Expect(capture.CloseCount == 2, "canceled send closes socket");
        Expect(!sendSocket.IsConnected(), "canceled send detaches socket");
        status = sendSocket.Close();
        Expect(NT_SUCCESS(status), "closing an already canceled send socket succeeds");
        Expect(capture.CloseCount == 2, "close after canceled send is idempotent");

        KernelHttp::net::WskSocket receiveSocket;
        status = receiveSocket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(NT_SUCCESS(status), "fake connect succeeds before receive timeout");
        capture.NextReceiveStatus = STATUS_IO_TIMEOUT;
        char receiveBuffer[8] = {};
        SIZE_T received = 99;
        status = receiveSocket.Receive(receiveBuffer, sizeof(receiveBuffer), &received);
        Expect(status == STATUS_IO_TIMEOUT, "receive timeout is returned");
        Expect(received == 0, "timed-out receive reports zero bytes");
        Expect(capture.CloseCount == 3, "timed-out receive closes socket");
        Expect(!receiveSocket.IsConnected(), "timed-out receive detaches socket");

        KernelHttp::net::WskTestSetSocketProvider(nullptr, nullptr);
    }

    void TestResolveAllSequentialConnectFallback() noexcept
    {
        KernelHttp::net::WskTestClearResolveCache();

        FakeResolveCapture resolveCapture = {};
        KernelHttp::net::WskTestSetResolveAll(FakeResolveAll, &resolveCapture);

        FakeWskSocketCapture socketCapture = {};
        socketCapture.ConnectStatusCount = 2;
        socketCapture.ConnectStatuses[0] = STATUS_IO_TIMEOUT;
        socketCapture.ConnectStatuses[1] = STATUS_SUCCESS;

        KernelHttp::net::WskTestSocketProvider provider = {};
        provider.Connect = FakeWskConnect;
        provider.Close = FakeWskClose;
        KernelHttp::net::WskTestSetSocketProvider(&provider, &socketCapture);

        KernelHttp::net::WskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "fake WSK client initializes for sequential connect");

        SOCKADDR_STORAGE addresses[KernelHttp::net::WskMaxResolvedAddresses] = {};
        SIZE_T addressCount = 0;
        status = client.ResolveAll(
            L"fallback.example",
            L"443",
            addresses,
            KernelHttp::net::WskMaxResolvedAddresses,
            &addressCount,
            KernelHttp::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "ResolveAll returns sequential connect candidates");
        Expect(addressCount == 2, "ResolveAll returns two ordered candidates");

        KernelHttp::net::WskSocket firstSocket;
        status = firstSocket.Connect(client, reinterpret_cast<const SOCKADDR*>(&addresses[0]));
        Expect(status == STATUS_IO_TIMEOUT, "first resolved address connect failure is surfaced");
        Expect(!firstSocket.IsConnected(), "failed first resolved address does not leave a connected socket");

        KernelHttp::net::WskSocket secondSocket;
        status = secondSocket.Connect(client, reinterpret_cast<const SOCKADDR*>(&addresses[1]));
        Expect(NT_SUCCESS(status), "second resolved address connect succeeds after first failure");
        Expect(secondSocket.IsConnected(), "second resolved address leaves socket connected");
        Expect(socketCapture.ConnectCount == 2, "two resolved addresses were tried in order");
        Expect(socketCapture.ConnectFamilies[0] == AF_INET, "first sequential candidate is IPv4");
        Expect(socketCapture.ConnectFamilies[1] == AF_INET6, "second sequential candidate is IPv6");
        Expect(socketCapture.ConnectPorts[0] == HostToNetworkPort(L"443"), "first sequential candidate keeps service port");
        Expect(socketCapture.ConnectPorts[1] == HostToNetworkPort(L"443"), "second sequential candidate keeps service port");

        status = secondSocket.Close();
        Expect(NT_SUCCESS(status), "closing sequential connect socket succeeds");
        Expect(socketCapture.CloseCount == 1, "only the successful sequential socket is closed");

        KernelHttp::net::WskTestSetSocketProvider(nullptr, nullptr);
        KernelHttp::net::WskTestSetResolveAll(nullptr, nullptr);
        KernelHttp::net::WskTestClearResolveCache();
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
        capture.FirstConnectionReusable = false;
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

    void TestChunkedRequestBody() noexcept
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for chunked request body");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for chunked request body");

        const char* url = "http://example.com/upload";
        status = KernelHttp::khttp::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for chunked request body");

        status = KernelHttp::khttp::RequestSetMethod(request, KernelHttp::khttp::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds for chunked request body");

        const char* body = "payload-bytes";
        status = KernelHttp::khttp::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for chunked request body");

        status = KernelHttp::khttp::RequestSetBodyMode(
            request,
            KernelHttp::khttp::RequestBodyMode::Chunked);
        Expect(NT_SUCCESS(status), "RequestSetBodyMode enables chunked request body");

        KernelHttp::khttp::Response* resp = nullptr;
        status = KernelHttp::khttp::Send(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "chunked request body send succeeds");
        Expect(KernelHttp::khttp::ResponseStatusCode(resp) == 201, "chunked request response status is 201");
        Expect(BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Transfer-Encoding: chunked"), "chunked request emits Transfer-Encoding");
        Expect(!BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Content-Length:"), "chunked request omits Content-Length");
        Expect(BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "\r\nd\r\npayload-bytes\r\n0\r\n\r\n"), "chunked request body is framed");

        KernelHttp::khttp::ResponseRelease(resp);
        KernelHttp::khttp::RequestRelease(request);
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

        const char* rangeName = "Range";
        const char* rangeValue = "bytes=0-3";
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            rangeName, Length(rangeName),
            rangeValue, Length(rangeValue));
        Expect(NT_SUCCESS(status), "Range header succeeds as pass-through");

        const char* conditionName = "If-None-Match";
        const char* conditionValue = "\"etag\"";
        status = KernelHttp::khttp::RequestSetHeader(
            request,
            conditionName, Length(conditionName),
            conditionValue, Length(conditionValue));
        Expect(NT_SUCCESS(status), "conditional request header succeeds as pass-through");

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
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Range: bytes=0-3\r\n"),
            "Range header is passed through");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "If-None-Match: \"etag\"\r\n"),
            "conditional request header is passed through");

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

    void TestRequestReservedHeadersRejected() noexcept
    {
        ExpectRejectedRequestHeader(
            "Host",
            "other.example",
            false,
            STATUS_INVALID_PARAMETER,
            "khttp send rejects caller-supplied Host header");

        ExpectRejectedRequestHeader(
            "Content-Length",
            "12",
            false,
            STATUS_INVALID_PARAMETER,
            "khttp send rejects caller-supplied Content-Length header");

        ExpectRejectedRequestHeader(
            "Connection",
            "close",
            false,
            STATUS_INVALID_PARAMETER,
            "khttp send rejects caller-supplied Connection header");

        ExpectRejectedRequestHeader(
            "TE",
            "trailers",
            false,
            STATUS_NOT_SUPPORTED,
            "khttp send rejects request TE header");

        ExpectRejectedRequestHeader(
            "Trailer",
            "Digest",
            false,
            STATUS_NOT_SUPPORTED,
            "khttp send rejects request Trailer header");

        ExpectRejectedRequestHeader(
            "Expect",
            "100-continue",
            true,
            STATUS_NOT_SUPPORTED,
            "khttp send rejects body with Expect: 100-continue");
    }

    void TestRequestMethodRejectsUnsupportedValues() noexcept
    {
        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for method boundary test");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for method boundary test");

        status = KernelHttp::khttp::RequestSetMethod(
            request,
            static_cast<KernelHttp::khttp::Method>(0xFFFFFFFFUL));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetMethod rejects unsupported method enum");

        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);
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

    struct AsyncReleaseDuringWorkerCapture
    {
        bool ObservedCanceledAfterRelease = false;
        NTSTATUS CancelStatus = STATUS_UNSUCCESSFUL;
        SIZE_T CleanupCount = 0;
        SIZE_T CompletionCount = 0;
        NTSTATUS CompletionStatus = STATUS_UNSUCCESSFUL;
    };

    void RecordAsyncReleaseDuringWorkerCompletion(void* context, NTSTATUS status) noexcept
    {
        auto* capture = static_cast<AsyncReleaseDuringWorkerCapture*>(context);
        if (capture == nullptr) {
            return;
        }

        ++capture->CompletionCount;
        capture->CompletionStatus = status;
    }

    void CleanupAsyncReleaseDuringWorker(void* context) noexcept
    {
        auto* capture = static_cast<AsyncReleaseDuringWorkerCapture*>(context);
        if (capture != nullptr) {
            ++capture->CleanupCount;
        }
    }

    NTSTATUS ReleaseDuringAsyncWorker(
        KernelHttp::engine::KH_ASYNC_OPERATION operation,
        void* context) noexcept
    {
        auto* capture = static_cast<AsyncReleaseDuringWorkerCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        capture->CancelStatus = KernelHttp::engine::KhAsyncOperationCancel(operation);
        KernelHttp::engine::KhAsyncOperationRelease(operation);
        capture->ObservedCanceledAfterRelease =
            KernelHttp::engine::KhAsyncOperationIsCanceled(operation);
        return capture->ObservedCanceledAfterRelease ? STATUS_CANCELLED : STATUS_UNSUCCESSFUL;
    }

    void TestAsyncWorkerObservesCancelAfterRelease() noexcept
    {
        KernelHttp::khttp::test::SetAsyncAutoRun(false);

        AsyncReleaseDuringWorkerCapture capture = {};
        KernelHttp::engine::KhAsyncCreateOptions options = {};
        options.Kind = KernelHttp::engine::KhAsyncOperationKind::HttpSend;
        options.WorkerRoutine = ReleaseDuringAsyncWorker;
        options.CleanupRoutine = CleanupAsyncReleaseDuringWorker;
        options.Context = &capture;
        options.CompletionCallback = RecordAsyncReleaseDuringWorkerCompletion;
        options.CompletionContext = &capture;

        KernelHttp::engine::KH_ASYNC_OPERATION operation = nullptr;
        NTSTATUS status = KernelHttp::engine::KhAsyncOperationCreate(options, &operation);
        Expect(NT_SUCCESS(status), "direct async operation create succeeds");
        Expect(operation != nullptr, "direct async operation is returned");

        status = KernelHttp::engine::KhTestRunAsyncOperation(operation);
        Expect(status == STATUS_CANCELLED, "manual run returns canceled after release");
        Expect(NT_SUCCESS(capture.CancelStatus), "worker cancel succeeds before release");
        Expect(capture.ObservedCanceledAfterRelease, "worker observes cancel after release");
        Expect(capture.CompletionCount == 1, "completion fires once when worker releases handle");
        Expect(capture.CompletionStatus == STATUS_CANCELLED, "completion status remains canceled");
        Expect(capture.CleanupCount == 1, "cleanup fires once after worker reference is released");
        Expect(NT_SUCCESS(KernelHttp::engine::KhEngineDrainAsync()), "async drain succeeds after manual worker release");

        KernelHttp::khttp::test::SetAsyncAutoRun(true);
    }

    struct AllocatorProbe
    {
        ULONG Magic = 0x504C4C41;
    };

    void TestNonPagedAllocatorBaseline() noexcept
    {
        void* empty = KernelHttp::AllocateNonPagedPoolBytes(0);
        Expect(empty == nullptr, "zero-byte nonpaged allocation is rejected");

        auto* bytes = static_cast<UCHAR*>(KernelHttp::AllocateNonPagedPoolBytes(16));
        Expect(bytes != nullptr, "nonpaged byte allocation succeeds");
        bool bytesAreZero = true;
        for (SIZE_T index = 0; bytes != nullptr && index < 16; ++index) {
            if (bytes[index] != 0) {
                bytesAreZero = false;
            }
        }
        Expect(bytesAreZero, "nonpaged byte allocation is zero initialized");
        KernelHttp::FreeNonPagedPoolBytes(bytes);

        KernelHttp::HeapArray<UCHAR> array(8);
        Expect(array.IsValid(), "HeapArray uses nonpaged allocator wrapper");
        bool arrayIsZero = true;
        for (SIZE_T index = 0; array.IsValid() && index < array.Count(); ++index) {
            if (array[index] != 0) {
                arrayIsZero = false;
            }
        }
        Expect(arrayIsZero, "HeapArray remains zero initialized");

        KernelHttp::HeapObject<AllocatorProbe> object;
        Expect(object.IsValid(), "HeapObject uses nonpaged allocator wrapper");
        Expect(object->Magic == 0x504C4C41, "HeapObject preserves constructor initialization");
    }

    void TestPagedPoolRejected() noexcept
    {
        KernelHttp::engine::KhWorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = KernelHttp::engine::KhPoolType::Paged;
        KernelHttp::engine::KhWorkspace* workspace = nullptr;
        NTSTATUS status = KernelHttp::engine::KhWorkspaceCreate(&workspaceOptions, &workspace);
        Expect(status == STATUS_INVALID_PARAMETER, "workspace rejects paged pool");
        Expect(workspace == nullptr, "workspace output remains null when paged pool is rejected");

        KernelHttp::engine::KhSessionOptions sessionOptions = {};
        sessionOptions.ResponsePoolType = KernelHttp::engine::KhPoolType::Paged;
        KernelHttp::engine::KH_SESSION apiSession = nullptr;
        status = KernelHttp::engine::KhSessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &sessionOptions,
            &apiSession);
        Expect(status == STATUS_INVALID_PARAMETER, "engine SessionCreate rejects paged response pool");
        Expect(apiSession == nullptr, "engine SessionCreate does not allocate a paged session");

        KernelHttp::khttp::SessionConfig config = {};
        config.ResponsePool = KernelHttp::khttp::PoolType::Paged;
        KernelHttp::khttp::Session* session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(status == STATUS_INVALID_PARAMETER, "khttp SessionCreate rejects paged response pool");
        Expect(session == nullptr, "khttp SessionCreate does not allocate a paged session");
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

    void TestWebSocketControlFramesAndCloseEx() noexcept
    {
        WsCapture capture = {};
        const UCHAR pingPayload[] = { 'h', 'b' };
        capture.NextType = KernelHttp::engine::KhWebSocketMessageType::Ping;
        capture.NextLength = sizeof(pingPayload);
        memcpy(capture.NextData, pingPayload, capture.NextLength);

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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws controls");

        const char* url = "ws://example.com/socket";
        const char* subprotocol = "chat";
        KernelHttp::khttp::WebSocket* ws = nullptr;
        KernelHttp::khttp::WsConnectConfig wsConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.Subprotocol = subprotocol;
        wsConfig.SubprotocolLength = Length(subprotocol);
        wsConfig.AutoReplyPing = false;
        status = KernelHttp::khttp::WsConnect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for control frame API");
        Expect(strcmp(capture.LastSubprotocol, subprotocol) == 0, "subprotocol is sent in websocket connect");

        const char* selectedSubprotocol = nullptr;
        SIZE_T selectedSubprotocolLength = 0;
        status = KernelHttp::khttp::WsSelectedSubprotocol(
            ws,
            &selectedSubprotocol,
            &selectedSubprotocolLength);
        Expect(NT_SUCCESS(status), "selected subprotocol query succeeds");
        Expect(
            selectedSubprotocol != nullptr &&
            selectedSubprotocolLength == Length(subprotocol) &&
            memcmp(selectedSubprotocol, subprotocol, selectedSubprotocolLength) == 0,
            "selected subprotocol matches negotiated token");

        KernelHttp::khttp::WsMessage message = {};
        status = KernelHttp::khttp::WsReceive(ws, &message);
        Expect(NT_SUCCESS(status), "WsReceive returns manual ping event");
        Expect(message.Type == KernelHttp::khttp::WsMsgType::Ping, "received ping type");
        Expect(message.DataLength == sizeof(pingPayload), "received ping payload length");

        status = KernelHttp::khttp::WsSendPong(ws, message.Data, message.DataLength);
        Expect(NT_SUCCESS(status), "WsSendPong succeeds");
        Expect(capture.LastSendType == KernelHttp::engine::KhWebSocketMessageType::Pong, "pong type captured");
        Expect(capture.LastSendLength == sizeof(pingPayload), "pong payload length captured");
        Expect(memcmp(capture.LastSendData, pingPayload, sizeof(pingPayload)) == 0, "pong payload captured");
        Expect(capture.LastSendFinalFragment, "pong is final");

        const UCHAR activePing[] = { 'p', 'i', 'n', 'g' };
        status = KernelHttp::khttp::WsSendPing(ws, activePing, sizeof(activePing));
        Expect(NT_SUCCESS(status), "WsSendPing succeeds");
        Expect(capture.LastSendType == KernelHttp::engine::KhWebSocketMessageType::Ping, "ping type captured");
        Expect(capture.LastSendLength == sizeof(activePing), "ping payload length captured");
        Expect(memcmp(capture.LastSendData, activePing, sizeof(activePing)) == 0, "ping payload captured");

        UCHAR tooLargePing[126] = {};
        status = KernelHttp::khttp::WsSendPing(ws, tooLargePing, sizeof(tooLargePing));
        Expect(status == STATUS_INVALID_PARAMETER, "WsSendPing rejects oversized control payload");

        const UCHAR reason[] = { 'b', 'y', 'e' };
        status = KernelHttp::khttp::WsCloseEx(ws, 1000, reason, sizeof(reason));
        Expect(NT_SUCCESS(status), "WsCloseEx succeeds");
        Expect(capture.LastSendType == KernelHttp::engine::KhWebSocketMessageType::Close, "close type captured");
        Expect(capture.LastSendLength == 2 + sizeof(reason), "close payload length captured");
        Expect(capture.LastSendData[0] == 0x03 && capture.LastSendData[1] == 0xe8, "close code captured");
        Expect(memcmp(capture.LastSendData + 2, reason, sizeof(reason)) == 0, "close reason captured");
        Expect(capture.CloseCount == 1, "CloseEx closes websocket once");

        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketFragmentedSendEnforcesTotalLimit() noexcept
    {
        WsCapture capture = {};
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws fragmented limit");

        const char* url = "ws://example.com/socket";
        KernelHttp::khttp::WebSocket* ws = nullptr;
        KernelHttp::khttp::WsConnectConfig wsConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.MaxMessageBytes = 5;
        status = KernelHttp::khttp::WsConnect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for fragmented limit");

        KernelHttp::khttp::WsSendOptions nonFinal = {};
        nonFinal.FinalFragment = false;
        const UCHAR first[] = { 'a', 'b', 'c' };
        status = KernelHttp::khttp::WsSendBinaryEx(ws, first, sizeof(first), &nonFinal);
        Expect(NT_SUCCESS(status), "first non-final binary fragment succeeds");
        Expect(capture.SendCount == 1, "first fragment reaches test transport");

        const UCHAR tooLarge[] = { 'd', 'e', 'f' };
        status = KernelHttp::khttp::WsSendContinuation(ws, tooLarge, sizeof(tooLarge));
        Expect(status == STATUS_BUFFER_TOO_SMALL, "continuation exceeding MaxMessageBytes is rejected");
        Expect(capture.SendCount == 1, "oversized continuation is not sent");

        const UCHAR final[] = { 'd', 'e' };
        status = KernelHttp::khttp::WsSendContinuation(ws, final, sizeof(final));
        Expect(NT_SUCCESS(status), "smaller final continuation still succeeds");
        Expect(capture.SendCount == 2, "final continuation reaches test transport");
        Expect(capture.LastSendType == KernelHttp::engine::KhWebSocketMessageType::Continuation,
            "final continuation type captured");
        Expect(capture.LastSendFinalFragment, "final continuation closes fragmented send");

        KernelHttp::khttp::WsClose(ws);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketReceiveCannotRaiseConnectionLimit() noexcept
    {
        WsCapture capture = {};
        const UCHAR payload[] = { 'a', 'b', 'c', 'd', 'e', 'f' };
        capture.NextType = KernelHttp::engine::KhWebSocketMessageType::Binary;
        capture.NextLength = sizeof(payload);
        memcpy(capture.NextData, payload, capture.NextLength);

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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws receive connection limit");

        const char* url = "ws://example.com/socket";
        KernelHttp::khttp::WebSocket* ws = nullptr;
        KernelHttp::khttp::WsConnectConfig wsConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.MaxMessageBytes = 5;
        status = KernelHttp::khttp::WsConnect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for receive connection limit");

        KernelHttp::khttp::WsReceiveOptions receiveOptions = {};
        receiveOptions.MaxMessageBytes = 10;
        KernelHttp::khttp::WsMessage message = {};
        status = KernelHttp::khttp::WsReceiveEx(ws, &receiveOptions, &message);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "WsReceiveEx cannot raise connection MaxMessageBytes");
        Expect(capture.ReceiveCount == 1, "oversized receive reaches test transport once");
        Expect(capture.CloseCount == 1, "oversized receive closes websocket transport");

        KernelHttp::khttp::WsClose(ws);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketPublicValidationMatchesRealPath() noexcept
    {
        WsCapture capture = {};
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws public validation");

        const char* url = "ws://example.com/socket";
        KernelHttp::khttp::WebSocket* ws = nullptr;
        KernelHttp::khttp::WsConnectConfig invalidConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        invalidConfig.Url = url;
        invalidConfig.UrlLength = Length(url);
        invalidConfig.Subprotocol = "bad token";
        invalidConfig.SubprotocolLength = Length(invalidConfig.Subprotocol);
        status = KernelHttp::khttp::WsConnect(session, &invalidConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "WsConnect rejects invalid subprotocol token");
        Expect(ws == nullptr, "invalid subprotocol does not allocate websocket");
        Expect(capture.ConnectCount == 0, "invalid subprotocol does not reach test transport");

        KernelHttp::khttp::WsConnectConfig validConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        validConfig.Url = url;
        validConfig.UrlLength = Length(url);
        status = KernelHttp::khttp::WsConnect(session, &validConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for public validation");

        const unsigned char invalidText[] = { 0xc3, 0x28 };
        status = KernelHttp::khttp::WsSendText(
            ws,
            reinterpret_cast<const char*>(invalidText),
            sizeof(invalidText));
        Expect(status == STATUS_INVALID_PARAMETER, "WsSendText rejects invalid UTF-8 before test transport");
        Expect(capture.SendCount == 0, "invalid text send does not reach test transport");

        const UCHAR invalidReason[] = { 0xc3, 0x28 };
        status = KernelHttp::khttp::WsCloseEx(ws, 1000, invalidReason, sizeof(invalidReason));
        Expect(status == STATUS_INVALID_PARAMETER, "WsCloseEx rejects invalid UTF-8 reason");
        Expect(capture.CloseCount == 0, "invalid close reason does not close websocket");

        KernelHttp::khttp::WsClose(ws);
        Expect(capture.CloseCount == 1, "valid cleanup close reaches test transport once");
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketTerminalTransportStatusDisconnectsHandle() noexcept
    {
        WsCapture capture = {};
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws terminal status");

        const char* url = "ws://example.com/socket";
        KernelHttp::khttp::WebSocket* ws = nullptr;
        KernelHttp::khttp::WsConnectConfig wsConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        status = KernelHttp::khttp::WsConnect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for send terminal status");

        capture.SendStatus = STATUS_IO_TIMEOUT;
        const char* text = "timeout";
        status = KernelHttp::khttp::WsSendText(ws, text, Length(text));
        Expect(status == STATUS_IO_TIMEOUT, "terminal send status is returned");
        Expect(capture.CloseCount == 1, "terminal send status closes test transport");
        capture.SendStatus = STATUS_SUCCESS;

        status = KernelHttp::khttp::WsSendText(ws, text, Length(text));
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "send after terminal send status is disconnected");
        Expect(capture.SendCount == 0, "send after terminal status does not reach test transport again");

        KernelHttp::khttp::WsClose(ws);
        Expect(capture.CloseCount == 1, "WsClose after terminal send status is idempotent");

        ws = nullptr;
        status = KernelHttp::khttp::WsConnect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for receive terminal status");
        capture.ReceiveStatus = STATUS_CANCELLED;
        KernelHttp::khttp::WsMessage message = {};
        status = KernelHttp::khttp::WsReceive(ws, &message);
        Expect(status == STATUS_CANCELLED, "terminal receive status is returned");
        Expect(capture.CloseCount == 2, "terminal receive status closes test transport");
        capture.ReceiveStatus = STATUS_SUCCESS;

        status = KernelHttp::khttp::WsReceive(ws, &message);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "receive after terminal status is disconnected");

        KernelHttp::khttp::WsClose(ws);
        Expect(capture.CloseCount == 2, "WsClose after terminal receive status is idempotent");

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
    TestResponseDuplicateHeaderSemantics();
    TestResponseTransferEncodingDecoded();
    TestTransferCodingCloseDelimitedHonorsTestTransportEof();
    TestResponseTrailersAreExposed();
    TestInformationalResponsesAreSkipped();
    TestSessionMaxResponseBytesLimitsSimpleApi();
    TestRequestRejectsHeaderAndUrlInjection();
    TestUrlRequestTargetAndHostSemantics();
    TestReusedConnectionFailureRetriesWithFreshConnection();
    TestReusedConnectionPostFailureDoesNotRetry();
    TestConnectionPoolHonorsMaxConnectionsPerHost();
    TestConnectionPoolHostQuotaSeparatesTlsReuseIdentity();
    TestConnectionPoolKeyIncludesTlsIdentity();
    TestResolveAllCacheBoundaries();
    TestResolveAllSequentialConnectFallback();
    TestWskFakeProviderCancellationAndCleanup();
    TestIdleTimeoutSkipsExpiredConnection();
    TestCloseDelimitedResponseDoesNotEnterPool();
    TestHttp10ConnectionReuseRules();
    TestSwitchingProtocolsDoesNotEnterHttpPool();
    TestFreshSafeConnectionTimeoutRetriesWithFreshConnection();
    TestFreshPostTimeoutDoesNotRetry();
    TestPostWithBody();
    TestChunkedRequestBody();
    TestSessionRequestBufferBytesLimitsRequestBody();
    TestRequestBuilder();
    TestRequestTransferEncodingRejected();
    TestRequestReservedHeadersRejected();
    TestRequestMethodRejectsUnsupportedValues();
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
    TestAsyncWorkerObservesCancelAfterRelease();
    TestNonPagedAllocatorBaseline();
    TestPagedPoolRejected();
    TestIrqlCheck();
    TestWebSocketRoundTrip();
    TestWebSocketControlFramesAndCloseEx();
    TestWebSocketFragmentedSendEnforcesTotalLimit();
    TestWebSocketReceiveCannotRaiseConnectionLimit();
    TestWebSocketPublicValidationMatchesRealPath();
    TestWebSocketTerminalTransportStatusDisconnectsHandle();

    if (g_failed) {
        printf("khttp tests FAILED\n");
        return 1;
    }
    printf("khttp tests passed\n");
    return 0;
}
