#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/TlsConnection.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::client::BuildHttp2RequestHeaders;
using KernelHttp::client::Http2ContentLengthBufferLength;
using KernelHttp::client::Http2MaxHeaderNameLength;
using KernelHttp::client::Http2MaxRequestHeaders;
using KernelHttp::client::Http2RequestOptions;
using KernelHttp::client::Http2TransportMode;
using KernelHttp::http::HttpHeader;
using KernelHttp::http::HttpMethod;
using KernelHttp::http::HttpText;
using KernelHttp::http::MakeText;
using KernelHttp::http2::Http2Connection;
using KernelHttp::http2::Http2FrameCodec;
using KernelHttp::http2::Http2InitialWindowSize;
using KernelHttp::http2::Http2MaxWindowSize;
using KernelHttp::http2::Http2Settings;
using KernelHttp::http2::Http2Transport;
namespace Http2FrameFlags = KernelHttp::http2::Http2FrameFlags;

namespace KernelHttp
{
namespace net
{
    WskSocket::~WskSocket() noexcept = default;

    NTSTATUS WskSocket::Connect(WskClient&, const SOCKADDR*, const SOCKADDR*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(WskBuffer&, SIZE_T, SIZE_T*, ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(const void*, SIZE_T, SIZE_T*, ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(WskBuffer&, SIZE_T, SIZE_T*, ULONG, ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(void*, SIZE_T, SIZE_T*, ULONG, ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Disconnect(ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Close() noexcept
    {
        return STATUS_SUCCESS;
    }

    bool WskSocket::IsConnected() const noexcept
    {
        return false;
    }

    PWSK_SOCKET WskSocket::NativeSocket() const noexcept
    {
        return nullptr;
    }
}

namespace tls
{
    TlsConnection::~TlsConnection() noexcept = default;

    NTSTATUS TlsConnection::Connect(core::ITransport&, const TlsClientConnectionOptions&) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS TlsConnection::Send(core::ITransport&, const void*, SIZE_T, SIZE_T*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS TlsConnection::Receive(core::ITransport&, void*, SIZE_T, SIZE_T*, ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    const char* TlsConnection::NegotiatedAlpn() const noexcept
    {
        return nullptr;
    }

    SIZE_T TlsConnection::NegotiatedAlpnLength() const noexcept
    {
        return 0;
    }
}
}

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message)
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    bool TextEquals(HttpText text, const char* literal)
    {
        const size_t len = strlen(literal);
        return text.Data != nullptr &&
            text.Length == len &&
            memcmp(text.Data, literal, len) == 0;
    }

    int CountHeaders(const HttpHeader* headers, size_t headerCount, const char* name)
    {
        int count = 0;
        for (size_t i = 0; i < headerCount; ++i) {
            if (TextEquals(headers[i].Name, name)) {
                ++count;
            }
        }
        return count;
    }

    const HttpHeader* FindHeader(const HttpHeader* headers, size_t headerCount, const char* name)
    {
        for (size_t i = 0; i < headerCount; ++i) {
            if (TextEquals(headers[i].Name, name)) {
                return headers + i;
            }
        }
        return nullptr;
    }

    class ScriptedHttp2Transport final : public Http2Transport
    {
    public:
        ScriptedHttp2Transport(const UCHAR* receiveBytes, SIZE_T receiveLength) noexcept
            : receiveBytes_(receiveBytes),
              receiveLength_(receiveLength)
        {
        }

        NTSTATUS Send(const UCHAR* data, SIZE_T length) noexcept override
        {
            if (data == nullptr && length != 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (length > sizeof(sentBytes_) - sentLength_) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (length != 0) {
                memcpy(sentBytes_ + sentLength_, data, length);
                sentLength_ += length;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS Receive(UCHAR* data, SIZE_T length, SIZE_T* bytesReceived) noexcept override
        {
            if (bytesReceived != nullptr) {
                *bytesReceived = 0;
            }
            if (data == nullptr || length == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (receiveOffset_ >= receiveLength_) {
                return STATUS_CONNECTION_DISCONNECTED;
            }

            SIZE_T available = receiveLength_ - receiveOffset_;
            SIZE_T toCopy = length < available ? length : available;
            memcpy(data, receiveBytes_ + receiveOffset_, toCopy);
            receiveOffset_ += toCopy;
            if (bytesReceived != nullptr) {
                *bytesReceived = toCopy;
            }
            return STATUS_SUCCESS;
        }

    private:
        const UCHAR* receiveBytes_ = nullptr;
        SIZE_T receiveLength_ = 0;
        SIZE_T receiveOffset_ = 0;
        UCHAR sentBytes_[4096] = {};
        SIZE_T sentLength_ = 0;
    };

    bool AppendServerSettings(UCHAR* script, SIZE_T capacity, SIZE_T* length)
    {
        Http2Settings settings = {};
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeSettings(
            settings,
            script + *length,
            capacity - *length,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *length += written;
        return true;
    }

    bool AppendResponseHeadersForStream(
        ULONG streamId,
        bool endStream,
        bool endHeaders,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        const UCHAR status200[] = { 0x88 };
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeHeaders(
            streamId,
            status200,
            sizeof(status200),
            endStream,
            endHeaders,
            script + *length,
            capacity - *length,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *length += written;
        return true;
    }

    bool AppendResponseHeaders(
        bool endStream,
        bool endHeaders,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        return AppendResponseHeadersForStream(1, endStream, endHeaders, script, capacity, length);
    }

    bool AppendResponseContinuation(UCHAR* script, SIZE_T capacity, SIZE_T* length)
    {
        const UCHAR status200[] = { 0x88 };
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeContinuation(
            1,
            status200,
            sizeof(status200),
            true,
            script + *length,
            capacity - *length,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *length += written;
        return true;
    }

    bool AppendEmptyData(UCHAR* script, SIZE_T capacity, SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeData(
            1,
            nullptr,
            0,
            false,
            script + *length,
            capacity - *length,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *length += written;
        return true;
    }

    bool AppendConnectionWindowUpdate(
        ULONG increment,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeWindowUpdate(
            0,
            increment,
            script + *length,
            capacity - *length,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *length += written;
        return true;
    }

    bool AppendEmptyContinuation(
        bool endHeaders,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeContinuation(
            1,
            nullptr,
            0,
            endHeaders,
            script + *length,
            capacity - *length,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *length += written;
        return true;
    }

    bool AppendRawFrame(
        KernelHttp::http2::Http2FrameType type,
        UCHAR flags,
        ULONG streamId,
        const UCHAR* payload,
        SIZE_T payloadLength,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        if (payloadLength > 0x00ffffffUL ||
            script == nullptr ||
            length == nullptr ||
            (payload == nullptr && payloadLength != 0) ||
            capacity - *length < payloadLength + 9) {
            return false;
        }

        UCHAR* frame = script + *length;
        frame[0] = static_cast<UCHAR>((payloadLength >> 16) & 0xff);
        frame[1] = static_cast<UCHAR>((payloadLength >> 8) & 0xff);
        frame[2] = static_cast<UCHAR>(payloadLength & 0xff);
        frame[3] = static_cast<UCHAR>(type);
        frame[4] = flags;
        frame[5] = static_cast<UCHAR>((streamId >> 24) & 0x7f);
        frame[6] = static_cast<UCHAR>((streamId >> 16) & 0xff);
        frame[7] = static_cast<UCHAR>((streamId >> 8) & 0xff);
        frame[8] = static_cast<UCHAR>(streamId & 0xff);
        if (payloadLength != 0) {
            memcpy(frame + 9, payload, payloadLength);
        }
        *length += payloadLength + 9;
        return true;
    }

    NTSTATUS SendScriptedHttp2Request(const UCHAR* script, SIZE_T scriptLength)
    {
        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };

        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
        char responseBody[32] = {};
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[128] = {};

        return connection.SendRequest(
            transport,
            requestHeaders,
            sizeof(requestHeaders) / sizeof(requestHeaders[0]),
            nullptr,
            0,
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            responseBody,
            sizeof(responseBody),
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));
    }

    void TestPromotedAcceptEncodingIsNotDuplicated()
    {
        const HttpHeader extraHeaders[] = {
            { MakeText("Accept"), MakeText("*/*") },
            { MakeText("Accept-Encoding"), MakeText("gzip, deflate, br, identity") }
        };

        Http2RequestOptions options = {};
        options.TransportMode = Http2TransportMode::TlsAlpn;
        options.ServerName = "nghttp2.org";
        options.ServerNameLength = strlen(options.ServerName);
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/httpbin/get");
        options.Authority = MakeText("nghttp2.org");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.AcceptEncoding = extraHeaders[1].Value;
        options.ExtraHeaders = extraHeaders;
        options.ExtraHeaderCount = sizeof(extraHeaders) / sizeof(extraHeaders[0]);

        HttpHeader headers[Http2MaxRequestHeaders] = {};
        char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength] = {};
        char contentLength[Http2ContentLengthBufferLength] = {};
        size_t headerCount = 0;

        NTSTATUS status = BuildHttp2RequestHeaders(
            options,
            headers,
            Http2MaxRequestHeaders,
            lowerHeaderNames,
            contentLength,
            &headerCount);

        Expect(status == STATUS_SUCCESS, "BuildHttp2RequestHeaders succeeds");
        Expect(CountHeaders(headers, headerCount, "accept-encoding") == 1, "accept-encoding is emitted once");

        const HttpHeader* acceptEncoding = FindHeader(headers, headerCount, "accept-encoding");
        Expect(acceptEncoding != nullptr, "accept-encoding header exists");
        Expect(TextEquals(acceptEncoding->Value, "gzip, deflate, br, identity"), "accept-encoding value is preserved");

        const HttpHeader* accept = FindHeader(headers, headerCount, "accept");
        Expect(accept != nullptr, "accept extra header is preserved");
        Expect(TextEquals(accept->Value, "*/*"), "accept value is preserved");
    }

    void TestExtraAcceptEncodingRemainsWhenNotPromoted()
    {
        const HttpHeader extraHeaders[] = {
            { MakeText("Accept-Encoding"), MakeText("identity") }
        };

        Http2RequestOptions options = {};
        options.TransportMode = Http2TransportMode::TlsAlpn;
        options.ServerName = "nghttp2.org";
        options.ServerNameLength = strlen(options.ServerName);
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/httpbin/get");
        options.Authority = MakeText("nghttp2.org");
        options.ExtraHeaders = extraHeaders;
        options.ExtraHeaderCount = sizeof(extraHeaders) / sizeof(extraHeaders[0]);

        HttpHeader headers[Http2MaxRequestHeaders] = {};
        char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength] = {};
        char contentLength[Http2ContentLengthBufferLength] = {};
        size_t headerCount = 0;

        NTSTATUS status = BuildHttp2RequestHeaders(
            options,
            headers,
            Http2MaxRequestHeaders,
            lowerHeaderNames,
            contentLength,
            &headerCount);

        Expect(status == STATUS_SUCCESS, "BuildHttp2RequestHeaders succeeds without promoted accept-encoding");
        Expect(CountHeaders(headers, headerCount, "accept-encoding") == 1, "extra accept-encoding remains");

        const HttpHeader* acceptEncoding = FindHeader(headers, headerCount, "accept-encoding");
        Expect(acceptEncoding != nullptr, "extra accept-encoding header exists");
        Expect(TextEquals(acceptEncoding->Value, "identity"), "extra accept-encoding value is preserved");
    }

    void TestUpgradeReceivesResponseOnStreamOne()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "Upgrade server settings fixture builds");
        Expect(AppendResponseHeadersForStream(1, true, true, script, sizeof(script), &scriptLength),
            "Upgrade stream 1 response fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.InitializeAfterUpgrade(transport);
        Expect(status == STATUS_SUCCESS, "InitializeAfterUpgrade succeeds");

        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
        char responseBody[32] = {};
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[128] = {};

        status = connection.ReceiveResponse(
            transport,
            1,
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            responseBody,
            sizeof(responseBody),
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));

        Expect(status == STATUS_SUCCESS, "Upgrade stream 1 response succeeds");
        Expect(statusCode == 200, "Upgrade stream 1 status is decoded");
        Expect(responseHeaderCount == 1, "Upgrade stream 1 header count matches");
        Expect(responseBodyLength == 0, "Upgrade stream 1 response body is empty");
    }

    void TestUpgradeReservesStreamOneForInitiatingRequest()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "Upgrade server settings fixture builds");
        Expect(AppendResponseHeadersForStream(3, true, true, script, sizeof(script), &scriptLength),
            "Upgrade stream 3 response fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.InitializeAfterUpgrade(transport);
        Expect(status == STATUS_SUCCESS, "InitializeAfterUpgrade reserves stream 1");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("http") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };

        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
        char responseBody[32] = {};
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[128] = {};

        status = connection.SendRequest(
            transport,
            requestHeaders,
            sizeof(requestHeaders) / sizeof(requestHeaders[0]),
            nullptr,
            0,
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            responseBody,
            sizeof(responseBody),
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));

        Expect(status == STATUS_SUCCESS, "Post-upgrade request uses stream 3");
        Expect(statusCode == 200, "Post-upgrade stream 3 status is decoded");
    }

    void TestConnectionRejectsOrphanContinuation()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseContinuation(script, sizeof(script), &scriptLength), "HTTP/2 orphan continuation fixture builds");

        const NTSTATUS status = SendScriptedHttp2Request(script, scriptLength);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 connection rejects orphan CONTINUATION");
    }

    void TestConnectionRejectsInterleavedFrameDuringContinuation()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseHeaders(false, false, script, sizeof(script), &scriptLength), "HTTP/2 split headers fixture builds");
        Expect(AppendEmptyData(script, sizeof(script), &scriptLength), "HTTP/2 interleaved data fixture builds");

        const NTSTATUS status = SendScriptedHttp2Request(script, scriptLength);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 connection rejects DATA before CONTINUATION completes");
    }

    void TestConnectionRejectsWindowUpdateOverflow()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendConnectionWindowUpdate(
            Http2MaxWindowSize - Http2InitialWindowSize,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 legal connection WINDOW_UPDATE fixture builds");
        Expect(AppendConnectionWindowUpdate(
            1,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 overflowing connection WINDOW_UPDATE fixture builds");

        const NTSTATUS status = SendScriptedHttp2Request(script, scriptLength);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 connection rejects connection window overflow");
    }

    void TestConnectionRejectsEmptyContinuationFlood()
    {
        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseHeaders(false, false, script, sizeof(script), &scriptLength), "HTTP/2 split headers fixture builds");
        for (ULONG index = 0; index < 5; ++index) {
            Expect(AppendEmptyContinuation(false, script, sizeof(script), &scriptLength), "HTTP/2 empty continuation fixture builds");
        }

        const NTSTATUS status = SendScriptedHttp2Request(script, scriptLength);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 connection rejects empty CONTINUATION flood");
    }

    void TestConnectionRejectsStreamZeroData()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Data,
            0,
            0,
            nullptr,
            0,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 stream zero DATA fixture builds");

        const NTSTATUS status = SendScriptedHttp2Request(script, scriptLength);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 connection rejects stream zero DATA");
    }

    void TestConnectionRejectsStreamZeroHeaders()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR status200[] = { 0x88 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Headers,
            Http2FrameFlags::EndHeaders,
            0,
            status200,
            sizeof(status200),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 stream zero HEADERS fixture builds");

        const NTSTATUS status = SendScriptedHttp2Request(script, scriptLength);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 connection rejects stream zero HEADERS");
    }

    void TestConnectionRejectsStreamZeroRstStream()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR cancelPayload[] = { 0, 0, 0, 8 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::RstStream,
            0,
            0,
            cancelPayload,
            sizeof(cancelPayload),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 stream zero RST_STREAM fixture builds");

        const NTSTATUS status = SendScriptedHttp2Request(script, scriptLength);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 connection rejects stream zero RST_STREAM");
    }
}

int main()
{
    TestPromotedAcceptEncodingIsNotDuplicated();
    TestExtraAcceptEncodingRemainsWhenNotPromoted();
    TestUpgradeReceivesResponseOnStreamOne();
    TestUpgradeReservesStreamOneForInitiatingRequest();
    TestConnectionRejectsOrphanContinuation();
    TestConnectionRejectsInterleavedFrameDuringContinuation();
    TestConnectionRejectsWindowUpdateOverflow();
    TestConnectionRejectsEmptyContinuationFlood();
    TestConnectionRejectsStreamZeroData();
    TestConnectionRejectsStreamZeroHeaders();
    TestConnectionRejectsStreamZeroRstStream();

    if (g_failed) {
        printf("HTTP2 CLIENT TESTS FAILED\n");
        return 1;
    }

    printf("HTTP2 CLIENT TESTS PASSED\n");
    return 0;
}
