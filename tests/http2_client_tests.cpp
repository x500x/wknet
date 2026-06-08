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

    NTSTATUS WskSocket::Connect(WskClient&, const SOCKADDR*, const SOCKADDR*, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(WskBuffer&, SIZE_T, SIZE_T*, ULONG, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(const void*, SIZE_T, SIZE_T*, ULONG, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(WskBuffer&, SIZE_T, SIZE_T*, ULONG, ULONG, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(void*, SIZE_T, SIZE_T*, ULONG, ULONG, const WskCancellationToken*) noexcept
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
        ScriptedHttp2Transport(
            const UCHAR* receiveBytes,
            SIZE_T receiveLength,
            bool timeoutAtEnd = false) noexcept
            : receiveBytes_(receiveBytes),
              receiveLength_(receiveLength),
              timeoutAtEnd_(timeoutAtEnd)
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
                return timeoutAtEnd_ ? STATUS_IO_TIMEOUT : STATUS_CONNECTION_DISCONNECTED;
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

        const UCHAR* SentBytes() const noexcept
        {
            return sentBytes_;
        }

        SIZE_T SentLength() const noexcept
        {
            return sentLength_;
        }

    private:
        const UCHAR* receiveBytes_ = nullptr;
        SIZE_T receiveLength_ = 0;
        SIZE_T receiveOffset_ = 0;
        bool timeoutAtEnd_ = false;
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

    bool AppendResponseHeaderBlock(
        const UCHAR* headerBlock,
        SIZE_T headerBlockLength,
        bool endStream,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeHeaders(
            1,
            headerBlock,
            headerBlockLength,
            endStream,
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

    bool AppendData(
        const UCHAR* data,
        SIZE_T dataLength,
        bool endStream,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeData(
            1,
            data,
            dataLength,
            endStream,
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

    SIZE_T CountSentFrames(
        const ScriptedHttp2Transport& transport,
        KernelHttp::http2::Http2FrameType type,
        ULONG streamId)
    {
        const UCHAR* data = transport.SentBytes();
        SIZE_T length = transport.SentLength();
        SIZE_T offset = 0;

        if (length >= KernelHttp::http2::Http2ConnectionPrefaceLength &&
            memcmp(
                data,
                KernelHttp::http2::Http2ConnectionPreface,
                KernelHttp::http2::Http2ConnectionPrefaceLength) == 0) {
            offset = KernelHttp::http2::Http2ConnectionPrefaceLength;
        }

        SIZE_T count = 0;
        while (offset + KernelHttp::http2::Http2FrameHeaderLength <= length) {
            KernelHttp::http2::Http2FrameHeader header = {};
            const NTSTATUS status = Http2FrameCodec::DecodeFrameHeader(
                data + offset,
                KernelHttp::http2::Http2FrameHeaderLength,
                &header);
            if (!NT_SUCCESS(status)) {
                break;
            }

            offset += KernelHttp::http2::Http2FrameHeaderLength;
            if (header.Length > length - offset) {
                break;
            }

            if (header.Type == type && header.StreamId == streamId) {
                ++count;
            }
            offset += header.Length;
        }

        return count;
    }

    bool FindSentFrame(
        const ScriptedHttp2Transport& transport,
        KernelHttp::http2::Http2FrameType type,
        ULONG streamId,
        SIZE_T ordinal,
        KernelHttp::http2::Http2FrameHeader* foundHeader,
        const UCHAR** foundPayload)
    {
        const UCHAR* data = transport.SentBytes();
        SIZE_T length = transport.SentLength();
        SIZE_T offset = 0;

        if (length >= KernelHttp::http2::Http2ConnectionPrefaceLength &&
            memcmp(
                data,
                KernelHttp::http2::Http2ConnectionPreface,
                KernelHttp::http2::Http2ConnectionPrefaceLength) == 0) {
            offset = KernelHttp::http2::Http2ConnectionPrefaceLength;
        }

        SIZE_T matched = 0;
        while (offset + KernelHttp::http2::Http2FrameHeaderLength <= length) {
            KernelHttp::http2::Http2FrameHeader header = {};
            const NTSTATUS status = Http2FrameCodec::DecodeFrameHeader(
                data + offset,
                KernelHttp::http2::Http2FrameHeaderLength,
                &header);
            if (!NT_SUCCESS(status)) {
                return false;
            }

            offset += KernelHttp::http2::Http2FrameHeaderLength;
            if (header.Length > length - offset) {
                return false;
            }

            if (header.Type == type && header.StreamId == streamId) {
                if (matched == ordinal) {
                    if (foundHeader != nullptr) {
                        *foundHeader = header;
                    }
                    if (foundPayload != nullptr) {
                        *foundPayload = data + offset;
                    }
                    return true;
                }
                ++matched;
            }

            offset += header.Length;
        }

        return false;
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

    NTSTATUS SendDefaultRequest(
        ScriptedHttp2Transport& transport,
        Http2Connection& connection,
        SIZE_T* responseBodyLength = nullptr) noexcept
    {
        if (responseBodyLength != nullptr) {
            *responseBodyLength = 0;
        }

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
        SIZE_T bodyLength = 0;
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
            &bodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));

        if (responseBodyLength != nullptr) {
            *responseBodyLength = bodyLength;
        }
        return status;
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

    void TestEndStreamDataSkipsStreamWindowUpdate()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR body[] = { 'h', 'e', 'l', 'l', 'o' };

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseHeaders(false, true, script, sizeof(script), &scriptLength),
            "HTTP/2 response headers fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Data,
            Http2FrameFlags::EndStream,
            1,
            body,
            sizeof(body),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 response END_STREAM DATA fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for END_STREAM DATA test");

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

        Expect(status == STATUS_SUCCESS, "END_STREAM DATA response succeeds");
        Expect(statusCode == 200, "END_STREAM DATA response status is decoded");
        Expect(responseBodyLength == sizeof(body), "END_STREAM DATA response body length matches");
        Expect(memcmp(responseBody, body, sizeof(body)) == 0, "END_STREAM DATA response body matches");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::WindowUpdate, 1) == 0,
            "closed stream does not receive WINDOW_UPDATE");
    }

    void TestTimeoutBeforeEndStreamFailsResponse()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR body[] = { 'p', 'a', 'r', 't' };

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 timeout server settings fixture builds");
        Expect(AppendResponseHeaders(false, true, script, sizeof(script), &scriptLength),
            "HTTP/2 timeout response headers fixture builds");
        Expect(AppendData(body, sizeof(body), false, script, sizeof(script), &scriptLength),
            "HTTP/2 timeout partial DATA fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength, true);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 timeout connection initializes");

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

        Expect(status == STATUS_IO_TIMEOUT, "HTTP/2 timeout before END_STREAM fails response");
        Expect(responseBodyLength == 0, "HTTP/2 incomplete timeout does not mark body complete");
    }

    void TestDeleteWithBodySendsDataEndStream()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR requestBody[] = { '{', '}' };

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseHeaders(true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 DELETE response headers fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for DELETE body test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("DELETE") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/httpbin/delete") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-length"), MakeText("2") }
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
            requestBody,
            sizeof(requestBody),
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            responseBody,
            sizeof(responseBody),
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));

        Expect(status == STATUS_SUCCESS, "HTTP/2 DELETE with body succeeds");
        Expect(statusCode == 200, "HTTP/2 DELETE response status is decoded");

        KernelHttp::http2::Http2FrameHeader headersFrame = {};
        Expect(
            FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Headers,
                1,
                0,
                &headersFrame,
                nullptr),
            "HTTP/2 DELETE request sends HEADERS");
        Expect((headersFrame.Flags & Http2FrameFlags::EndStream) == 0,
            "HTTP/2 DELETE HEADERS keeps stream open for body");

        KernelHttp::http2::Http2FrameHeader dataFrame = {};
        const UCHAR* dataPayload = nullptr;
        Expect(
            FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Data,
                1,
                0,
                &dataFrame,
                &dataPayload),
            "HTTP/2 DELETE request sends DATA");
        Expect((dataFrame.Flags & Http2FrameFlags::EndStream) != 0,
            "HTTP/2 DELETE DATA ends stream");
        Expect(dataFrame.Length == sizeof(requestBody), "HTTP/2 DELETE DATA length matches body");
        Expect(dataPayload != nullptr && memcmp(dataPayload, requestBody, sizeof(requestBody)) == 0,
            "HTTP/2 DELETE DATA payload matches body");
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

    void TestConnectionErrorSendsGoAway()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR payload[] = { 0 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 GOAWAY server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Data,
            0,
            0,
            payload,
            sizeof(payload),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 stream zero DATA fixture builds for GOAWAY");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        const NTSTATUS status = SendDefaultRequest(transport, connection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 stream zero DATA still fails request");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::GoAway, 0) == 1,
            "HTTP/2 connection-level protocol error sends GOAWAY");
    }

    void TestStreamErrorSendsRstStream()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR payload[] = { 'x' };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 RST server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Data,
            Http2FrameFlags::EndStream,
            1,
            payload,
            sizeof(payload),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 DATA before headers fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        const NTSTATUS status = SendDefaultRequest(transport, connection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 DATA before headers fails request");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 1,
            "HTTP/2 stream-local protocol error sends RST_STREAM");
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

    void TestConnectionRejectsSettingsAckWithPayload()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR payload[] = { 0 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Settings,
            Http2FrameFlags::Ack,
            0,
            payload,
            sizeof(payload),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 invalid SETTINGS ACK fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        const NTSTATUS status = SendDefaultRequest(transport, connection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 rejects SETTINGS ACK with payload");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::GoAway, 0) == 1,
            "HTTP/2 invalid SETTINGS ACK sends GOAWAY");
    }

    void TestConnectionRejectsInvalidPingLengths()
    {
        const UCHAR flagsList[] = { static_cast<UCHAR>(0), Http2FrameFlags::Ack };
        for (SIZE_T i = 0; i < sizeof(flagsList) / sizeof(flagsList[0]); ++i) {
            const UCHAR flags = flagsList[i];
            UCHAR script[256] = {};
            SIZE_T scriptLength = 0;
            const UCHAR payload[] = { 1, 2, 3, 4, 5, 6, 7 };
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
            Expect(AppendRawFrame(
                KernelHttp::http2::Http2FrameType::Ping,
                flags,
                0,
                payload,
                sizeof(payload),
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 invalid PING fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 rejects invalid PING payload length");
            Expect(
                CountSentFrames(transport, KernelHttp::http2::Http2FrameType::GoAway, 0) == 1,
                "HTTP/2 invalid PING sends GOAWAY");
        }
    }

    void TestConnectionRejectsPushPromiseWhenPushDisabled()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR promisedStream[] = { 0, 0, 0, 2 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::PushPromise,
            Http2FrameFlags::EndHeaders,
            1,
            promisedStream,
            sizeof(promisedStream),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 PUSH_PROMISE fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        const NTSTATUS status = SendDefaultRequest(transport, connection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 rejects PUSH_PROMISE when ENABLE_PUSH is 0");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::GoAway, 0) == 1,
            "HTTP/2 PUSH_PROMISE protocol error sends GOAWAY");
    }

    void ExpectResponseHeaderBlockRejected(
        const UCHAR* headerBlock,
        SIZE_T headerBlockLength,
        const char* message)
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseHeaderBlock(
            headerBlock,
            headerBlockLength,
            true,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 response header fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        const NTSTATUS status = SendDefaultRequest(transport, connection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, message);
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 1,
            "HTTP/2 malformed response headers send RST_STREAM");
    }

    void TestConnectionRejectsMalformedResponseHeaders()
    {
        const UCHAR duplicateStatus[] = { 0x88, 0x88 };
        ExpectResponseHeaderBlockRejected(
            duplicateStatus,
            sizeof(duplicateStatus),
            "HTTP/2 rejects duplicate :status");

        const UCHAR missingStatus[] = { 0xb6 };
        ExpectResponseHeaderBlockRejected(
            missingStatus,
            sizeof(missingStatus),
            "HTTP/2 rejects missing :status");

        const UCHAR pseudoAfterRegular[] = { 0xb6, 0x88 };
        ExpectResponseHeaderBlockRejected(
            pseudoAfterRegular,
            sizeof(pseudoAfterRegular),
            "HTTP/2 rejects pseudo-header after regular header");

        const UCHAR uppercaseName[] = {
            0x88, 0x00, 0x06, 'S', 'e', 'r', 'v', 'e', 'r', 0x00
        };
        ExpectResponseHeaderBlockRejected(
            uppercaseName,
            sizeof(uppercaseName),
            "HTTP/2 rejects uppercase response field name");

        const UCHAR connectionHeader[] = {
            0x88, 0x00, 0x0a,
            'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n',
            0x05, 'c', 'l', 'o', 's', 'e'
        };
        ExpectResponseHeaderBlockRejected(
            connectionHeader,
            sizeof(connectionHeader),
            "HTTP/2 rejects connection-specific response field");

        const UCHAR upgradeHeader[] = {
            0x88, 0x00, 0x07, 'u', 'p', 'g', 'r', 'a', 'd', 'e',
            0x03, 'h', '2', 'c'
        };
        ExpectResponseHeaderBlockRejected(
            upgradeHeader,
            sizeof(upgradeHeader),
            "HTTP/2 rejects upgrade response field");

        const UCHAR invalidTe[] = {
            0x88, 0x00, 0x02, 't', 'e', 0x04, 'g', 'z', 'i', 'p'
        };
        ExpectResponseHeaderBlockRejected(
            invalidTe,
            sizeof(invalidTe),
            "HTTP/2 rejects TE value other than trailers");
    }

    void TestConnectionAcceptsResponseTrailers()
    {
        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        const UCHAR status200[] = { 0x88 };
        const UCHAR data[] = { 'o', 'k' };
        const UCHAR trailerBlock[] = {
            0x00, 0x08, 'c', 'h', 'e', 'c', 'k', 's', 'u', 'm',
            0x02, 'o', 'k'
        };

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseHeaderBlock(status200, sizeof(status200), false, script, sizeof(script), &scriptLength),
            "HTTP/2 initial response headers fixture builds");
        Expect(AppendData(data, sizeof(data), false, script, sizeof(script), &scriptLength),
            "HTTP/2 response data fixture builds");
        Expect(AppendResponseHeaderBlock(trailerBlock, sizeof(trailerBlock), true, script, sizeof(script), &scriptLength),
            "HTTP/2 response trailers fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for trailer test");

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

        Expect(status == STATUS_SUCCESS, "HTTP/2 accepts response trailers after DATA with END_STREAM");
        Expect(statusCode == 200, "HTTP/2 trailer response preserves status");
        Expect(responseHeaderCount == 1, "HTTP/2 trailer response preserves initial header count");
        Expect(responseBodyLength == sizeof(data), "HTTP/2 trailer response body length");
        Expect(memcmp(responseBody, data, sizeof(data)) == 0, "HTTP/2 trailer response body bytes");
    }
}

int main()
{
    TestPromotedAcceptEncodingIsNotDuplicated();
    TestExtraAcceptEncodingRemainsWhenNotPromoted();
    TestUpgradeReceivesResponseOnStreamOne();
    TestUpgradeReservesStreamOneForInitiatingRequest();
    TestEndStreamDataSkipsStreamWindowUpdate();
    TestTimeoutBeforeEndStreamFailsResponse();
    TestDeleteWithBodySendsDataEndStream();
    TestConnectionRejectsOrphanContinuation();
    TestConnectionRejectsInterleavedFrameDuringContinuation();
    TestConnectionRejectsWindowUpdateOverflow();
    TestConnectionRejectsEmptyContinuationFlood();
    TestConnectionRejectsStreamZeroData();
    TestConnectionErrorSendsGoAway();
    TestStreamErrorSendsRstStream();
    TestConnectionRejectsStreamZeroHeaders();
    TestConnectionRejectsStreamZeroRstStream();
    TestConnectionRejectsSettingsAckWithPayload();
    TestConnectionRejectsInvalidPingLengths();
    TestConnectionRejectsPushPromiseWhenPushDisabled();
    TestConnectionRejectsMalformedResponseHeaders();
    TestConnectionAcceptsResponseTrailers();

    if (g_failed) {
        printf("HTTP2 CLIENT TESTS FAILED\n");
        return 1;
    }

    printf("HTTP2 CLIENT TESTS PASSED\n");
    return 0;
}
