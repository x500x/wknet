#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/client/HttpsClient.h>
#include <KernelHttp/engine/Workspace.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/TlsConnection.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

using KernelHttp::client::BuildHttp2RequestHeaders;
using KernelHttp::client::Http2ContentLengthBufferLength;
using KernelHttp::client::Http2MaxHeaderNameLength;
using KernelHttp::client::Http2MaxRequestHeaders;
using KernelHttp::client::Http2RequestOptions;
using KernelHttp::client::Http2TransportMode;
using KernelHttp::client::HttpsResponseBuffers;
using KernelHttp::engine::KhWorkspace;
using KernelHttp::engine::KhWorkspaceAppendResponse;
using KernelHttp::engine::KhWorkspaceCreate;
using KernelHttp::engine::KhWorkspaceOptions;
using KernelHttp::engine::KhWorkspaceRelease;
using KernelHttp::engine::KhWorkspaceResponseInitialBytes;
using KernelHttp::http::HttpHeader;
using KernelHttp::http::HttpMethod;
using KernelHttp::http::HttpText;
using KernelHttp::http::MakeText;
using KernelHttp::http2::Http2Connection;
using KernelHttp::http2::Http2DefaultMaxFrameSize;
using KernelHttp::http2::Http2ErrorCode;
using KernelHttp::http2::Http2FrameCodec;
using KernelHttp::http2::Http2FrameHeader;
using KernelHttp::http2::Http2InitialWindowSize;
using KernelHttp::http2::Http2MaxWindowSize;
using KernelHttp::http2::Http2ResponseBodySink;
using KernelHttp::http2::Http2Settings;
using KernelHttp::http2::Http2Transport;
using KernelHttp::http2::HpackEncoder;
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

    bool TextDataInBuffer(HttpText text, const char* buffer, SIZE_T bufferLength)
    {
        if (text.Data == nullptr || buffer == nullptr || text.Length > bufferLength) {
            return false;
        }

        const uintptr_t bufferStart = reinterpret_cast<uintptr_t>(buffer);
        const uintptr_t bufferEnd = bufferStart + bufferLength;
        const uintptr_t textStart = reinterpret_cast<uintptr_t>(text.Data);
        const uintptr_t textEnd = textStart + text.Length;
        if (bufferEnd < bufferStart || textEnd < textStart) {
            return false;
        }

        return textStart >= bufferStart && textEnd <= bufferEnd;
    }

    NTSTATUS AppendWorkspaceResponseForTest(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        return KhWorkspaceAppendResponse(static_cast<KhWorkspace*>(context), data, dataLength);
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
        UCHAR sentBytes_[131072] = {};
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

    bool AppendServerSettingsWithInitialWindow(
        ULONG initialWindowSize,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        Http2Settings settings = {};
        settings.InitialWindowSize = initialWindowSize;
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

    bool AppendEncodedResponseHeaders(
        const HttpHeader* headers,
        SIZE_T headerCount,
        bool endStream,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        UCHAR headerBlock[256] = {};
        SIZE_T headerBlockLength = 0;
        Http2Settings settings = {};
        HpackEncoder encoder;
        NTSTATUS status = encoder.Initialize(settings.HeaderTableSize);
        if (!NT_SUCCESS(status)) {
            return false;
        }

        status = encoder.Encode(
            headers,
            headerCount,
            headerBlock,
            sizeof(headerBlock),
            &headerBlockLength);
        if (!NT_SUCCESS(status)) {
            return false;
        }

        return AppendResponseHeaderBlock(
            headerBlock,
            headerBlockLength,
            endStream,
            script,
            capacity,
            length);
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

    bool AppendStreamWindowUpdate(
        ULONG streamId,
        ULONG increment,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeWindowUpdate(
            streamId,
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

    bool FindSentGoAwayError(
        const ScriptedHttp2Transport& transport,
        ULONG* errorCode,
        ULONG* lastStreamId = nullptr)
    {
        Http2FrameHeader header = {};
        const UCHAR* payload = nullptr;
        if (!FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::GoAway,
                0,
                0,
                &header,
                &payload)) {
            return false;
        }

        ULONG decodedLastStreamId = 0;
        ULONG decodedErrorCode = 0;
        const NTSTATUS status = Http2FrameCodec::DecodeGoAwayPayload(
            payload,
            header.Length,
            &decodedLastStreamId,
            &decodedErrorCode);
        if (!NT_SUCCESS(status)) {
            return false;
        }

        if (errorCode != nullptr) {
            *errorCode = decodedErrorCode;
        }
        if (lastStreamId != nullptr) {
            *lastStreamId = decodedLastStreamId;
        }
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
            { MakeText("accept"), MakeText("*/*") },
            { MakeText("accept-encoding"), MakeText("gzip, deflate, br, identity") }
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
            { MakeText("accept-encoding"), MakeText("identity") }
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

    void TestRequestTeHeaderValidation()
    {
        const HttpHeader validTe[] = {
            { MakeText("te"), MakeText("trailers") }
        };

        Http2RequestOptions options = {};
        options.TransportMode = Http2TransportMode::TlsAlpn;
        options.ServerName = "nghttp2.org";
        options.ServerNameLength = strlen(options.ServerName);
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/httpbin/get");
        options.Authority = MakeText("nghttp2.org");
        options.ExtraHeaders = validTe;
        options.ExtraHeaderCount = sizeof(validTe) / sizeof(validTe[0]);

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

        Expect(status == STATUS_SUCCESS, "BuildHttp2RequestHeaders accepts TE trailers");
        const HttpHeader* te = FindHeader(headers, headerCount, "te");
        Expect(te != nullptr, "TE trailers is emitted as lowercase te");
        Expect(te != nullptr && TextEquals(te->Value, "trailers"), "TE trailers value is preserved");

        const HttpHeader invalidTe[] = {
            { MakeText("TE"), MakeText("gzip") }
        };
        options.ExtraHeaders = invalidTe;
        options.ExtraHeaderCount = sizeof(invalidTe) / sizeof(invalidTe[0]);
        headerCount = 0;
        status = BuildHttp2RequestHeaders(
            options,
            headers,
            Http2MaxRequestHeaders,
            lowerHeaderNames,
            contentLength,
            &headerCount);

        Expect(status == STATUS_INVALID_PARAMETER, "BuildHttp2RequestHeaders rejects TE other than trailers");
    }

    void ExpectBuildHttp2HeadersRejected(
        const HttpHeader* extraHeaders,
        SIZE_T extraHeaderCount,
        const char* message)
    {
        Http2RequestOptions options = {};
        options.TransportMode = Http2TransportMode::TlsAlpn;
        options.ServerName = "nghttp2.org";
        options.ServerNameLength = strlen(options.ServerName);
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/httpbin/get");
        options.Authority = MakeText("nghttp2.org");
        options.ExtraHeaders = extraHeaders;
        options.ExtraHeaderCount = extraHeaderCount;

        HttpHeader headers[Http2MaxRequestHeaders] = {};
        char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength] = {};
        char contentLength[Http2ContentLengthBufferLength] = {};
        size_t headerCount = 0;

        const NTSTATUS status = BuildHttp2RequestHeaders(
            options,
            headers,
            Http2MaxRequestHeaders,
            lowerHeaderNames,
            contentLength,
            &headerCount);

        Expect(status == STATUS_INVALID_PARAMETER, message);
    }

    void TestRequestNormalizesMixedCaseExtraHeaders()
    {
        const HttpHeader mixedCaseName[] = {
            { MakeText("Accept"), MakeText("*/*") }
        };

        Http2RequestOptions options = {};
        options.TransportMode = Http2TransportMode::TlsAlpn;
        options.ServerName = "nghttp2.org";
        options.ServerNameLength = strlen(options.ServerName);
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/httpbin/get");
        options.Authority = MakeText("nghttp2.org");
        options.ExtraHeaders = mixedCaseName;
        options.ExtraHeaderCount = sizeof(mixedCaseName) / sizeof(mixedCaseName[0]);

        HttpHeader headers[Http2MaxRequestHeaders] = {};
        char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength] = {};
        char contentLength[Http2ContentLengthBufferLength] = {};
        size_t headerCount = 0;

        const NTSTATUS status = BuildHttp2RequestHeaders(
            options,
            headers,
            Http2MaxRequestHeaders,
            lowerHeaderNames,
            contentLength,
            &headerCount);

        Expect(status == STATUS_SUCCESS, "BuildHttp2RequestHeaders accepts mixed-case extra header name");
        const HttpHeader* accept = FindHeader(headers, headerCount, "accept");
        Expect(accept != nullptr, "mixed-case Accept extra header is emitted as lowercase accept");
        Expect(accept != nullptr && TextEquals(accept->Value, "*/*"), "mixed-case Accept value is preserved");

        for (SIZE_T headerIndex = 0; headerIndex < headerCount; ++headerIndex) {
            for (SIZE_T charIndex = 0; charIndex < headers[headerIndex].Name.Length; ++charIndex) {
                const char ch = headers[headerIndex].Name.Data[charIndex];
                Expect(ch < 'A' || ch > 'Z', "HTTP/2 request header output contains no uppercase bytes");
            }
        }
    }

    void TestRequestRejectsInvalidExtraHeaders()
    {
        const HttpHeader pseudoPath[] = {
            { MakeText(":path"), MakeText("/evil") }
        };
        ExpectBuildHttp2HeadersRejected(
            pseudoPath,
            sizeof(pseudoPath) / sizeof(pseudoPath[0]),
            "BuildHttp2RequestHeaders rejects :path injection");

        const HttpHeader pseudoAuthority[] = {
            { MakeText(":authority"), MakeText("evil.example") }
        };
        ExpectBuildHttp2HeadersRejected(
            pseudoAuthority,
            sizeof(pseudoAuthority) / sizeof(pseudoAuthority[0]),
            "BuildHttp2RequestHeaders rejects :authority injection");

        const HttpHeader emptyName[] = {
            { MakeText(""), MakeText("value") }
        };
        ExpectBuildHttp2HeadersRejected(
            emptyName,
            sizeof(emptyName) / sizeof(emptyName[0]),
            "BuildHttp2RequestHeaders rejects empty field name");

        const HttpHeader colonName[] = {
            { MakeText("x:test"), MakeText("value") }
        };
        ExpectBuildHttp2HeadersRejected(
            colonName,
            sizeof(colonName) / sizeof(colonName[0]),
            "BuildHttp2RequestHeaders rejects colon in extra field name");

        const HttpHeader hostName[] = {
            { MakeText("host"), MakeText("evil.example") }
        };
        ExpectBuildHttp2HeadersRejected(
            hostName,
            sizeof(hostName) / sizeof(hostName[0]),
            "BuildHttp2RequestHeaders rejects Host injection");

        const HttpHeader connectionName[] = {
            { MakeText("connection"), MakeText("close") }
        };
        ExpectBuildHttp2HeadersRejected(
            connectionName,
            sizeof(connectionName) / sizeof(connectionName[0]),
            "BuildHttp2RequestHeaders rejects connection-specific field");

        const HttpHeader crlfValue[] = {
            { MakeText("x-test"), MakeText("a\r\nb") }
        };
        ExpectBuildHttp2HeadersRejected(
            crlfValue,
            sizeof(crlfValue) / sizeof(crlfValue[0]),
            "BuildHttp2RequestHeaders rejects CRLF field value");

        const HttpHeader paddedValue[] = {
            { MakeText("x-test"), MakeText(" value") }
        };
        ExpectBuildHttp2HeadersRejected(
            paddedValue,
            sizeof(paddedValue) / sizeof(paddedValue[0]),
            "BuildHttp2RequestHeaders rejects leading SP field value");
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
        Expect(responseHeaderCount == 0, "Upgrade stream 1 pseudo-header is hidden");
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

    void TestLargeResponseReplenishesStreamWindow()
    {
        constexpr SIZE_T FirstChunkLength = 32768;
        constexpr SIZE_T SecondChunkLength = 32768;
        constexpr SIZE_T FinalChunkLength = 1024;
        constexpr SIZE_T TotalBodyLength =
            FirstChunkLength + SecondChunkLength + FinalChunkLength;

        static UCHAR firstChunk[FirstChunkLength] = {};
        static UCHAR secondChunk[SecondChunkLength] = {};
        static UCHAR finalChunk[FinalChunkLength] = {};
        static UCHAR script[70000] = {};
        static char responseBody[TotalBodyLength] = {};
        SIZE_T scriptLength = 0;

        for (SIZE_T i = 0; i < FirstChunkLength; ++i) {
            firstChunk[i] = static_cast<UCHAR>('a' + (i % 26));
        }
        for (SIZE_T i = 0; i < SecondChunkLength; ++i) {
            secondChunk[i] = static_cast<UCHAR>('A' + (i % 26));
        }
        for (SIZE_T i = 0; i < FinalChunkLength; ++i) {
            finalChunk[i] = static_cast<UCHAR>('0' + (i % 10));
        }

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 large response server settings fixture builds");
        Expect(AppendResponseHeaders(false, true, script, sizeof(script), &scriptLength),
            "HTTP/2 large response headers fixture builds");
        Expect(AppendData(firstChunk, sizeof(firstChunk), false, script, sizeof(script), &scriptLength),
            "HTTP/2 large response first DATA fixture builds");
        Expect(AppendData(secondChunk, sizeof(secondChunk), false, script, sizeof(script), &scriptLength),
            "HTTP/2 large response second DATA fixture builds");
        Expect(AppendData(finalChunk, sizeof(finalChunk), true, script, sizeof(script), &scriptLength),
            "HTTP/2 large response final DATA fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 large response connection initializes");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };
        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
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

        Expect(status == STATUS_SUCCESS, "HTTP/2 receives response larger than initial stream window");
        Expect(statusCode == 200, "HTTP/2 large response status is decoded");
        Expect(responseBodyLength == TotalBodyLength, "HTTP/2 large response body length matches");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::WindowUpdate, 1) >= 2,
            "HTTP/2 large response sends stream WINDOW_UPDATE frames");
    }

    void TestWorkspaceResponseSinkGrowsForLargeResponse()
    {
        constexpr SIZE_T FirstChunkLength = 32768;
        constexpr SIZE_T SecondChunkLength = 32768;
        constexpr SIZE_T FinalChunkLength = 24 * 1024;
        constexpr SIZE_T TotalBodyLength =
            FirstChunkLength + SecondChunkLength + FinalChunkLength;

        static UCHAR firstChunk[FirstChunkLength] = {};
        static UCHAR secondChunk[SecondChunkLength] = {};
        static UCHAR finalChunk[FinalChunkLength] = {};
        static UCHAR script[92 * 1024] = {};
        SIZE_T scriptLength = 0;

        for (SIZE_T i = 0; i < FirstChunkLength; ++i) {
            firstChunk[i] = static_cast<UCHAR>('a' + (i % 26));
        }
        for (SIZE_T i = 0; i < SecondChunkLength; ++i) {
            secondChunk[i] = static_cast<UCHAR>('A' + (i % 26));
        }
        for (SIZE_T i = 0; i < FinalChunkLength; ++i) {
            finalChunk[i] = static_cast<UCHAR>('0' + (i % 10));
        }

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 workspace sink server settings fixture builds");
        Expect(AppendResponseHeaders(false, true, script, sizeof(script), &scriptLength),
            "HTTP/2 workspace sink headers fixture builds");
        Expect(AppendData(firstChunk, sizeof(firstChunk), false, script, sizeof(script), &scriptLength),
            "HTTP/2 workspace sink first DATA fixture builds");
        Expect(AppendData(secondChunk, sizeof(secondChunk), false, script, sizeof(script), &scriptLength),
            "HTTP/2 workspace sink second DATA fixture builds");
        Expect(AppendData(finalChunk, sizeof(finalChunk), true, script, sizeof(script), &scriptLength),
            "HTTP/2 workspace sink final DATA fixture builds");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/post") },
            { MakeText(":authority"), MakeText("example.com") }
        };

        {
            KhWorkspaceOptions options = {};
            options.MaxResponseBytes = 128 * 1024;
            KhWorkspace* workspace = nullptr;
            NTSTATUS status = KhWorkspaceCreate(&options, &workspace);
            Expect(NT_SUCCESS(status) && workspace != nullptr, "workspace creates for large H2 response");
            Expect(
                workspace != nullptr &&
                    workspace->Response.Length == KhWorkspaceResponseInitialBytes,
                "workspace starts with initial response capacity");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            status = connection.Initialize(transport);
            Expect(status == STATUS_SUCCESS, "HTTP/2 workspace sink connection initializes");

            HttpHeader responseHeaders[4] = {};
            SIZE_T responseHeaderCount = 0;
            SIZE_T responseBodyLength = 0;
            USHORT statusCode = 0;
            char nameValueBuffer[128] = {};
            Http2ResponseBodySink sink = {};
            sink.Append = AppendWorkspaceResponseForTest;
            sink.Context = workspace;

            status = connection.SendRequest(
                transport,
                requestHeaders,
                sizeof(requestHeaders) / sizeof(requestHeaders[0]),
                nullptr,
                0,
                responseHeaders,
                sizeof(responseHeaders) / sizeof(responseHeaders[0]),
                &responseHeaderCount,
                sink,
                &responseBodyLength,
                &statusCode,
                nameValueBuffer,
                sizeof(nameValueBuffer));

            Expect(status == STATUS_SUCCESS, "HTTP/2 workspace sink receives large response");
            Expect(statusCode == 200, "HTTP/2 workspace sink status is decoded");
            Expect(responseBodyLength == TotalBodyLength, "HTTP/2 workspace sink body length matches");
            Expect(workspace != nullptr && workspace->ResponseLength == TotalBodyLength,
                "workspace records H2 response length");
            Expect(workspace != nullptr && workspace->Response.Length >= TotalBodyLength,
                "workspace response buffer grows for H2 DATA");
            Expect(workspace != nullptr && memcmp(workspace->Response.Data, firstChunk, FirstChunkLength) == 0,
                "workspace response starts with first chunk");
            Expect(
                CountSentFrames(transport, KernelHttp::http2::Http2FrameType::WindowUpdate, 1) >= 2,
                "HTTP/2 workspace sink still sends stream WINDOW_UPDATE frames");

            KhWorkspaceRelease(workspace);
        }

        {
            KhWorkspaceOptions options = {};
            options.MaxResponseBytes = 64 * 1024;
            KhWorkspace* workspace = nullptr;
            NTSTATUS status = KhWorkspaceCreate(&options, &workspace);
            Expect(NT_SUCCESS(status) && workspace != nullptr, "limited workspace creates for H2 response");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            status = connection.Initialize(transport);
            Expect(status == STATUS_SUCCESS, "limited HTTP/2 workspace sink connection initializes");

            HttpHeader responseHeaders[4] = {};
            SIZE_T responseHeaderCount = 0;
            SIZE_T responseBodyLength = 0;
            USHORT statusCode = 0;
            char nameValueBuffer[128] = {};
            Http2ResponseBodySink sink = {};
            sink.Append = AppendWorkspaceResponseForTest;
            sink.Context = workspace;

            status = connection.SendRequest(
                transport,
                requestHeaders,
                sizeof(requestHeaders) / sizeof(requestHeaders[0]),
                nullptr,
                0,
                responseHeaders,
                sizeof(responseHeaders) / sizeof(responseHeaders[0]),
                &responseHeaderCount,
                sink,
                &responseBodyLength,
                &statusCode,
                nameValueBuffer,
                sizeof(nameValueBuffer));

            Expect(status == STATUS_BUFFER_TOO_SMALL,
                "HTTP/2 workspace sink honors MaxResponseBytes");
            Expect(workspace != nullptr && workspace->ResponseLength == 64 * 1024,
                "limited workspace keeps received bytes up to response limit");

            KhWorkspaceRelease(workspace);
        }
    }

    void TestConnectionAcceptsRaisedMaxFrameSizePayload()
    {
        constexpr SIZE_T BodyLength = 32768;
        static UCHAR body[BodyLength] = {};
        static UCHAR script[BodyLength + 512] = {};
        static char responseBody[BodyLength] = {};
        SIZE_T scriptLength = 0;

        for (SIZE_T i = 0; i < BodyLength; ++i) {
            body[i] = static_cast<UCHAR>(i & 0xff);
        }

        Http2Settings settings = {};
        settings.MaxFrameSize = 32768;
        SIZE_T settingsWritten = 0;
        NTSTATUS status = Http2FrameCodec::EncodeSettings(
            settings,
            script,
            sizeof(script),
            &settingsWritten);
        Expect(NT_SUCCESS(status), "HTTP/2 raised MAX_FRAME_SIZE settings fixture builds");
        scriptLength += settingsWritten;
        Expect(AppendResponseHeaders(false, true, script, sizeof(script), &scriptLength),
            "HTTP/2 32KB frame response headers fixture builds");
        Expect(AppendData(body, sizeof(body), true, script, sizeof(script), &scriptLength),
            "HTTP/2 32KB DATA fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 32KB frame connection initializes");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };
        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
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

        Expect(status == STATUS_SUCCESS, "HTTP/2 accepts 32KB DATA frame after max frame settings");
        Expect(responseBodyLength == sizeof(body), "HTTP/2 32KB DATA length matches");
        Expect(memcmp(responseBody, body, sizeof(body)) == 0, "HTTP/2 32KB DATA payload matches");
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

    void TestInitialWindowSizeDoesNotOverwriteConnectionWindow()
    {
        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettingsWithInitialWindow(
            Http2InitialWindowSize + 1,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 enlarged initial window settings fixture builds");
        Expect(AppendConnectionWindowUpdate(1, script, sizeof(script), &scriptLength),
            "HTTP/2 connection WINDOW_UPDATE fixture builds");
        Expect(AppendResponseHeaders(true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 response headers fixture builds after large upload");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for connection window test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-length"), MakeText("65536") }
        };
        static UCHAR requestBody[Http2InitialWindowSize + 1] = {};
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

        Expect(status == STATUS_SUCCESS, "HTTP/2 large upload succeeds after connection WINDOW_UPDATE");
        const SIZE_T dataFrameCount =
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Data, 1);
        if (dataFrameCount != 5) {
            printf("HTTP/2 DATA frame count for connection window test: %zu\n", dataFrameCount);
        }
        Expect(dataFrameCount == 5, "INITIAL_WINDOW_SIZE does not overwrite connection send window");
    }

    void TestDynamicInitialWindowSizeAdjustsActiveStreamWindow()
    {
        UCHAR script[768] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 dynamic window server settings fixture builds");
        Expect(AppendConnectionWindowUpdate(1, script, sizeof(script), &scriptLength),
            "HTTP/2 dynamic window connection WINDOW_UPDATE fixture builds");
        Expect(AppendServerSettingsWithInitialWindow(
            Http2InitialWindowSize + 1,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 dynamic initial window SETTINGS fixture builds");
        Expect(AppendResponseHeaders(true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 response headers fixture builds after dynamic window update");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for dynamic window test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-length"), MakeText("65536") }
        };
        static UCHAR requestBody[Http2InitialWindowSize + 1] = {};
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

        Expect(status == STATUS_SUCCESS,
            "HTTP/2 upload succeeds after dynamic SETTINGS_INITIAL_WINDOW_SIZE increase");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Settings, 0) >= 2,
            "HTTP/2 dynamic SETTINGS is acknowledged");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Data, 1) == 5,
            "HTTP/2 dynamic SETTINGS_INITIAL_WINDOW_SIZE releases exactly one blocked DATA byte");
    }

    void RunPostBodyExceedingInitialWindowWithBothUpdates(
        bool connectionWindowFirst,
        const char* successMessage,
        const char* dataCountMessage,
        const char* finalDataMessage)
    {
        static_assert(Http2InitialWindowSize + 1 == 65536, "flow-control test expects a 65536-byte body");

        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 65536-byte POST server settings fixture builds");
        if (connectionWindowFirst) {
            Expect(AppendConnectionWindowUpdate(1, script, sizeof(script), &scriptLength),
                "HTTP/2 65536-byte POST connection WINDOW_UPDATE fixture builds");
            Expect(AppendStreamWindowUpdate(1, 1, script, sizeof(script), &scriptLength),
                "HTTP/2 65536-byte POST stream WINDOW_UPDATE fixture builds");
        }
        else {
            Expect(AppendStreamWindowUpdate(1, 1, script, sizeof(script), &scriptLength),
                "HTTP/2 65536-byte POST stream WINDOW_UPDATE fixture builds");
            Expect(AppendConnectionWindowUpdate(1, script, sizeof(script), &scriptLength),
                "HTTP/2 65536-byte POST connection WINDOW_UPDATE fixture builds");
        }
        Expect(AppendResponseHeaders(true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 65536-byte POST response headers fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for 65536-byte POST test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-length"), MakeText("65536") }
        };
        static UCHAR requestBody[Http2InitialWindowSize + 1] = {};
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

        Expect(status == STATUS_SUCCESS, successMessage);
        Expect(statusCode == 200, "HTTP/2 65536-byte POST response status is decoded");

        const SIZE_T dataFrameCount =
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Data, 1);
        if (dataFrameCount != 5) {
            printf(
                "HTTP/2 DATA frame count for 65536-byte POST %s order: %zu\n",
                connectionWindowFirst ? "connection-first" : "stream-first",
                dataFrameCount);
        }
        Expect(dataFrameCount == 5, dataCountMessage);

        KernelHttp::http2::Http2FrameHeader finalDataFrame = {};
        const UCHAR* finalDataPayload = nullptr;
        Expect(
            FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Data,
                1,
                4,
                &finalDataFrame,
                &finalDataPayload),
            finalDataMessage);
        Expect(finalDataFrame.Length == 1, "HTTP/2 65536-byte POST final DATA carries one byte");
        Expect((finalDataFrame.Flags & Http2FrameFlags::EndStream) != 0,
            "HTTP/2 65536-byte POST final DATA ends stream");
        Expect(finalDataPayload != nullptr, "HTTP/2 65536-byte POST final DATA payload is present");
    }

    void TestPostBodyExceedingInitialWindowAcceptsBothWindowUpdateOrders()
    {
        RunPostBodyExceedingInitialWindowWithBothUpdates(
            true,
            "HTTP/2 POST handles 65536-byte body with connection WINDOW_UPDATE first",
            "HTTP/2 POST sends final DATA after connection-first WINDOW_UPDATE pair",
            "HTTP/2 POST records final DATA after connection-first WINDOW_UPDATE pair");
        RunPostBodyExceedingInitialWindowWithBothUpdates(
            false,
            "HTTP/2 POST handles 65536-byte body with stream WINDOW_UPDATE first",
            "HTTP/2 POST sends final DATA after stream-first WINDOW_UPDATE pair",
            "HTTP/2 POST records final DATA after stream-first WINDOW_UPDATE pair");
    }

    void TestNonActiveStreamWindowUpdateDoesNotIncreaseConnectionWindow()
    {
        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 non-active WINDOW_UPDATE server settings fixture builds");
        Expect(AppendStreamWindowUpdate(3, 1, script, sizeof(script), &scriptLength),
            "HTTP/2 non-active stream WINDOW_UPDATE fixture builds");
        Expect(AppendStreamWindowUpdate(1, 1, script, sizeof(script), &scriptLength),
            "HTTP/2 active stream WINDOW_UPDATE fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength, true);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for non-active WINDOW_UPDATE test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-length"), MakeText("65536") }
        };
        static UCHAR requestBody[Http2InitialWindowSize + 1] = {};
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

        Expect(status == STATUS_IO_TIMEOUT, "HTTP/2 remains blocked without connection WINDOW_UPDATE");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Data, 1) == 4,
            "HTTP/2 non-active stream WINDOW_UPDATE does not unlock final DATA byte");
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

    void TestHpackDecodeErrorsSendCompressionGoAway()
    {
        const UCHAR invalidIndex[] = { 0xff, 0x00 };
        const UCHAR invalidHuffmanName[] = { 0x00, 0x81, 0xff, 0x00 };
        const UCHAR overflowingIndex[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x10 };

        const struct Case final
        {
            const UCHAR* HeaderBlock;
            SIZE_T HeaderBlockLength;
            const char* Message;
        } cases[] = {
            { invalidIndex, sizeof(invalidIndex), "HTTP/2 invalid HPACK index fails request" },
            { invalidHuffmanName, sizeof(invalidHuffmanName), "HTTP/2 invalid HPACK Huffman fails request" },
            { overflowingIndex, sizeof(overflowingIndex), "HTTP/2 overflowing HPACK integer fails request" }
        };

        for (SIZE_T i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            UCHAR script[256] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 HPACK error server settings fixture builds");
            Expect(AppendResponseHeaderBlock(
                cases[i].HeaderBlock,
                cases[i].HeaderBlockLength,
                true,
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 HPACK error response header fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(!NT_SUCCESS(status), cases[i].Message);

            ULONG errorCode = 0;
            ULONG lastStreamId = 0;
            Expect(FindSentGoAwayError(transport, &errorCode, &lastStreamId),
                "HTTP/2 HPACK decode error sends GOAWAY");
            Expect(errorCode == static_cast<ULONG>(Http2ErrorCode::CompressionError),
                "HTTP/2 HPACK decode error uses COMPRESSION_ERROR");
            Expect(lastStreamId == 1, "HTTP/2 HPACK GOAWAY last_stream_id fixes current stream");
            Expect(
                CountSentFrames(transport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 0,
                "HTTP/2 HPACK decode error is not stream-local RST_STREAM");
        }
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

    void TestConnectionRejectsStreamZeroContinuationAndPriority()
    {
        const UCHAR priorityPayload[] = { 0, 0, 0, 0, 0 };

        const struct Case final
        {
            KernelHttp::http2::Http2FrameType Type;
            UCHAR Flags;
            const UCHAR* Payload;
            SIZE_T PayloadLength;
            const char* Message;
        } cases[] = {
            {
                KernelHttp::http2::Http2FrameType::Continuation,
                Http2FrameFlags::EndHeaders,
                nullptr,
                0,
                "HTTP/2 connection rejects stream zero CONTINUATION"
            },
            {
                KernelHttp::http2::Http2FrameType::Priority,
                0,
                priorityPayload,
                sizeof(priorityPayload),
                "HTTP/2 connection rejects stream zero PRIORITY"
            }
        };

        for (SIZE_T i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            UCHAR script[256] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 stream zero frame server settings fixture builds");
            Expect(AppendRawFrame(
                cases[i].Type,
                cases[i].Flags,
                0,
                cases[i].Payload,
                cases[i].PayloadLength,
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 stream zero frame fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, cases[i].Message);

            ULONG errorCode = 0;
            Expect(FindSentGoAwayError(transport, &errorCode),
                "HTTP/2 stream zero frame sends GOAWAY");
            Expect(errorCode == static_cast<ULONG>(Http2ErrorCode::ProtocolError),
                "HTTP/2 stream zero frame uses PROTOCOL_ERROR");
        }
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

    void TestConnectionRejectsInvalidSettingsValues()
    {
        const struct Case final
        {
            Http2Settings Settings;
            ULONG ExpectedErrorCode;
            const char* Message;
        } cases[] = {
            {
                []() noexcept {
                    Http2Settings settings = {};
                    settings.EnablePush = 1;
                    return settings;
                }(),
                static_cast<ULONG>(Http2ErrorCode::ProtocolError),
                "HTTP/2 rejects server SETTINGS_ENABLE_PUSH=1"
            },
            {
                []() noexcept {
                    Http2Settings settings = {};
                    settings.InitialWindowSize = Http2MaxWindowSize + 1;
                    return settings;
                }(),
                static_cast<ULONG>(Http2ErrorCode::FlowControlError),
                "HTTP/2 rejects oversized SETTINGS_INITIAL_WINDOW_SIZE"
            },
            {
                []() noexcept {
                    Http2Settings settings = {};
                    settings.MaxFrameSize = Http2DefaultMaxFrameSize - 1;
                    return settings;
                }(),
                static_cast<ULONG>(Http2ErrorCode::ProtocolError),
                "HTTP/2 rejects undersized SETTINGS_MAX_FRAME_SIZE"
            }
        };

        for (SIZE_T i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            UCHAR script[256] = {};
            SIZE_T written = 0;
            const NTSTATUS encodeStatus = Http2FrameCodec::EncodeSettings(
                cases[i].Settings,
                script,
                sizeof(script),
                &written);
            Expect(NT_SUCCESS(encodeStatus), "HTTP/2 invalid settings fixture builds");

            ScriptedHttp2Transport transport(script, written);
            Http2Connection connection;
            const NTSTATUS status = connection.Initialize(transport);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, cases[i].Message);

            ULONG errorCode = 0;
            Expect(FindSentGoAwayError(transport, &errorCode),
                "HTTP/2 invalid settings value sends GOAWAY");
            Expect(errorCode == cases[i].ExpectedErrorCode,
                "HTTP/2 invalid settings value maps to expected error code");
        }
    }

    void TestSettingsAckTimeoutSendsGoAway()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 settings-timeout server settings fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength, true);
        Http2Connection connection;
        const NTSTATUS status = SendDefaultRequest(transport, connection);
        Expect(status == STATUS_IO_TIMEOUT, "HTTP/2 missing SETTINGS ACK eventually times out");

        ULONG errorCode = 0;
        Expect(FindSentGoAwayError(transport, &errorCode),
            "HTTP/2 missing SETTINGS ACK sends GOAWAY");
        Expect(errorCode == static_cast<ULONG>(Http2ErrorCode::SettingsTimeout),
            "HTTP/2 missing SETTINGS ACK uses SETTINGS_TIMEOUT");
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

    void TestConnectionAcceptsResponseFieldValueOptionalWhitespace()
    {
        const HttpHeader headers[] = {
            { MakeText(":status"), MakeText("200") },
            { MakeText("content-security-policy"), MakeText(" frame-ancestors 'self'") },
            { MakeText("x-trailing-tab"), { "ok\t", 3 } },
            { MakeText("content-length"), MakeText("0") }
        };

        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 OWS response server settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            true,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 OWS response headers fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 OWS response connection initializes");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };
        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
        char responseBody[8] = {};
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[160] = {};

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

        Expect(status == STATUS_SUCCESS, "HTTP/2 accepts response field value OWS");
        Expect(statusCode == 200, "HTTP/2 OWS response status is decoded");
        const HttpHeader* csp = FindHeader(
            responseHeaders,
            responseHeaderCount,
            "content-security-policy");
        Expect(csp != nullptr, "HTTP/2 OWS response preserves CSP header");
        Expect(
            csp != nullptr &&
                csp->Value.Length == sizeof(" frame-ancestors 'self'") - 1 &&
                memcmp(csp->Value.Data, " frame-ancestors 'self'", csp->Value.Length) == 0,
            "HTTP/2 OWS response preserves leading SP value");
    }

    void TestConnectionHidesResponsePseudoHeaders()
    {
        const HttpHeader headers[] = {
            { MakeText(":status"), MakeText("200") },
            { MakeText("content-type"), MakeText("application/json") },
            { MakeText("content-length"), MakeText("0") }
        };

        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 pseudo-hide server settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            true,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 pseudo-hide response headers fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 pseudo-hide connection initializes");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };
        HttpHeader responseHeaders[2] = {};
        SIZE_T responseHeaderCount = 0;
        char responseBody[8] = {};
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[160] = {};

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

        Expect(status == STATUS_SUCCESS, "HTTP/2 accepts response when visible header capacity excludes :status");
        Expect(statusCode == 200, "HTTP/2 hidden pseudo-header still drives status");
        Expect(responseHeaderCount == 2, "HTTP/2 exposes only regular response headers");
        Expect(FindHeader(responseHeaders, responseHeaderCount, ":status") == nullptr,
            "HTTP/2 response headers do not expose :status");
        Expect(FindHeader(responseHeaders, responseHeaderCount, "content-type") != nullptr,
            "HTTP/2 response preserves content-type header");
        Expect(FindHeader(responseHeaders, responseHeaderCount, "content-length") != nullptr,
            "HTTP/2 response preserves content-length header");
    }

    void TestHttpsH2HeaderNameValueBufferSurvivesDecodedBodyWrite()
    {
        const HttpHeader headers[] = {
            { MakeText(":status"), MakeText("200") },
            { MakeText("content-type"), MakeText("application/json") }
        };
        const UCHAR body[] = "{ \"args\": true }";

        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTPS/H2 lifetime server settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            false,
            script,
            sizeof(script),
            &scriptLength), "HTTPS/H2 lifetime response headers fixture builds");
        Expect(AppendData(body, sizeof(body) - 1, true, script, sizeof(script), &scriptLength),
            "HTTPS/H2 lifetime response body fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTPS/H2 lifetime connection initializes");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };

        char requestBuffer[128] = {};
        char responseBody[64] = {};
        char decodedBody[64] = {};
        char scratchBody[64] = {};
        char headerNameValue[192] = {};
        HttpHeader responseHeaders[4] = {};

        HttpsResponseBuffers buffers = {};
        buffers.RequestBuffer = requestBuffer;
        buffers.RequestBufferLength = sizeof(requestBuffer);
        buffers.ResponseBuffer = responseBody;
        buffers.ResponseBufferLength = sizeof(responseBody);
        buffers.DecodedBodyBuffer = decodedBody;
        buffers.DecodedBodyBufferLength = sizeof(decodedBody);
        buffers.ScratchBodyBuffer = scratchBody;
        buffers.ScratchBodyBufferLength = sizeof(scratchBody);
        buffers.HeaderNameValueBuffer = headerNameValue;
        buffers.HeaderNameValueBufferLength = sizeof(headerNameValue);
        buffers.Headers = responseHeaders;
        buffers.HeaderCapacity = sizeof(responseHeaders) / sizeof(responseHeaders[0]);

        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        status = connection.SendRequest(
            transport,
            requestHeaders,
            sizeof(requestHeaders) / sizeof(requestHeaders[0]),
            nullptr,
            0,
            buffers.Headers,
            buffers.HeaderCapacity,
            &responseHeaderCount,
            buffers.ResponseBuffer,
            buffers.ResponseBufferLength,
            &responseBodyLength,
            &statusCode,
            buffers.HeaderNameValueBuffer,
            buffers.HeaderNameValueBufferLength);

        Expect(status == STATUS_SUCCESS, "HTTPS/H2 lifetime request succeeds");
        Expect(statusCode == 200, "HTTPS/H2 lifetime status is decoded");
        Expect(responseBodyLength == sizeof(body) - 1, "HTTPS/H2 lifetime body length is decoded");

        if (responseBodyLength <= buffers.DecodedBodyBufferLength) {
            memcpy(buffers.DecodedBodyBuffer, buffers.ResponseBuffer, responseBodyLength);
        }

        const HttpHeader* contentType = FindHeader(
            buffers.Headers,
            responseHeaderCount,
            "content-type");
        Expect(contentType != nullptr, "HTTPS/H2 lifetime content-type header is present");
        Expect(
            contentType != nullptr && TextEquals(contentType->Name, "content-type"),
            "HTTPS/H2 header name survives decoded body write");
        Expect(
            contentType != nullptr && TextEquals(contentType->Value, "application/json"),
            "HTTPS/H2 header value survives decoded body write");
        Expect(
            contentType != nullptr &&
                TextDataInBuffer(contentType->Name, buffers.HeaderNameValueBuffer, buffers.HeaderNameValueBufferLength) &&
                TextDataInBuffer(contentType->Value, buffers.HeaderNameValueBuffer, buffers.HeaderNameValueBufferLength),
            "HTTPS/H2 header name/value live in the header buffer");
        Expect(
            contentType != nullptr &&
                !TextDataInBuffer(contentType->Name, buffers.DecodedBodyBuffer, buffers.DecodedBodyBufferLength) &&
                !TextDataInBuffer(contentType->Value, buffers.DecodedBodyBuffer, buffers.DecodedBodyBufferLength),
            "HTTPS/H2 header name/value do not live in decoded body buffer");
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

        const UCHAR controlName[] = {
            0x88, 0x00, 0x03, 'x', 0x1f, 'x', 0x01, 'v'
        };
        ExpectResponseHeaderBlockRejected(
            controlName,
            sizeof(controlName),
            "HTTP/2 rejects control character in response field name");

        const UCHAR colonName[] = {
            0x88, 0x00, 0x08, 'b', 'a', 'd', ':', 'n', 'a', 'm', 'e', 0x01, 'v'
        };
        ExpectResponseHeaderBlockRejected(
            colonName,
            sizeof(colonName),
            "HTTP/2 rejects colon in regular response field name");

        const UCHAR nonAsciiName[] = {
            0x88, 0x00, 0x03, 'x', 0x80, 'x', 0x01, 'v'
        };
        ExpectResponseHeaderBlockRejected(
            nonAsciiName,
            sizeof(nonAsciiName),
            "HTTP/2 rejects non-ASCII response field name");

        const UCHAR nulValue[] = {
            0x88, 0x00, 0x06, 'x', '-', 't', 'e', 's', 't', 0x01, 0x00
        };
        ExpectResponseHeaderBlockRejected(
            nulValue,
            sizeof(nulValue),
            "HTTP/2 rejects NUL response field value");

        const UCHAR crValue[] = {
            0x88, 0x00, 0x06, 'x', '-', 't', 'e', 's', 't', 0x03, 'a', '\r', 'b'
        };
        ExpectResponseHeaderBlockRejected(
            crValue,
            sizeof(crValue),
            "HTTP/2 rejects CR response field value");

        const UCHAR lfValue[] = {
            0x88, 0x00, 0x06, 'x', '-', 't', 'e', 's', 't', 0x03, 'a', '\n', 'b'
        };
        ExpectResponseHeaderBlockRejected(
            lfValue,
            sizeof(lfValue),
            "HTTP/2 rejects LF response field value");
    }

    void TestConnectionValidatesResponseContentLength()
    {
        const UCHAR body[] = { 'o', 'k' };
        const HttpHeader matchingHeaders[] = {
            { MakeText(":status"), MakeText("200") },
            { MakeText("content-length"), MakeText("2") }
        };

        UCHAR matchingScript[512] = {};
        SIZE_T matchingScriptLength = 0;
        Expect(AppendServerSettings(matchingScript, sizeof(matchingScript), &matchingScriptLength),
            "HTTP/2 matching content-length settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            matchingHeaders,
            sizeof(matchingHeaders) / sizeof(matchingHeaders[0]),
            false,
            matchingScript,
            sizeof(matchingScript),
            &matchingScriptLength), "HTTP/2 matching content-length headers fixture builds");
        Expect(AppendData(body, sizeof(body), true, matchingScript, sizeof(matchingScript), &matchingScriptLength),
            "HTTP/2 matching content-length DATA fixture builds");

        ScriptedHttp2Transport matchingTransport(matchingScript, matchingScriptLength);
        Http2Connection matchingConnection;
        NTSTATUS status = SendDefaultRequest(matchingTransport, matchingConnection);
        Expect(status == STATUS_SUCCESS, "HTTP/2 accepts matching content-length and DATA length");

        const HttpHeader mismatchedHeaders[] = {
            { MakeText(":status"), MakeText("200") },
            { MakeText("content-length"), MakeText("5") }
        };

        UCHAR mismatchScript[512] = {};
        SIZE_T mismatchScriptLength = 0;
        Expect(AppendServerSettings(mismatchScript, sizeof(mismatchScript), &mismatchScriptLength),
            "HTTP/2 mismatched content-length settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            mismatchedHeaders,
            sizeof(mismatchedHeaders) / sizeof(mismatchedHeaders[0]),
            false,
            mismatchScript,
            sizeof(mismatchScript),
            &mismatchScriptLength), "HTTP/2 mismatched content-length headers fixture builds");
        Expect(AppendData(body, sizeof(body), true, mismatchScript, sizeof(mismatchScript), &mismatchScriptLength),
            "HTTP/2 mismatched content-length DATA fixture builds");

        ScriptedHttp2Transport mismatchTransport(mismatchScript, mismatchScriptLength);
        Http2Connection mismatchConnection;
        status = SendDefaultRequest(mismatchTransport, mismatchConnection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 rejects mismatched content-length and DATA length");
        Expect(
            CountSentFrames(mismatchTransport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 1,
            "HTTP/2 content-length mismatch sends RST_STREAM");
    }

    void TestConnectionRejectsDataForNoBodyResponses()
    {
        const UCHAR body[] = { 'x' };

        {
            UCHAR script[512] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 HEAD no-body server settings fixture builds");
            Expect(AppendResponseHeaders(false, true, script, sizeof(script), &scriptLength),
                "HTTP/2 HEAD response headers fixture builds");
            Expect(AppendData(body, sizeof(body), true, script, sizeof(script), &scriptLength),
                "HTTP/2 HEAD illegal DATA fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            NTSTATUS status = connection.Initialize(transport);
            Expect(status == STATUS_SUCCESS, "HTTP/2 HEAD no-body connection initializes");

            const HttpHeader requestHeaders[] = {
                { MakeText(":method"), MakeText("HEAD") },
                { MakeText(":scheme"), MakeText("https") },
                { MakeText(":path"), MakeText("/") },
                { MakeText(":authority"), MakeText("example.com") }
            };
            HttpHeader responseHeaders[4] = {};
            SIZE_T responseHeaderCount = 0;
            char responseBody[8] = {};
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

            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 rejects DATA in HEAD response");
            Expect(
                CountSentFrames(transport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 1,
                "HTTP/2 HEAD response DATA sends RST_STREAM");
        }

        const HttpHeader noBodyStatuses[][1] = {
            { { MakeText(":status"), MakeText("204") } },
            { { MakeText(":status"), MakeText("304") } }
        };
        const char* messages[] = {
            "HTTP/2 rejects DATA in 204 response",
            "HTTP/2 rejects DATA in 304 response"
        };

        for (SIZE_T i = 0; i < sizeof(noBodyStatuses) / sizeof(noBodyStatuses[0]); ++i) {
            UCHAR script[512] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 no-body status server settings fixture builds");
            Expect(AppendEncodedResponseHeaders(
                noBodyStatuses[i],
                1,
                false,
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 no-body status headers fixture builds");
            Expect(AppendData(body, sizeof(body), true, script, sizeof(script), &scriptLength),
                "HTTP/2 no-body status illegal DATA fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, messages[i]);
            Expect(
                CountSentFrames(transport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 1,
                "HTTP/2 no-body status DATA sends RST_STREAM");
        }
    }

    void TestConnectionHandlesInformationalResponses()
    {
        const HttpHeader status100[] = {
            { MakeText(":status"), MakeText("100") }
        };
        const HttpHeader status200[] = {
            { MakeText(":status"), MakeText("200") }
        };

        UCHAR successScript[512] = {};
        SIZE_T successScriptLength = 0;
        Expect(AppendServerSettings(successScript, sizeof(successScript), &successScriptLength),
            "HTTP/2 informational server settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            status100,
            sizeof(status100) / sizeof(status100[0]),
            false,
            successScript,
            sizeof(successScript),
            &successScriptLength), "HTTP/2 100 response fixture builds");
        Expect(AppendEncodedResponseHeaders(
            status200,
            sizeof(status200) / sizeof(status200[0]),
            true,
            successScript,
            sizeof(successScript),
            &successScriptLength), "HTTP/2 final response fixture builds");

        ScriptedHttp2Transport successTransport(successScript, successScriptLength);
        Http2Connection successConnection;
        NTSTATUS status = SendDefaultRequest(successTransport, successConnection);
        Expect(status == STATUS_SUCCESS, "HTTP/2 accepts 100 followed by final response");

        UCHAR endStreamScript[512] = {};
        SIZE_T endStreamScriptLength = 0;
        Expect(AppendServerSettings(endStreamScript, sizeof(endStreamScript), &endStreamScriptLength),
            "HTTP/2 1xx END_STREAM server settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            status100,
            sizeof(status100) / sizeof(status100[0]),
            true,
            endStreamScript,
            sizeof(endStreamScript),
            &endStreamScriptLength), "HTTP/2 1xx END_STREAM fixture builds");

        ScriptedHttp2Transport endStreamTransport(endStreamScript, endStreamScriptLength);
        Http2Connection endStreamConnection;
        status = SendDefaultRequest(endStreamTransport, endStreamConnection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 rejects 1xx response with END_STREAM");

        const HttpHeader status101[] = {
            { MakeText(":status"), MakeText("101") }
        };
        UCHAR switchingScript[512] = {};
        SIZE_T switchingScriptLength = 0;
        Expect(AppendServerSettings(switchingScript, sizeof(switchingScript), &switchingScriptLength),
            "HTTP/2 101 server settings fixture builds");
        Expect(AppendEncodedResponseHeaders(
            status101,
            sizeof(status101) / sizeof(status101[0]),
            false,
            switchingScript,
            sizeof(switchingScript),
            &switchingScriptLength), "HTTP/2 101 fixture builds");

        ScriptedHttp2Transport switchingTransport(switchingScript, switchingScriptLength);
        Http2Connection switchingConnection;
        status = SendDefaultRequest(switchingTransport, switchingConnection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/2 rejects 101 response");
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
        Expect(responseHeaderCount == 0, "HTTP/2 trailer response hides initial pseudo-header");
        Expect(responseBodyLength == sizeof(data), "HTTP/2 trailer response body length");
        Expect(memcmp(responseBody, data, sizeof(data)) == 0, "HTTP/2 trailer response body bytes");
    }

    void TestConnectionRejectsInvalidResponseTrailers()
    {
        const HttpHeader status200[] = {
            { MakeText(":status"), MakeText("200") }
        };
        const HttpHeader regularTrailer[] = {
            { MakeText("checksum"), MakeText("ok") }
        };
        const HttpHeader pseudoTrailer[] = {
            { MakeText(":status"), MakeText("200") }
        };
        const UCHAR data[] = { 'o', 'k' };

        {
            UCHAR script[512] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 trailer-before-data server settings fixture builds");
            Expect(AppendEncodedResponseHeaders(
                status200,
                sizeof(status200) / sizeof(status200[0]),
                false,
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 initial response headers fixture builds");
            Expect(AppendEncodedResponseHeaders(
                regularTrailer,
                sizeof(regularTrailer) / sizeof(regularTrailer[0]),
                true,
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 trailer-before-data fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE,
                "HTTP/2 rejects response trailers before DATA");
            Expect(
                CountSentFrames(transport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 1,
                "HTTP/2 trailer before DATA sends RST_STREAM");
        }

        {
            UCHAR script[512] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 pseudo trailer server settings fixture builds");
            Expect(AppendEncodedResponseHeaders(
                status200,
                sizeof(status200) / sizeof(status200[0]),
                false,
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 pseudo trailer initial headers fixture builds");
            Expect(AppendData(data, sizeof(data), false, script, sizeof(script), &scriptLength),
                "HTTP/2 pseudo trailer DATA fixture builds");
            Expect(AppendEncodedResponseHeaders(
                pseudoTrailer,
                sizeof(pseudoTrailer) / sizeof(pseudoTrailer[0]),
                true,
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 pseudo trailer fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE,
                "HTTP/2 rejects response trailers with pseudo-header");
            Expect(
                CountSentFrames(transport, KernelHttp::http2::Http2FrameType::RstStream, 1) == 1,
                "HTTP/2 pseudo trailer sends RST_STREAM");
        }
    }
}

int main()
{
    TestPromotedAcceptEncodingIsNotDuplicated();
    TestExtraAcceptEncodingRemainsWhenNotPromoted();
    TestRequestTeHeaderValidation();
    TestRequestNormalizesMixedCaseExtraHeaders();
    TestRequestRejectsInvalidExtraHeaders();
    TestUpgradeReceivesResponseOnStreamOne();
    TestUpgradeReservesStreamOneForInitiatingRequest();
    TestEndStreamDataSkipsStreamWindowUpdate();
    TestLargeResponseReplenishesStreamWindow();
    TestWorkspaceResponseSinkGrowsForLargeResponse();
    TestConnectionAcceptsRaisedMaxFrameSizePayload();
    TestTimeoutBeforeEndStreamFailsResponse();
    TestDeleteWithBodySendsDataEndStream();
    TestInitialWindowSizeDoesNotOverwriteConnectionWindow();
    TestDynamicInitialWindowSizeAdjustsActiveStreamWindow();
    TestPostBodyExceedingInitialWindowAcceptsBothWindowUpdateOrders();
    TestNonActiveStreamWindowUpdateDoesNotIncreaseConnectionWindow();
    TestConnectionRejectsOrphanContinuation();
    TestConnectionRejectsInterleavedFrameDuringContinuation();
    TestConnectionRejectsWindowUpdateOverflow();
    TestConnectionRejectsEmptyContinuationFlood();
    TestConnectionRejectsStreamZeroData();
    TestConnectionErrorSendsGoAway();
    TestHpackDecodeErrorsSendCompressionGoAway();
    TestStreamErrorSendsRstStream();
    TestConnectionRejectsStreamZeroHeaders();
    TestConnectionRejectsStreamZeroRstStream();
    TestConnectionRejectsStreamZeroContinuationAndPriority();
    TestConnectionRejectsSettingsAckWithPayload();
    TestConnectionRejectsInvalidSettingsValues();
    TestSettingsAckTimeoutSendsGoAway();
    TestConnectionRejectsInvalidPingLengths();
    TestConnectionRejectsPushPromiseWhenPushDisabled();
    TestConnectionAcceptsResponseFieldValueOptionalWhitespace();
    TestConnectionHidesResponsePseudoHeaders();
    TestHttpsH2HeaderNameValueBufferSurvivesDecodedBodyWrite();
    TestConnectionRejectsMalformedResponseHeaders();
    TestConnectionValidatesResponseContentLength();
    TestConnectionRejectsDataForNoBodyResponses();
    TestConnectionHandlesInformationalResponses();
    TestConnectionAcceptsResponseTrailers();
    TestConnectionRejectsInvalidResponseTrailers();

    if (g_failed) {
        printf("HTTP2 CLIENT TESTS FAILED\n");
        return 1;
    }

    printf("HTTP2 CLIENT TESTS PASSED\n");
    return 0;
}
