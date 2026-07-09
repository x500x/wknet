#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/client/HttpsClient.h>
#include <KernelHttp/engine/Workspace.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/TlsConnection.h>
#include <KernelHttp/websocket/WebSocketFrame.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

using KernelHttp::client::BuildHttp2RequestHeaders;
using KernelHttp::client::Http2ContentLengthBufferLength;
using KernelHttp::client::Http2MaxHeaderNameLength;
using KernelHttp::client::Http2MaxRequestHeaders;
using KernelHttp::client::Http2RequestOptions;
using KernelHttp::client::Http2TransportMode;
using KernelHttp::client::HttpsClient;
using KernelHttp::client::HttpsRequestOptions;
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
using KernelHttp::http2::Http2Priority;
using KernelHttp::http2::Http2RequestBody;
using KernelHttp::http2::Http2RequestBodySource;
using KernelHttp::http2::Http2ResponseBodySink;
using KernelHttp::http2::Http2Settings;
using KernelHttp::http2::Http2Transport;
using KernelHttp::http2::HpackDecoder;
using KernelHttp::http2::HpackEncoder;
using KernelHttp::websocket::WebSocketCodec;
using KernelHttp::websocket::WebSocketFrameHeader;
using KernelHttp::websocket::WebSocketOpcode;
namespace Http2FrameFlags = KernelHttp::http2::Http2FrameFlags;

namespace
{
    struct CapturedAlpnProtocol final
    {
        char Name[16] = {};
        SIZE_T Length = 0;
    };

    struct HttpsClientStubState final
    {
        bool Enabled = false;
        const char* Response = nullptr;
        SIZE_T ResponseLength = 0;
        SIZE_T ResponseOffset = 0;
        const char* ProxyResponse = nullptr;
        SIZE_T ProxyResponseLength = 0;
        SIZE_T ProxyResponseOffset = 0;
        ULONG ConnectCalls = 0;
        ULONG RawSendCalls = 0;
        ULONG RawReceiveCalls = 0;
        ULONG TlsConnectCalls = 0;
        ULONG TlsSendCalls = 0;
        ULONG TlsReceiveCalls = 0;
        SIZE_T CapturedAlpnCount = 0;
        CapturedAlpnProtocol CapturedAlpn[4] = {};
        char RawSent[1024] = {};
        SIZE_T RawSentLength = 0;
    };

    HttpsClientStubState g_httpsClientStub = {};

    void ResetHttpsClientStub(const char* response)
    {
        g_httpsClientStub = {};
        g_httpsClientStub.Enabled = true;
        g_httpsClientStub.Response = response;
        g_httpsClientStub.ResponseLength = response != nullptr ? strlen(response) : 0;
    }

    void ResetHttpsClientProxyStub(const char* proxyResponse, const char* tlsResponse)
    {
        ResetHttpsClientStub(tlsResponse);
        g_httpsClientStub.ProxyResponse = proxyResponse;
        g_httpsClientStub.ProxyResponseLength = proxyResponse != nullptr ? strlen(proxyResponse) : 0;
    }

    void DisableHttpsClientStub()
    {
        g_httpsClientStub = {};
    }
}

namespace KernelHttp
{
namespace net
{
    WskSocket::~WskSocket() noexcept = default;

    NTSTATUS WskSocket::Connect(WskClient&, const SOCKADDR*, const SOCKADDR*, const WskCancellationToken*) noexcept
    {
        if (g_httpsClientStub.Enabled) {
            ++g_httpsClientStub.ConnectCalls;
            return STATUS_SUCCESS;
        }
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(WskBuffer&, SIZE_T, SIZE_T*, ULONG, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(const void* data, SIZE_T length, SIZE_T* bytesSent, ULONG, const WskCancellationToken*) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }
        if (g_httpsClientStub.Enabled) {
            ++g_httpsClientStub.RawSendCalls;
            if (data == nullptr && length != 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (length > sizeof(g_httpsClientStub.RawSent) - g_httpsClientStub.RawSentLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (length != 0) {
                memcpy(
                    g_httpsClientStub.RawSent + g_httpsClientStub.RawSentLength,
                    data,
                    length);
                g_httpsClientStub.RawSentLength += length;
            }
            if (bytesSent != nullptr) {
                *bytesSent = length;
            }
            return STATUS_SUCCESS;
        }
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(WskBuffer&, SIZE_T, SIZE_T*, ULONG, ULONG, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(void* data, SIZE_T length, SIZE_T* bytesReceived, ULONG, ULONG, const WskCancellationToken*) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }
        if (g_httpsClientStub.Enabled) {
            ++g_httpsClientStub.RawReceiveCalls;
            if (data == nullptr || length == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (g_httpsClientStub.ProxyResponse == nullptr ||
                g_httpsClientStub.ProxyResponseOffset >= g_httpsClientStub.ProxyResponseLength) {
                return STATUS_CONNECTION_DISCONNECTED;
            }

            const SIZE_T remaining =
                g_httpsClientStub.ProxyResponseLength - g_httpsClientStub.ProxyResponseOffset;
            const SIZE_T copyLength = remaining < length ? remaining : length;
            memcpy(
                data,
                g_httpsClientStub.ProxyResponse + g_httpsClientStub.ProxyResponseOffset,
                copyLength);
            g_httpsClientStub.ProxyResponseOffset += copyLength;
            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }
            return STATUS_SUCCESS;
        }
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
        if (g_httpsClientStub.Enabled) {
            return true;
        }
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

    NTSTATUS TlsConnection::Connect(core::ITransport&, const TlsClientConnectionOptions& options) noexcept
    {
        if (g_httpsClientStub.Enabled) {
            ++g_httpsClientStub.TlsConnectCalls;
            g_httpsClientStub.CapturedAlpnCount = options.AlpnProtocolCount;
            constexpr SIZE_T CapturedAlpnCapacity =
                sizeof(g_httpsClientStub.CapturedAlpn) / sizeof(g_httpsClientStub.CapturedAlpn[0]);
            const SIZE_T captureCount =
                options.AlpnProtocolCount < CapturedAlpnCapacity ?
                options.AlpnProtocolCount :
                CapturedAlpnCapacity;
            for (SIZE_T index = 0; index < captureCount; ++index) {
                const KernelHttp::tls::TlsAlpnProtocol& protocol = options.AlpnProtocols[index];
                const SIZE_T copyLength =
                    protocol.NameLength < sizeof(g_httpsClientStub.CapturedAlpn[index].Name) - 1 ?
                    protocol.NameLength :
                    sizeof(g_httpsClientStub.CapturedAlpn[index].Name) - 1;
                if (protocol.Name != nullptr && copyLength != 0) {
                    memcpy(g_httpsClientStub.CapturedAlpn[index].Name, protocol.Name, copyLength);
                }
                g_httpsClientStub.CapturedAlpn[index].Name[copyLength] = '\0';
                g_httpsClientStub.CapturedAlpn[index].Length = protocol.NameLength;
            }
            return STATUS_SUCCESS;
        }
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS TlsConnection::Send(core::ITransport&, const void*, SIZE_T length, SIZE_T* bytesSent) noexcept
    {
        if (g_httpsClientStub.Enabled) {
            ++g_httpsClientStub.TlsSendCalls;
            if (bytesSent != nullptr) {
                *bytesSent = length;
            }
            return STATUS_SUCCESS;
        }
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS TlsConnection::Receive(core::ITransport&, void* data, SIZE_T length, SIZE_T* bytesReceived, ULONG) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }
        if (g_httpsClientStub.Enabled) {
            ++g_httpsClientStub.TlsReceiveCalls;
            if (data == nullptr || length == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (g_httpsClientStub.Response == nullptr ||
                g_httpsClientStub.ResponseOffset >= g_httpsClientStub.ResponseLength) {
                return STATUS_CONNECTION_DISCONNECTED;
            }

            const SIZE_T remaining =
                g_httpsClientStub.ResponseLength - g_httpsClientStub.ResponseOffset;
            const SIZE_T copyLength = remaining < length ? remaining : length;
            memcpy(
                data,
                g_httpsClientStub.Response + g_httpsClientStub.ResponseOffset,
                copyLength);
            g_httpsClientStub.ResponseOffset += copyLength;
            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }
            return STATUS_SUCCESS;
        }
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

    const TlsHandshakeFailure& TlsConnection::LastHandshakeFailure() const noexcept
    {
        static const TlsHandshakeFailure failure = {};
        return failure;
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

    bool BufferContainsLiteral(const char* buffer, SIZE_T bufferLength, const char* literal)
    {
        if (buffer == nullptr || literal == nullptr) {
            return false;
        }

        const SIZE_T literalLength = strlen(literal);
        if (literalLength == 0 || literalLength > bufferLength) {
            return false;
        }

        for (SIZE_T offset = 0; offset + literalLength <= bufferLength; ++offset) {
            if (memcmp(buffer + offset, literal, literalLength) == 0) {
                return true;
            }
        }

        return false;
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

    NTSTATUS SendHttpsClientAlpnCapture(
        const KernelHttp::tls::TlsAlpnProtocol* alpnProtocols,
        SIZE_T alpnProtocolCount,
        bool preferHttp2,
        USHORT* statusCode)
    {
        if (statusCode != nullptr) {
            *statusCode = 0;
        }

        char requestBuffer[256] = {};
        char responseBuffer[256] = {};
        char decodedBody[64] = {};
        char scratchBody[64] = {};
        char headerNameValue[256] = {};
        HttpHeader responseHeaders[8] = {};

        HttpsResponseBuffers buffers = {};
        buffers.RequestBuffer = requestBuffer;
        buffers.RequestBufferLength = sizeof(requestBuffer);
        buffers.ResponseBuffer = responseBuffer;
        buffers.ResponseBufferLength = sizeof(responseBuffer);
        buffers.DecodedBodyBuffer = decodedBody;
        buffers.DecodedBodyBufferLength = sizeof(decodedBody);
        buffers.ScratchBodyBuffer = scratchBody;
        buffers.ScratchBodyBufferLength = sizeof(scratchBody);
        buffers.HeaderNameValueBuffer = headerNameValue;
        buffers.HeaderNameValueBufferLength = sizeof(headerNameValue);
        buffers.Headers = responseHeaders;
        buffers.HeaderCapacity = sizeof(responseHeaders) / sizeof(responseHeaders[0]);

        SOCKADDR_STORAGE remoteAddress = {};
        remoteAddress.ss_family = AF_INET;

        HttpsRequestOptions options = {};
        options.RemoteAddress = reinterpret_cast<const SOCKADDR*>(&remoteAddress);
        options.ServerName = "example.test";
        options.ServerNameLength = sizeof("example.test") - 1;
        options.Request.Method = HttpMethod::Get;
        options.Request.Path = MakeText("/");
        options.Request.Host = MakeText("example.test");
        options.Request.Connection = KernelHttp::http::HttpConnectionDirective::Close;
        options.VerifyCertificate = false;
        options.PreferHttp2 = preferHttp2;
        options.AlpnProtocols = alpnProtocols;
        options.AlpnProtocolCount = alpnProtocolCount;

        HttpsClient client;
        KernelHttp::http::HttpResponse response = {};
        auto& wskClient = *reinterpret_cast<KernelHttp::net::WskClient*>(0x1);
        const NTSTATUS status = client.SendRequest(wskClient, options, buffers, response);
        if (NT_SUCCESS(status) && statusCode != nullptr) {
            *statusCode = response.StatusCode;
        }
        return status;
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

    NTSTATUS IgnoreResponseBodyForTest(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        (void)context;
        (void)data;
        (void)dataLength;
        return STATUS_SUCCESS;
    }

    struct RequestBodySourceContext final
    {
        const UCHAR* Data = nullptr;
        SIZE_T Length = 0;
        SIZE_T Offset = 0;
        SIZE_T MaxChunk = 0;
        SIZE_T ReadCount = 0;
    };

    NTSTATUS ReadRequestBodySourceForTest(
        void* context,
        UCHAR* buffer,
        SIZE_T bufferCapacity,
        SIZE_T* bytesRead,
        bool* endOfBody) noexcept
    {
        auto* source = static_cast<RequestBodySourceContext*>(context);
        if (source == nullptr ||
            buffer == nullptr ||
            bufferCapacity == 0 ||
            bytesRead == nullptr ||
            endOfBody == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *bytesRead = 0;
        *endOfBody = false;
        ++source->ReadCount;
        if (source->Offset >= source->Length) {
            *endOfBody = true;
            return STATUS_SUCCESS;
        }

        SIZE_T remaining = source->Length - source->Offset;
        SIZE_T chunk = remaining < bufferCapacity ? remaining : bufferCapacity;
        if (source->MaxChunk != 0 && chunk > source->MaxChunk) {
            chunk = source->MaxChunk;
        }

        memcpy(buffer, source->Data + source->Offset, chunk);
        source->Offset += chunk;
        *bytesRead = chunk;
        *endOfBody = source->Offset >= source->Length;
        return STATUS_SUCCESS;
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

        NTSTATUS ReceiveWithTimeout(
            UCHAR* data,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override
        {
            LastReceiveTimeoutMilliseconds = timeoutMilliseconds;
            return Receive(data, length, bytesReceived);
        }

        const UCHAR* SentBytes() const noexcept
        {
            return sentBytes_;
        }

        SIZE_T SentLength() const noexcept
        {
            return sentLength_;
        }

        ULONG LastReceiveTimeoutMilliseconds = 0;

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

    bool AppendServerSettingsWithMaxConcurrentStreams(
        ULONG maxConcurrentStreams,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        Http2Settings settings = {};
        settings.MaxConcurrentStreams = maxConcurrentStreams;
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

    bool AppendServerSettingsWithExtendedConnect(
        bool enabled,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        Http2Settings settings = {};
        settings.EnableConnectProtocol = enabled ? 1 : 0;
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

    bool AppendDataForStream(
        ULONG streamId,
        const UCHAR* data,
        SIZE_T dataLength,
        bool endStream,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeData(
            streamId,
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

    bool AppendRstStream(
        ULONG streamId,
        ULONG errorCode,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeRstStream(
            streamId,
            errorCode,
            script + *length,
            capacity - *length,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *length += written;
        return true;
    }

    bool AppendGoAway(
        ULONG lastStreamId,
        ULONG errorCode,
        UCHAR* script,
        SIZE_T capacity,
        SIZE_T* length)
    {
        SIZE_T written = 0;
        const NTSTATUS status = Http2FrameCodec::EncodeGoAway(
            lastStreamId,
            errorCode,
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

    bool DecodeSentHeadersFrame(
        const ScriptedHttp2Transport& transport,
        SIZE_T ordinal,
        HpackDecoder& decoder,
        HttpHeader* headers,
        SIZE_T headerCapacity,
        SIZE_T* headerCount,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity)
    {
        if (headers == nullptr || headerCount == nullptr || nameValueBuffer == nullptr) {
            return false;
        }

        Http2FrameHeader frameHeader = {};
        const UCHAR* payload = nullptr;
        if (!FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Headers,
                1,
                ordinal,
                &frameHeader,
                &payload)) {
            return false;
        }
        if ((frameHeader.Flags & Http2FrameFlags::EndHeaders) == 0) {
            return false;
        }

        SIZE_T nameValueUsed = 0;
        const NTSTATUS status = decoder.Decode(
            payload,
            frameHeader.Length,
            headers,
            headerCapacity,
            headerCount,
            nameValueBuffer,
            nameValueCapacity,
            &nameValueUsed,
            4096);
        return NT_SUCCESS(status);
    }

    bool HeaderListContains(
        const HttpHeader* headers,
        SIZE_T headerCount,
        const char* name,
        const char* value)
    {
        const HttpText expectedName = MakeText(name);
        const HttpText expectedValue = MakeText(value);
        for (SIZE_T index = 0; index < headerCount; ++index) {
            if (headers[index].Name.Length == expectedName.Length &&
                headers[index].Value.Length == expectedValue.Length &&
                memcmp(headers[index].Name.Data, expectedName.Data, expectedName.Length) == 0 &&
                memcmp(headers[index].Value.Data, expectedValue.Data, expectedValue.Length) == 0) {
                return true;
            }
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

    void TestBeginRequestSendsPriorityInInitialHeaders()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 priority fixture settings builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(NT_SUCCESS(status), "HTTP/2 priority connection initializes");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };

        Http2Priority priority = {};
        priority.StreamDependency = 0;
        priority.Weight = 200;
        priority.Exclusive = true;

        Http2RequestBody requestBody = {};
        requestBody.Priority = &priority;

        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
        Http2ResponseBodySink sink = {};
        sink.Append = IgnoreResponseBodyForTest;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[128] = {};
        ULONG streamId = 0;

        status = connection.BeginRequest(
            transport,
            requestHeaders,
            sizeof(requestHeaders) / sizeof(requestHeaders[0]),
            requestBody,
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            sink,
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer),
            &streamId);
        Expect(NT_SUCCESS(status), "HTTP/2 BeginRequest with priority succeeds");
        Expect(streamId == 1, "HTTP/2 priority request uses stream 1");

        Http2FrameHeader frameHeader = {};
        const UCHAR* payload = nullptr;
        Expect(FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Headers,
                1,
                0,
                &frameHeader,
                &payload),
            "HTTP/2 priority request sends HEADERS");
        Expect((frameHeader.Flags & Http2FrameFlags::Priority) != 0,
            "HTTP/2 priority request marks HEADERS priority flag");
        Expect(frameHeader.Length > 5, "HTTP/2 priority HEADERS includes priority plus header block");
        Expect(payload[0] == 0x80 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0,
            "HTTP/2 priority request encodes exclusive root dependency");
        Expect(payload[4] == 199, "HTTP/2 priority request encodes wire weight");

        const UCHAR* headerBlock = nullptr;
        SIZE_T headerBlockLength = 0;
        status = Http2FrameCodec::StripPriority(
            frameHeader.Flags,
            payload,
            frameHeader.Length,
            &headerBlock,
            &headerBlockLength);
        Expect(NT_SUCCESS(status), "HTTP/2 priority header block strips priority field");

        HpackDecoder decoder;
        status = decoder.Initialize(4096);
        Expect(NT_SUCCESS(status), "HTTP/2 priority test decoder initializes");
        HttpHeader decodedHeaders[8] = {};
        SIZE_T decodedHeaderCount = 0;
        char decodedNameValues[256] = {};
        SIZE_T decodedNameValueUsed = 0;
        status = decoder.Decode(
            headerBlock,
            headerBlockLength,
            decodedHeaders,
            sizeof(decodedHeaders) / sizeof(decodedHeaders[0]),
            &decodedHeaderCount,
            decodedNameValues,
            sizeof(decodedNameValues),
            &decodedNameValueUsed,
            4096);
        Expect(NT_SUCCESS(status), "HTTP/2 priority request header block decodes");
        Expect(HeaderListContains(decodedHeaders, decodedHeaderCount, ":method", "GET"),
            "HTTP/2 priority request preserves :method");
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

    void TestExtendedConnectRequestHeaders()
    {
        Http2RequestOptions options = {};
        options.TransportMode = Http2TransportMode::TlsAlpn;
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.Method = HttpMethod::Connect;
        options.Path = MakeText("/chat");
        options.Authority = MakeText("example.com");
        options.ConnectProtocol = MakeText("websocket");

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

        Expect(status == STATUS_SUCCESS, "BuildHttp2RequestHeaders accepts RFC 8441 CONNECT");
        const HttpHeader* method = FindHeader(headers, headerCount, ":method");
        const HttpHeader* protocol = FindHeader(headers, headerCount, ":protocol");
        Expect(method != nullptr && TextEquals(method->Value, "CONNECT"),
            "RFC 8441 request emits CONNECT method");
        Expect(protocol != nullptr && TextEquals(protocol->Value, "websocket"),
            "RFC 8441 request emits :protocol websocket");

        options.Method = HttpMethod::Get;
        headerCount = 0;
        status = BuildHttp2RequestHeaders(
            options,
            headers,
            Http2MaxRequestHeaders,
            lowerHeaderNames,
            contentLength,
            &headerCount);
        Expect(status == STATUS_INVALID_PARAMETER,
            "BuildHttp2RequestHeaders rejects :protocol without CONNECT");
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

    void TestBeginRequestRoutesInterleavedResponses()
    {
        UCHAR script[1024] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 interleaved server settings fixture builds");
        Expect(AppendResponseHeadersForStream(3, true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 interleaved stream 3 response fixture builds");
        Expect(AppendResponseHeadersForStream(1, true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 interleaved stream 1 response fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 interleaved connection initializes");
        if (!NT_SUCCESS(status)) {
            return;
        }

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };

        Http2ResponseBodySink sink = {};
        sink.Append = IgnoreResponseBodyForTest;

        HttpHeader responseHeaders1[4] = {};
        HttpHeader responseHeaders3[4] = {};
        SIZE_T responseHeaderCount1 = 0;
        SIZE_T responseHeaderCount3 = 0;
        SIZE_T responseBodyLength1 = 0;
        SIZE_T responseBodyLength3 = 0;
        USHORT statusCode1 = 0;
        USHORT statusCode3 = 0;
        char nameValueBuffer1[128] = {};
        char nameValueBuffer3[128] = {};
        ULONG stream1 = 0;
        ULONG stream3 = 0;

        status = connection.BeginRequest(
            transport,
            requestHeaders,
            sizeof(requestHeaders) / sizeof(requestHeaders[0]),
            nullptr,
            0,
            responseHeaders1,
            sizeof(responseHeaders1) / sizeof(responseHeaders1[0]),
            &responseHeaderCount1,
            sink,
            &responseBodyLength1,
            &statusCode1,
            nameValueBuffer1,
            sizeof(nameValueBuffer1),
            &stream1);
        Expect(NT_SUCCESS(status), "HTTP/2 stream 1 BeginRequest succeeds");
        Expect(stream1 == 1, "HTTP/2 first BeginRequest uses stream 1");

        status = connection.BeginRequest(
            transport,
            requestHeaders,
            sizeof(requestHeaders) / sizeof(requestHeaders[0]),
            nullptr,
            0,
            responseHeaders3,
            sizeof(responseHeaders3) / sizeof(responseHeaders3[0]),
            &responseHeaderCount3,
            sink,
            &responseBodyLength3,
            &statusCode3,
            nameValueBuffer3,
            sizeof(nameValueBuffer3),
            &stream3);
        Expect(NT_SUCCESS(status), "HTTP/2 stream 3 BeginRequest succeeds");
        Expect(stream3 == 3, "HTTP/2 second BeginRequest uses stream 3");

        status = connection.ReceiveResponse(transport, stream1);
        Expect(NT_SUCCESS(status), "HTTP/2 ReceiveResponse stream 1 succeeds after routing stream 3");
        Expect(statusCode1 == 200, "HTTP/2 stream 1 status is decoded");
        Expect(statusCode3 == 200, "HTTP/2 stream 3 status is decoded while waiting for stream 1");
        Expect(responseBodyLength1 == 0, "HTTP/2 stream 1 body remains empty");

        status = connection.ReceiveResponse(transport, stream3);
        Expect(NT_SUCCESS(status), "HTTP/2 ReceiveResponse stream 3 completes from routed state");
        Expect(responseBodyLength3 == 0, "HTTP/2 stream 3 body remains empty");
    }

    void TestBeginRequestHonorsLocalConcurrentStreamHardLimit()
    {
        UCHAR script[128] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettingsWithMaxConcurrentStreams(
            KernelHttp::KH_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL + 1,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 high concurrency server settings fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 hard concurrency connection initializes");
        if (!NT_SUCCESS(status)) {
            return;
        }

        Expect(
            connection.MaxConcurrentStreams() == KernelHttp::KH_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL,
            "HTTP/2 max concurrent streams clamps to local hard limit");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };

        Http2ResponseBodySink sink = {};
        sink.Append = IgnoreResponseBodyForTest;

        constexpr ULONG Limit = KernelHttp::KH_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL;
        static HttpHeader responseHeaders[Limit][4] = {};
        static SIZE_T responseHeaderCounts[Limit] = {};
        static SIZE_T responseBodyLengths[Limit] = {};
        static USHORT statusCodes[Limit] = {};
        static char nameValueBuffers[Limit][128] = {};
        static ULONG streamIds[Limit] = {};
        memset(responseHeaders, 0, sizeof(responseHeaders));
        memset(responseHeaderCounts, 0, sizeof(responseHeaderCounts));
        memset(responseBodyLengths, 0, sizeof(responseBodyLengths));
        memset(statusCodes, 0, sizeof(statusCodes));
        memset(nameValueBuffers, 0, sizeof(nameValueBuffers));
        memset(streamIds, 0, sizeof(streamIds));

        for (ULONG index = 0; index < Limit; ++index) {
            status = connection.BeginRequest(
                transport,
                requestHeaders,
                sizeof(requestHeaders) / sizeof(requestHeaders[0]),
                nullptr,
                0,
                responseHeaders[index],
                sizeof(responseHeaders[index]) / sizeof(responseHeaders[index][0]),
                &responseHeaderCounts[index],
                sink,
                &responseBodyLengths[index],
                &statusCodes[index],
                nameValueBuffers[index],
                sizeof(nameValueBuffers[index]),
                &streamIds[index]);
            Expect(NT_SUCCESS(status), "HTTP/2 BeginRequest within local concurrency limit succeeds");
        }

        HttpHeader blockedHeaders[4] = {};
        SIZE_T blockedHeaderCount = 0;
        SIZE_T blockedBodyLength = 0;
        USHORT blockedStatusCode = 0;
        char blockedNameValueBuffer[128] = {};
        ULONG blockedStreamId = 0;
        status = connection.BeginRequest(
            transport,
            requestHeaders,
            sizeof(requestHeaders) / sizeof(requestHeaders[0]),
            nullptr,
            0,
            blockedHeaders,
            sizeof(blockedHeaders) / sizeof(blockedHeaders[0]),
            &blockedHeaderCount,
            sink,
            &blockedBodyLength,
            &blockedStatusCode,
            blockedNameValueBuffer,
            sizeof(blockedNameValueBuffer),
            &blockedStreamId);
        Expect(status == STATUS_INSUFFICIENT_RESOURCES, "HTTP/2 BeginRequest rejects beyond local hard limit");
        Expect(blockedStreamId == 0, "HTTP/2 rejected stream id remains zero");

        for (ULONG index = 0; index < Limit; ++index) {
            connection.ReleaseStream(streamIds[index]);
        }
    }

    void TestExtendedConnectRequiresPeerSetting()
    {
        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 default settings fixture builds for extended CONNECT rejection");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 extended CONNECT rejection connection initializes");
        if (!NT_SUCCESS(status)) {
            return;
        }

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("CONNECT") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/chat") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText(":protocol"), MakeText("websocket") }
        };

        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[128] = {};
        ULONG streamId = 0;
        Http2ResponseBodySink sink = {};
        sink.Append = IgnoreResponseBodyForTest;

        status = connection.BeginRequest(
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
            sizeof(nameValueBuffer),
            &streamId);

        Expect(status == STATUS_NOT_SUPPORTED,
            "HTTP/2 extended CONNECT requires peer ENABLE_CONNECT_PROTOCOL");
        Expect(streamId == 0, "HTTP/2 rejected extended CONNECT does not allocate stream");
    }

    void TestExtendedConnectBeginsWhenPeerSettingEnabled()
    {
        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        const UCHAR serverWebSocketFrame[] = { 0x81, 0x02, 'o', 'k' };
        Expect(AppendServerSettingsWithExtendedConnect(true, script, sizeof(script), &scriptLength),
            "HTTP/2 extended CONNECT settings fixture builds");
        Expect(AppendResponseHeadersForStream(1, false, true, script, sizeof(script), &scriptLength),
            "HTTP/2 extended CONNECT response fixture builds");
        Expect(AppendDataForStream(
            1,
            serverWebSocketFrame,
            sizeof(serverWebSocketFrame),
            false,
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 extended CONNECT websocket DATA fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 extended CONNECT connection initializes");
        if (!NT_SUCCESS(status)) {
            return;
        }

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("CONNECT") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/chat") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText(":protocol"), MakeText("websocket") }
        };

        HttpHeader responseHeaders[4] = {};
        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        char nameValueBuffer[128] = {};
        ULONG streamId = 0;
        Http2ResponseBodySink sink = {};
        sink.Append = IgnoreResponseBodyForTest;

        status = connection.BeginRequest(
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
            sizeof(nameValueBuffer),
            &streamId);
        Expect(NT_SUCCESS(status), "HTTP/2 extended CONNECT BeginRequest succeeds");
        Expect(streamId == 1, "HTTP/2 extended CONNECT uses stream 1");

        status = connection.ReceiveResponseHeaders(transport, streamId);
        Expect(NT_SUCCESS(status), "HTTP/2 extended CONNECT response headers are received");
        Expect(statusCode == 200, "HTTP/2 extended CONNECT status is decoded");

        const UCHAR clientTunnelBytes[] = { 0x81, 0x00 };
        status = connection.SendStreamData(
            transport,
            streamId,
            clientTunnelBytes,
            sizeof(clientTunnelBytes),
            false);
        Expect(NT_SUCCESS(status), "HTTP/2 extended CONNECT sends DATA on tunnel stream");
        Expect(
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Data, 1) == 1,
            "HTTP/2 extended CONNECT emits one DATA frame");

        UCHAR receivedTunnelBytes[16] = {};
        SIZE_T receivedTunnelLength = 0;
        bool tunnelEndStream = false;
        status = connection.ReceiveStreamData(
            transport,
            streamId,
            receivedTunnelBytes,
            sizeof(receivedTunnelBytes),
            &receivedTunnelLength,
            &tunnelEndStream);
        Expect(NT_SUCCESS(status), "HTTP/2 extended CONNECT receives DATA from tunnel stream");
        Expect(receivedTunnelLength == sizeof(serverWebSocketFrame),
            "HTTP/2 extended CONNECT preserves WebSocket frame byte length");
        Expect(!tunnelEndStream, "HTTP/2 extended CONNECT DATA keeps stream open");

        WebSocketFrameHeader wsHeader = {};
        status = WebSocketCodec::DecodeFrameHeader(receivedTunnelBytes, receivedTunnelLength, &wsHeader);
        Expect(NT_SUCCESS(status), "HTTP/2 extended CONNECT DATA contains decodable WebSocket frame");
        Expect(wsHeader.Opcode == WebSocketOpcode::Text, "HTTP/2 extended CONNECT WebSocket opcode is text");
        UCHAR decodedPayload[8] = {};
        SIZE_T decodedPayloadLength = 0;
        status = WebSocketCodec::DecodeFramePayload(
            wsHeader,
            receivedTunnelBytes,
            receivedTunnelLength,
            decodedPayload,
            sizeof(decodedPayload),
            &decodedPayloadLength);
        Expect(NT_SUCCESS(status), "HTTP/2 extended CONNECT WebSocket payload decodes");
        Expect(decodedPayloadLength == 2 &&
            decodedPayload[0] == 'o' &&
            decodedPayload[1] == 'k',
            "HTTP/2 extended CONNECT WebSocket payload is preserved");
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
            options.MaxResponseBytes = 0;
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

    void TestGetWithoutBodySendsHeadersEndStream()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength), "HTTP/2 server settings fixture builds");
        Expect(AppendResponseHeaders(true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 GET response headers fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for GET end-stream test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("GET") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/httpbin/get") },
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

        Expect(status == STATUS_SUCCESS, "HTTP/2 GET without body succeeds");
        Expect(statusCode == 200, "HTTP/2 GET response status is decoded");

        KernelHttp::http2::Http2FrameHeader headersFrame = {};
        Expect(
            FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Headers,
                1,
                0,
                &headersFrame,
                nullptr),
            "HTTP/2 GET request sends HEADERS");
        Expect((headersFrame.Flags & Http2FrameFlags::EndStream) != 0,
            "HTTP/2 GET HEADERS ends stream when there is no request body");
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

    void TestRequestBodySourceHandlesFlowControlAndWindowUpdateOrder()
    {
        static_assert(Http2InitialWindowSize + 1 == 65536, "body source flow-control test expects 65536 bytes");

        UCHAR script[512] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 body source server settings fixture builds");
        Expect(AppendStreamWindowUpdate(1, 1, script, sizeof(script), &scriptLength),
            "HTTP/2 body source stream WINDOW_UPDATE fixture builds");
        Expect(AppendConnectionWindowUpdate(1, script, sizeof(script), &scriptLength),
            "HTTP/2 body source connection WINDOW_UPDATE fixture builds");
        Expect(AppendResponseHeaders(true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 body source response fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for body source test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-length"), MakeText("65536") }
        };
        static UCHAR requestBytes[Http2InitialWindowSize + 1] = {};
        RequestBodySourceContext sourceContext = {};
        sourceContext.Data = requestBytes;
        sourceContext.Length = sizeof(requestBytes);
        sourceContext.MaxChunk = 8192;

        Http2RequestBodySource source = {};
        source.Read = ReadRequestBodySourceForTest;
        source.Context = &sourceContext;
        source.ContentLength = sizeof(requestBytes);
        source.ContentLengthKnown = true;

        Http2RequestBody requestBody = {};
        requestBody.Source = &source;
        requestBody.HasBody = true;

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
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            responseBody,
            sizeof(responseBody),
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));

        Expect(status == STATUS_SUCCESS, "HTTP/2 body source sends through exhausted flow-control windows");
        Expect(sourceContext.ReadCount > 1, "HTTP/2 body source is read incrementally");
        const SIZE_T dataFrameCount =
            CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Data, 1);
        Expect(dataFrameCount > 1, "HTTP/2 body source emits multiple DATA frames");

        Http2FrameHeader finalDataFrame = {};
        const UCHAR* finalPayload = nullptr;
        Expect(
            FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Data,
                1,
                dataFrameCount - 1,
                &finalDataFrame,
                &finalPayload),
            "HTTP/2 body source final DATA frame is present");
        Expect(finalDataFrame.Length == 1, "HTTP/2 body source final DATA carries the post-WINDOW_UPDATE byte");
        Expect((finalDataFrame.Flags & Http2FrameFlags::EndStream) != 0,
            "HTTP/2 body source final DATA ends the stream");
    }

    void TestRequestTrailersUseFinalHeaders()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 request trailer server settings fixture builds");
        Expect(AppendResponseHeaders(true, true, script, sizeof(script), &scriptLength),
            "HTTP/2 request trailer response fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for request trailer test");

        const UCHAR body[] = { 'o', 'k' };
        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-length"), MakeText("2") },
            { MakeText("te"), MakeText("trailers") }
        };
        const HttpHeader trailers[] = {
            { MakeText("x-checksum"), MakeText("ok") }
        };

        Http2RequestBody requestBody = {};
        requestBody.Data = body;
        requestBody.DataLength = sizeof(body);
        requestBody.HasBody = true;
        requestBody.Trailers = trailers;
        requestBody.TrailerCount = sizeof(trailers) / sizeof(trailers[0]);

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
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            responseBody,
            sizeof(responseBody),
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));

        Expect(status == STATUS_SUCCESS, "HTTP/2 request with trailers succeeds");
        Expect(CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Headers, 1) == 2,
            "HTTP/2 request trailers are emitted as a second HEADERS frame");

        Http2FrameHeader dataFrame = {};
        const UCHAR* dataPayload = nullptr;
        Expect(
            FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Data,
                1,
                0,
                &dataFrame,
                &dataPayload),
            "HTTP/2 request DATA frame is present before trailers");
        Expect((dataFrame.Flags & Http2FrameFlags::EndStream) == 0,
            "HTTP/2 request DATA does not end stream when trailers follow");

        Http2FrameHeader trailerFrame = {};
        const UCHAR* trailerPayload = nullptr;
        Expect(
            FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Headers,
                1,
                1,
                &trailerFrame,
                &trailerPayload),
            "HTTP/2 request trailing HEADERS frame is present");
        Expect((trailerFrame.Flags & Http2FrameFlags::EndStream) != 0,
            "HTTP/2 request trailing HEADERS ends stream");

        HpackDecoder decoder;
        status = decoder.Initialize();
        Expect(NT_SUCCESS(status), "HPACK decoder initializes for sent request headers");
        HttpHeader decoded[8] = {};
        SIZE_T decodedCount = 0;
        char decodeBuffer[256] = {};
        Expect(
            DecodeSentHeadersFrame(
                transport,
                0,
                decoder,
                decoded,
                sizeof(decoded) / sizeof(decoded[0]),
                &decodedCount,
                decodeBuffer,
                sizeof(decodeBuffer)),
            "HTTP/2 initial request HEADERS decode");
        decodedCount = 0;
        memset(decoded, 0, sizeof(decoded));
        memset(decodeBuffer, 0, sizeof(decodeBuffer));
        Expect(
            DecodeSentHeadersFrame(
                transport,
                1,
                decoder,
                decoded,
                sizeof(decoded) / sizeof(decoded[0]),
                &decodedCount,
                decodeBuffer,
                sizeof(decodeBuffer)),
            "HTTP/2 request trailer HEADERS decode");
        Expect(HeaderListContains(decoded, decodedCount, "x-checksum", "ok"),
            "HTTP/2 request trailer header is HPACK encoded in trailing HEADERS");
    }

    void TestRequestTrailersRejectPseudoHeaders()
    {
        UCHAR script[128] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 pseudo request trailer server settings fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(status == STATUS_SUCCESS, "HTTP/2 connection initializes for pseudo request trailer test");

        const HttpHeader requestHeaders[] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/") },
            { MakeText(":authority"), MakeText("example.com") }
        };
        const HttpHeader trailers[] = {
            { MakeText(":status"), MakeText("200") }
        };
        Http2RequestBody requestBody = {};
        requestBody.Trailers = trailers;
        requestBody.TrailerCount = sizeof(trailers) / sizeof(trailers[0]);

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
            responseHeaders,
            sizeof(responseHeaders) / sizeof(responseHeaders[0]),
            &responseHeaderCount,
            responseBody,
            sizeof(responseBody),
            &responseBodyLength,
            &statusCode,
            nameValueBuffer,
            sizeof(nameValueBuffer));

        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/2 request trailers reject pseudo-headers");
        Expect(CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Headers, 1) == 0,
            "HTTP/2 pseudo request trailer rejection happens before request HEADERS are sent");
    }

    void TestGoAwayAndRefusedStreamReturnRetry()
    {
        {
            UCHAR script[256] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 GOAWAY retry server settings fixture builds");
            Expect(AppendGoAway(
                0,
                static_cast<ULONG>(Http2ErrorCode::NoError),
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 GOAWAY retry fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(status == STATUS_RETRY,
                "HTTP/2 GOAWAY NO_ERROR before stream is processed returns STATUS_RETRY");
        }

        {
            UCHAR script[256] = {};
            SIZE_T scriptLength = 0;
            Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
                "HTTP/2 REFUSED_STREAM server settings fixture builds");
            Expect(AppendRstStream(
                1,
                static_cast<ULONG>(Http2ErrorCode::RefusedStream),
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 REFUSED_STREAM fixture builds");

            ScriptedHttp2Transport transport(script, scriptLength);
            Http2Connection connection;
            const NTSTATUS status = SendDefaultRequest(transport, connection);
            Expect(status == STATUS_RETRY,
                "HTTP/2 RST_STREAM REFUSED_STREAM returns STATUS_RETRY");
        }
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

    void TestConnectionControlSignalFloodSendsGoAway()
    {
        constexpr SIZE_T PingFrameLength = 17;
        constexpr SIZE_T ScriptCapacity =
            64 + (KernelHttp::KH_HARD_MAX_CONNECTION_CONTROL_SIGNALS + 1) * PingFrameLength;
        static UCHAR script[ScriptCapacity] = {};
        SIZE_T scriptLength = 0;
        const UCHAR pingPayload[8] = {};

        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 control signal flood server settings fixture builds");
        for (ULONG index = 0; index <= KernelHttp::KH_HARD_MAX_CONNECTION_CONTROL_SIGNALS; ++index) {
            Expect(AppendRawFrame(
                KernelHttp::http2::Http2FrameType::Ping,
                Http2FrameFlags::Ack,
                0,
                pingPayload,
                sizeof(pingPayload),
                script,
                sizeof(script),
                &scriptLength), "HTTP/2 control signal flood PING fixture builds");
        }

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        const NTSTATUS status = SendDefaultRequest(transport, connection);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE,
            "HTTP/2 rejects connection control signal flood");

        ULONG errorCode = 0;
        Expect(FindSentGoAwayError(transport, &errorCode),
            "HTTP/2 control signal flood sends GOAWAY");
        Expect(errorCode == static_cast<ULONG>(Http2ErrorCode::EnhanceYourCalm),
            "HTTP/2 control signal flood uses ENHANCE_YOUR_CALM");
    }

    void TestConnectionSendsActivePing()
    {
        UCHAR script[128] = {};
        SIZE_T scriptLength = 0;
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 active PING server settings fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(NT_SUCCESS(status), "HTTP/2 active PING connection initializes");

        const UCHAR opaqueData[8] = { 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87 };
        status = connection.SendPing(transport, opaqueData);
        Expect(NT_SUCCESS(status), "HTTP/2 active PING sends");

        Http2FrameHeader header = {};
        const UCHAR* payload = nullptr;
        Expect(FindSentFrame(
                transport,
                KernelHttp::http2::Http2FrameType::Ping,
                0,
                0,
                &header,
                &payload),
            "HTTP/2 active PING frame is emitted");
        Expect(header.Length == 8, "HTTP/2 active PING payload length is 8");
        Expect((header.Flags & Http2FrameFlags::Ack) == 0, "HTTP/2 active PING is not an ACK");
        Expect(payload != nullptr && memcmp(payload, opaqueData, sizeof(opaqueData)) == 0,
            "HTTP/2 active PING preserves opaque data");
    }

    void TestConnectionPingWaitsForMatchingAck()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR opaqueData[8] = { 0x90, 0x81, 0x72, 0x63, 0x54, 0x45, 0x36, 0x27 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 PING ACK server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Ping,
            Http2FrameFlags::Ack,
            0,
            opaqueData,
            sizeof(opaqueData),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 matching PING ACK fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(NT_SUCCESS(status), "HTTP/2 PING ACK wait connection initializes");

        status = connection.SendPingAndWaitForAck(transport, opaqueData, 1234);
        Expect(NT_SUCCESS(status), "HTTP/2 PING waits for matching ACK");
        Expect(transport.LastReceiveTimeoutMilliseconds == 1234,
            "HTTP/2 PING ACK wait uses caller timeout");
        Expect(CountSentFrames(transport, KernelHttp::http2::Http2FrameType::Ping, 0) == 1,
            "HTTP/2 PING ACK wait emits one active PING");
    }

    void TestConnectionPingIgnoresMismatchedAck()
    {
        UCHAR script[256] = {};
        SIZE_T scriptLength = 0;
        const UCHAR opaqueData[8] = { 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78 };
        const UCHAR wrongOpaqueData[8] = { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 mismatched PING ACK server settings fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Ping,
            Http2FrameFlags::Ack,
            0,
            wrongOpaqueData,
            sizeof(wrongOpaqueData),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 mismatched PING ACK fixture builds");
        Expect(AppendRawFrame(
            KernelHttp::http2::Http2FrameType::Ping,
            Http2FrameFlags::Ack,
            0,
            opaqueData,
            sizeof(opaqueData),
            script,
            sizeof(script),
            &scriptLength), "HTTP/2 later matching PING ACK fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(NT_SUCCESS(status), "HTTP/2 mismatched PING ACK connection initializes");

        status = connection.SendPingAndWaitForAck(transport, opaqueData, 2000);
        Expect(NT_SUCCESS(status), "HTTP/2 PING ignores mismatched ACK and waits for matching ACK");
    }

    void TestConnectionPingAckTimeoutFailsClosed()
    {
        UCHAR script[128] = {};
        SIZE_T scriptLength = 0;
        const UCHAR opaqueData[8] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20 };
        Expect(AppendServerSettings(script, sizeof(script), &scriptLength),
            "HTTP/2 PING ACK timeout server settings fixture builds");

        ScriptedHttp2Transport transport(script, scriptLength, true);
        Http2Connection connection;
        NTSTATUS status = connection.Initialize(transport);
        Expect(NT_SUCCESS(status), "HTTP/2 PING ACK timeout connection initializes");

        status = connection.SendPingAndWaitForAck(transport, opaqueData, 50);
        Expect(status == STATUS_IO_TIMEOUT, "HTTP/2 PING ACK timeout fails closed");
        Expect(CountSentFrames(transport, KernelHttp::http2::Http2FrameType::GoAway, 0) == 0,
            "HTTP/2 PING ACK timeout does not report SETTINGS timeout");
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

    void TestHttpsClientExplicitHttp11Alpn()
    {
        static const char OkResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        const KernelHttp::tls::TlsAlpnProtocol http11Alpn[] = {
            { "http/1.1", sizeof("http/1.1") - 1 }
        };

        ResetHttpsClientStub(OkResponse);
        USHORT statusCode = 0;
        NTSTATUS status = SendHttpsClientAlpnCapture(
            http11Alpn,
            sizeof(http11Alpn) / sizeof(http11Alpn[0]),
            false,
            &statusCode);
        Expect(NT_SUCCESS(status), "HTTPS client explicit HTTP/1.1 ALPN request succeeds");
        Expect(statusCode == 200, "HTTPS client explicit HTTP/1.1 ALPN response status is decoded");
        Expect(g_httpsClientStub.ConnectCalls == 1, "HTTPS client explicit HTTP/1.1 ALPN opens one socket");
        Expect(g_httpsClientStub.TlsConnectCalls == 1, "HTTPS client explicit HTTP/1.1 ALPN starts TLS once");
        Expect(g_httpsClientStub.CapturedAlpnCount == 1, "HTTPS client forwards one explicit ALPN protocol");
        Expect(
            g_httpsClientStub.CapturedAlpn[0].Length == sizeof("http/1.1") - 1 &&
                strcmp(g_httpsClientStub.CapturedAlpn[0].Name, "http/1.1") == 0,
            "HTTPS client forwards explicit HTTP/1.1 ALPN");
        DisableHttpsClientStub();

        ResetHttpsClientStub(OkResponse);
        statusCode = 0;
        status = SendHttpsClientAlpnCapture(nullptr, 0, false, &statusCode);
        Expect(NT_SUCCESS(status), "HTTPS client keeps no-ALPN mode when PreferHttp2 is disabled");
        Expect(statusCode == 200, "HTTPS client no-ALPN response status is decoded");
        Expect(g_httpsClientStub.CapturedAlpnCount == 0, "HTTPS client no-ALPN mode remains unchanged");
        DisableHttpsClientStub();
    }

    void TestHttpsClientProxyConnectTunnel()
    {
        ResetHttpsClientProxyStub(
            "HTTP/1.1 200 Connection Established\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

        char requestBuffer[512] = {};
        char responseBuffer[512] = {};
        char decodedBody[64] = {};
        char scratchBody[64] = {};
        char headerNameValue[256] = {};
        HttpHeader responseHeaders[8] = {};

        HttpsResponseBuffers buffers = {};
        buffers.RequestBuffer = requestBuffer;
        buffers.RequestBufferLength = sizeof(requestBuffer);
        buffers.ResponseBuffer = responseBuffer;
        buffers.ResponseBufferLength = sizeof(responseBuffer);
        buffers.DecodedBodyBuffer = decodedBody;
        buffers.DecodedBodyBufferLength = sizeof(decodedBody);
        buffers.ScratchBodyBuffer = scratchBody;
        buffers.ScratchBodyBufferLength = sizeof(scratchBody);
        buffers.HeaderNameValueBuffer = headerNameValue;
        buffers.HeaderNameValueBufferLength = sizeof(headerNameValue);
        buffers.Headers = responseHeaders;
        buffers.HeaderCapacity = sizeof(responseHeaders) / sizeof(responseHeaders[0]);

        SOCKADDR_STORAGE remoteAddress = {};
        remoteAddress.ss_family = AF_INET;
        SOCKADDR_STORAGE proxyAddress = {};
        proxyAddress.ss_family = AF_INET;

        HttpsRequestOptions options = {};
        options.RemoteAddress = reinterpret_cast<const SOCKADDR*>(&remoteAddress);
        options.ProxyAddress = reinterpret_cast<const SOCKADDR*>(&proxyAddress);
        options.ProxyAuthority = "example.test:443";
        options.ProxyAuthorityLength = strlen(options.ProxyAuthority);
        options.ServerName = "example.test";
        options.ServerNameLength = strlen(options.ServerName);
        options.Request.Method = HttpMethod::Get;
        options.Request.Path = MakeText("/");
        options.Request.Host = MakeText("example.test");
        options.Request.UserAgent = MakeText("KernelHttp/0.1");
        options.Request.Connection = KernelHttp::http::HttpConnectionDirective::Close;
        options.VerifyCertificate = false;
        options.PreferHttp2 = false;

        HttpsClient client;
        KernelHttp::http::HttpResponse response = {};
        auto& wskClient = *reinterpret_cast<KernelHttp::net::WskClient*>(0x1);
        const NTSTATUS status = client.SendRequest(wskClient, options, buffers, response);

        Expect(NT_SUCCESS(status), "HTTPS client proxy CONNECT request succeeds");
        Expect(g_httpsClientStub.ConnectCalls == 1, "HTTPS proxy CONNECT opens one TCP connection");
        Expect(g_httpsClientStub.RawSendCalls == 1, "HTTPS proxy CONNECT sends one plaintext CONNECT request");
        Expect(g_httpsClientStub.RawReceiveCalls >= 1, "HTTPS proxy CONNECT reads proxy response");
        Expect(g_httpsClientStub.TlsConnectCalls == 1, "HTTPS proxy CONNECT starts TLS after tunnel");
        Expect(BufferContainsLiteral(
            g_httpsClientStub.RawSent,
            g_httpsClientStub.RawSentLength,
            "CONNECT example.test:443 HTTP/1.1\r\n"),
            "HTTPS proxy CONNECT request line targets authority");
        Expect(BufferContainsLiteral(
            g_httpsClientStub.RawSent,
            g_httpsClientStub.RawSentLength,
            "Host: example.test:443\r\n"),
            "HTTPS proxy CONNECT includes Host authority");
        Expect(response.StatusCode == 200, "HTTPS proxy CONNECT inner response status is decoded");
        Expect(response.BodyLength == 2 && memcmp(response.Body, "ok", 2) == 0,
            "HTTPS proxy CONNECT inner response body is decoded");

        DisableHttpsClientStub();
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
    TestBeginRequestSendsPriorityInInitialHeaders();
    TestPromotedAcceptEncodingIsNotDuplicated();
    TestExtraAcceptEncodingRemainsWhenNotPromoted();
    TestRequestTeHeaderValidation();
    TestExtendedConnectRequestHeaders();
    TestRequestNormalizesMixedCaseExtraHeaders();
    TestRequestRejectsInvalidExtraHeaders();
    TestUpgradeReceivesResponseOnStreamOne();
    TestUpgradeReservesStreamOneForInitiatingRequest();
    TestEndStreamDataSkipsStreamWindowUpdate();
    TestBeginRequestRoutesInterleavedResponses();
    TestBeginRequestHonorsLocalConcurrentStreamHardLimit();
    TestExtendedConnectRequiresPeerSetting();
    TestExtendedConnectBeginsWhenPeerSettingEnabled();
    TestLargeResponseReplenishesStreamWindow();
    TestWorkspaceResponseSinkGrowsForLargeResponse();
    TestConnectionAcceptsRaisedMaxFrameSizePayload();
    TestTimeoutBeforeEndStreamFailsResponse();
    TestDeleteWithBodySendsDataEndStream();
    TestGetWithoutBodySendsHeadersEndStream();
    TestInitialWindowSizeDoesNotOverwriteConnectionWindow();
    TestDynamicInitialWindowSizeAdjustsActiveStreamWindow();
    TestPostBodyExceedingInitialWindowAcceptsBothWindowUpdateOrders();
    TestRequestBodySourceHandlesFlowControlAndWindowUpdateOrder();
    TestRequestTrailersUseFinalHeaders();
    TestRequestTrailersRejectPseudoHeaders();
    TestGoAwayAndRefusedStreamReturnRetry();
    TestNonActiveStreamWindowUpdateDoesNotIncreaseConnectionWindow();
    TestConnectionRejectsOrphanContinuation();
    TestConnectionRejectsInterleavedFrameDuringContinuation();
    TestConnectionRejectsWindowUpdateOverflow();
    TestConnectionRejectsEmptyContinuationFlood();
    TestConnectionRejectsStreamZeroData();
    TestConnectionErrorSendsGoAway();
    TestConnectionControlSignalFloodSendsGoAway();
    TestConnectionSendsActivePing();
    TestConnectionPingWaitsForMatchingAck();
    TestConnectionPingIgnoresMismatchedAck();
    TestConnectionPingAckTimeoutFailsClosed();
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
    TestHttpsClientExplicitHttp11Alpn();
    TestHttpsClientProxyConnectTunnel();
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
