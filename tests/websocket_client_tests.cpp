#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/client/WebSocketClient.h"

#include <stdio.h>
#include <string.h>

using KernelHttp::client::WebSocketClient;
using KernelHttp::client::WebSocketConnectOptions;
using KernelHttp::client::WebSocketIoBuffers;
using KernelHttp::http::HttpHeader;
using KernelHttp::websocket::WebSocketCodec;
using KernelHttp::websocket::WebSocketFrameHeader;
using KernelHttp::websocket::WebSocketOpcode;

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

    void AppendBytes(
        unsigned char* destination,
        size_t destinationCapacity,
        size_t* destinationLength,
        const void* source,
        size_t sourceLength)
    {
        if (destination == nullptr ||
            destinationLength == nullptr ||
            source == nullptr ||
            sourceLength > destinationCapacity - *destinationLength) {
            g_failed = true;
            printf("FAIL: append test bytes\n");
            return;
        }

        memcpy(destination + *destinationLength, source, sourceLength);
        *destinationLength += sourceLength;
    }

    void AppendServerFrame(
        unsigned char* destination,
        size_t destinationCapacity,
        size_t* destinationLength,
        WebSocketOpcode opcode,
        const unsigned char* payload,
        size_t payloadLength)
    {
        if (payloadLength > 125 ||
            destination == nullptr ||
            destinationLength == nullptr ||
            (payload == nullptr && payloadLength != 0) ||
            destinationCapacity - *destinationLength < payloadLength + 2) {
            g_failed = true;
            printf("FAIL: append websocket server frame\n");
            return;
        }

        unsigned char* cursor = destination + *destinationLength;
        cursor[0] = static_cast<unsigned char>(0x80 | static_cast<unsigned char>(opcode));
        cursor[1] = static_cast<unsigned char>(payloadLength);
        if (payloadLength != 0) {
            memcpy(cursor + 2, payload, payloadLength);
        }
        *destinationLength += payloadLength + 2;
    }

    const char* FindHeaderValue(const char* request, const char* name, size_t* valueLength)
    {
        if (valueLength != nullptr) {
            *valueLength = 0;
        }
        if (request == nullptr || name == nullptr || valueLength == nullptr) {
            return nullptr;
        }

        const char* found = strstr(request, name);
        if (found == nullptr) {
            return nullptr;
        }

        found += strlen(name);
        if (found[0] != ':' || found[1] != ' ') {
            return nullptr;
        }

        found += 2;
        const char* end = strstr(found, "\r\n");
        if (end == nullptr || end <= found) {
            return nullptr;
        }

        *valueLength = static_cast<size_t>(end - found);
        return found;
    }

    struct FakeWebSocketServer
    {
        unsigned char ReceiveBytes[4096] = {};
        size_t ReceiveLength = 0;
        size_t ReceiveOffset = 0;
        unsigned char InitialFrames[512] = {};
        size_t InitialFrameLength = 0;
        unsigned char LastClientPayload[256] = {};
        size_t LastClientPayloadLength = 0;
        size_t PongCount = 0;
        size_t ConnectAttempts = 0;
        size_t FailConnectAttempts = 0;
        bool EchoAfterPing = false;
        bool Connected = false;
        NTSTATUS CloseStatus = STATUS_SUCCESS;

        void Reset()
        {
            *this = {};
        }

        void QueueReceive(const void* data, size_t dataLength)
        {
            AppendBytes(ReceiveBytes, sizeof(ReceiveBytes), &ReceiveLength, data, dataLength);
        }

        NTSTATUS Connect()
        {
            ++ConnectAttempts;
            if (ConnectAttempts <= FailConnectAttempts) {
                return STATUS_CONNECTION_DISCONNECTED;
            }

            Connected = true;
            return STATUS_SUCCESS;
        }

        NTSTATUS Send(const void* data, size_t dataLength, size_t* bytesSent)
        {
            if (bytesSent != nullptr) {
                *bytesSent = 0;
            }
            if (!Connected || data == nullptr || dataLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            const char* text = static_cast<const char*>(data);
            if (dataLength >= 4 && memcmp(text, "GET ", 4) == 0) {
                char request[1024] = {};
                const size_t copyLength = dataLength < sizeof(request) - 1 ? dataLength : sizeof(request) - 1;
                memcpy(request, data, copyLength);

                size_t clientKeyLength = 0;
                const char* clientKey = FindHeaderValue(request, "Sec-WebSocket-Key", &clientKeyLength);
                if (clientKey == nullptr) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                char accept[64] = {};
                size_t acceptLength = 0;
                NTSTATUS status = WebSocketCodec::ComputeAcceptValue(
                    clientKey,
                    clientKeyLength,
                    accept,
                    sizeof(accept),
                    &acceptLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                char response[512] = {};
                const int written = snprintf(
                    response,
                    sizeof(response),
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: %.*s\r\n"
                    "\r\n",
                    static_cast<int>(acceptLength),
                    accept);
                if (written <= 0 || static_cast<size_t>(written) >= sizeof(response)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                QueueReceive(response, static_cast<size_t>(written));
                if (InitialFrameLength != 0) {
                    QueueReceive(InitialFrames, InitialFrameLength);
                }

                if (bytesSent != nullptr) {
                    *bytesSent = dataLength;
                }
                return STATUS_SUCCESS;
            }

            WebSocketFrameHeader header = {};
            NTSTATUS status = WebSocketCodec::DecodeFrameHeader(
                static_cast<const unsigned char*>(data),
                dataLength,
                &header);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (header.Opcode == WebSocketOpcode::Pong) {
                ++PongCount;
                if (bytesSent != nullptr) {
                    *bytesSent = dataLength;
                }
                return STATUS_SUCCESS;
            }

            if (header.Opcode != WebSocketOpcode::Text && header.Opcode != WebSocketOpcode::Binary) {
                if (bytesSent != nullptr) {
                    *bytesSent = dataLength;
                }
                return STATUS_SUCCESS;
            }

            status = WebSocketCodec::DecodeFramePayload(
                header,
                static_cast<const unsigned char*>(data),
                dataLength,
                LastClientPayload,
                sizeof(LastClientPayload),
                &LastClientPayloadLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (EchoAfterPing) {
                AppendServerFrame(ReceiveBytes, sizeof(ReceiveBytes), &ReceiveLength, WebSocketOpcode::Ping, nullptr, 0);
            }
            AppendServerFrame(
                ReceiveBytes,
                sizeof(ReceiveBytes),
                &ReceiveLength,
                header.Opcode,
                LastClientPayload,
                LastClientPayloadLength);

            if (bytesSent != nullptr) {
                *bytesSent = dataLength;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS Receive(void* data, size_t length, size_t* bytesReceived)
        {
            if (bytesReceived != nullptr) {
                *bytesReceived = 0;
            }
            if (!Connected || data == nullptr || length == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            const size_t available = ReceiveLength - ReceiveOffset;
            if (available == 0) {
                return STATUS_IO_TIMEOUT;
            }

            const size_t toCopy = available < length ? available : length;
            memcpy(data, ReceiveBytes + ReceiveOffset, toCopy);
            ReceiveOffset += toCopy;
            if (bytesReceived != nullptr) {
                *bytesReceived = toCopy;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS Close()
        {
            Connected = false;
            return CloseStatus;
        }
    };

    FakeWebSocketServer* g_server = nullptr;

    WebSocketIoBuffers MakeBuffers(
        char* request,
        size_t requestLength,
        char* response,
        size_t responseLength,
        unsigned char* frame,
        size_t frameLength,
        unsigned char* payload,
        size_t payloadLength,
        HttpHeader* headers,
        size_t headerCapacity)
    {
        WebSocketIoBuffers buffers = {};
        buffers.RequestBuffer = request;
        buffers.RequestBufferLength = requestLength;
        buffers.ResponseBuffer = response;
        buffers.ResponseBufferLength = responseLength;
        buffers.FrameBuffer = frame;
        buffers.FrameBufferLength = frameLength;
        buffers.PayloadBuffer = payload;
        buffers.PayloadBufferLength = payloadLength;
        buffers.Headers = headers;
        buffers.HeaderCapacity = headerCapacity;
        return buffers;
    }

    WebSocketConnectOptions MakeConnectOptions()
    {
        WebSocketConnectOptions options = {};
        options.ServerName = L"example.test";
        options.ServiceName = L"80";
        options.Host = "example.test";
        options.HostLength = strlen(options.Host);
        options.Path = "/";
        options.PathLength = 1;
        options.UseTls = false;
        options.VerifyCertificate = false;
        return options;
    }

    void TestHandshakeBufferedFrameSurvivesSendScratchReuse()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char banner[] = "Request served by test";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            banner,
            sizeof(banner) - 1);

        KernelHttp::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[256] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        USHORT statusCode = 0;
        NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers, &statusCode);
        Expect(NT_SUCCESS(status), "websocket connect with buffered frame succeeds");
        Expect(statusCode == 101, "handshake status is 101");

        const char text[] = "kernel-http high-level websocket echo";
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(NT_SUCCESS(status), "text send after buffered handshake frame succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "buffered banner frame survives send scratch reuse");
        Expect(opcode == WebSocketOpcode::Text, "buffered banner opcode is text");
        Expect(bytesReceived == sizeof(banner) - 1, "buffered banner length matches");
        Expect(memcmp(payload, banner, sizeof(banner) - 1) == 0, "buffered banner payload matches");

        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "echo frame after buffered banner is received");
        Expect(opcode == WebSocketOpcode::Text, "echo opcode is text");
        Expect(bytesReceived == sizeof(text) - 1, "echo length matches");
        Expect(memcmp(payload, text, sizeof(text) - 1) == 0, "echo payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestConnectRetriesResolvedAddresses()
    {
        FakeWebSocketServer server;
        server.FailConnectAttempts = 1;
        g_server = &server;

        KernelHttp::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[256] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        WebSocketConnectOptions options = MakeConnectOptions();
        options.AddressFamily = KernelHttp::net::WskAddressFamily::Any;

        const NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "websocket connect retries later resolved addresses");
        Expect(server.ConnectAttempts == 2, "websocket connect attempts the next resolved address");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestAutoPongDoesNotCorruptBufferedEcho()
    {
        FakeWebSocketServer server;
        server.EchoAfterPing = true;
        g_server = &server;

        KernelHttp::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[256] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(NT_SUCCESS(status), "websocket connect for ping test succeeds");

        const char text[] = "kernel-http high-level websocket echo";
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(NT_SUCCESS(status), "text send before ping/echo receive succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "echo after coalesced ping is received");
        Expect(server.PongCount == 1, "client auto-replies to ping once");
        Expect(opcode == WebSocketOpcode::Text, "coalesced echo opcode is text");
        Expect(bytesReceived == sizeof(text) - 1, "coalesced echo length matches");
        Expect(memcmp(payload, text, sizeof(text) - 1) == 0, "coalesced echo payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveHonorsOutputCapacity()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char banner[] = "capacity-check";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            banner,
            sizeof(banner) - 1);

        KernelHttp::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[4] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(NT_SUCCESS(status), "websocket connect for capacity test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "websocket receive rejects undersized output buffer");
        Expect(bytesReceived == sizeof(banner) - 1, "undersized receive reports required payload length");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestCloseTreatsConnectionResetAsClosed()
    {
        FakeWebSocketServer server;
        server.CloseStatus = STATUS_CONNECTION_RESET;
        g_server = &server;

        KernelHttp::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[256] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(NT_SUCCESS(status), "websocket connect for reset close test succeeds");

        status = client.Close(buffers);
        Expect(NT_SUCCESS(status), "websocket close treats connection reset as already closed");
        g_server = nullptr;
    }

    void TestClosePropagatesNonTerminalErrors()
    {
        FakeWebSocketServer server;
        server.CloseStatus = STATUS_INVALID_DEVICE_STATE;
        g_server = &server;

        KernelHttp::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[256] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(NT_SUCCESS(status), "websocket connect for close error test succeeds");

        status = client.Close(buffers);
        Expect(status == STATUS_INVALID_DEVICE_STATE, "websocket close propagates non-terminal errors");
        g_server = nullptr;
    }

    void TestTlsVersionRangeValidation()
    {
        FakeWebSocketServer server;
        g_server = &server;

        KernelHttp::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[256] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        WebSocketConnectOptions options = MakeConnectOptions();
        options.ServiceName = L"443";
        options.TlsServerName = "example.test";
        options.TlsServerNameLength = strlen(options.TlsServerName);
        options.UseTls = true;
        options.VerifyCertificate = false;
        options.MinimumTlsProtocol = KernelHttp::tls::TlsProtocol::Tls13;
        options.MaximumTlsProtocol = KernelHttp::tls::TlsProtocol::Tls12;

        const NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket TLS rejects reversed protocol range");
        Expect(!server.Connected, "websocket TLS validation fails before socket connect");
        g_server = nullptr;
    }
}

namespace KernelHttp
{
namespace net
{
    WskClient::WskClient() noexcept = default;
    WskClient::~WskClient() noexcept = default;

    NTSTATUS WskClient::Initialize(ULONG) noexcept
    {
        return STATUS_SUCCESS;
    }

    void WskClient::Shutdown() noexcept
    {
    }

    bool WskClient::IsInitialized() const noexcept
    {
        return true;
    }

    PWSK_CLIENT WskClient::ProviderClient() const noexcept
    {
        return nullptr;
    }

    const WSK_PROVIDER_DISPATCH* WskClient::ProviderDispatch() const noexcept
    {
        return nullptr;
    }

    NTSTATUS WskClient::Resolve(
        const wchar_t*,
        const wchar_t*,
        SOCKADDR_STORAGE* remoteAddress,
        WskAddressFamily) noexcept
    {
        if (remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        remoteAddress->ss_family = 2;
        return STATUS_SUCCESS;
    }

    NTSTATUS WskClient::ResolveAll(
        const wchar_t*,
        const wchar_t*,
        SOCKADDR_STORAGE* remoteAddresses,
        SIZE_T addressCapacity,
        SIZE_T* addressCount,
        WskAddressFamily) noexcept
    {
        if (addressCount != nullptr) {
            *addressCount = 0;
        }
        if (remoteAddresses == nullptr || addressCapacity == 0 || addressCount == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T count = addressCapacity < 2 ? addressCapacity : 2;
        for (SIZE_T index = 0; index < count; ++index) {
            remoteAddresses[index].ss_family = 2;
        }
        *addressCount = count;
        return STATUS_SUCCESS;
    }

    WskSocket::~WskSocket() noexcept = default;

    NTSTATUS WskSocket::Connect(WskClient&, const SOCKADDR*, const SOCKADDR*) noexcept
    {
        if (g_server == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        socket_ = reinterpret_cast<PWSK_SOCKET>(g_server);
        return g_server->Connect();
    }

    NTSTATUS WskSocket::Send(WskBuffer&, SIZE_T, SIZE_T*, ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(const void* data, SIZE_T length, SIZE_T* bytesSent, ULONG) noexcept
    {
        if (g_server == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        return g_server->Send(data, length, bytesSent);
    }

    NTSTATUS WskSocket::Receive(WskBuffer&, SIZE_T, SIZE_T*, ULONG, ULONG) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(void* data, SIZE_T length, SIZE_T* bytesReceived, ULONG, ULONG) noexcept
    {
        if (g_server == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        return g_server->Receive(data, length, bytesReceived);
    }

    NTSTATUS WskSocket::Disconnect(ULONG) noexcept
    {
        return STATUS_SUCCESS;
    }

    NTSTATUS WskSocket::Close() noexcept
    {
        if (g_server != nullptr) {
            const NTSTATUS status = g_server->Close();
            socket_ = nullptr;
            return status;
        }

        socket_ = nullptr;
        return STATUS_SUCCESS;
    }

    bool WskSocket::IsConnected() const noexcept
    {
        return socket_ != nullptr;
    }

    PWSK_SOCKET WskSocket::NativeSocket() const noexcept
    {
        return socket_;
    }
}
}

int main()
{
    TestHandshakeBufferedFrameSurvivesSendScratchReuse();
    TestConnectRetriesResolvedAddresses();
    TestAutoPongDoesNotCorruptBufferedEcho();
    TestReceiveHonorsOutputCapacity();
    TestCloseTreatsConnectionResetAsClosed();
    TestClosePropagatesNonTerminalErrors();
    TestTlsVersionRangeValidation();

    if (g_failed) {
        printf("WEBSOCKET CLIENT TESTS FAILED\n");
        return 1;
    }

    printf("WEBSOCKET CLIENT TESTS PASSED\n");
    return 0;
}
