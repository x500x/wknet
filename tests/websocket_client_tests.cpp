#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "client/WebSocketClient.h"

#include <stdio.h>
#include <string.h>

using wknet::client::WebSocketClient;
using wknet::client::WebSocketConnectOptions;
using wknet::client::WebSocketHandshakeChallenge;
using wknet::client::WebSocketHandshakeRetryAction;
using wknet::client::WebSocketIoBuffers;
using wknet::client::WebSocketTransportMode;
using wknet::http1::HttpHeader;
using wknet::ws::WebSocketCodec;
using wknet::ws::WebSocketDeflateContext;
using wknet::ws::WebSocketFrameHeader;
using wknet::ws::WebSocketOpcode;

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
        size_t payloadLength,
        bool fin = true,
        bool rsv1 = false)
    {
        if (destination == nullptr ||
            destinationLength == nullptr ||
            (payload == nullptr && payloadLength != 0) ||
            payloadLength > static_cast<size_t>(0x7fffffffffffffffULL)) {
            g_failed = true;
            printf("FAIL: append websocket server frame\n");
            return;
        }

        size_t headerLength = 2;
        if (payloadLength > 0xffff) {
            headerLength = 10;
        }
        else if (payloadLength > 125) {
            headerLength = 4;
        }
        if (destinationCapacity - *destinationLength < payloadLength + headerLength) {
            g_failed = true;
            printf("FAIL: append websocket server frame capacity\n");
            return;
        }

        unsigned char* cursor = destination + *destinationLength;
        cursor[0] = static_cast<unsigned char>(
            (fin ? 0x80 : 0x00) |
            (rsv1 ? 0x40 : 0x00) |
            static_cast<unsigned char>(opcode));
        size_t payloadOffset = 2;
        if (payloadLength <= 125) {
            cursor[1] = static_cast<unsigned char>(payloadLength);
        }
        else if (payloadLength <= 0xffff) {
            cursor[1] = 126;
            cursor[2] = static_cast<unsigned char>((payloadLength >> 8) & 0xff);
            cursor[3] = static_cast<unsigned char>(payloadLength & 0xff);
            payloadOffset = 4;
        }
        else {
            cursor[1] = 127;
            unsigned long long length64 = static_cast<unsigned long long>(payloadLength);
            for (size_t index = 0; index < 8; ++index) {
                cursor[2 + index] = static_cast<unsigned char>((length64 >> (56 - (index * 8))) & 0xff);
            }
            payloadOffset = 10;
        }
        if (payloadLength != 0) {
            memcpy(cursor + payloadOffset, payload, payloadLength);
        }
        *destinationLength += payloadLength + headerLength;
    }

    NTSTATUS DecodeClientFramePayload(
        const void* data,
        size_t dataLength,
        WebSocketOpcode* opcode,
        bool* fin,
        bool* rsv1,
        unsigned char* payload,
        size_t payloadCapacity,
        size_t* payloadLength)
    {
        if (opcode != nullptr) {
            *opcode = WebSocketOpcode::Continuation;
        }
        if (fin != nullptr) {
            *fin = false;
        }
        if (rsv1 != nullptr) {
            *rsv1 = false;
        }
        if (payloadLength != nullptr) {
            *payloadLength = 0;
        }
        if (data == nullptr ||
            opcode == nullptr ||
            fin == nullptr ||
            rsv1 == nullptr ||
            payload == nullptr ||
            payloadLength == nullptr ||
            dataLength < 6) {
            return STATUS_INVALID_PARAMETER;
        }

        const unsigned char* bytes = static_cast<const unsigned char*>(data);
        if ((bytes[0] & 0x30) != 0 || (bytes[1] & 0x80) == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        *fin = (bytes[0] & 0x80) != 0;
        *rsv1 = (bytes[0] & 0x40) != 0;
        *opcode = static_cast<WebSocketOpcode>(bytes[0] & 0x0f);
        size_t cursor = 2;
        size_t length = bytes[1] & 0x7f;
        if (length == 126) {
            if (dataLength < 8) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }
            length = (static_cast<size_t>(bytes[2]) << 8) | bytes[3];
            cursor = 4;
        }
        else if (length == 127) {
            if (dataLength < 14) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }
            length = 0;
            for (size_t index = 0; index < 8; ++index) {
                if (length > (static_cast<size_t>(-1) >> 8)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                length = (length << 8) | bytes[2 + index];
            }
            cursor = 10;
        }

        if (payloadCapacity < length) {
            *payloadLength = length;
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (dataLength - cursor < 4 || dataLength - cursor - 4 < length) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        const unsigned char* mask = bytes + cursor;
        const unsigned char* encoded = mask + 4;
        for (size_t index = 0; index < length; ++index) {
            payload[index] = static_cast<unsigned char>(encoded[index] ^ mask[index % 4]);
        }
        *payloadLength = length;
        return STATUS_SUCCESS;
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
        unsigned char ReceiveBytes[65536] = {};
        size_t ReceiveLength = 0;
        size_t ReceiveOffset = 0;
        unsigned char InitialFrames[32768] = {};
        size_t InitialFrameLength = 0;
        char LastHandshakeRequest[1024] = {};
        size_t LastHandshakeRequestLength = 0;
        unsigned char LastClientPayload[32768] = {};
        size_t LastClientPayloadLength = 0;
        WebSocketOpcode LastClientOpcode = WebSocketOpcode::Continuation;
        unsigned char LastClosePayload[125] = {};
        size_t LastClosePayloadLength = 0;
        unsigned char FragmentPayload[32768] = {};
        size_t FragmentPayloadLength = 0;
        WebSocketOpcode FragmentOpcode = WebSocketOpcode::Continuation;
        bool LastClientFin = false;
        bool LastClientRsv1 = false;
        bool FragmentOpen = false;
        size_t ClientFrameCount = 0;
        size_t PongCount = 0;
        size_t ConnectAttempts = 0;
        size_t FailConnectAttempts = 0;
        const char* SelectedSubprotocol = nullptr;
        size_t SelectedSubprotocolLength = 0;
        const char* ResponseExtensions = nullptr;
        size_t ResponseExtensionsLength = 0;
        unsigned int HandshakeStatusCode = 101;
        const char* HandshakeReason = "Switching Protocols";
        const char* UpgradeWhenHeaderName = nullptr;
        const char* UpgradeWhenHeaderValue = nullptr;
        const char* UpgradeWhenPath = nullptr;
        bool EchoAfterPing = false;
        bool Connected = false;
        NTSTATUS DataSendStatus = STATUS_SUCCESS;
        NTSTATUS ReceiveStatus = STATUS_IO_TIMEOUT;
        NTSTATUS CloseStatus = STATUS_SUCCESS;
        size_t TransportCloseCount = 0;
        size_t CloseCount = 0;

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
                memcpy(LastHandshakeRequest, request, copyLength);
                LastHandshakeRequest[copyLength] = '\0';
                LastHandshakeRequestLength = copyLength;

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

                bool headerAllowsUpgrade = false;
                if (UpgradeWhenHeaderName != nullptr && UpgradeWhenHeaderValue != nullptr) {
                    size_t challengeHeaderLength = 0;
                    const char* challengeHeader = FindHeaderValue(
                        request,
                        UpgradeWhenHeaderName,
                        &challengeHeaderLength);
                    headerAllowsUpgrade =
                        challengeHeader != nullptr &&
                        challengeHeaderLength == strlen(UpgradeWhenHeaderValue) &&
                        memcmp(challengeHeader, UpgradeWhenHeaderValue, challengeHeaderLength) == 0;
                }
                const bool pathAllowsUpgrade =
                    UpgradeWhenPath != nullptr &&
                    dataLength >= 5 + strlen(UpgradeWhenPath) &&
                    memcmp(text, "GET ", 4) == 0 &&
                    memcmp(text + 4, UpgradeWhenPath, strlen(UpgradeWhenPath)) == 0 &&
                    text[4 + strlen(UpgradeWhenPath)] == ' ';

                char response[512] = {};
                if (HandshakeStatusCode != 101 && !headerAllowsUpgrade && !pathAllowsUpgrade) {
                    const int written = snprintf(
                        response,
                        sizeof(response),
                        "HTTP/1.1 %u %s\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n",
                        HandshakeStatusCode,
                        HandshakeReason != nullptr ? HandshakeReason : "WebSocket Rejected");
                    if (written <= 0 || static_cast<size_t>(written) >= sizeof(response)) {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    QueueReceive(response, static_cast<size_t>(written));
                    if (bytesSent != nullptr) {
                        *bytesSent = dataLength;
                    }
                    return STATUS_SUCCESS;
                }

                const char* extensions = ResponseExtensions != nullptr ? ResponseExtensions : "";
                const int extensionsLength = static_cast<int>(
                    ResponseExtensions != nullptr ? ResponseExtensionsLength : 0);
                const char* extensionsPrefix = ResponseExtensions != nullptr ?
                    "Sec-WebSocket-Extensions: " :
                    "";
                const char* extensionsSuffix = ResponseExtensions != nullptr ?
                    "\r\n" :
                    "";
                const int written = SelectedSubprotocol != nullptr ?
                    snprintf(
                        response,
                        sizeof(response),
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %.*s\r\n"
                        "Sec-WebSocket-Protocol: %.*s\r\n"
                        "%s%.*s%s"
                        "\r\n",
                        static_cast<int>(acceptLength),
                        accept,
                        static_cast<int>(SelectedSubprotocolLength),
                        SelectedSubprotocol,
                        extensionsPrefix,
                        extensionsLength,
                        extensions,
                        extensionsSuffix) :
                    snprintf(
                        response,
                        sizeof(response),
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %.*s\r\n"
                        "%s%.*s%s"
                        "\r\n",
                        static_cast<int>(acceptLength),
                        accept,
                        extensionsPrefix,
                        extensionsLength,
                        extensions,
                        extensionsSuffix);
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

            WebSocketOpcode opcode = WebSocketOpcode::Continuation;
            NTSTATUS status = DecodeClientFramePayload(
                data,
                dataLength,
                &opcode,
                &LastClientFin,
                &LastClientRsv1,
                LastClientPayload,
                sizeof(LastClientPayload),
                &LastClientPayloadLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!NT_SUCCESS(DataSendStatus)) {
                return DataSendStatus;
            }
            ++ClientFrameCount;
            LastClientOpcode = opcode;

            if (opcode == WebSocketOpcode::Pong) {
                ++PongCount;
                if (bytesSent != nullptr) {
                    *bytesSent = dataLength;
                }
                return STATUS_SUCCESS;
            }

            if (opcode == WebSocketOpcode::Close) {
                ++CloseCount;
                LastClosePayloadLength = LastClientPayloadLength < sizeof(LastClosePayload) ?
                    LastClientPayloadLength :
                    sizeof(LastClosePayload);
                if (LastClosePayloadLength != 0) {
                    memcpy(LastClosePayload, LastClientPayload, LastClosePayloadLength);
                }
                if (bytesSent != nullptr) {
                    *bytesSent = dataLength;
                }
                return STATUS_SUCCESS;
            }

            if (opcode == WebSocketOpcode::Continuation) {
                if (!FragmentOpen ||
                    LastClientPayloadLength > sizeof(FragmentPayload) - FragmentPayloadLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (LastClientPayloadLength != 0) {
                    memcpy(
                        FragmentPayload + FragmentPayloadLength,
                        LastClientPayload,
                        LastClientPayloadLength);
                }
                FragmentPayloadLength += LastClientPayloadLength;

                if (!LastClientFin) {
                    if (bytesSent != nullptr) {
                        *bytesSent = dataLength;
                    }
                    return STATUS_SUCCESS;
                }

                opcode = FragmentOpcode;
                LastClientPayloadLength = FragmentPayloadLength;
                if (LastClientPayloadLength != 0) {
                    memcpy(LastClientPayload, FragmentPayload, LastClientPayloadLength);
                }
                LastClientOpcode = opcode;
                FragmentOpen = false;
                FragmentPayloadLength = 0;
            }

            if (opcode != WebSocketOpcode::Text && opcode != WebSocketOpcode::Binary) {
                if (bytesSent != nullptr) {
                    *bytesSent = dataLength;
                }
                return STATUS_SUCCESS;
            }

            if (!LastClientFin) {
                if (FragmentOpen) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (LastClientPayloadLength != 0) {
                    memcpy(FragmentPayload, LastClientPayload, LastClientPayloadLength);
                }
                FragmentPayloadLength = LastClientPayloadLength;
                FragmentOpcode = opcode;
                FragmentOpen = true;
                if (bytesSent != nullptr) {
                    *bytesSent = dataLength;
                }
                return STATUS_SUCCESS;
            }

            if (EchoAfterPing) {
                AppendServerFrame(ReceiveBytes, sizeof(ReceiveBytes), &ReceiveLength, WebSocketOpcode::Ping, nullptr, 0);
            }
            AppendServerFrame(
                ReceiveBytes,
                sizeof(ReceiveBytes),
                &ReceiveLength,
                opcode,
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
                return ReceiveStatus;
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
            ++TransportCloseCount;
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

    void TestTransportModeDefaults()
    {
        Expect(
            static_cast<ULONG>(WebSocketTransportMode::Auto) == 0,
            "client websocket Auto transport mode remains ABI zero");

        WebSocketConnectOptions defaults = {};
        Expect(
            defaults.TransportMode == WebSocketTransportMode::Auto,
            "client websocket connect options default to Auto");

        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "plaintext websocket default Auto connect succeeds");
        Expect(
            strncmp(server.LastHandshakeRequest, "GET / HTTP/1.1\r\n", strlen("GET / HTTP/1.1\r\n")) == 0,
            "plaintext websocket default Auto uses HTTP/1.1 handshake");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void ExpectHandshakeHost(const char* host, USHORT port, const wchar_t* serviceName, const char* expectedHost)
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.Host = host;
        options.HostLength = strlen(host);
        options.Port = port;
        options.ServiceName = serviceName;

        NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "websocket connect succeeds for Host header formatting");

        size_t hostLength = 0;
        const char* hostValue = FindHeaderValue(server.LastHandshakeRequest, "Host", &hostLength);
        Expect(hostValue != nullptr, "websocket handshake contains Host header");
        Expect(
            hostValue != nullptr &&
            hostLength == strlen(expectedHost) &&
            memcmp(hostValue, expectedHost, hostLength) == 0,
            "websocket Host header matches expected authority");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestHandshakeHostHeaderFormatting()
    {
        ExpectHandshakeHost("example.test", 0, L"80", "example.test");
        ExpectHandshakeHost("example.test", 80, L"80", "example.test");
        ExpectHandshakeHost("example.test", 8080, L"8080", "example.test:8080");
        ExpectHandshakeHost("::1", 80, L"80", "[::1]");
        ExpectHandshakeHost("::1", 8080, L"8080", "[::1]:8080");
    }

    void TestHandshakeCustomHeaders()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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

        HttpHeader extra[2] = {};
        extra[0] = { { "Origin", strlen("Origin") }, { "https://example.test", strlen("https://example.test") } };
        extra[1] = { { "Authorization", strlen("Authorization") }, { "Bearer token123", strlen("Bearer token123") } };

        WebSocketConnectOptions options = MakeConnectOptions();
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = 2;

        NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "websocket connect succeeds with custom headers");

        size_t valueLength = 0;
        const char* origin = FindHeaderValue(server.LastHandshakeRequest, "Origin", &valueLength);
        Expect(origin != nullptr &&
            valueLength == strlen("https://example.test") &&
            memcmp(origin, "https://example.test", valueLength) == 0,
            "custom Origin header is emitted on the wire");

        const char* authorization = FindHeaderValue(server.LastHandshakeRequest, "Authorization", &valueLength);
        Expect(authorization != nullptr &&
            valueLength == strlen("Bearer token123") &&
            memcmp(authorization, "Bearer token123", valueLength) == 0,
            "custom Authorization header is emitted on the wire");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
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

        wknet::net::WskClient wskClient;
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
        Expect(strstr(request, "Connection: Upgrade\r\n") != nullptr, "websocket handshake requests connection upgrade");

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

    void TestSendTextCanEmitNonFinalFrame()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for non-final send succeeds");

        const char text[] = "fragment-start";
        status = client.SendText(text, sizeof(text) - 1, buffers, false);
        Expect(NT_SUCCESS(status), "non-final text send succeeds");
        Expect(!server.LastClientFin, "non-final text send clears FIN");
        Expect(server.LastClientPayloadLength == sizeof(text) - 1, "non-final text payload length matches");
        Expect(memcmp(server.LastClientPayload, text, sizeof(text) - 1) == 0, "non-final text payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestSendAllowsEmptyMessagesAndRejectsInvalidUtf8()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for empty send succeeds");

        const char empty[] = "";
        status = client.SendText(empty, 0, buffers);
        Expect(NT_SUCCESS(status), "empty text send succeeds");
        Expect(server.LastClientPayloadLength == 0, "empty text payload length is zero");

        status = client.SendBinary(nullptr, 0, buffers);
        Expect(NT_SUCCESS(status), "empty binary send succeeds with null payload pointer");
        Expect(server.LastClientPayloadLength == 0, "empty binary payload length is zero");

        status = client.SendText(empty, 0, buffers, false);
        Expect(NT_SUCCESS(status), "empty non-final text send succeeds");
        status = client.SendContinuation(nullptr, 0, buffers, true);
        Expect(NT_SUCCESS(status), "empty continuation send succeeds");

        const unsigned char invalidText[] = { 0xc3, 0x28 };
        status = client.SendText(
            reinterpret_cast<const char*>(invalidText),
            sizeof(invalidText),
            buffers);
        Expect(status == STATUS_INVALID_PARAMETER, "invalid UTF-8 text send is rejected before framing");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestContinuationCompletesFragmentedText()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for continuation send succeeds");

        const char first[] = "fragment-";
        const char second[] = "complete";
        status = client.SendText(first, sizeof(first) - 1, buffers, false);
        Expect(NT_SUCCESS(status), "fragmented text first frame sends");

        status = client.SendContinuation(
            reinterpret_cast<const unsigned char*>(second),
            sizeof(second) - 1,
            buffers,
            true);
        Expect(NT_SUCCESS(status), "fragmented text continuation sends");
        Expect(server.LastClientFin, "final continuation sets FIN");

        const char expected[] = "fragment-complete";
        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "fragmented text echo is received");
        Expect(opcode == WebSocketOpcode::Text, "fragmented text echo opcode is text");
        Expect(bytesReceived == sizeof(expected) - 1, "fragmented text echo length matches");
        Expect(memcmp(payload, expected, sizeof(expected) - 1) == 0, "fragmented text echo payload matches");

        status = client.SendContinuation(
            reinterpret_cast<const unsigned char*>(second),
            sizeof(second) - 1,
            buffers,
            true);
        Expect(status == STATUS_INVALID_DEVICE_STATE, "orphan continuation is rejected");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestSendFragmentedTextUtf8AllowsSplitCodePoint()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for split UTF-8 send succeeds");

        const unsigned char first[] = { 'A', 0xe2 };
        status = client.SendText(reinterpret_cast<const char*>(first), sizeof(first), buffers, false);
        Expect(NT_SUCCESS(status), "text fragment may end inside a UTF-8 code point");

        const unsigned char second[] = { 0x82, 0xac, 'Z' };
        status = client.SendContinuation(second, sizeof(second), buffers, true);
        Expect(NT_SUCCESS(status), "continuation may complete split UTF-8 code point");

        const unsigned char expected[] = { 'A', 0xe2, 0x82, 0xac, 'Z' };
        Expect(server.LastClientFin, "split UTF-8 final continuation sets FIN");
        Expect(server.LastClientPayloadLength == sizeof(expected), "split UTF-8 payload length matches");
        Expect(memcmp(server.LastClientPayload, expected, sizeof(expected)) == 0, "split UTF-8 payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestSendFragmentedTextUtf8RejectsInvalidContinuation()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for invalid split UTF-8 test succeeds");

        const unsigned char first[] = { 0xe2 };
        status = client.SendText(reinterpret_cast<const char*>(first), sizeof(first), buffers, false);
        Expect(NT_SUCCESS(status), "text fragment can hold pending UTF-8 state");

        const unsigned char invalid[] = { '(' };
        status = client.SendContinuation(invalid, sizeof(invalid), buffers, true);
        Expect(status == STATUS_INVALID_PARAMETER, "invalid UTF-8 continuation is rejected");
        Expect(server.LastClientPayloadLength == sizeof(first), "invalid continuation is not sent");

        const unsigned char valid[] = { 0x82, 0xac };
        status = client.SendContinuation(valid, sizeof(valid), buffers, true);
        Expect(NT_SUCCESS(status), "UTF-8 state remains usable after rejected continuation");

        const unsigned char expected[] = { 0xe2, 0x82, 0xac };
        Expect(server.LastClientPayloadLength == sizeof(expected), "recovered split UTF-8 payload length matches");
        Expect(memcmp(server.LastClientPayload, expected, sizeof(expected)) == 0, "recovered split UTF-8 payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestSendFragmentedTextUtf8RejectsUnfinishedFinalSequence()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for unfinished UTF-8 send succeeds");

        const unsigned char unfinished[] = { 0xf0, 0x9f };
        status = client.SendText(reinterpret_cast<const char*>(unfinished), sizeof(unfinished), buffers, true);
        Expect(status == STATUS_INVALID_PARAMETER, "final text frame rejects unfinished UTF-8 sequence");
        Expect(server.LastClientPayloadLength == 0, "unfinished final UTF-8 frame is not sent");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestConnectRetriesResolvedAddresses()
    {
        FakeWebSocketServer server;
        server.FailConnectAttempts = 1;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.AddressFamily = wknet::net::WskAddressFamily::Any;

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

        wknet::net::WskClient wskClient;
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

    void TestReceiveFragmentedTextWithInterleavedPing()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char first[] = "hello ";
        const unsigned char ping[] = "hb";
        const unsigned char second[] = "world";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            first,
            sizeof(first) - 1,
            false);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Ping,
            ping,
            sizeof(ping) - 1);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Continuation,
            second,
            sizeof(second) - 1);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for fragmented text receive succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        const char expected[] = "hello world";
        Expect(NT_SUCCESS(status), "fragmented text receive succeeds");
        Expect(server.PongCount == 1, "client replies to ping interleaved with fragmented text");
        Expect(opcode == WebSocketOpcode::Text, "fragmented text opcode is text");
        Expect(bytesReceived == sizeof(expected) - 1, "fragmented text length matches");
        Expect(memcmp(payload, expected, sizeof(expected) - 1) == 0, "fragmented text payload is concatenated");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveFragmentedBinary()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char first[] = { 0x01, 0x02 };
        const unsigned char second[] = { 0x03 };
        const unsigned char third[] = { 0x04, 0x05 };
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Binary,
            first,
            sizeof(first),
            false);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Continuation,
            second,
            sizeof(second),
            false);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Continuation,
            third,
            sizeof(third));

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for fragmented binary receive succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        const unsigned char expected[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        Expect(NT_SUCCESS(status), "fragmented binary receive succeeds");
        Expect(opcode == WebSocketOpcode::Binary, "fragmented binary opcode is binary");
        Expect(bytesReceived == sizeof(expected), "fragmented binary length matches");
        Expect(memcmp(payload, expected, sizeof(expected)) == 0, "fragmented binary payload is concatenated");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveRejectsOrphanContinuation()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char payloadBytes[] = "orphan";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Continuation,
            payloadBytes,
            sizeof(payloadBytes) - 1);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for orphan continuation test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Text;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "orphan continuation is rejected");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveRejectsNewDataFrameDuringFragment()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char first[] = "fragment";
        const unsigned char second[] = "new-message";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            first,
            sizeof(first) - 1,
            false);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            second,
            sizeof(second) - 1);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for nested data frame test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Text;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "new data frame during fragment is rejected");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestConnectAcceptsMatchingSubprotocol()
    {
        FakeWebSocketServer server;
        server.SelectedSubprotocol = "chat";
        server.SelectedSubprotocolLength = strlen(server.SelectedSubprotocol);
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.Subprotocol = "chat, superchat";
        options.SubprotocolLength = strlen(options.Subprotocol);
        const NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "websocket connect accepts selected requested subprotocol");

        size_t selectedSubprotocolLength = 0;
        const char* selectedSubprotocol = client.SelectedSubprotocol(&selectedSubprotocolLength);
        Expect(selectedSubprotocol != nullptr, "selected subprotocol is exposed");
        Expect(selectedSubprotocolLength == server.SelectedSubprotocolLength, "selected subprotocol length matches");
        Expect(
            selectedSubprotocol != nullptr &&
            memcmp(selectedSubprotocol, server.SelectedSubprotocol, selectedSubprotocolLength) == 0,
            "selected subprotocol value matches server response");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestConnectRejectsSubprotocolMismatch()
    {
        FakeWebSocketServer server;
        server.SelectedSubprotocol = "other";
        server.SelectedSubprotocolLength = strlen(server.SelectedSubprotocol);
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.Subprotocol = "chat";
        options.SubprotocolLength = strlen(options.Subprotocol);
        USHORT statusCode = 0;
        const NTSTATUS status = client.Connect(wskClient, options, buffers, &statusCode);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "websocket connect rejects unrequested selected subprotocol");
        Expect(statusCode == 101, "subprotocol mismatch happens after 101 response");
        g_server = nullptr;
    }

    void TestConnectRejectsUnexpectedSubprotocol()
    {
        FakeWebSocketServer server;
        server.SelectedSubprotocol = "chat";
        server.SelectedSubprotocolLength = strlen(server.SelectedSubprotocol);
        g_server = &server;

        wknet::net::WskClient wskClient;
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

        const NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "websocket connect rejects selected subprotocol when none was requested");
        g_server = nullptr;
    }

    void TestConnectRejectsUnrequestedExtensions()
    {
        FakeWebSocketServer server;
        server.ResponseExtensions = "permessage-deflate";
        server.ResponseExtensionsLength = strlen(server.ResponseExtensions);
        g_server = &server;

        wknet::net::WskClient wskClient;
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

        const NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "websocket connect rejects unrequested extensions");
        g_server = nullptr;
    }

    void TestConnectDefaultDoesNotOfferPerMessageDeflate()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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

        const NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(NT_SUCCESS(status), "default websocket connect succeeds without permessage-deflate");

        size_t extensionLength = 0;
        const char* extension = FindHeaderValue(
            server.LastHandshakeRequest,
            "Sec-WebSocket-Extensions",
            &extensionLength);
        Expect(extension == nullptr, "default websocket connect does not offer permessage-deflate");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestConnectOffersPerMessageDeflateWhenEnabled()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.PerMessageDeflate.Enable = true;
        options.PerMessageDeflate.ClientNoContextTakeover = true;
        options.PerMessageDeflate.ServerNoContextTakeover = true;
        options.PerMessageDeflate.ClientMaxWindowBits = 12;
        options.PerMessageDeflate.ServerMaxWindowBits = 13;

        const NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "permessage-deflate websocket connect succeeds when server omits extension");

        size_t extensionLength = 0;
        const char* extension = FindHeaderValue(
            server.LastHandshakeRequest,
            "Sec-WebSocket-Extensions",
            &extensionLength);
        Expect(extension != nullptr, "enabled websocket connect offers permessage-deflate");
        Expect(extension != nullptr &&
            strstr(server.LastHandshakeRequest, "permessage-deflate") != nullptr &&
            strstr(server.LastHandshakeRequest, "client_max_window_bits=12") != nullptr &&
            strstr(server.LastHandshakeRequest, "server_max_window_bits=13") != nullptr &&
            strstr(server.LastHandshakeRequest, "client_no_context_takeover") != nullptr &&
            strstr(server.LastHandshakeRequest, "server_no_context_takeover") != nullptr,
            "permessage-deflate offer includes requested parameters");

        UNREFERENCED_PARAMETER(extensionLength);
        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestConnectAcceptsNegotiatedPerMessageDeflate()
    {
        FakeWebSocketServer server;
        server.ResponseExtensions =
            "permessage-deflate; server_no_context_takeover; client_max_window_bits=12; server_max_window_bits=13";
        server.ResponseExtensionsLength = strlen(server.ResponseExtensions);
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.PerMessageDeflate.Enable = true;
        options.PerMessageDeflate.ClientMaxWindowBits = 15;
        options.PerMessageDeflate.ServerMaxWindowBits = 15;

        const NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "websocket connect accepts negotiated permessage-deflate");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestSendCompressedTextSetsRsv1AndDeflatesPayload()
    {
        FakeWebSocketServer server;
        server.ResponseExtensions = "permessage-deflate";
        server.ResponseExtensionsLength = strlen(server.ResponseExtensions);
        g_server = &server;

        wknet::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[512] = {};
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
        options.PerMessageDeflate.Enable = true;

        NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "websocket connect negotiates permessage-deflate for compressed send");

        const char text[] = "kernel websocket compressed text";
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(NT_SUCCESS(status), "compressed text send succeeds");
        Expect(server.LastClientOpcode == WebSocketOpcode::Text, "compressed text send uses text opcode");
        Expect(server.LastClientFin, "compressed text send is final");
        Expect(server.LastClientRsv1, "compressed text send sets RSV1");

        WebSocketDeflateContext inflater;
        status = inflater.Initialize(15);
        Expect(NT_SUCCESS(status), "test inflate context initializes for compressed send");
        size_t decodedLength = 0;
        if (NT_SUCCESS(status)) {
            status = inflater.InflateMessage(
                server.LastClientPayload,
                server.LastClientPayloadLength,
                payload,
                sizeof(payload),
                &decodedLength);
        }
        Expect(NT_SUCCESS(status), "compressed client payload inflates");
        Expect(decodedLength == sizeof(text) - 1, "compressed client payload decoded length matches");
        Expect(memcmp(payload, text, sizeof(text) - 1) == 0, "compressed client payload decoded bytes match");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveCompressedTextInflatesPayload()
    {
        FakeWebSocketServer server;
        server.ResponseExtensions = "permessage-deflate";
        server.ResponseExtensionsLength = strlen(server.ResponseExtensions);
        g_server = &server;

        const unsigned char text[] = "server compressed websocket text";
        unsigned char compressed[256] = {};
        size_t compressedLength = 0;
        NTSTATUS status = WebSocketDeflateContext::DeflateMessage(
            text,
            sizeof(text) - 1,
            true,
            compressed,
            sizeof(compressed),
            &compressedLength);
        Expect(NT_SUCCESS(status), "server compressed test payload deflates");
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            compressed,
            compressedLength,
            true,
            true);

        wknet::net::WskClient wskClient;
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
        options.PerMessageDeflate.Enable = true;

        status = client.Connect(wskClient, options, buffers);
        Expect(NT_SUCCESS(status), "websocket connect negotiates permessage-deflate for compressed receive");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "compressed server text receive succeeds");
        Expect(opcode == WebSocketOpcode::Text, "compressed server text opcode is text");
        Expect(bytesReceived == sizeof(text) - 1, "compressed server text decoded length matches");
        Expect(memcmp(payload, text, sizeof(text) - 1) == 0, "compressed server text decoded bytes match");

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

        wknet::net::WskClient wskClient;
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

    void TestReceiveMessageLargerThanFrameScratch()
    {
        FakeWebSocketServer server;
        g_server = &server;

        static unsigned char largeMessage[20000] = {};
        for (size_t index = 0; index < sizeof(largeMessage); ++index) {
            largeMessage[index] = static_cast<unsigned char>('a' + (index % 26));
        }
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            largeMessage,
            sizeof(largeMessage));

        wknet::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        static unsigned char payload[21000] = {};
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
        Expect(NT_SUCCESS(status), "websocket connect for large message test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "websocket receive accepts message larger than frame scratch");
        Expect(opcode == WebSocketOpcode::Text, "large receive opcode is text");
        Expect(bytesReceived == sizeof(largeMessage), "large receive length matches");
        Expect(memcmp(payload, largeMessage, sizeof(largeMessage)) == 0, "large receive payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveOversizedTextFrameHeaderSendsClose1009()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char oversizedTextHeader[] = { 0x81, 100 };
        AppendBytes(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            oversizedTextHeader,
            sizeof(oversizedTextHeader));

        wknet::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[8] = {};
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
        Expect(NT_SUCCESS(status), "websocket connect for oversized header test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "oversized text frame is rejected from decoded header");
        Expect(bytesReceived == 100, "oversized text frame reports declared payload length");
        Expect(server.CloseCount == 1, "oversized text frame sends one close frame");
        Expect(server.LastClosePayloadLength == 2, "oversized text frame close carries status code");
        Expect(server.LastClosePayload[0] == 0x03 && server.LastClosePayload[1] == 0xf1,
            "oversized text frame close status is 1009");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveOversizedContinuationFrameHeaderSendsClose1009()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char first[] = { 'a', 'b', 'c' };
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            first,
            sizeof(first),
            false);
        const unsigned char oversizedContinuationHeader[] = { 0x80, 100 };
        AppendBytes(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            oversizedContinuationHeader,
            sizeof(oversizedContinuationHeader));

        wknet::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[8] = {};
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
        Expect(NT_SUCCESS(status), "websocket connect for oversized continuation header test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "oversized continuation frame is rejected from decoded header");
        Expect(bytesReceived == sizeof(first) + 100, "oversized continuation reports total declared message length");
        Expect(server.CloseCount == 1, "oversized continuation sends one close frame");
        Expect(server.LastClosePayloadLength == 2, "oversized continuation close carries status code");
        Expect(server.LastClosePayload[0] == 0x03 && server.LastClosePayload[1] == 0xf1,
            "oversized continuation close status is 1009");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceivePingWithoutAutoReplyReturnsControlEvent()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char ping[] = "hb";
        const unsigned char text[] = "after-ping";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Ping,
            ping,
            sizeof(ping) - 1);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            text,
            sizeof(text) - 1);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for manual ping test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived, false);
        Expect(NT_SUCCESS(status), "manual ping receive succeeds");
        Expect(opcode == WebSocketOpcode::Ping, "manual ping returns ping opcode");
        Expect(bytesReceived == sizeof(ping) - 1, "manual ping payload length matches");
        Expect(memcmp(payload, ping, sizeof(ping) - 1) == 0, "manual ping payload matches");
        Expect(server.PongCount == 0, "manual ping receive does not auto-reply");

        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "data after manual ping is received");
        Expect(opcode == WebSocketOpcode::Text, "data after manual ping opcode is text");
        Expect(bytesReceived == sizeof(text) - 1, "data after manual ping length matches");
        Expect(memcmp(payload, text, sizeof(text) - 1) == 0, "data after manual ping payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceivePongWithoutAutoReplyReturnsControlEvent()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char pong[] = "hb";
        const unsigned char text[] = "after-pong";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Pong,
            pong,
            sizeof(pong) - 1);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            text,
            sizeof(text) - 1);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for manual pong test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived, false);
        Expect(NT_SUCCESS(status), "manual pong receive succeeds");
        Expect(opcode == WebSocketOpcode::Pong, "manual pong returns pong opcode");
        Expect(bytesReceived == sizeof(pong) - 1, "manual pong payload length matches");
        Expect(memcmp(payload, pong, sizeof(pong) - 1) == 0, "manual pong payload matches");

        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "data after manual pong is received");
        Expect(opcode == WebSocketOpcode::Text, "data after manual pong opcode is text");
        Expect(bytesReceived == sizeof(text) - 1, "data after manual pong length matches");
        Expect(memcmp(payload, text, sizeof(text) - 1) == 0, "data after manual pong payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestAutoReplyPingUsesControlBufferWhenOutputIsSmall()
    {
        FakeWebSocketServer server;
        g_server = &server;

        unsigned char ping[125] = {};
        for (size_t index = 0; index < sizeof(ping); ++index) {
            ping[index] = static_cast<unsigned char>('A' + (index % 26));
        }
        const unsigned char text[] = "ok";
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Ping,
            ping,
            sizeof(ping));
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            text,
            sizeof(text) - 1);

        wknet::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[2] = {};
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
        Expect(NT_SUCCESS(status), "websocket connect for small output auto-pong test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "small output receive skips auto-ponged 125-byte ping");
        Expect(server.PongCount == 1, "small output receive auto-replies to 125-byte ping");
        Expect(server.LastClientOpcode == WebSocketOpcode::Pong, "small output auto-reply emits Pong");
        Expect(server.LastClientPayloadLength == sizeof(ping), "small output Pong payload length matches");
        Expect(memcmp(server.LastClientPayload, ping, sizeof(ping)) == 0, "small output Pong payload matches");
        Expect(opcode == WebSocketOpcode::Text, "small output receive returns following text message");
        Expect(bytesReceived == sizeof(text) - 1, "small output receive text length matches");
        Expect(memcmp(payload, text, sizeof(text) - 1) == 0, "small output receive text payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestSendPingAndPongControlFrames()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for explicit control sends succeeds");

        const unsigned char pingPayload[] = { 'p', 'i', 'n', 'g' };
        status = client.SendPing(pingPayload, sizeof(pingPayload), buffers);
        Expect(NT_SUCCESS(status), "websocket SendPing succeeds");
        Expect(server.LastClientOpcode == WebSocketOpcode::Ping, "SendPing emits ping opcode");
        Expect(server.LastClientFin, "SendPing emits final control frame");
        Expect(server.LastClientPayloadLength == sizeof(pingPayload), "SendPing payload length matches");
        Expect(memcmp(server.LastClientPayload, pingPayload, sizeof(pingPayload)) == 0, "SendPing payload matches");

        const unsigned char pongPayload[] = { 'p', 'o', 'n', 'g' };
        status = client.SendPong(pongPayload, sizeof(pongPayload), buffers);
        Expect(NT_SUCCESS(status), "websocket SendPong succeeds");
        Expect(server.LastClientOpcode == WebSocketOpcode::Pong, "SendPong emits pong opcode");
        Expect(server.PongCount == 1, "SendPong is observed by fake server");
        Expect(server.LastClientPayloadLength == sizeof(pongPayload), "SendPong payload length matches");
        Expect(memcmp(server.LastClientPayload, pongPayload, sizeof(pongPayload)) == 0, "SendPong payload matches");

        unsigned char oversizedControlPayload[126] = {};
        status = client.SendPing(oversizedControlPayload, sizeof(oversizedControlPayload), buffers);
        Expect(status == STATUS_INVALID_PARAMETER, "SendPing rejects oversized control payload");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestSendLargeTextAutomaticallyFragments()
    {
        FakeWebSocketServer server;
        g_server = &server;

        static char largeMessage[20000] = {};
        for (size_t index = 0; index < sizeof(largeMessage); ++index) {
            largeMessage[index] = static_cast<char>('a' + (index % 26));
        }

        wknet::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frame[1024] = {};
        unsigned char payload[21000] = {};
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
        Expect(NT_SUCCESS(status), "websocket connect for large send test succeeds");

        status = client.SendText(largeMessage, sizeof(largeMessage), buffers);
        Expect(NT_SUCCESS(status), "websocket SendText auto-fragments large message");
        Expect(server.ClientFrameCount > 1, "large send emits multiple WebSocket frames");
        Expect(server.LastClientFin, "large send final frame sets FIN");
        Expect(server.LastClientOpcode == WebSocketOpcode::Text, "large send reassembles as text");
        Expect(server.LastClientPayloadLength == sizeof(largeMessage), "large send payload length matches");
        Expect(memcmp(server.LastClientPayload, largeMessage, sizeof(largeMessage)) == 0,
            "large send payload matches");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "large send echo receive succeeds");
        Expect(opcode == WebSocketOpcode::Text, "large send echo opcode is text");
        Expect(bytesReceived == sizeof(largeMessage), "large send echo length matches");
        Expect(memcmp(payload, largeMessage, sizeof(largeMessage)) == 0, "large send echo payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestCloseExSendsStatusCodeAndReason()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for CloseEx succeeds");

        const unsigned char reason[] = { 'b', 'y', 'e' };
        status = client.Close(1000, reason, sizeof(reason), buffers);
        Expect(NT_SUCCESS(status), "websocket CloseEx succeeds");
        Expect(server.CloseCount == 1, "CloseEx sends one close frame");
        Expect(server.LastClosePayloadLength == 2 + sizeof(reason), "CloseEx payload length matches");
        Expect(server.LastClosePayload[0] == 0x03 && server.LastClosePayload[1] == 0xe8, "CloseEx status code matches");
        Expect(memcmp(server.LastClosePayload + 2, reason, sizeof(reason)) == 0, "CloseEx reason matches");
        g_server = nullptr;
    }

    void ExpectProtocolErrorClosesTransport(
        const unsigned char* frame,
        size_t frameLength,
        const char* rejectedMessage,
        const char* closeMessage,
        const char* transportMessage)
    {
        FakeWebSocketServer server;
        g_server = &server;

        AppendBytes(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            frame,
            frameLength);

        wknet::net::WskClient wskClient;
        WebSocketClient client;
        char request[1024] = {};
        char response[1024] = {};
        unsigned char frameBuffer[1024] = {};
        unsigned char payload[256] = {};
        HttpHeader headers[8] = {};
        WebSocketIoBuffers buffers = MakeBuffers(
            request,
            sizeof(request),
            response,
            sizeof(response),
            frameBuffer,
            sizeof(frameBuffer),
            payload,
            sizeof(payload),
            headers,
            sizeof(headers) / sizeof(headers[0]));

        NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers);
        Expect(NT_SUCCESS(status), "websocket connect for protocol error helper succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, rejectedMessage);
        Expect(server.CloseCount == 1, closeMessage);
        Expect(server.LastClosePayloadLength == 2, "protocol error close carries status code");
        Expect(server.LastClosePayload[0] == 0x03 && server.LastClosePayload[1] == 0xea,
            "protocol error close status is 1002");
        Expect(!server.Connected, transportMessage);
        Expect(server.TransportCloseCount == 1, "protocol error closes transport exactly once");

        status = client.Close(buffers);
        Expect(NT_SUCCESS(status), "websocket Close after protocol error is idempotent");
        Expect(server.TransportCloseCount == 1, "Close after protocol error does not close transport twice");
        g_server = nullptr;
    }

    void TestReceiveProtocolHeaderErrorSendsClose1002AndTerminates()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char maskedServerFrame[] = {
            0x81, 0x80, 0x01, 0x02, 0x03, 0x04
        };
        AppendBytes(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            maskedServerFrame,
            sizeof(maskedServerFrame));

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for header error test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "masked server frame is a protocol error");
        Expect(server.CloseCount == 1, "protocol header error sends one close frame");
        Expect(server.LastClosePayloadLength == 2, "protocol header error close carries status code");
        Expect(server.LastClosePayload[0] == 0x03 && server.LastClosePayload[1] == 0xea,
            "protocol header error close status is 1002");
        Expect(!server.Connected, "protocol header error closes the transport");
        Expect(server.TransportCloseCount == 1, "protocol header error closes transport exactly once");

        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "receive after protocol error is disconnected");

        const char text[] = "after-error";
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "send after protocol error is disconnected");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        Expect(server.TransportCloseCount == 1, "explicit Close after protocol error does not close transport twice");
        g_server = nullptr;
    }

    void TestReceiveHeaderDecodeErrorsCloseTransport()
    {
        const unsigned char rsvTextFrame[] = { 0xc1, 0x00 };
        ExpectProtocolErrorClosesTransport(
            rsvTextFrame,
            sizeof(rsvTextFrame),
            "RSV server frame is a protocol error",
            "RSV server frame sends one close frame",
            "RSV server frame closes the transport");

        const unsigned char reservedOpcodeFrame[] = { 0x83, 0x00 };
        ExpectProtocolErrorClosesTransport(
            reservedOpcodeFrame,
            sizeof(reservedOpcodeFrame),
            "reserved opcode server frame is a protocol error",
            "reserved opcode server frame sends one close frame",
            "reserved opcode server frame closes the transport");
    }

    void TestReceiveCloseEchoesAndBlocksData()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char closePayload[] = { 0x03, 0xe8, 'b', 'y', 'e' };
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Close,
            closePayload,
            sizeof(closePayload));

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for close echo test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(NT_SUCCESS(status), "websocket receive close succeeds");
        Expect(opcode == WebSocketOpcode::Close, "close receive returns close opcode");
        Expect(bytesReceived == sizeof(closePayload), "close receive payload length matches");
        Expect(memcmp(payload, closePayload, sizeof(closePayload)) == 0, "close receive payload matches");
        Expect(server.CloseCount == 1, "client echoes close exactly once");
        Expect(server.LastClosePayloadLength == sizeof(closePayload), "close echo payload length matches");
        Expect(memcmp(server.LastClosePayload, closePayload, sizeof(closePayload)) == 0, "close echo payload matches");
        Expect(server.TransportCloseCount == 1, "receive close closes transport after echo");
        Expect(!server.Connected, "receive close disconnects fake server");

        const char text[] = "should-not-send";
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "send after close receive is disconnected");

        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "receive after close state is disconnected");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        Expect(server.TransportCloseCount == 1, "Close after received close does not close transport twice");
        g_server = nullptr;
    }

    void TestReceiveRejectsInvalidTextUtf8()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char invalidText[] = { 0xc3, 0x28 };
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            invalidText,
            sizeof(invalidText));

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for invalid text UTF-8 test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "websocket receive rejects invalid text UTF-8");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveDefaultAggregatesWireFragments()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char first[] = { 'h', 'e' };
        const unsigned char second[] = { 'l', 'l', 'o' };
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            first,
            sizeof(first),
            false);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Continuation,
            second,
            sizeof(second),
            true);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for aggregate fragment test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        bool finalFragment = false;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived, true, false, &finalFragment);
        Expect(NT_SUCCESS(status), "default receive aggregates wire fragments");
        Expect(opcode == WebSocketOpcode::Text, "aggregated fragmented message reports original opcode");
        Expect(finalFragment, "aggregated fragmented message is final");
        Expect(bytesReceived == 5, "aggregated fragmented message length matches");
        Expect(memcmp(payload, "hello", 5) == 0, "aggregated fragmented message payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveCanDeliverWireFragments()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char first[] = { 'h', 'i', ' ', 0xf0, 0x9f };
        const unsigned char second[] = { 0x98, 0x80, '!' };
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            first,
            sizeof(first),
            false);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Continuation,
            second,
            sizeof(second),
            true);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for wire fragment delivery test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        bool finalFragment = true;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived, true, true, &finalFragment);
        Expect(NT_SUCCESS(status), "first wire fragment is delivered");
        Expect(opcode == WebSocketOpcode::Text, "first wire fragment reports text opcode");
        Expect(!finalFragment, "first wire fragment is non-final");
        Expect(bytesReceived == sizeof(first), "first wire fragment length matches");
        Expect(memcmp(payload, first, sizeof(first)) == 0, "first wire fragment payload matches");

        opcode = WebSocketOpcode::Text;
        bytesReceived = 0;
        finalFragment = false;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived, true, true, &finalFragment);
        Expect(NT_SUCCESS(status), "continuation wire fragment is delivered");
        Expect(opcode == WebSocketOpcode::Continuation, "continuation wire fragment reports continuation opcode");
        Expect(finalFragment, "continuation wire fragment carries final flag");
        Expect(bytesReceived == sizeof(second), "continuation wire fragment length matches");
        Expect(memcmp(payload, second, sizeof(second)) == 0, "continuation wire fragment payload matches");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveFragmentedTextRejectsUnfinishedFinalCodePoint()
    {
        FakeWebSocketServer server;
        g_server = &server;

        const unsigned char first[] = { 'x', 0xe2 };
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Text,
            first,
            sizeof(first),
            false);
        AppendServerFrame(
            server.InitialFrames,
            sizeof(server.InitialFrames),
            &server.InitialFrameLength,
            WebSocketOpcode::Continuation,
            nullptr,
            0,
            true);

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for unfinished UTF-8 receive test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        bool finalFragment = true;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived, true, true, &finalFragment);
        Expect(NT_SUCCESS(status), "first unfinished UTF-8 wire fragment is held open");

        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived, true, true, &finalFragment);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "final wire fragment rejects unfinished UTF-8 code point");
        Expect(server.LastClosePayloadLength >= 2, "unfinished UTF-8 sends close status");
        if (server.LastClosePayloadLength >= 2) {
            const unsigned int closeCode =
                (static_cast<unsigned int>(server.LastClosePayload[0]) << 8) |
                server.LastClosePayload[1];
            Expect(closeCode == 1007, "unfinished UTF-8 closes with 1007");
        }

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestReceiveRejectsMalformedCloseFrames()
    {
        const unsigned char oneByteClose[] = { 0x03 };
        const unsigned char invalidCodeClose[] = { 0x03, 0xe7 };
        const unsigned char invalidReasonClose[] = { 0x03, 0xe8, 0xc3, 0x28 };
        const unsigned char* payloads[] = {
            oneByteClose,
            invalidCodeClose,
            invalidReasonClose
        };
        const size_t payloadLengths[] = {
            sizeof(oneByteClose),
            sizeof(invalidCodeClose),
            sizeof(invalidReasonClose)
        };
        const char* messages[] = {
            "websocket receive rejects 1-byte close payload",
            "websocket receive rejects invalid close status code",
            "websocket receive rejects invalid close reason UTF-8"
        };

        for (size_t index = 0; index < sizeof(payloads) / sizeof(payloads[0]); ++index) {
            FakeWebSocketServer server;
            g_server = &server;
            AppendServerFrame(
                server.InitialFrames,
                sizeof(server.InitialFrames),
                &server.InitialFrameLength,
                WebSocketOpcode::Close,
                payloads[index],
                payloadLengths[index]);

            wknet::net::WskClient wskClient;
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
            Expect(NT_SUCCESS(status), "websocket connect for malformed close test succeeds");

            WebSocketOpcode opcode = WebSocketOpcode::Continuation;
            size_t bytesReceived = 0;
            status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, messages[index]);
            Expect(server.CloseCount == 1, "malformed close sends one protocol-error close");
            Expect(server.TransportCloseCount == 1, "malformed close closes transport exactly once");
            Expect(!server.Connected, "malformed close terminates the transport");

            const NTSTATUS closeStatus = client.Close(buffers);
            UNREFERENCED_PARAMETER(closeStatus);
            Expect(server.TransportCloseCount == 1, "Close after malformed close does not close transport twice");
            g_server = nullptr;
        }
    }

    void TestReceiveTimeoutTerminatesTransport()
    {
        FakeWebSocketServer server;
        server.ReceiveStatus = STATUS_IO_TIMEOUT;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for receive timeout test succeeds");

        WebSocketOpcode opcode = WebSocketOpcode::Continuation;
        size_t bytesReceived = 0;
        status = client.ReceiveMessage(buffers, &opcode, payload, sizeof(payload), &bytesReceived);
        Expect(status == STATUS_IO_TIMEOUT, "websocket receive timeout is returned");
        Expect(server.TransportCloseCount == 1, "websocket receive timeout closes transport");
        Expect(!server.Connected, "websocket receive timeout disconnects fake server");

        const char text[] = "after-timeout";
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "send after receive timeout is disconnected");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        Expect(server.TransportCloseCount == 1, "Close after receive timeout is idempotent");
        g_server = nullptr;
    }

    void TestSendTimeoutTerminatesTransport()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        Expect(NT_SUCCESS(status), "websocket connect for send timeout test succeeds");

        server.DataSendStatus = STATUS_IO_TIMEOUT;
        const char text[] = "send-timeout";
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(status == STATUS_IO_TIMEOUT, "websocket send timeout is returned");
        Expect(server.TransportCloseCount == 1, "websocket send timeout closes transport");
        Expect(!server.Connected, "websocket send timeout disconnects fake server");

        server.DataSendStatus = STATUS_SUCCESS;
        status = client.SendText(text, sizeof(text) - 1, buffers);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "send after send timeout is disconnected");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        Expect(server.TransportCloseCount == 1, "Close after send timeout is idempotent");
        g_server = nullptr;
    }

    void TestCloseTreatsConnectionResetAsClosed()
    {
        FakeWebSocketServer server;
        server.CloseStatus = STATUS_CONNECTION_RESET;
        g_server = &server;

        wknet::net::WskClient wskClient;
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

        wknet::net::WskClient wskClient;
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

    void ExpectHandshakePolicyStatus(
        unsigned int statusCode,
        const char* reason,
        NTSTATUS expectedStatus,
        const char* message)
    {
        FakeWebSocketServer server;
        server.HandshakeStatusCode = statusCode;
        server.HandshakeReason = reason;
        g_server = &server;

        wknet::net::WskClient wskClient;
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

        USHORT observedStatusCode = 0;
        const NTSTATUS status = client.Connect(wskClient, MakeConnectOptions(), buffers, &observedStatusCode);
        Expect(status == expectedStatus, message);
        Expect(observedStatusCode == statusCode, "websocket failed handshake exposes response status code");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestOpeningHandshakePolicyFailuresAreVisible()
    {
        ExpectHandshakePolicyStatus(
            302,
            "Found",
            STATUS_NOT_SUPPORTED,
            "websocket opening handshake rejects redirect as unsupported policy");
        ExpectHandshakePolicyStatus(
            401,
            "Unauthorized",
            STATUS_NOT_SUPPORTED,
            "websocket opening handshake rejects authentication challenge as unsupported policy");
        ExpectHandshakePolicyStatus(
            200,
            "OK",
            STATUS_INVALID_NETWORK_RESPONSE,
            "websocket opening handshake rejects non-upgrade success as invalid response");
    }

    struct ChallengeCallbackCapture
    {
        SIZE_T Calls = 0;
        USHORT LastStatusCode = 0;
        HttpHeader Header = {};
    };

    NTSTATUS AddAuthorizationOnChallenge(
        void* context,
        const WebSocketHandshakeChallenge* challenge,
        WebSocketHandshakeRetryAction* action)
    {
        auto* capture = static_cast<ChallengeCallbackCapture*>(context);
        if (capture == nullptr || challenge == nullptr || action == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->Calls;
        capture->LastStatusCode = challenge->StatusCode;
        capture->Header = {
            { "Authorization", strlen("Authorization") },
            { "Basic dGVzdA==", strlen("Basic dGVzdA==") }
        };
        action->Headers = &capture->Header;
        action->HeaderCount = 1;
        return STATUS_SUCCESS;
    }

    void TestOpeningHandshakeAuthChallengeCallbackRetries()
    {
        FakeWebSocketServer server;
        server.HandshakeStatusCode = 401;
        server.HandshakeReason = "Unauthorized";
        server.UpgradeWhenHeaderName = "Authorization";
        server.UpgradeWhenHeaderValue = "Basic dGVzdA==";
        g_server = &server;

        wknet::net::WskClient wskClient;
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

        ChallengeCallbackCapture capture = {};
        WebSocketConnectOptions options = MakeConnectOptions();
        options.ChallengeCallback = AddAuthorizationOnChallenge;
        options.ChallengeContext = &capture;

        USHORT observedStatusCode = 0;
        NTSTATUS status = client.Connect(wskClient, options, buffers, &observedStatusCode);
        Expect(NT_SUCCESS(status), "websocket auth challenge callback retries opening handshake");
        Expect(capture.Calls == 1, "websocket auth challenge callback called once");
        Expect(capture.LastStatusCode == 401, "websocket auth challenge callback receives 401");
        Expect(observedStatusCode == 101, "websocket auth challenge retry observes final 101 status");

        size_t authLength = 0;
        const char* auth = FindHeaderValue(server.LastHandshakeRequest, "Authorization", &authLength);
        Expect(auth != nullptr, "websocket retry sends Authorization header");
        Expect(
            auth != nullptr &&
            authLength == strlen("Basic dGVzdA==") &&
            memcmp(auth, "Basic dGVzdA==", authLength) == 0,
            "websocket retry Authorization header matches callback value");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    NTSTATUS FollowRedirectPathOnChallenge(
        void* context,
        const WebSocketHandshakeChallenge* challenge,
        WebSocketHandshakeRetryAction* action)
    {
        UNREFERENCED_PARAMETER(context);
        if (challenge == nullptr || action == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!challenge->Redirect || challenge->StatusCode != 302) {
            return STATUS_NOT_SUPPORTED;
        }

        action->RedirectPath = "/next";
        action->RedirectPathLength = strlen(action->RedirectPath);
        return STATUS_SUCCESS;
    }

    void TestOpeningHandshakeRedirectCallbackRetriesPath()
    {
        FakeWebSocketServer server;
        server.HandshakeStatusCode = 302;
        server.HandshakeReason = "Found";
        server.UpgradeWhenPath = "/next";
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.ChallengeCallback = FollowRedirectPathOnChallenge;

        USHORT observedStatusCode = 0;
        NTSTATUS status = client.Connect(wskClient, options, buffers, &observedStatusCode);
        Expect(NT_SUCCESS(status), "websocket redirect callback retries opening handshake");
        Expect(observedStatusCode == 101, "websocket redirect retry observes final 101 status");
        Expect(
            memcmp(server.LastHandshakeRequest, "GET /next ", strlen("GET /next ")) == 0,
            "websocket redirect retry uses callback path");

        const NTSTATUS closeStatus = client.Close(buffers);
        UNREFERENCED_PARAMETER(closeStatus);
        g_server = nullptr;
    }

    void TestTlsVersionRangeValidation()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.MinimumTlsProtocol = wknet::tls::TlsProtocol::Tls13;
        options.MaximumTlsProtocol = wknet::tls::TlsProtocol::Tls12;

        const NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket TLS rejects reversed protocol range");
        Expect(!server.Connected, "websocket TLS validation fails before socket connect");
        g_server = nullptr;
    }

    void TestTlsSha1CompatibilityPolicyValidation()
    {
        FakeWebSocketServer server;
        g_server = &server;

        wknet::net::WskClient wskClient;
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
        options.TlsServerName = "ws.postman-echo.com";
        options.TlsServerNameLength = strlen(options.TlsServerName);
        options.UseTls = true;
        options.VerifyCertificate = false;
        options.MinimumTlsProtocol = wknet::tls::TlsProtocol::Tls12;
        options.MaximumTlsProtocol = wknet::tls::TlsProtocol::Tls12;
        options.Policy.EnableTls12Sha1Signatures = true;

        NTSTATUS status = client.Connect(wskClient, options, buffers);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket rejects SHA1 signature switch on modern TLS policy");
        Expect(!server.Connected, "websocket invalid modern SHA1 policy fails before socket connect");

        options.Policy.Profile = wknet::tls::TlsSecurityProfile::CompatibilityExplicit;
        status = wknet::tls::TlsValidatePolicy(options.Policy);
        Expect(status == STATUS_SUCCESS, "websocket accepts explicit compatibility TLS policy with SHA1 signatures");
        g_server = nullptr;
    }
}

namespace wknet
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

    NTSTATUS WskSocket::Connect(WskClient&, const SOCKADDR*, const SOCKADDR*, const WskCancellationToken*) noexcept
    {
        if (g_server == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        socket_ = reinterpret_cast<PWSK_SOCKET>(g_server);
        return g_server->Connect();
    }

    NTSTATUS WskSocket::Send(WskBuffer&, SIZE_T, SIZE_T*, ULONG, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Send(
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG,
        const WskCancellationToken*) noexcept
    {
        if (g_server == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        return g_server->Send(data, length, bytesSent);
    }

    NTSTATUS WskSocket::Receive(WskBuffer&, SIZE_T, SIZE_T*, ULONG, ULONG, const WskCancellationToken*) noexcept
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WskSocket::Receive(
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG,
        ULONG,
        const WskCancellationToken*) noexcept
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
    TestTransportModeDefaults();
    TestHandshakeHostHeaderFormatting();
    TestHandshakeCustomHeaders();
    TestHandshakeBufferedFrameSurvivesSendScratchReuse();
    TestSendTextCanEmitNonFinalFrame();
    TestSendAllowsEmptyMessagesAndRejectsInvalidUtf8();
    TestContinuationCompletesFragmentedText();
    TestSendFragmentedTextUtf8AllowsSplitCodePoint();
    TestSendFragmentedTextUtf8RejectsInvalidContinuation();
    TestSendFragmentedTextUtf8RejectsUnfinishedFinalSequence();
    TestConnectRetriesResolvedAddresses();
    TestAutoPongDoesNotCorruptBufferedEcho();
    TestReceiveFragmentedTextWithInterleavedPing();
    TestReceiveFragmentedBinary();
    TestReceiveRejectsOrphanContinuation();
    TestReceiveRejectsNewDataFrameDuringFragment();
    TestConnectAcceptsMatchingSubprotocol();
    TestConnectRejectsSubprotocolMismatch();
    TestConnectRejectsUnexpectedSubprotocol();
    TestConnectRejectsUnrequestedExtensions();
    TestConnectDefaultDoesNotOfferPerMessageDeflate();
    TestConnectOffersPerMessageDeflateWhenEnabled();
    TestConnectAcceptsNegotiatedPerMessageDeflate();
    TestSendCompressedTextSetsRsv1AndDeflatesPayload();
    TestReceiveCompressedTextInflatesPayload();
    TestReceiveHonorsOutputCapacity();
    TestReceiveMessageLargerThanFrameScratch();
    TestReceiveOversizedTextFrameHeaderSendsClose1009();
    TestReceiveOversizedContinuationFrameHeaderSendsClose1009();
    TestReceivePingWithoutAutoReplyReturnsControlEvent();
    TestReceivePongWithoutAutoReplyReturnsControlEvent();
    TestAutoReplyPingUsesControlBufferWhenOutputIsSmall();
    TestSendPingAndPongControlFrames();
    TestSendLargeTextAutomaticallyFragments();
    TestCloseExSendsStatusCodeAndReason();
    TestReceiveProtocolHeaderErrorSendsClose1002AndTerminates();
    TestReceiveHeaderDecodeErrorsCloseTransport();
    TestReceiveCloseEchoesAndBlocksData();
    TestReceiveRejectsInvalidTextUtf8();
    TestReceiveDefaultAggregatesWireFragments();
    TestReceiveCanDeliverWireFragments();
    TestReceiveFragmentedTextRejectsUnfinishedFinalCodePoint();
    TestReceiveRejectsMalformedCloseFrames();
    TestReceiveTimeoutTerminatesTransport();
    TestSendTimeoutTerminatesTransport();
    TestCloseTreatsConnectionResetAsClosed();
    TestClosePropagatesNonTerminalErrors();
    TestOpeningHandshakePolicyFailuresAreVisible();
    TestOpeningHandshakeAuthChallengeCallbackRetries();
    TestOpeningHandshakeRedirectCallbackRetriesPath();
    TestTlsVersionRangeValidation();
    TestTlsSha1CompatibilityPolicyValidation();

    if (g_failed) {
        printf("WEBSOCKET CLIENT TESTS FAILED\n");
        return 1;
    }

    printf("WEBSOCKET CLIENT TESTS PASSED\n");
    return 0;
}
