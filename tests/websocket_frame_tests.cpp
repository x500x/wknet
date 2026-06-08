#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/websocket/WebSocketFrame.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::http::HttpHeader;
using KernelHttp::http::HttpResponse;
using KernelHttp::http::MakeText;
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

    bool BytesEqual(const unsigned char* left, const unsigned char* right, size_t length)
    {
        for (size_t index = 0; index < length; ++index) {
            if (left[index] != right[index]) {
                return false;
            }
        }
        return true;
    }

    void TestComputeAcceptValueRfcExample()
    {
        const char clientKey[] = "dGhlIHNhbXBsZSBub25jZQ==";
        char accept[64] = {};
        size_t acceptLength = 0;

        const NTSTATUS status = WebSocketCodec::ComputeAcceptValue(
            clientKey,
            strlen(clientKey),
            accept,
            sizeof(accept),
            &acceptLength);

        const char expected[] = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        Expect(NT_SUCCESS(status), "Sec-WebSocket-Accept computes successfully");
        Expect(acceptLength == strlen(expected), "accept length matches RFC example");
        Expect(memcmp(accept, expected, strlen(expected)) == 0, "accept value matches RFC example");
    }

    void TestValidateHandshake()
    {
        const char clientKey[] = "dGhlIHNhbXBsZSBub25jZQ==";
        HttpHeader headers[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("keep-alive, Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") }
        };

        HttpResponse response = {};
        response.StatusCode = 101;
        response.Headers = headers;
        response.HeaderCount = sizeof(headers) / sizeof(headers[0]);

        const NTSTATUS status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey));
        Expect(NT_SUCCESS(status), "valid server handshake is accepted");
    }

    void TestValidateHandshakeRejectsBadAccept()
    {
        const char clientKey[] = "dGhlIHNhbXBsZSBub25jZQ==";
        HttpHeader headers[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("wrong") }
        };

        HttpResponse response = {};
        response.StatusCode = 101;
        response.Headers = headers;
        response.HeaderCount = sizeof(headers) / sizeof(headers[0]);

        const NTSTATUS status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "bad accept value is rejected");
    }

    void TestValidateHandshakeRejectsDuplicateAccept()
    {
        const char clientKey[] = "dGhlIHNhbXBsZSBub25jZQ==";
        HttpHeader headers[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") }
        };

        HttpResponse response = {};
        response.MajorVersion = 1;
        response.MinorVersion = 1;
        response.StatusCode = 101;
        response.Headers = headers;
        response.HeaderCount = sizeof(headers) / sizeof(headers[0]);

        const NTSTATUS status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "duplicate Sec-WebSocket-Accept is rejected");
    }

    void TestValidateHandshakeRejectsHttp10()
    {
        const char clientKey[] = "dGhlIHNhbXBsZSBub25jZQ==";
        HttpHeader headers[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") }
        };

        HttpResponse response = {};
        response.MajorVersion = 1;
        response.MinorVersion = 0;
        response.StatusCode = 101;
        response.Headers = headers;
        response.HeaderCount = sizeof(headers) / sizeof(headers[0]);

        const NTSTATUS status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/1.0 WebSocket upgrade is rejected");
    }

    void TestValidateHandshakeSubprotocolRules()
    {
        const char clientKey[] = "dGhlIHNhbXBsZSBub25jZQ==";
        HttpHeader matchingHeaders[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") },
            { MakeText("Sec-WebSocket-Protocol"), MakeText("chat") }
        };
        HttpResponse response = {};
        response.StatusCode = 101;
        response.Headers = matchingHeaders;
        response.HeaderCount = sizeof(matchingHeaders) / sizeof(matchingHeaders[0]);

        NTSTATUS status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey),
            "chat, superchat",
            strlen("chat, superchat"));
        Expect(NT_SUCCESS(status), "selected subprotocol from request list is accepted");

        status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey),
            "other",
            strlen("other"));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "unrequested selected subprotocol is rejected");

        status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "unexpected selected subprotocol is rejected");

        HttpHeader emptySelected[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") },
            { MakeText("Sec-WebSocket-Protocol"), { "", 0 } }
        };
        response.Headers = emptySelected;
        response.HeaderCount = sizeof(emptySelected) / sizeof(emptySelected[0]);
        status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey),
            "chat",
            strlen("chat"));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "empty selected subprotocol is rejected");

        HttpHeader duplicateSelected[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") },
            { MakeText("Sec-WebSocket-Protocol"), MakeText("chat") },
            { MakeText("Sec-WebSocket-Protocol"), MakeText("chat") }
        };
        response.Headers = duplicateSelected;
        response.HeaderCount = sizeof(duplicateSelected) / sizeof(duplicateSelected[0]);
        status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey),
            "chat",
            strlen("chat"));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "duplicate selected subprotocol header is rejected");

        HttpHeader listSelected[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") },
            { MakeText("Sec-WebSocket-Protocol"), MakeText("chat, superchat") }
        };
        response.Headers = listSelected;
        response.HeaderCount = sizeof(listSelected) / sizeof(listSelected[0]);
        status = WebSocketCodec::ValidateServerHandshake(
            response,
            clientKey,
            strlen(clientKey),
            "chat, superchat",
            strlen("chat, superchat"));
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "list-valued selected subprotocol is rejected");
    }

    void TestEncodeClientTextFrame()
    {
        const unsigned char payload[] = { 'H', 'e', 'l', 'l', 'o' };
        const unsigned char mask[] = { 0x37, 0xFA, 0x21, 0x3D };
        unsigned char frame[32] = {};
        size_t frameLength = 0;

        const NTSTATUS status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Text,
            true,
            payload,
            sizeof(payload),
            mask,
            frame,
            sizeof(frame),
            &frameLength);

        const unsigned char expected[] = {
            0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D,
            0x7F, 0x9F, 0x4D, 0x51, 0x58
        };
        Expect(NT_SUCCESS(status), "client text frame encodes");
        Expect(frameLength == sizeof(expected), "client text frame length matches");
        Expect(BytesEqual(frame, expected, sizeof(expected)), "client text frame bytes match RFC sample");
    }

    void TestEncodeHighLevelEchoTextFrame()
    {
        const unsigned char payload[] = "kernel-http high-level websocket echo";
        const unsigned char mask[] = { 0x37, 0xFA, 0x21, 0x3D };
        unsigned char frame[64] = {};
        size_t frameLength = 0;

        const NTSTATUS status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Text,
            true,
            payload,
            sizeof(payload) - 1,
            mask,
            frame,
            sizeof(frame),
            &frameLength);

        const unsigned char expected[] = {
            0x81, 0xA5, 0x37, 0xFA, 0x21, 0x3D,
            0x5C, 0x9F, 0x53, 0x53, 0x52, 0x96,
            0x0C, 0x55, 0x43, 0x8E, 0x51, 0x1D,
            0x5F, 0x93, 0x46, 0x55, 0x1A, 0x96,
            0x44, 0x4B, 0x52, 0x96, 0x01, 0x4A,
            0x52, 0x98, 0x52, 0x52, 0x54, 0x91,
            0x44, 0x49, 0x17, 0x9F, 0x42, 0x55,
            0x58
        };

        Expect(NT_SUCCESS(status), "high-level sample text frame encodes");
        Expect(frameLength == sizeof(expected), "high-level sample text frame length matches");
        Expect(BytesEqual(frame, expected, sizeof(expected)), "high-level sample text frame bytes match");
    }

    void TestEncodeClientFrameLengthBoundaries()
    {
        const unsigned char mask[] = { 0x37, 0xFA, 0x21, 0x3D };
        const unsigned char payload[1] = { 0 };
        unsigned char frame[8] = {};
        size_t frameLength = 0;

        NTSTATUS status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Binary,
            true,
            payload,
            125,
            mask,
            frame,
            0,
            &frameLength);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "payload length 125 reports required size");
        Expect(frameLength == 131, "payload length 125 required size includes base header and mask");

        status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Binary,
            true,
            payload,
            126,
            mask,
            frame,
            0,
            &frameLength);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "payload length 126 reports required size");
        Expect(frameLength == 134, "payload length 126 required size includes 16-bit length");

        status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Binary,
            true,
            payload,
            65535,
            mask,
            frame,
            0,
            &frameLength);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "payload length 65535 reports required size");
        Expect(frameLength == 65543, "payload length 65535 required size includes 16-bit length");

        status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Binary,
            true,
            payload,
            65536,
            mask,
            frame,
            0,
            &frameLength);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "payload length 65536 reports required size");
        Expect(frameLength == 65550, "payload length 65536 required size includes 64-bit length");

#if defined(_WIN64) || defined(__x86_64__) || defined(_M_X64)
        status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Binary,
            true,
            payload,
            static_cast<size_t>(0x7fffffffffffffffULL),
            mask,
            frame,
            0,
            &frameLength);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "maximum legal 63-bit length reports required size");

        status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Binary,
            true,
            payload,
            static_cast<size_t>(0x8000000000000000ULL),
            mask,
            frame,
            sizeof(frame),
            &frameLength);
        Expect(status == STATUS_INVALID_PARAMETER, "payload length with high bit set is rejected");
#endif
    }

    void TestDecodeServerTextFrame()
    {
        const unsigned char frame[] = {
            0x81, 0x05, 'H', 'e', 'l', 'l', 'o'
        };

        WebSocketFrameHeader header = {};
        NTSTATUS status = WebSocketCodec::DecodeFrameHeader(frame, sizeof(frame), &header);
        Expect(NT_SUCCESS(status), "server text frame header decodes");
        Expect(header.Fin, "server text frame fin is set");
        Expect(!header.Masked, "server text frame is unmasked");
        Expect(header.Opcode == WebSocketOpcode::Text, "server text opcode is parsed");
        Expect(header.PayloadLength == 5, "server text payload length is parsed");

        unsigned char payload[8] = {};
        size_t payloadLength = 0;
        status = WebSocketCodec::DecodeFramePayload(
            header,
            frame,
            sizeof(frame),
            payload,
            sizeof(payload),
            &payloadLength);
        Expect(NT_SUCCESS(status), "server text payload decodes");
        Expect(payloadLength == 5, "server text payload length matches");
        Expect(memcmp(payload, "Hello", 5) == 0, "server text payload bytes match");
    }

    void TestDecodeExtendedPayloadLength()
    {
        unsigned char frame[132] = {};
        frame[0] = 0x82;
        frame[1] = 126;
        frame[2] = 0;
        frame[3] = 126;
        for (size_t index = 0; index < 126; ++index) {
            frame[4 + index] = static_cast<unsigned char>(index);
        }

        WebSocketFrameHeader header = {};
        NTSTATUS status = WebSocketCodec::DecodeFrameHeader(frame, sizeof(frame), &header);
        Expect(NT_SUCCESS(status), "extended payload frame header decodes");
        Expect(header.PayloadLength == 126, "extended payload length is decoded");
        Expect(header.HeaderLength == 4, "extended payload header length is decoded");
    }

    void TestControlFrameRejectsFragmented()
    {
        const unsigned char frame[] = {
            0x09, 0x00
        };

        WebSocketFrameHeader header = {};
        const NTSTATUS status = WebSocketCodec::DecodeFrameHeader(frame, sizeof(frame), &header);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "fragmented control frame is rejected");
    }

    void TestDecodeRejectsMaskedServerFrame()
    {
        const unsigned char frame[] = {
            0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D,
            0x7F, 0x9F, 0x4D, 0x51, 0x58
        };

        WebSocketFrameHeader header = {};
        const NTSTATUS status = WebSocketCodec::DecodeFrameHeader(frame, sizeof(frame), &header);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "masked server frame is rejected");
    }

    void TestEncodeCloseRejectsOversizedControlPayload()
    {
        unsigned char payload[126] = {};
        unsigned char mask[4] = {};
        unsigned char frame[256] = {};
        size_t frameLength = 0;

        const NTSTATUS status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Close,
            true,
            payload,
            sizeof(payload),
            mask,
            frame,
            sizeof(frame),
            &frameLength);
        Expect(status == STATUS_INVALID_PARAMETER, "oversized close frame is rejected");
    }
}

int main()
{
    TestComputeAcceptValueRfcExample();
    TestValidateHandshake();
    TestValidateHandshakeRejectsBadAccept();
    TestValidateHandshakeRejectsDuplicateAccept();
    TestValidateHandshakeRejectsHttp10();
    TestValidateHandshakeSubprotocolRules();
    TestEncodeClientTextFrame();
    TestEncodeHighLevelEchoTextFrame();
    TestEncodeClientFrameLengthBoundaries();
    TestDecodeServerTextFrame();
    TestDecodeExtendedPayloadLength();
    TestControlFrameRejectsFragmented();
    TestDecodeRejectsMaskedServerFrame();
    TestEncodeCloseRejectsOversizedControlPayload();

    if (g_failed) {
        printf("WEBSOCKET FRAME TESTS FAILED\n");
        return 1;
    }

    printf("WEBSOCKET FRAME TESTS PASSED\n");
    return 0;
}
