#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "ws/WebSocketFrame.h"

#include <stdio.h>
#include <string.h>

using wknet::http1::HttpHeader;
using wknet::http1::HttpResponse;
using wknet::http1::MakeText;
using wknet::ws::WebSocketCodec;
using wknet::ws::WebSocketDeflateContext;
using wknet::ws::WebSocketFrameHeader;
using wknet::ws::WebSocketOpcode;
using wknet::ws::PerMessageDeflateNegotiation;
using wknet::ws::PerMessageDeflateOptions;

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
        response.MajorVersion = 1;
        response.MinorVersion = 1;
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
        response.MajorVersion = 1;
        response.MinorVersion = 1;
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
        response.MajorVersion = 1;
        response.MinorVersion = 1;
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

    void TestEncodeHttp2ClientFrameIsUnmasked()
    {
        const unsigned char payload[] = { 'h', '2' };
        unsigned char frame[8] = {};
        size_t frameLength = 0;

        const NTSTATUS status = WebSocketCodec::EncodeClientFrameForHttp2(
            WebSocketOpcode::Text,
            true,
            payload,
            sizeof(payload),
            frame,
            sizeof(frame),
            &frameLength);

        const unsigned char expected[] = { 0x81, 0x02, 'h', '2' };
        Expect(NT_SUCCESS(status), "HTTP/2 websocket client frame encodes");
        Expect(frameLength == sizeof(expected), "HTTP/2 websocket frame length excludes mask");
        Expect(BytesEqual(frame, expected, sizeof(expected)), "HTTP/2 websocket frame is unmasked");
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

    void TestRsv1RoundTripsForCompressedDataFrame()
    {
        const unsigned char payload[] = { 'z' };
        const unsigned char mask[] = { 1, 2, 3, 4 };
        unsigned char frame[32] = {};
        size_t frameLength = 0;

        NTSTATUS status = WebSocketCodec::EncodeClientFrame(
            WebSocketOpcode::Text,
            true,
            true,
            payload,
            sizeof(payload),
            mask,
            frame,
            sizeof(frame),
            &frameLength);
        Expect(NT_SUCCESS(status), "RSV1 client frame encodes");
        Expect((frame[0] & 0x40) != 0, "RSV1 bit is set on encoded frame");

        const unsigned char serverFrame[] = { 0xc1, 0x01, 'z' };
        WebSocketFrameHeader header = {};
        status = WebSocketCodec::DecodeFrameHeader(serverFrame, sizeof(serverFrame), &header);
        Expect(NT_SUCCESS(status), "RSV1 server frame header decodes");
        Expect(header.Rsv1, "RSV1 flag is reported by decoder");
    }

    void TestPerMessageDeflateNegotiation()
    {
        HttpHeader headers[] = {
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") },
            {
                MakeText("Sec-WebSocket-Extensions"),
                MakeText("permessage-deflate; server_no_context_takeover; client_max_window_bits=12; server_max_window_bits=13")
            }
        };

        HttpResponse response = {};
        response.StatusCode = 101;
        response.MajorVersion = 1;
        response.MinorVersion = 1;
        response.Headers = headers;
        response.HeaderCount = sizeof(headers) / sizeof(headers[0]);

        PerMessageDeflateOptions options = {};
        options.Enable = true;
        options.ClientMaxWindowBits = 15;
        options.ServerMaxWindowBits = 15;
        PerMessageDeflateNegotiation negotiated = {};
        const NTSTATUS status = WebSocketCodec::ValidateServerHandshake(
            response,
            "dGhlIHNhbXBsZSBub25jZQ==",
            strlen("dGhlIHNhbXBsZSBub25jZQ=="),
            nullptr,
            0,
            nullptr,
            &options,
            &negotiated);
        Expect(NT_SUCCESS(status), "permessage-deflate extension is accepted when requested");
        Expect(negotiated.Enabled, "permessage-deflate negotiation is enabled");
        Expect(negotiated.ServerNoContextTakeover, "server no-context-takeover is recorded");
        Expect(negotiated.ClientMaxWindowBits == 12, "client max window bits is negotiated");
        Expect(negotiated.ServerMaxWindowBits == 13, "server max window bits is negotiated");
    }

    void TestPerMessageDeflateRejectsIllegalResponse()
    {
        HttpHeader headers[] = {
            { MakeText("Connection"), MakeText("Upgrade") },
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Sec-WebSocket-Accept"), MakeText("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") },
            { MakeText("Sec-WebSocket-Extensions"), MakeText("permessage-deflate; server_max_window_bits=7") }
        };

        HttpResponse response = {};
        response.StatusCode = 101;
        response.MajorVersion = 1;
        response.MinorVersion = 1;
        response.Headers = headers;
        response.HeaderCount = sizeof(headers) / sizeof(headers[0]);

        PerMessageDeflateOptions options = {};
        options.Enable = true;
        const NTSTATUS status = WebSocketCodec::ValidateServerHandshake(
            response,
            "dGhlIHNhbXBsZSBub25jZQ==",
            strlen("dGhlIHNhbXBsZSBub25jZQ=="),
            nullptr,
            0,
            nullptr,
            &options,
            nullptr);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "illegal permessage-deflate parameter is rejected");
    }

    void TestWebSocketDeflateStoredRoundTrip()
    {
        const unsigned char message[] = "kernel websocket permessage deflate";
        unsigned char compressed[128] = {};
        unsigned char decoded[128] = {};
        size_t compressedLength = 0;
        size_t decodedLength = 0;

        NTSTATUS status = WebSocketDeflateContext::DeflateMessage(
            message,
            sizeof(message) - 1,
            true,
            compressed,
            sizeof(compressed),
            &compressedLength);
        Expect(NT_SUCCESS(status), "stored deflate message encodes");
        Expect(compressedLength != 0, "stored deflate emits bytes");

        WebSocketDeflateContext context;
        status = context.Initialize(15);
        Expect(NT_SUCCESS(status), "deflate context initializes");
        if (NT_SUCCESS(status)) {
            status = context.InflateMessage(
                compressed,
                compressedLength,
                decoded,
                sizeof(decoded),
                &decodedLength);
        }
        Expect(NT_SUCCESS(status), "stored deflate message inflates");
        Expect(decodedLength == sizeof(message) - 1, "inflated length matches original");
        Expect(BytesEqual(decoded, message, decodedLength), "inflated bytes match original");
    }

    void TestWebSocketDeflateInflatesFixedHuffman()
    {
        const unsigned char compressed[] = {
            0x4a, 0xcb, 0xac, 0x48, 0x4d, 0x51, 0xc8, 0x28,
            0x4d, 0x4b, 0xcb, 0x4d, 0xcc, 0x53, 0x28, 0x4f,
            0x4d, 0x2a, 0xce, 0x4f, 0xce, 0x4e, 0x2d, 0x51,
            0x28, 0x48, 0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0x49,
            0xc3, 0x2f, 0x0d, 0x00
        };
        const unsigned char expected[] =
            "fixed huffman websocket payloadfixed huffman websocket payload";
        unsigned char decoded[96] = {};
        size_t decodedLength = 0;

        WebSocketDeflateContext context;
        NTSTATUS status = context.Initialize(15);
        Expect(NT_SUCCESS(status), "fixed Huffman inflate context initializes");
        if (NT_SUCCESS(status)) {
            status = context.InflateMessage(
                compressed,
                sizeof(compressed),
                decoded,
                sizeof(decoded),
                &decodedLength);
        }

        Expect(NT_SUCCESS(status), "fixed Huffman deflate payload inflates");
        Expect(decodedLength == sizeof(expected) - 1, "fixed Huffman decoded length matches");
        Expect(BytesEqual(decoded, expected, decodedLength), "fixed Huffman decoded bytes match");
    }

    void TestWebSocketDeflateInflatesDynamicHuffman()
    {
        const unsigned char compressed[] = {
            0x04, 0xc1, 0x11, 0x00, 0x80, 0x30, 0x00, 0x00,
            0xb0, 0x4b, 0x12, 0x25, 0x97, 0x28, 0x49, 0xa2,
            0x24, 0x39, 0x25, 0x49, 0x74, 0x49, 0x4e, 0x97,
            0x24, 0x4a, 0x92, 0xe8, 0x92, 0x44, 0x97, 0x24,
            0xba, 0x5c, 0xa2, 0xcb, 0x25, 0x4a, 0x92, 0x28,
            0xb9, 0x44, 0x49, 0x72, 0x4a, 0x92, 0x53, 0x1b,
            0x88, 0xcb, 0x76, 0x5a, 0x6f, 0x2f, 0xc1, 0xdd,
            0xbc, 0x3d, 0x7e, 0x5a, 0xf5, 0x62, 0xb7, 0x41,
            0x46, 0x98, 0x3c, 0x5e, 0x88, 0xe8, 0xb0, 0x9c,
            0x5f, 0x98, 0xd7, 0xa3, 0x32, 0x2e, 0x2a, 0x1a,
            0xae, 0x2f, 0x10, 0x97, 0xed, 0xb4, 0xde, 0x5e,
            0x82, 0xbb, 0x79, 0x7b, 0xfc, 0xb4, 0xea, 0xc5,
            0x6e, 0x83, 0x8c, 0x30, 0x79, 0xbc, 0x10, 0xd1,
            0x61, 0x39, 0xbf, 0x30, 0xaf, 0x47, 0x65, 0x5c,
            0x54, 0x34, 0x5c, 0x5f, 0x20, 0x2e, 0xdb, 0x69,
            0xbd, 0xbd, 0x04, 0x77, 0xf3, 0xf6, 0xf8, 0x69,
            0xd5, 0x8b, 0xdd, 0x06, 0x19, 0x61, 0xf2, 0x78,
            0x21, 0xa2, 0xc3, 0x72, 0x7e, 0x61, 0x5e, 0x8f,
            0xca, 0xb8, 0xa8, 0x68, 0xb8, 0xbe, 0x40, 0x5c,
            0xb6, 0xd3, 0x7a, 0x7b, 0x09, 0xee, 0xe6, 0xed,
            0xf1, 0xd3, 0xaa, 0x17, 0xbb, 0x0d, 0x32, 0xc2,
            0xe4, 0xf1, 0x42, 0x44, 0x87, 0xe5, 0xfc, 0xc2,
            0xbc, 0x1e, 0x95, 0x71, 0x51, 0xd1, 0x70, 0x7d,
            0xfd, 0x00
        };
        unsigned char expected[192] = {};
        unsigned char decoded[192] = {};
        for (size_t index = 0; index < sizeof(expected); ++index) {
            expected[index] = static_cast<unsigned char>((index * 37 + index / 3) & 0xff);
        }

        WebSocketDeflateContext context;
        NTSTATUS status = context.Initialize(15);
        Expect(NT_SUCCESS(status), "dynamic Huffman inflate context initializes");
        size_t decodedLength = 0;
        if (NT_SUCCESS(status)) {
            status = context.InflateMessage(
                compressed,
                sizeof(compressed),
                decoded,
                sizeof(decoded),
                &decodedLength);
        }

        Expect(NT_SUCCESS(status), "dynamic Huffman deflate payload inflates");
        Expect(decodedLength == sizeof(expected), "dynamic Huffman decoded length matches");
        Expect(BytesEqual(decoded, expected, decodedLength), "dynamic Huffman decoded bytes match");
    }

    void TestWebSocketDeflateReportsOutputCapacity()
    {
        const unsigned char message[] = "capacity";
        unsigned char compressed[32] = {};
        size_t compressedLength = 0;
        NTSTATUS status = WebSocketDeflateContext::DeflateMessage(
            message,
            sizeof(message) - 1,
            true,
            compressed,
            sizeof(compressed),
            &compressedLength);
        Expect(NT_SUCCESS(status), "capacity test payload deflates");

        WebSocketDeflateContext context;
        status = context.Initialize(15);
        Expect(NT_SUCCESS(status), "capacity inflate context initializes");
        unsigned char decoded[4] = {};
        size_t decodedLength = 0;
        if (NT_SUCCESS(status)) {
            status = context.InflateMessage(
                compressed,
                compressedLength,
                decoded,
                sizeof(decoded),
                &decodedLength);
        }

        Expect(status == STATUS_BUFFER_TOO_SMALL, "inflate reports output capacity exhaustion");
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
    TestEncodeHttp2ClientFrameIsUnmasked();
    TestEncodeClientFrameLengthBoundaries();
    TestDecodeServerTextFrame();
    TestDecodeExtendedPayloadLength();
    TestControlFrameRejectsFragmented();
    TestDecodeRejectsMaskedServerFrame();
    TestEncodeCloseRejectsOversizedControlPayload();
    TestRsv1RoundTripsForCompressedDataFrame();
    TestPerMessageDeflateNegotiation();
    TestPerMessageDeflateRejectsIllegalResponse();
    TestWebSocketDeflateStoredRoundTrip();
    TestWebSocketDeflateInflatesFixedHuffman();
    TestWebSocketDeflateInflatesDynamicHuffman();
    TestWebSocketDeflateReportsOutputCapacity();

    if (g_failed) {
        printf("WEBSOCKET FRAME TESTS FAILED\n");
        return 1;
    }

    printf("WEBSOCKET FRAME TESTS PASSED\n");
    return 0;
}
