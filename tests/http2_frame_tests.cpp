#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/http2/Http2Frame.h"
#include "../src/KernelHttp/http2/Http2Stream.h"

#include <stdio.h>
#include <string.h>

using KernelHttp::http2::Http2FrameCodec;
using KernelHttp::http2::Http2FrameHeader;
using KernelHttp::http2::Http2FrameHeaderLength;
using KernelHttp::http2::Http2FrameType;
using KernelHttp::http2::Http2Settings;
using KernelHttp::http2::Http2SettingId;
using KernelHttp::http2::Http2ErrorCode;
using KernelHttp::http2::Http2DefaultMaxFrameSize;
using KernelHttp::http2::Http2MaxAllowedFrameSize;
using KernelHttp::http2::Http2InitialWindowSize;
using KernelHttp::http2::Http2Stream;
using KernelHttp::http2::Http2StreamState;
namespace Http2FrameFlags = KernelHttp::http2::Http2FrameFlags;

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

    bool BytesEqual(const unsigned char* a, size_t aLen, const unsigned char* b, size_t bLen)
    {
        if (aLen != bLen) return false;
        for (size_t i = 0; i < aLen; ++i) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    // ========================================================================
    // Frame header encode/decode round-trip
    // ========================================================================

    void TestFrameHeaderRoundTrip()
    {
        Http2FrameHeader input = {};
        input.Length = 16384;
        input.Type = Http2FrameType::Data;
        input.Flags = Http2FrameFlags::EndStream;
        input.StreamId = 1;

        unsigned char buf[9] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeFrameHeader(input, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeFrameHeader should succeed");
        Expect(written == 9, "EncodeFrameHeader writes 9 bytes");

        Http2FrameHeader output = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, written, &output);
        Expect(NT_SUCCESS(s), "DecodeFrameHeader should succeed");
        Expect(output.Length == 16384, "Decoded length == 16384");
        Expect(output.Type == Http2FrameType::Data, "Decoded type == Data");
        Expect(output.Flags == Http2FrameFlags::EndStream, "Decoded flags == EndStream");
        Expect(output.StreamId == 1, "Decoded streamId == 1");
    }

    void TestFrameHeaderMaxValues()
    {
        Http2FrameHeader input = {};
        input.Length = Http2MaxAllowedFrameSize;
        input.Type = Http2FrameType::Continuation;
        input.Flags = 0xFF;
        input.StreamId = 0x7FFFFFFF;

        unsigned char buf[9] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeFrameHeader(input, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeFrameHeader max values should succeed");

        Http2FrameHeader output = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, written, &output);
        Expect(NT_SUCCESS(s), "DecodeFrameHeader max values should succeed");
        Expect(output.Length == Http2MaxAllowedFrameSize, "Max length preserved");
        Expect(output.StreamId == 0x7FFFFFFF, "Max streamId preserved");
        Expect(output.Flags == 0xFF, "Max flags preserved");
    }

    void TestFrameHeaderZeroPayload()
    {
        Http2FrameHeader input = {};
        input.Length = 0;
        input.Type = Http2FrameType::Settings;
        input.Flags = Http2FrameFlags::Ack;
        input.StreamId = 0;

        unsigned char buf[9] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeFrameHeader(input, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeFrameHeader zero payload");

        Http2FrameHeader output = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, written, &output);
        Expect(NT_SUCCESS(s), "DecodeFrameHeader zero payload");
        Expect(output.Length == 0, "Zero length");
        Expect(output.Type == Http2FrameType::Settings, "Type == Settings");
        Expect(output.Flags == Http2FrameFlags::Ack, "Flags == Ack");
        Expect(output.StreamId == 0, "StreamId == 0");
    }

    void TestDecodeFrameHeaderTooShort()
    {
        unsigned char buf[5] = {};
        Http2FrameHeader output = {};
        NTSTATUS s = Http2FrameCodec::DecodeFrameHeader(buf, sizeof(buf), &output);
        Expect(s == STATUS_MORE_PROCESSING_REQUIRED, "DecodeFrameHeader too short returns MORE_PROCESSING_REQUIRED");
    }

    // ========================================================================
    // SETTINGS frame
    // ========================================================================

    void TestEncodeSettings()
    {
        Http2Settings settings = {};
        settings.HeaderTableSize = 4096;
        settings.EnablePush = 0;
        settings.MaxConcurrentStreams = 100;
        settings.InitialWindowSize = 65535;
        settings.MaxFrameSize = 16384;
        settings.MaxHeaderListSize = 65536;

        unsigned char buf[256] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeSettings(settings, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeSettings should succeed");
        // 9 header + 6 settings * 6 bytes = 9 + 36 = 45
        Expect(written == 45, "EncodeSettings writes 45 bytes");

        // Decode the frame header
        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode SETTINGS header");
        Expect(hdr.Type == Http2FrameType::Settings, "SETTINGS type");
        Expect(hdr.Length == 36, "SETTINGS payload length == 36");
        Expect(hdr.Flags == 0, "SETTINGS flags == 0");
        Expect(hdr.StreamId == 0, "SETTINGS streamId == 0");

        // Decode the payload
        Http2Settings decoded = {};
        s = Http2FrameCodec::DecodeSettingsPayload(buf + 9, 36, &decoded);
        Expect(NT_SUCCESS(s), "DecodeSettingsPayload should succeed");
        Expect(decoded.HeaderTableSize == 4096, "Decoded HeaderTableSize");
        Expect(decoded.EnablePush == 0, "Decoded EnablePush");
        Expect(decoded.MaxConcurrentStreams == 100, "Decoded MaxConcurrentStreams");
        Expect(decoded.InitialWindowSize == 65535, "Decoded InitialWindowSize");
        Expect(decoded.MaxFrameSize == 16384, "Decoded MaxFrameSize");
        Expect(decoded.MaxHeaderListSize == 65536, "Decoded MaxHeaderListSize");
    }

    void TestEncodeSettingsAck()
    {
        unsigned char buf[16] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeSettingsAck(buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeSettingsAck should succeed");
        Expect(written == 9, "EncodeSettingsAck writes 9 bytes");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode SETTINGS ACK header");
        Expect(hdr.Type == Http2FrameType::Settings, "SETTINGS ACK type");
        Expect(hdr.Length == 0, "SETTINGS ACK payload == 0");
        Expect(hdr.Flags == Http2FrameFlags::Ack, "SETTINGS ACK flag");
        Expect(hdr.StreamId == 0, "SETTINGS ACK streamId == 0");
    }

    void TestDecodeSettingsInvalidPayloadLength()
    {
        // Payload length not multiple of 6
        unsigned char payload[7] = {};
        Http2Settings settings = {};
        NTSTATUS s = Http2FrameCodec::DecodeSettingsPayload(payload, sizeof(payload), &settings);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "DecodeSettings invalid length");
    }

    void TestDecodeSettingsInvalidWindowSize()
    {
        // INITIAL_WINDOW_SIZE > 2^31-1
        unsigned char payload[6] = {};
        // Setting ID = 0x0004 (InitialWindowSize)
        payload[0] = 0x00; payload[1] = 0x04;
        // Value = 0x80000000 (exceeds max)
        payload[2] = 0x80; payload[3] = 0x00; payload[4] = 0x00; payload[5] = 0x00;

        Http2Settings settings = {};
        NTSTATUS s = Http2FrameCodec::DecodeSettingsPayload(payload, sizeof(payload), &settings);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "DecodeSettings invalid window size");
    }

    void TestDecodeSettingsUnknownIgnored()
    {
        // Unknown setting ID should be ignored
        unsigned char payload[6] = {};
        payload[0] = 0x00; payload[1] = 0xFF; // Unknown ID 0x00FF
        payload[2] = 0x00; payload[3] = 0x00; payload[4] = 0x00; payload[5] = 0x01;

        Http2Settings settings = {};
        settings.HeaderTableSize = 4096;
        NTSTATUS s = Http2FrameCodec::DecodeSettingsPayload(payload, sizeof(payload), &settings);
        Expect(NT_SUCCESS(s), "DecodeSettings unknown ID ignored");
        Expect(settings.HeaderTableSize == 4096, "Existing settings unchanged");
    }

    // ========================================================================
    // WINDOW_UPDATE frame
    // ========================================================================

    void TestEncodeDecodeWindowUpdate()
    {
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeWindowUpdate(3, 32768, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeWindowUpdate should succeed");
        Expect(written == 13, "EncodeWindowUpdate writes 13 bytes");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode WINDOW_UPDATE header");
        Expect(hdr.Type == Http2FrameType::WindowUpdate, "WINDOW_UPDATE type");
        Expect(hdr.Length == 4, "WINDOW_UPDATE payload == 4");
        Expect(hdr.StreamId == 3, "WINDOW_UPDATE streamId == 3");

        ULONG increment = 0;
        s = Http2FrameCodec::DecodeWindowUpdatePayload(buf + 9, 4, &increment);
        Expect(NT_SUCCESS(s), "DecodeWindowUpdatePayload should succeed");
        Expect(increment == 32768, "WINDOW_UPDATE increment == 32768");
    }

    void TestWindowUpdateZeroIncrement()
    {
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeWindowUpdate(1, 0, buf, sizeof(buf), &written);
        Expect(s == STATUS_INVALID_PARAMETER, "EncodeWindowUpdate zero increment fails");
    }

    void TestDecodeWindowUpdateZero()
    {
        // Payload with increment = 0
        unsigned char payload[4] = { 0x00, 0x00, 0x00, 0x00 };
        ULONG increment = 0;
        NTSTATUS s = Http2FrameCodec::DecodeWindowUpdatePayload(payload, 4, &increment);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "DecodeWindowUpdate zero increment fails");
    }

    // ========================================================================
    // PING frame
    // ========================================================================

    void TestEncodeDecodePing()
    {
        unsigned char opaqueData[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodePing(opaqueData, false, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodePing should succeed");
        Expect(written == 17, "EncodePing writes 17 bytes");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode PING header");
        Expect(hdr.Type == Http2FrameType::Ping, "PING type");
        Expect(hdr.Length == 8, "PING payload == 8");
        Expect(hdr.Flags == 0, "PING flags == 0");
        Expect(hdr.StreamId == 0, "PING streamId == 0");
        Expect(BytesEqual(buf + 9, 8, opaqueData, 8), "PING opaque data preserved");
    }

    void TestEncodePingAck()
    {
        unsigned char opaqueData[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodePing(opaqueData, true, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodePing ACK should succeed");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode PING ACK header");
        Expect(hdr.Flags == Http2FrameFlags::Ack, "PING ACK flag set");
        Expect(BytesEqual(buf + 9, 8, opaqueData, 8), "PING ACK opaque data preserved");
    }

    // ========================================================================
    // GOAWAY frame
    // ========================================================================

    void TestEncodeDecodeGoAway()
    {
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeGoAway(7, static_cast<ULONG>(Http2ErrorCode::NoError),
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeGoAway should succeed");
        Expect(written == 17, "EncodeGoAway writes 17 bytes");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode GOAWAY header");
        Expect(hdr.Type == Http2FrameType::GoAway, "GOAWAY type");
        Expect(hdr.Length == 8, "GOAWAY payload == 8");
        Expect(hdr.StreamId == 0, "GOAWAY streamId == 0");

        ULONG lastStreamId = 0;
        ULONG errorCode = 0;
        s = Http2FrameCodec::DecodeGoAwayPayload(buf + 9, 8, &lastStreamId, &errorCode);
        Expect(NT_SUCCESS(s), "DecodeGoAwayPayload should succeed");
        Expect(lastStreamId == 7, "GOAWAY lastStreamId == 7");
        Expect(errorCode == 0, "GOAWAY errorCode == NoError");
    }

    void TestGoAwayWithError()
    {
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeGoAway(
            0x7FFFFFFF, static_cast<ULONG>(Http2ErrorCode::ProtocolError),
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeGoAway with error");

        ULONG lastStreamId = 0;
        ULONG errorCode = 0;
        s = Http2FrameCodec::DecodeGoAwayPayload(buf + 9, 8, &lastStreamId, &errorCode);
        Expect(NT_SUCCESS(s), "DecodeGoAway with error");
        Expect(lastStreamId == 0x7FFFFFFF, "GOAWAY max lastStreamId");
        Expect(errorCode == static_cast<ULONG>(Http2ErrorCode::ProtocolError), "GOAWAY ProtocolError");
    }

    // ========================================================================
    // RST_STREAM frame
    // ========================================================================

    void TestEncodeDecodeRstStream()
    {
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeRstStream(5, static_cast<ULONG>(Http2ErrorCode::Cancel),
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeRstStream should succeed");
        Expect(written == 13, "EncodeRstStream writes 13 bytes");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode RST_STREAM header");
        Expect(hdr.Type == Http2FrameType::RstStream, "RST_STREAM type");
        Expect(hdr.Length == 4, "RST_STREAM payload == 4");
        Expect(hdr.StreamId == 5, "RST_STREAM streamId == 5");

        ULONG errorCode = 0;
        s = Http2FrameCodec::DecodeRstStreamPayload(buf + 9, 4, &errorCode);
        Expect(NT_SUCCESS(s), "DecodeRstStreamPayload should succeed");
        Expect(errorCode == static_cast<ULONG>(Http2ErrorCode::Cancel), "RST_STREAM Cancel");
    }

    void TestRstStreamZeroStreamId()
    {
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeRstStream(0, 0, buf, sizeof(buf), &written);
        Expect(s == STATUS_INVALID_PARAMETER, "EncodeRstStream streamId=0 fails");
    }

    // ========================================================================
    // HEADERS frame
    // ========================================================================

    void TestEncodeHeaders()
    {
        const unsigned char headerBlock[] = { 0x82, 0x86, 0x84, 0x41, 0x0f };
        unsigned char buf[64] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeHeaders(
            1, headerBlock, sizeof(headerBlock), true, true,
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeHeaders should succeed");
        Expect(written == 9 + sizeof(headerBlock), "EncodeHeaders total length");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode HEADERS header");
        Expect(hdr.Type == Http2FrameType::Headers, "HEADERS type");
        Expect(hdr.Length == sizeof(headerBlock), "HEADERS payload length");
        Expect(hdr.StreamId == 1, "HEADERS streamId == 1");
        Expect((hdr.Flags & Http2FrameFlags::EndStream) != 0, "HEADERS EndStream set");
        Expect((hdr.Flags & Http2FrameFlags::EndHeaders) != 0, "HEADERS EndHeaders set");
        Expect(BytesEqual(buf + 9, sizeof(headerBlock), headerBlock, sizeof(headerBlock)),
            "HEADERS payload matches");
    }

    void TestEncodeHeadersNoEndStream()
    {
        const unsigned char headerBlock[] = { 0x82 };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeHeaders(
            3, headerBlock, sizeof(headerBlock), false, true,
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeHeaders no EndStream");

        Http2FrameHeader hdr = {};
        Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect((hdr.Flags & Http2FrameFlags::EndStream) == 0, "EndStream not set");
        Expect((hdr.Flags & Http2FrameFlags::EndHeaders) != 0, "EndHeaders set");
    }

    void TestEncodeHeadersStreamIdZero()
    {
        const unsigned char headerBlock[] = { 0x82 };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeHeaders(
            0, headerBlock, sizeof(headerBlock), true, true,
            buf, sizeof(buf), &written);
        Expect(s == STATUS_INVALID_PARAMETER, "EncodeHeaders streamId=0 fails");
    }

    // ========================================================================
    // CONTINUATION frame
    // ========================================================================

    void TestEncodeContinuation()
    {
        const unsigned char block[] = { 0x01, 0x02, 0x03 };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeContinuation(
            1, block, sizeof(block), true,
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeContinuation should succeed");
        Expect(written == 9 + sizeof(block), "EncodeContinuation total length");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode CONTINUATION header");
        Expect(hdr.Type == Http2FrameType::Continuation, "CONTINUATION type");
        Expect(hdr.Length == sizeof(block), "CONTINUATION payload length");
        Expect(hdr.StreamId == 1, "CONTINUATION streamId == 1");
        Expect((hdr.Flags & Http2FrameFlags::EndHeaders) != 0, "CONTINUATION EndHeaders set");
    }

    void TestEncodeContinuationNotEnd()
    {
        const unsigned char block[] = { 0xAA };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeContinuation(
            5, block, sizeof(block), false,
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeContinuation not end");

        Http2FrameHeader hdr = {};
        Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect((hdr.Flags & Http2FrameFlags::EndHeaders) == 0, "CONTINUATION EndHeaders not set");
    }

    // ========================================================================
    // DATA frame
    // ========================================================================

    void TestEncodeData()
    {
        const unsigned char data[] = { 'H', 'e', 'l', 'l', 'o' };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeData(
            1, data, sizeof(data), true,
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeData should succeed");
        Expect(written == 9 + sizeof(data), "EncodeData total length");

        Http2FrameHeader hdr = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(NT_SUCCESS(s), "Decode DATA header");
        Expect(hdr.Type == Http2FrameType::Data, "DATA type");
        Expect(hdr.Length == sizeof(data), "DATA payload length");
        Expect(hdr.StreamId == 1, "DATA streamId == 1");
        Expect((hdr.Flags & Http2FrameFlags::EndStream) != 0, "DATA EndStream set");
        Expect(BytesEqual(buf + 9, sizeof(data), data, sizeof(data)), "DATA payload matches");
    }

    void TestEncodeDataEmpty()
    {
        unsigned char buf[16] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeData(
            3, nullptr, 0, true,
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeData empty should succeed");
        Expect(written == 9, "EncodeData empty writes 9 bytes");

        Http2FrameHeader hdr = {};
        Http2FrameCodec::DecodeFrameHeader(buf, 9, &hdr);
        Expect(hdr.Length == 0, "DATA empty payload == 0");
        Expect((hdr.Flags & Http2FrameFlags::EndStream) != 0, "DATA empty EndStream");
    }

    void TestEncodeDataStreamIdZero()
    {
        const unsigned char data[] = { 0x01 };
        unsigned char buf[32] = {};
        size_t written = 0;
        NTSTATUS s = Http2FrameCodec::EncodeData(
            0, data, sizeof(data), false,
            buf, sizeof(buf), &written);
        Expect(s == STATUS_INVALID_PARAMETER, "EncodeData streamId=0 fails");
    }

    // ========================================================================
    // StripPadding
    // ========================================================================

    void TestStripPaddingNoPadFlag()
    {
        const unsigned char payload[] = { 0x01, 0x02, 0x03 };
        const unsigned char* content = nullptr;
        size_t contentLen = 0;
        NTSTATUS s = Http2FrameCodec::StripPadding(0, payload, sizeof(payload), &content, &contentLen);
        Expect(NT_SUCCESS(s), "StripPadding no flag");
        Expect(content == payload, "StripPadding no flag content ptr");
        Expect(contentLen == sizeof(payload), "StripPadding no flag length");
    }

    void TestStripPaddingWithPad()
    {
        // Pad length = 2, content = {0xAA, 0xBB}, padding = {0x00, 0x00}
        const unsigned char payload[] = { 0x02, 0xAA, 0xBB, 0x00, 0x00 };
        const unsigned char* content = nullptr;
        size_t contentLen = 0;
        NTSTATUS s = Http2FrameCodec::StripPadding(Http2FrameFlags::Padded,
            payload, sizeof(payload), &content, &contentLen);
        Expect(NT_SUCCESS(s), "StripPadding with pad");
        Expect(content == payload + 1, "StripPadding content starts after pad length");
        Expect(contentLen == 2, "StripPadding content length == 2");
        Expect(content[0] == 0xAA && content[1] == 0xBB, "StripPadding content bytes");
    }

    void TestStripPaddingInvalid()
    {
        // Pad length exceeds payload
        const unsigned char payload[] = { 0x05, 0xAA };
        const unsigned char* content = nullptr;
        size_t contentLen = 0;
        NTSTATUS s = Http2FrameCodec::StripPadding(Http2FrameFlags::Padded,
            payload, sizeof(payload), &content, &contentLen);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "StripPadding invalid pad length");
    }

    // ========================================================================
    // StripPriority
    // ========================================================================

    void TestStripPriorityNoFlag()
    {
        const unsigned char payload[] = { 0x01, 0x02, 0x03 };
        const unsigned char* content = nullptr;
        size_t contentLen = 0;
        NTSTATUS s = Http2FrameCodec::StripPriority(0, payload, sizeof(payload), &content, &contentLen);
        Expect(NT_SUCCESS(s), "StripPriority no flag");
        Expect(content == payload, "StripPriority no flag ptr");
        Expect(contentLen == sizeof(payload), "StripPriority no flag length");
    }

    void TestStripPriorityWithFlag()
    {
        // 4 bytes stream dep + 1 byte weight + actual content
        const unsigned char payload[] = { 0x00, 0x00, 0x00, 0x01, 0x10, 0xAA, 0xBB };
        const unsigned char* content = nullptr;
        size_t contentLen = 0;
        NTSTATUS s = Http2FrameCodec::StripPriority(Http2FrameFlags::Priority,
            payload, sizeof(payload), &content, &contentLen);
        Expect(NT_SUCCESS(s), "StripPriority with flag");
        Expect(content == payload + 5, "StripPriority content after priority");
        Expect(contentLen == 2, "StripPriority content length == 2");
        Expect(content[0] == 0xAA && content[1] == 0xBB, "StripPriority content bytes");
    }

    void TestStripPriorityTooShort()
    {
        const unsigned char payload[] = { 0x00, 0x00, 0x00 };
        const unsigned char* content = nullptr;
        size_t contentLen = 0;
        NTSTATUS s = Http2FrameCodec::StripPriority(Http2FrameFlags::Priority,
            payload, sizeof(payload), &content, &contentLen);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "StripPriority too short fails");
    }

    // ========================================================================
    // EncodeFrame
    // ========================================================================

    void TestEncodeFrameComplete()
    {
        Http2FrameHeader hdr = {};
        hdr.Length = 4;
        hdr.Type = Http2FrameType::Data;
        hdr.Flags = 0;
        hdr.StreamId = 1;

        const unsigned char payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        unsigned char buf[32] = {};
        size_t written = 0;

        NTSTATUS s = Http2FrameCodec::EncodeFrame(hdr, payload, sizeof(payload),
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeFrame should succeed");
        Expect(written == 13, "EncodeFrame writes 9 + 4 = 13 bytes");

        Http2FrameHeader decoded = {};
        s = Http2FrameCodec::DecodeFrameHeader(buf, 9, &decoded);
        Expect(NT_SUCCESS(s), "EncodeFrame decode header");
        Expect(decoded.Length == 4, "EncodeFrame decoded length");
        Expect(BytesEqual(buf + 9, 4, payload, 4), "EncodeFrame payload preserved");
    }

    // ========================================================================
    // Buffer too small
    // ========================================================================

    void TestBufferTooSmall()
    {
        unsigned char tinyBuf[3] = {};
        size_t written = 0;

        NTSTATUS s = Http2FrameCodec::EncodeSettingsAck(tinyBuf, sizeof(tinyBuf), &written);
        Expect(s == STATUS_BUFFER_TOO_SMALL, "EncodeSettingsAck buf too small");

        s = Http2FrameCodec::EncodeWindowUpdate(1, 100, tinyBuf, sizeof(tinyBuf), &written);
        Expect(s == STATUS_BUFFER_TOO_SMALL, "EncodeWindowUpdate buf too small");

        unsigned char opaque[8] = {};
        s = Http2FrameCodec::EncodePing(opaque, false, tinyBuf, sizeof(tinyBuf), &written);
        Expect(s == STATUS_BUFFER_TOO_SMALL, "EncodePing buf too small");
    }

    void TestStreamStateMachine()
    {
        Http2Stream stream;
        stream.Initialize(1, Http2InitialWindowSize, Http2InitialWindowSize);
        Expect(stream.StreamId() == 1, "Stream id initialized");
        Expect(stream.State() == Http2StreamState::Idle, "Stream starts idle");

        NTSTATUS s = stream.SendHeaders(false);
        Expect(NT_SUCCESS(s), "SendHeaders opens stream");
        Expect(stream.State() == Http2StreamState::Open, "Stream is open after headers");

        s = stream.SendData(10, true);
        Expect(NT_SUCCESS(s), "SendData end local succeeds");
        Expect(stream.State() == Http2StreamState::HalfClosedLocal, "Stream half-closed local");
        Expect(stream.RemoteWindow() == static_cast<LONG>(Http2InitialWindowSize - 10), "Remote window consumed");

        s = stream.ReceiveData(5, true);
        Expect(NT_SUCCESS(s), "ReceiveData end remote succeeds");
        Expect(stream.State() == Http2StreamState::Closed, "Stream closed after both ends closed");
    }

    void TestStreamFlowControl()
    {
        Http2Stream stream;
        stream.Initialize(3, 10, 10);
        NTSTATUS s = stream.SendHeaders(false);
        Expect(NT_SUCCESS(s), "Stream flow setup");

        s = stream.SendData(11, false);
        Expect(s == STATUS_BUFFER_TOO_SMALL, "Stream remote window prevents oversized send");

        s = stream.IncreaseRemoteWindow(5);
        Expect(NT_SUCCESS(s), "Increase remote window");
        s = stream.SendData(11, false);
        Expect(NT_SUCCESS(s), "Send after window update succeeds");

        s = stream.ReceiveData(16, false);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "Local window prevents oversized receive");
    }
}

int main()
{
    TestFrameHeaderRoundTrip();
    TestFrameHeaderMaxValues();
    TestFrameHeaderZeroPayload();
    TestDecodeFrameHeaderTooShort();
    TestEncodeSettings();
    TestEncodeSettingsAck();
    TestDecodeSettingsInvalidPayloadLength();
    TestDecodeSettingsInvalidWindowSize();
    TestDecodeSettingsUnknownIgnored();
    TestEncodeDecodeWindowUpdate();
    TestWindowUpdateZeroIncrement();
    TestDecodeWindowUpdateZero();
    TestEncodeDecodePing();
    TestEncodePingAck();
    TestEncodeDecodeGoAway();
    TestGoAwayWithError();
    TestEncodeDecodeRstStream();
    TestRstStreamZeroStreamId();
    TestEncodeHeaders();
    TestEncodeHeadersNoEndStream();
    TestEncodeHeadersStreamIdZero();
    TestEncodeContinuation();
    TestEncodeContinuationNotEnd();
    TestEncodeData();
    TestEncodeDataEmpty();
    TestEncodeDataStreamIdZero();
    TestStripPaddingNoPadFlag();
    TestStripPaddingWithPad();
    TestStripPaddingInvalid();
    TestStripPriorityNoFlag();
    TestStripPriorityWithFlag();
    TestStripPriorityTooShort();
    TestEncodeFrameComplete();
    TestBufferTooSmall();
    TestStreamStateMachine();
    TestStreamFlowControl();

    if (g_failed) {
        printf("HTTP2 FRAME TESTS FAILED\n");
        return 1;
    }
    printf("HTTP2 FRAME TESTS PASSED\n");
    return 0;
}
