#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/http2/Hpack.h>

#include <stdio.h>
#include <string.h>
#include <initializer_list>

using KernelHttp::http2::HpackDecoder;
using KernelHttp::http2::HpackDecodeInteger;
using KernelHttp::http2::HpackEncodeInteger;
using KernelHttp::http2::HpackEncoder;
using KernelHttp::http2::HpackHuffmanDecode;
using KernelHttp::http2::HpackHuffmanEncode;
using KernelHttp::http2::HpackHuffmanEncodedLength;
using KernelHttp::http2::HpackStaticTableSize;
using KernelHttp::http::HttpHeader;
using KernelHttp::http::HttpText;
using KernelHttp::http::MakeText;

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

    bool TextEqualsLiteral(HttpText t, const char* literal)
    {
        size_t len = strlen(literal);
        return t.Length == len && t.Data != nullptr && memcmp(t.Data, literal, len) == 0;
    }

    bool AppendLiteralWithIndexing(
        unsigned char* block,
        size_t capacity,
        size_t* blockLen,
        const char* name,
        size_t nameLen,
        const char* value,
        size_t valueLen)
    {
        if (block == nullptr || blockLen == nullptr || name == nullptr || value == nullptr ||
            nameLen > 127 || valueLen > 127) {
            return false;
        }
        if (*blockLen > capacity ||
            capacity - *blockLen < 3 + nameLen + valueLen) {
            return false;
        }

        block[(*blockLen)++] = 0x40;
        block[(*blockLen)++] = static_cast<unsigned char>(nameLen);
        memcpy(block + *blockLen, name, nameLen);
        *blockLen += nameLen;
        block[(*blockLen)++] = static_cast<unsigned char>(valueLen);
        memcpy(block + *blockLen, value, valueLen);
        *blockLen += valueLen;
        return true;
    }

    bool AppendLiteralWithIndexedName(
        unsigned char* block,
        size_t capacity,
        size_t* blockLen,
        ULONG index,
        const char* value,
        size_t valueLen)
    {
        if (block == nullptr || blockLen == nullptr || value == nullptr || valueLen > 127) {
            return false;
        }
        if (*blockLen > capacity) {
            return false;
        }

        size_t written = 0;
        NTSTATUS status = HpackEncodeInteger(
            index,
            0x40,
            6,
            block + *blockLen,
            capacity - *blockLen,
            &written);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        *blockLen += written;

        if (capacity - *blockLen < 1 + valueLen) {
            return false;
        }
        block[(*blockLen)++] = static_cast<unsigned char>(valueLen);
        memcpy(block + *blockLen, value, valueLen);
        *blockLen += valueLen;
        return true;
    }

    // RFC 7541 C.1.1 - Encoding 10 using a 5-bit prefix
    void TestEncodeIntegerSimple()
    {
        unsigned char buf[16] = {};
        size_t written = 0;
        NTSTATUS s = HpackEncodeInteger(10, 0x00, 5, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeInteger(10,5) should succeed");
        Expect(written == 1, "EncodeInteger(10,5) should write 1 byte");
        Expect(buf[0] == 0x0a, "EncodeInteger(10,5) value");
    }

    // RFC 7541 C.1.2 - Encoding 1337 using a 5-bit prefix
    void TestEncodeIntegerMultibyte()
    {
        unsigned char buf[16] = {};
        size_t written = 0;
        NTSTATUS s = HpackEncodeInteger(1337, 0x00, 5, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeInteger(1337,5) should succeed");
        Expect(written == 3, "EncodeInteger(1337,5) should write 3 bytes");
        // Expected: 0x1f 0x9a 0x0a
        Expect(buf[0] == 0x1f && buf[1] == 0x9a && buf[2] == 0x0a, "EncodeInteger(1337,5) bytes");
    }

    // RFC 7541 C.1.3 - Encoding 42 using an 8-bit prefix
    void TestEncodeIntegerEightBit()
    {
        unsigned char buf[16] = {};
        size_t written = 0;
        NTSTATUS s = HpackEncodeInteger(42, 0x00, 8, buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "EncodeInteger(42,8) should succeed");
        Expect(written == 1, "EncodeInteger(42,8) should write 1 byte");
        Expect(buf[0] == 0x2a, "EncodeInteger(42,8) value");
    }

    void TestDecodeIntegerSimple()
    {
        unsigned char data[] = { 0x0a };
        ULONG value = 0;
        size_t consumed = 0;
        NTSTATUS s = HpackDecodeInteger(data, sizeof(data), 5, &value, &consumed);
        Expect(NT_SUCCESS(s), "DecodeInteger(0x0a, 5) should succeed");
        Expect(value == 10, "DecodeInteger(0x0a, 5) value");
        Expect(consumed == 1, "DecodeInteger(0x0a, 5) consumed");
    }

    void TestDecodeIntegerMultibyte()
    {
        unsigned char data[] = { 0x1f, 0x9a, 0x0a };
        ULONG value = 0;
        size_t consumed = 0;
        NTSTATUS s = HpackDecodeInteger(data, sizeof(data), 5, &value, &consumed);
        Expect(NT_SUCCESS(s), "DecodeInteger multibyte should succeed");
        Expect(value == 1337, "DecodeInteger multibyte value");
        Expect(consumed == 3, "DecodeInteger multibyte consumed");
    }

    void TestDecodeIntegerRejectsOverflow()
    {
        const unsigned char data[] = { 0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f };
        ULONG value = 0;
        size_t consumed = 0;
        NTSTATUS s = HpackDecodeInteger(data, sizeof(data), 5, &value, &consumed);
        Expect(s == STATUS_INTEGER_OVERFLOW, "DecodeInteger rejects ULONG overflow");
    }

    void TestDecodeIntegerRejectsTooManyContinuationBytes()
    {
        const unsigned char data[] = { 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };
        ULONG value = 0;
        size_t consumed = 0;
        NTSTATUS s = HpackDecodeInteger(data, sizeof(data), 5, &value, &consumed);
        Expect(s == STATUS_INTEGER_OVERFLOW, "DecodeInteger rejects too many continuation bytes");
    }

    void TestIntegerRoundTrip()
    {
        for (ULONG val : { 0u, 1u, 14u, 15u, 16u, 127u, 128u, 1337u, 100000u, 0x7fffffffu }) {
            const UCHAR prefixes[] = { 4, 5, 6, 7, 8 };
            for (UCHAR prefix : prefixes) {
                unsigned char buf[16] = {};
                size_t written = 0;
                NTSTATUS s = HpackEncodeInteger(val, 0x00, prefix, buf, sizeof(buf), &written);
                Expect(NT_SUCCESS(s), "RoundTrip encode succeeds");

                ULONG decoded = 0;
                size_t consumed = 0;
                s = HpackDecodeInteger(buf, written, prefix, &decoded, &consumed);
                Expect(NT_SUCCESS(s), "RoundTrip decode succeeds");
                Expect(decoded == val, "RoundTrip value matches");
                Expect(consumed == written, "RoundTrip bytes match");
            }
        }
    }

    // RFC 7541 C.4.1 - "www.example.com" Huffman encoded
    void TestHuffmanEncodeExample()
    {
        const char* input = "www.example.com";
        size_t inputLen = strlen(input);
        unsigned char buf[64] = {};
        size_t written = 0;
        NTSTATUS s = HpackHuffmanEncode(
            reinterpret_cast<const unsigned char*>(input), inputLen,
            buf, sizeof(buf), &written);
        Expect(NT_SUCCESS(s), "HuffmanEncode should succeed");

        // RFC 7541 C.4.1 expected: f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff
        const unsigned char expected[] = {
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
        };
        Expect(written == sizeof(expected), "HuffmanEncode length matches");
        Expect(BytesEqual(buf, written, expected, sizeof(expected)), "HuffmanEncode bytes match");
    }

    void TestHuffmanRoundTrip()
    {
        const char* inputs[] = {
            "www.example.com",
            "no-cache",
            "custom-key",
            "custom-value",
            "/sample/path",
            "Mon, 21 Oct 2013 20:13:21 GMT",
            "https://www.example.com",
            ""
        };

        for (const char* input : inputs) {
            size_t inputLen = strlen(input);
            unsigned char encoded[256] = {};
            size_t encodedLen = 0;
            NTSTATUS s = HpackHuffmanEncode(
                reinterpret_cast<const unsigned char*>(input), inputLen,
                encoded, sizeof(encoded), &encodedLen);
            Expect(NT_SUCCESS(s), "HuffmanEncode roundtrip encode");

            unsigned char decoded[256] = {};
            size_t decodedLen = 0;
            s = HpackHuffmanDecode(encoded, encodedLen, decoded, sizeof(decoded), &decodedLen);
            Expect(NT_SUCCESS(s), "HuffmanEncode roundtrip decode");
            Expect(decodedLen == inputLen, "HuffmanEncode roundtrip length");
            Expect(BytesEqual(decoded, decodedLen,
                reinterpret_cast<const unsigned char*>(input), inputLen),
                "HuffmanEncode roundtrip bytes");
        }
    }

    void TestHuffmanRejectsInvalidPaddingAndEos()
    {
        const unsigned char badPadding[] = { 0x00 };
        unsigned char decoded[16] = {};
        size_t decodedLen = 0;
        NTSTATUS s = HpackHuffmanDecode(
            badPadding,
            sizeof(badPadding),
            decoded,
            sizeof(decoded),
            &decodedLen);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "HuffmanDecode rejects non-1 padding bits");

        const unsigned char eosPrefix[] = { 0xff, 0xff, 0xff, 0xff };
        decodedLen = 0;
        s = HpackHuffmanDecode(
            eosPrefix,
            sizeof(eosPrefix),
            decoded,
            sizeof(decoded),
            &decodedLen);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "HuffmanDecode rejects EOS symbol");
    }

    // RFC 7541 C.2.1 - Literal Header Field with Indexing
    // custom-key: custom-header
    void TestDecodeLiteralWithIndexing()
    {
        // From RFC 7541 C.2.1:
        // 400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572
        const unsigned char block[] = {
            0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d,
            0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x63, 0x75, 0x73,
            0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64,
            0x65, 0x72
        };

        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(4096);
        Expect(NT_SUCCESS(s), "Decoder init");

        HttpHeader headers[8] = {};
        size_t headerCount = 0;
        char nvBuffer[256] = {};
        size_t nvUsed = 0;

        s = decoder.Decode(block, sizeof(block), headers, 8, &headerCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(NT_SUCCESS(s), "Decode literal-with-indexing");
        Expect(headerCount == 1, "Header count == 1");
        Expect(TextEqualsLiteral(headers[0].Name, "custom-key"), "Name == custom-key");
        Expect(TextEqualsLiteral(headers[0].Value, "custom-header"), "Value == custom-header");
    }

    // RFC 7541 C.2.4 - Indexed Header Field (index 2 == :method GET)
    void TestDecodeIndexed()
    {
        const unsigned char block[] = { 0x82 };

        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(4096);
        Expect(NT_SUCCESS(s), "Decoder init");

        HttpHeader headers[8] = {};
        size_t headerCount = 0;
        char nvBuffer[256] = {};
        size_t nvUsed = 0;

        s = decoder.Decode(block, sizeof(block), headers, 8, &headerCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(NT_SUCCESS(s), "Decode indexed");
        Expect(headerCount == 1, "Header count == 1 (indexed)");
        Expect(TextEqualsLiteral(headers[0].Name, ":method"), "Name == :method");
        Expect(TextEqualsLiteral(headers[0].Value, "GET"), "Value == GET");
    }

    // RFC 7541 C.3.1 - First Request: GET http://www.example.com/
    // 8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d
    void TestDecodeFirstRequest()
    {
        const unsigned char block[] = {
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77,
            0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x2e, 0x63, 0x6f, 0x6d
        };

        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(4096);
        Expect(NT_SUCCESS(s), "Decoder init");

        HttpHeader headers[8] = {};
        size_t headerCount = 0;
        char nvBuffer[256] = {};
        size_t nvUsed = 0;

        s = decoder.Decode(block, sizeof(block), headers, 8, &headerCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(NT_SUCCESS(s), "Decode C.3.1");
        Expect(headerCount == 4, "C.3.1 header count == 4");
        Expect(TextEqualsLiteral(headers[0].Name, ":method"), "C.3.1 :method");
        Expect(TextEqualsLiteral(headers[0].Value, "GET"), "C.3.1 GET");
        Expect(TextEqualsLiteral(headers[1].Name, ":scheme"), "C.3.1 :scheme");
        Expect(TextEqualsLiteral(headers[1].Value, "http"), "C.3.1 http");
        Expect(TextEqualsLiteral(headers[2].Name, ":path"), "C.3.1 :path");
        Expect(TextEqualsLiteral(headers[2].Value, "/"), "C.3.1 /");
        Expect(TextEqualsLiteral(headers[3].Name, ":authority"), "C.3.1 :authority");
        Expect(TextEqualsLiteral(headers[3].Value, "www.example.com"), "C.3.1 authority value");
    }

    // RFC 7541 C.4.1 - First Request with Huffman: GET http://www.example.com/
    // 8286 8441 8c f1e3c2e5f23a6ba0ab90f4ff
    void TestDecodeFirstRequestHuffman()
    {
        const unsigned char block[] = {
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
            0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
            0xff
        };

        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(4096);
        Expect(NT_SUCCESS(s), "Decoder init");

        HttpHeader headers[8] = {};
        size_t headerCount = 0;
        char nvBuffer[256] = {};
        size_t nvUsed = 0;

        s = decoder.Decode(block, sizeof(block), headers, 8, &headerCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(NT_SUCCESS(s), "Decode C.4.1 (Huffman)");
        Expect(headerCount == 4, "C.4.1 header count == 4");
        Expect(TextEqualsLiteral(headers[3].Name, ":authority"), "C.4.1 :authority");
        Expect(TextEqualsLiteral(headers[3].Value, "www.example.com"), "C.4.1 huffman value decoded");
    }

    // Round-trip test: encode some headers, decode them, verify they match
    void TestEncoderDecoderRoundTrip()
    {
        HpackEncoder encoder;
        HpackDecoder decoder;
        encoder.Initialize(4096);
        decoder.Initialize(4096);

        HttpHeader inputHeaders[5] = {
            { MakeText(":method"), MakeText("POST") },
            { MakeText(":scheme"), MakeText("https") },
            { MakeText(":path"), MakeText("/api/v1/data") },
            { MakeText(":authority"), MakeText("example.com") },
            { MakeText("content-type"), MakeText("application/json") }
        };

        unsigned char block[256] = {};
        size_t blockLen = 0;
        NTSTATUS s = encoder.Encode(inputHeaders, 5, block, sizeof(block), &blockLen);
        Expect(NT_SUCCESS(s), "Encode round-trip");
        Expect(blockLen > 0, "Encoded length > 0");

        HttpHeader outHeaders[8] = {};
        size_t outCount = 0;
        char nvBuffer[512] = {};
        size_t nvUsed = 0;

        s = decoder.Decode(block, blockLen, outHeaders, 8, &outCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(NT_SUCCESS(s), "Decode round-trip");
        Expect(outCount == 5, "Round-trip count == 5");
        Expect(TextEqualsLiteral(outHeaders[0].Name, ":method"), "RT :method");
        Expect(TextEqualsLiteral(outHeaders[0].Value, "POST"), "RT POST");
        Expect(TextEqualsLiteral(outHeaders[2].Value, "/api/v1/data"), "RT path");
        Expect(TextEqualsLiteral(outHeaders[4].Name, "content-type"), "RT content-type");
        Expect(TextEqualsLiteral(outHeaders[4].Value, "application/json"), "RT json");
    }

    void TestDecoderRejectsOversizedDynamicTableUpdate()
    {
        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(128);
        Expect(NT_SUCCESS(s), "Decoder init for oversized table update");

        unsigned char block[8] = {};
        size_t blockLen = 0;
        s = HpackEncodeInteger(4096, 0x20, 5, block, sizeof(block), &blockLen);
        Expect(NT_SUCCESS(s), "Encode oversized dynamic table update");

        HttpHeader headers[1] = {};
        size_t headerCount = 0;
        char nvBuffer[32] = {};
        size_t nvUsed = 0;
        s = decoder.Decode(block, blockLen, headers, 1, &headerCount, nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "Decoder rejects dynamic table update above configured max");
    }

    void TestDecoderRejectsDynamicTableUpdateAfterHeader()
    {
        const unsigned char block[] = { 0x82, 0x20 };

        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(4096);
        Expect(NT_SUCCESS(s), "Decoder init for late table update");

        HttpHeader headers[2] = {};
        size_t headerCount = 0;
        char nvBuffer[64] = {};
        size_t nvUsed = 0;
        s = decoder.Decode(block, sizeof(block), headers, 2, &headerCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "Decoder rejects table size update after a header field");
    }

    void TestDecoderEnforcesHeaderListSize()
    {
        const unsigned char block[] = {
            0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d,
            0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x63, 0x75, 0x73,
            0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64,
            0x65, 0x72
        };

        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(4096);
        Expect(NT_SUCCESS(s), "Decoder init for header-list limit");

        HttpHeader headers[2] = {};
        size_t headerCount = 0;
        char nvBuffer[128] = {};
        size_t nvUsed = 0;
        s = decoder.Decode(block, sizeof(block), headers, 2, &headerCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed, 54);
        Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "Decoder rejects header list above configured limit");
    }

    void TestDecoderRejectsInvalidIndexesAndIntegerOverflow()
    {
        {
            const unsigned char block[] = { 0xff, 0x00 };
            HpackDecoder decoder;
            NTSTATUS s = decoder.Initialize(4096);
            Expect(NT_SUCCESS(s), "Decoder init for invalid index");

            HttpHeader headers[1] = {};
            size_t headerCount = 0;
            char nvBuffer[32] = {};
            size_t nvUsed = 0;
            s = decoder.Decode(block, sizeof(block), headers, 1, &headerCount,
                nvBuffer, sizeof(nvBuffer), &nvUsed);
            Expect(s == STATUS_INVALID_NETWORK_RESPONSE, "Decoder rejects index outside static and dynamic tables");
        }

        {
            const unsigned char block[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x10 };
            HpackDecoder decoder;
            NTSTATUS s = decoder.Initialize(4096);
            Expect(NT_SUCCESS(s), "Decoder init for overflowing index");

            HttpHeader headers[1] = {};
            size_t headerCount = 0;
            char nvBuffer[32] = {};
            size_t nvUsed = 0;
            s = decoder.Decode(block, sizeof(block), headers, 1, &headerCount,
                nvBuffer, sizeof(nvBuffer), &nvUsed);
            Expect(s == STATUS_INTEGER_OVERFLOW, "Decoder rejects overflowing indexed header integer");
        }
    }

    void TestEncoderUsesNeverIndexedForSensitiveHeaders()
    {
        const char* names[] = {
            "authorization",
            "cookie",
            "proxy-authorization"
        };

        for (const char* name : names) {
            HpackEncoder encoder;
            HpackDecoder decoder;
            NTSTATUS s = encoder.Initialize(4096);
            Expect(NT_SUCCESS(s), "Encoder init for sensitive header");
            s = decoder.Initialize(4096);
            Expect(NT_SUCCESS(s), "Decoder init for sensitive header");

            HttpHeader input[] = {
                { MakeText(name), MakeText("secret") }
            };
            unsigned char block[128] = {};
            size_t blockLen = 0;
            s = encoder.Encode(input, 1, block, sizeof(block), &blockLen);
            Expect(NT_SUCCESS(s), "Encode sensitive header");
            Expect(blockLen > 0, "Sensitive header encoded bytes exist");
            Expect((block[0] & 0xf0) == 0x10, "Sensitive header uses never-indexed literal");

            HttpHeader output[1] = {};
            size_t outputCount = 0;
            char nvBuffer[128] = {};
            size_t nvUsed = 0;
            s = decoder.Decode(block, blockLen, output, 1, &outputCount,
                nvBuffer, sizeof(nvBuffer), &nvUsed);
            Expect(NT_SUCCESS(s), "Decode never-indexed sensitive header");
            Expect(outputCount == 1, "Sensitive header decode count");
            Expect(TextEqualsLiteral(output[0].Name, name), "Sensitive header name round-trips");
            Expect(TextEqualsLiteral(output[0].Value, "secret"), "Sensitive header value round-trips");
        }
    }

    void TestDecodeDynamicNameInsertAcrossReallocation()
    {
        constexpr size_t NameLen = 80;
        constexpr size_t FillCount = 12;
        unsigned char block[2048] = {};
        size_t blockLen = 0;
        char name[NameLen] = {};
        const char value[] = { 'v' };

        for (size_t i = 0; i < FillCount; ++i) {
            for (size_t j = 0; j < NameLen; ++j) {
                name[j] = static_cast<char>('a' + i);
            }
            Expect(AppendLiteralWithIndexing(
                block,
                sizeof(block),
                &blockLen,
                name,
                sizeof(name),
                value,
                sizeof(value)), "HPACK fill entry fixture builds");
        }

        char expectedName[NameLen] = {};
        for (size_t i = 0; i < NameLen; ++i) {
            expectedName[i] = static_cast<char>('a' + FillCount - 1);
        }

        const char finalValue[] = { 'z' };
        Expect(AppendLiteralWithIndexedName(
            block,
            sizeof(block),
            &blockLen,
            static_cast<ULONG>(HpackStaticTableSize + 1),
            finalValue,
            sizeof(finalValue)), "HPACK self-referenced insert fixture builds");

        HpackDecoder decoder;
        NTSTATUS s = decoder.Initialize(128);
        Expect(NT_SUCCESS(s), "Decoder init for dynamic self-reference test");

        HttpHeader headers[16] = {};
        size_t headerCount = 0;
        char nvBuffer[2048] = {};
        size_t nvUsed = 0;

        s = decoder.Decode(block, blockLen, headers, 16, &headerCount,
            nvBuffer, sizeof(nvBuffer), &nvUsed);
        Expect(NT_SUCCESS(s), "Decode dynamic-table name insert across reallocation");
        Expect(headerCount == FillCount + 1, "Dynamic self-reference header count");
        Expect(headers[FillCount].Name.Length == NameLen, "Dynamic self-reference name length");
        Expect(headers[FillCount].Name.Data != nullptr &&
            memcmp(headers[FillCount].Name.Data, expectedName, sizeof(expectedName)) == 0,
            "Dynamic self-reference name remains intact");
        Expect(headers[FillCount].Value.Length == sizeof(finalValue), "Dynamic self-reference value length");
        Expect(headers[FillCount].Value.Data != nullptr &&
            memcmp(headers[FillCount].Value.Data, finalValue, sizeof(finalValue)) == 0,
            "Dynamic self-reference value remains intact");
    }

    void TestHuffmanEncodedLength()
    {
        // "www.example.com" -> 12 bytes per RFC C.4.1
        size_t len = HpackHuffmanEncodedLength(
            reinterpret_cast<const unsigned char*>("www.example.com"), 15);
        Expect(len == 12, "HuffmanEncodedLength www.example.com == 12");
    }
}

int main()
{
    TestEncodeIntegerSimple();
    TestEncodeIntegerMultibyte();
    TestEncodeIntegerEightBit();
    TestDecodeIntegerSimple();
    TestDecodeIntegerMultibyte();
    TestDecodeIntegerRejectsOverflow();
    TestDecodeIntegerRejectsTooManyContinuationBytes();
    TestIntegerRoundTrip();
    TestHuffmanEncodeExample();
    TestHuffmanEncodedLength();
    TestHuffmanRoundTrip();
    TestHuffmanRejectsInvalidPaddingAndEos();
    TestDecodeIndexed();
    TestDecodeLiteralWithIndexing();
    TestDecodeFirstRequest();
    TestDecodeFirstRequestHuffman();
    TestEncoderDecoderRoundTrip();
    TestDecoderRejectsOversizedDynamicTableUpdate();
    TestDecoderRejectsDynamicTableUpdateAfterHeader();
    TestDecoderEnforcesHeaderListSize();
    TestDecoderRejectsInvalidIndexesAndIntegerOverflow();
    TestEncoderUsesNeverIndexedForSensitiveHeaders();
    TestDecodeDynamicNameInsertAcrossReallocation();

    if (g_failed) {
        printf("HPACK TESTS FAILED\n");
        return 1;
    }
    printf("HPACK TESTS PASSED\n");
    return 0;
}
