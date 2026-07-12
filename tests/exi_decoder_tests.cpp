#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "../src/wknetlib/codec/ExiEventReader.h"
#include "../src/wknetlib/codec/ExiOptions.h"
#include "../src/wknetlib/codec/ExiStringTable.h"
#include "../src/wknetlib/codec/ExiDecoder.h"
#include "../src/wknetlib/codec/XmlWriter.h"
#include <wknet/codec/Codec.h>
#include <wknet/crypto/CngProvider.h>

#include <stdio.h>
#include <string.h>

using wknet::codec::HttpExiBitInput;
using wknet::codec::HttpExiAlignment;
using wknet::codec::HttpExiOptions;
using wknet::codec::HttpExiParseHeader;
using wknet::codec::HttpExiReadLiteralString;
using wknet::codec::HttpExiStringTable;
using wknet::codec::HttpExiValueTable;
using wknet::codec::DecodeExiContent;
using wknet::codec::DecodeExi;
using wknet::codec::HttpXmlText;
using wknet::codec::HttpXmlName;
using wknet::codec::HttpXmlWriter;
using wknet::crypto::CngProvider;
using wknet::crypto::HashAlgorithm;
using wknet::HeapArray;

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

    bool HexDigestEquals(const UCHAR* digest, SIZE_T digestLength, const char* expected) noexcept
    {
        if (digest == nullptr || expected == nullptr || digestLength != 32) return false;
        for (SIZE_T index = 0; index < digestLength; ++index) {
            const auto digit = [](char value) noexcept -> int {
                if (value >= '0' && value <= '9') return value - '0';
                if (value >= 'a' && value <= 'f') return value - 'a' + 10;
                if (value >= 'A' && value <= 'F') return value - 'A' + 10;
                return -1;
            };
            const int high = digit(expected[index * 2]);
            const int low = digit(expected[index * 2 + 1]);
            if (high < 0 || low < 0 ||
                digest[index] != static_cast<UCHAR>((high << 4) | low)) {
                return false;
            }
        }
        return expected[digestLength * 2] == '\0';
    }

    bool LoadFile(const char* path, _Inout_ HeapArray<UCHAR>* bytes) noexcept
    {
        if (path == nullptr || bytes == nullptr) return false;
        FILE* file = nullptr;
        if (fopen_s(&file, path, "rb") != 0 || file == nullptr) return false;
        if (fseek(file, 0, SEEK_END) != 0) {
            fclose(file);
            return false;
        }
        const long length = ftell(file);
        if (length < 0 || fseek(file, 0, SEEK_SET) != 0 ||
            !NT_SUCCESS(bytes->Allocate(static_cast<SIZE_T>(length)))) {
            fclose(file);
            return false;
        }
        const bool loaded = bytes->Count() == 0 ||
            fread(bytes->Get(), 1, bytes->Count(), file) == bytes->Count();
        fclose(file);
        return loaded;
    }

    bool DecodeExiFixture(
        const char* fixtureName,
        const char* expectedName,
        const char* expectedSha256) noexcept
    {
        char fixturePath[192] = {};
        char expectedPath[192] = {};
        if (sprintf_s(
                fixturePath,
                "tests/fixtures/exi/corpus/%s",
                fixtureName) <= 0 ||
            sprintf_s(
                expectedPath,
                "tests/fixtures/exi/corpus/%s",
                expectedName) <= 0) {
            return false;
        }
        HeapArray<UCHAR> fixture = {};
        HeapArray<UCHAR> expected = {};
        if (!LoadFile(fixturePath, &fixture) || !LoadFile(expectedPath, &expected)) return false;
        UCHAR digest[32] = {};
        SIZE_T digestLength = 0;
        if (!NT_SUCCESS(CngProvider::Hash(
                HashAlgorithm::Sha256,
                fixture.Get(),
                fixture.Count(),
                digest,
                sizeof(digest),
                &digestLength)) ||
            !HexDigestEquals(digest, digestLength, expectedSha256)) {
            return false;
        }
        HeapArray<char> output(1024);
        if (!output.IsValid()) return false;
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExi(
            fixture.Get(),
            fixture.Count(),
            output.Get(),
            output.Count(),
            &outputLength);
        return NT_SUCCESS(status) && outputLength == expected.Count() &&
            (outputLength == 0 || memcmp(output.Get(), expected.Get(), outputLength) == 0);
    }

    bool RejectExiFixture(const char* fixtureName, const char* expectedSha256) noexcept
    {
        char fixturePath[192] = {};
        if (sprintf_s(
                fixturePath,
                "tests/fixtures/exi/corpus/%s",
                fixtureName) <= 0) {
            return false;
        }
        HeapArray<UCHAR> fixture = {};
        if (!LoadFile(fixturePath, &fixture)) return false;
        UCHAR digest[32] = {};
        SIZE_T digestLength = 0;
        if (!NT_SUCCESS(CngProvider::Hash(
                HashAlgorithm::Sha256,
                fixture.Get(),
                fixture.Count(),
                digest,
                sizeof(digest),
                &digestLength)) ||
            !HexDigestEquals(digest, digestLength, expectedSha256)) {
            return false;
        }
        char output[256] = {};
        SIZE_T outputLength = 1;
        const NTSTATUS status = DecodeExi(
            fixture.Get(),
            fixture.Count(),
            output,
            sizeof(output),
            &outputLength);
        return status == STATUS_INVALID_NETWORK_RESPONSE && outputLength == 0;
    }

    class TestBitWriter final
    {
    public:
        TestBitWriter(unsigned char* bytes, size_t capacity) : bytes_(bytes), capacity_(capacity)
        {
        }

        bool WriteBits(ULONG value, UCHAR count)
        {
            for (UCHAR index = 0; index < count; ++index) {
                if (bitLength_ >= capacity_ * 8) {
                    return false;
                }
                const UCHAR shift = static_cast<UCHAR>(count - index - 1);
                const UCHAR bit = static_cast<UCHAR>((value >> shift) & 1U);
                const size_t byteOffset = bitLength_ / 8;
                const UCHAR bitOffset = static_cast<UCHAR>(7 - (bitLength_ % 8));
                bytes_[byteOffset] = static_cast<unsigned char>(bytes_[byteOffset] | (bit << bitOffset));
                ++bitLength_;
            }
            return true;
        }

        bool WriteUnsigned(ULONG value)
        {
            do {
                UCHAR octet = static_cast<UCHAR>(value & 0x7fU);
                value >>= 7;
                if (value != 0) {
                    octet = static_cast<UCHAR>(octet | 0x80U);
                }
                if (!WriteBits(octet, 8)) {
                    return false;
                }
            } while (value != 0);
            return true;
        }

        bool WriteAsciiString(const char* value)
        {
            const size_t length = strlen(value);
            if (length > 0xffffffffULL || !WriteUnsigned(static_cast<ULONG>(length))) {
                return false;
            }
            return WriteAsciiOnly(value);
        }

        bool WriteAsciiOnly(const char* value)
        {
            const size_t length = strlen(value);
            for (size_t index = 0; index < length; ++index) {
                if (!WriteUnsigned(static_cast<UCHAR>(value[index]))) {
                    return false;
                }
            }
            return true;
        }

        size_t Length() const
        {
            return (bitLength_ + 7) / 8;
        }

    private:
        unsigned char* bytes_ = nullptr;
        size_t capacity_ = 0;
        size_t bitLength_ = 0;
    };

    void TestUnsignedIntegerRemainsBitPacked()
    {
        const unsigned char bytes[] = { 0x81, 0x00 };
        HttpExiBitInput input(bytes, sizeof(bytes));
        ULONG prefix = 0;
        ULONG value = 0;
        Expect(input.ReadBits(1, &prefix) && prefix == 1, "exi reads leading bit");
        Expect(
            input.ReadUnsignedInteger(&value) && value == 2,
            "exi unsigned integer continues at current bit offset");
    }

    void TestLiteralStringDecodesUnicodeCodePoints()
    {
        // String length 1 followed by U+00E9 encoded as an EXI Unsigned Integer.
        const unsigned char bytes[] = { 0x01, 0xe9, 0x01 };
        HttpExiBitInput input(bytes, sizeof(bytes));
        HttpExiStringTable table = {};
        NTSTATUS status = table.Initialize(4, 16);
        Expect(NT_SUCCESS(status), "exi unicode string table initializes");

        HttpXmlText value = {};
        status = HttpExiReadLiteralString(&input, &table, &value);
        const unsigned char expected[] = { 0xc3, 0xa9 };
        Expect(
            NT_SUCCESS(status) &&
                value.Length == sizeof(expected) &&
                value.Data != nullptr &&
                memcmp(value.Data, expected, sizeof(expected)) == 0,
            "exi literal string converts Unicode code points to UTF-8");
    }

    void TestXmlWriterAcceptsUnicodeNamesAndEntities()
    {
        const char unicodeName[] = { static_cast<char>(0xc3), static_cast<char>(0xa9) };
        char output[64] = {};
        HttpXmlWriter writer(output, sizeof(output));
        HttpXmlName name = {};
        name.LocalName = { unicodeName, sizeof(unicodeName) };
        NTSTATUS status = writer.WriteStartElement(name);
        Expect(NT_SUCCESS(status), "xml writer accepts a valid Unicode XML name");
        status = writer.WriteEntityReference({ "amp", 3 });
        Expect(NT_SUCCESS(status), "xml writer emits entity references");
        status = writer.WriteEndElement(name);
        Expect(NT_SUCCESS(status), "xml writer closes Unicode element");

        const unsigned char expected[] = {
            '<', 0xc3, 0xa9, '>', '&', 'a', 'm', 'p', ';',
            '<', '/', 0xc3, 0xa9, '>'
        };
        Expect(
            writer.Length() == sizeof(expected) &&
                memcmp(output, expected, sizeof(expected)) == 0,
            "xml writer Unicode and entity output is deterministic");
    }

    void TestSchemaLessBitPackedDocument()
    {
        unsigned char encoded[64] = {};
        TestBitWriter writer(encoded, sizeof(encoded));
        Expect(writer.WriteBits(0x80, 8), "exi test writes default header");
        // SD and document SE have zero-width event codes.
        Expect(writer.WriteBits(1, 2), "exi test references the initial empty URI");
        Expect(writer.WriteUnsigned(5), "exi test writes literal local-name length plus one");
        Expect(writer.WriteAsciiOnly("root"), "exi test writes root local name");
        Expect(writer.WriteBits(3, 2), "exi test writes CH event tuple");
        Expect(writer.WriteUnsigned(6), "exi test writes value length plus two");
        Expect(writer.WriteAsciiOnly("text"), "exi test writes character value");
        Expect(writer.WriteBits(0, 1), "exi test writes EE event tuple");

        const unsigned char reference[] = {
            0x80, 0x41, 0x5c, 0x9b, 0xdb, 0xdd,
            0x30, 0x67, 0x46, 0x57, 0x87, 0x40
        };
        Expect(
            writer.Length() == sizeof(reference) &&
                memcmp(encoded, reference, sizeof(reference)) == 0,
            "EXI test encoder matches EXIficient 1.0.7 bit-packed bytes");

        char output[64] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            writer.Length(),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == 17 &&
                memcmp(output, "<root>text</root>", 17) == 0,
            "schema-less EXI bit-packed document decodes to XML");
    }

    void ExpectSimpleDocumentDecodes(
        const unsigned char* encoded,
        size_t encodedLength,
        const char* message)
    {
        char output[64] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            encodedLength,
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == 17 &&
                memcmp(output, "<root>text</root>", 17) == 0,
            message);
    }

    void TestCookieOptionsAndByteAlignment()
    {
        const unsigned char cookie[] = {
            0x24, 0x45, 0x58, 0x49, 0x80, 0x41, 0x5c, 0x9b,
            0xdb, 0xdd, 0x30, 0x67, 0x46, 0x57, 0x87, 0x40
        };
        const unsigned char bitPackedOptions[] = {
            0xa0, 0x68, 0x2b, 0x93, 0x7b, 0x7b, 0xa6, 0x0c,
            0xe8, 0xca, 0xf0, 0xe8
        };
        const unsigned char byteAlignedOptions[] = {
            0xa0, 0x00, 0x4a, 0x01, 0x05, 0x72, 0x6f, 0x6f,
            0x74, 0x03, 0x06, 0x74, 0x65, 0x78, 0x74, 0x00
        };
        const unsigned char schemaIdNil[] = {
            0xa0, 0x37, 0x41, 0x5c, 0x9b, 0xdb, 0xdd,
            0x30, 0x67, 0x46, 0x57, 0x87, 0x40
        };

        ExpectSimpleDocumentDecodes(cookie, sizeof(cookie), "EXI cookie stream decodes");
        ExpectSimpleDocumentDecodes(
            bitPackedOptions,
            sizeof(bitPackedOptions),
            "EXI empty options document preserves bit-packed decoding");
        ExpectSimpleDocumentDecodes(
            byteAlignedOptions,
            sizeof(byteAlignedOptions),
            "EXI byte-aligned options stream decodes");
        HttpExiOptions options = {};
        SIZE_T bodyBitOffset = 0;
        const NTSTATUS headerStatus = HttpExiParseHeader(
            schemaIdNil,
            sizeof(schemaIdNil),
            &options,
            &bodyBitOffset);
        Expect(
            NT_SUCCESS(headerStatus) &&
                options.HasSchemaId &&
                !options.BuiltInSchemaTypesOnly &&
                bodyBitOffset < sizeof(schemaIdNil) * 8,
            "EXI schemaId xsi:nil selects schema-less grammar");
        ExpectSimpleDocumentDecodes(
            schemaIdNil,
            sizeof(schemaIdNil),
            "EXI schemaId xsi:nil schema-less stream decodes");
    }

    void TestReorderedAlignmentsAreParsed()
    {
        const unsigned char preCompression[] = {
            0xa0, 0x00, 0xca, 0x01, 0x05, 0x72, 0x6f, 0x6f,
            0x74, 0x03, 0x00, 0x06, 0x74, 0x65, 0x78, 0x74
        };
        const unsigned char compression[] = {
            0xa0, 0x25, 0x63, 0x64, 0x2d, 0xca, 0xcf, 0x2f,
            0x61, 0x66, 0x60, 0x2b, 0x49, 0xad, 0x28, 0x01,
            0x00
        };

        HttpExiOptions options = {};
        SIZE_T bodyBitOffset = 0;
        NTSTATUS status = HttpExiParseHeader(
            preCompression,
            sizeof(preCompression),
            &options,
            &bodyBitOffset);
        Expect(
            NT_SUCCESS(status) &&
                options.Alignment == HttpExiAlignment::PreCompression &&
                (bodyBitOffset % 8) == 0,
            "EXI options parser selects pre-compression alignment");
        ExpectSimpleDocumentDecodes(
            preCompression,
            sizeof(preCompression),
            "EXI pre-compression channel ordering decodes");

        options = {};
        bodyBitOffset = 0;
        status = HttpExiParseHeader(compression, sizeof(compression), &options, &bodyBitOffset);
        Expect(
            NT_SUCCESS(status) &&
                options.Alignment == HttpExiAlignment::Compression &&
                (bodyBitOffset % 8) == 0,
            "EXI options parser selects compression alignment");
        ExpectSimpleDocumentDecodes(
            compression,
            sizeof(compression),
            "EXI compression channel stream decodes");
    }

    void TestBuiltInGrammarLearning()
    {
        const unsigned char repeatedBitPacked[] = {
            0x80, 0x41, 0x5c, 0x9b, 0xdb, 0xdd, 0x24, 0x15,
            0xa5, 0xd1, 0x95, 0xb7, 0x03, 0x61, 0x48, 0x04,
            0x06, 0xc4, 0x40
        };
        const unsigned char repeatedByteAligned[] = {
            0xa0, 0x00, 0x4a, 0x01, 0x05, 0x72, 0x6f, 0x6f,
            0x74, 0x02, 0x01, 0x05, 0x69, 0x74, 0x65, 0x6d,
            0x03, 0x03, 0x61, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x03, 0x62, 0x00, 0x01
        };
        const char expected[] = "<root><item>a</item><item>b</item></root>";

        char output[96] = {};
        SIZE_T outputLength = 0;
        NTSTATUS status = DecodeExiContent(
            repeatedBitPacked,
            sizeof(repeatedBitPacked),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI bit-packed built-in grammar learns repeated productions");

        RtlZeroMemory(output, sizeof(output));
        outputLength = 0;
        status = DecodeExiContent(
            repeatedByteAligned,
            sizeof(repeatedByteAligned),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI byte-aligned built-in grammar learns repeated productions");
    }

    void TestPreservedNamespaceAndAttribute()
    {
        const unsigned char encoded[] = {
            0xa0, 0x09, 0xf0, 0x10, 0xea, 0xe4, 0xdc, 0x74,
            0xe8, 0xca, 0xe6, 0xe8, 0x0a, 0xe4, 0xde, 0xde,
            0xe8, 0xa0, 0x0b, 0x84, 0xc0, 0x26, 0x10, 0x37,
            0x8c, 0x06, 0x74, 0x65, 0x78, 0x74, 0x00
        };
        const char expected[] =
            "<p:root xmlns:p=\"urn:test\" p:a=\"x\">text</p:root>";
        char output[128] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            sizeof(encoded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI preserved prefix, namespace, and attribute decode");
    }

    void TestSynthesizedNamespacePrefix()
    {
        const unsigned char encoded[] = {
            0x80, 0x02, 0x1d, 0x5c, 0x9b, 0x8e, 0x9d, 0x19,
            0x5c, 0xdd, 0x01, 0x5c, 0x9b, 0xdb, 0xdd, 0x18,
            0x04, 0xc2, 0x06, 0xf1, 0xc1, 0x9d, 0x19, 0x5e,
            0x1d, 0x00
        };
        const char expected[] =
            "<ns0:root xmlns:ns0=\"urn:test\" ns0:a=\"x\">text</ns0:root>";
        char output[160] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            sizeof(encoded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI decoder synthesizes deterministic namespace prefixes");
    }

    void TestLocalAndGlobalValuePartitions()
    {
        const unsigned char encoded[] = {
            0x80, 0x41, 0x5c, 0x9b, 0xdb, 0xdd, 0x24, 0x09,
            0x87, 0x06, 0x73, 0x61, 0x6d, 0x65, 0x48, 0x04,
            0x00, 0x88, 0x13, 0x16, 0x02, 0x80
        };
        const char expected[] =
            "<root><a>same</a><a>same</a><b>same</b></root>";
        char output[160] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            sizeof(encoded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI local and global value partition hits decode");
    }

    void TestBoundedValuePartitionsAndValueMaxLength()
    {
        const unsigned char bounded[] = {
            0xa0, 0x03, 0x02, 0xd2, 0x0a, 0xe4, 0xde, 0xde,
            0xe9, 0x20, 0x4c, 0x38, 0x2b, 0x7b, 0x73, 0x2a,
            0x40, 0x98, 0xb0, 0x57, 0x47, 0x76, 0xf4, 0x40,
            0x98, 0xf0, 0x77, 0x46, 0x87, 0x26, 0x56, 0x56,
            0x40, 0x10, 0x2b, 0x7b, 0x73, 0x28, 0x00, 0x26
        };
        const char boundedExpected[] =
            "<root><a>one</a><b>two</b><c>three</c><a>one</a><a>one</a></root>";
        char output[192] = {};
        SIZE_T outputLength = 0;
        NTSTATUS status = DecodeExiContent(
            bounded,
            sizeof(bounded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(boundedExpected) - 1 &&
                memcmp(output, boundedExpected, sizeof(boundedExpected) - 1) == 0,
            "EXI bounded value partition evicts and reassigns global slots");

        const unsigned char maxLength[] = {
            0xa0, 0x02, 0x01, 0xa9, 0x05, 0x72, 0x6f, 0x6f,
            0x74, 0x90, 0x26, 0x1c, 0x19, 0xb1, 0xbd, 0xb9,
            0x9d, 0x20, 0x10, 0x33, 0x63, 0x7b, 0x73, 0x39
        };
        const char maxLengthExpected[] =
            "<root><a>long</a><a>long</a></root>";
        RtlZeroMemory(output, sizeof(output));
        outputLength = 0;
        status = DecodeExiContent(
            maxLength,
            sizeof(maxLength),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(maxLengthExpected) - 1 &&
                memcmp(output, maxLengthExpected, sizeof(maxLengthExpected) - 1) == 0,
            "EXI valueMaxLength excludes long values from partitions");
    }

    void TestEvictedLocalValueIdentifierIsInvalid()
    {
        HttpExiValueTable table = {};
        NTSTATUS status = table.Initialize(8, 64, 0xffffffffUL, 2);
        Expect(NT_SUCCESS(status), "EXI bounded value table initializes");

        HttpXmlText stored = {};
        status = table.AddLiteral(7, 3, { "one", 3 }, &stored);
        Expect(NT_SUCCESS(status), "EXI bounded table adds first local value");
        status = table.AddLiteral(7, 3, { "two", 3 }, &stored);
        Expect(NT_SUCCESS(status), "EXI bounded table adds second local value");
        status = table.AddLiteral(7, 5, { "three", 5 }, &stored);
        Expect(NT_SUCCESS(status), "EXI bounded table evicts first local value");

        const unsigned char evictedId[] = { 0x00 };
        HttpExiBitInput evictedInput(evictedId, sizeof(evictedId));
        HttpXmlText value = {};
        status = table.ReadLocal(&evictedInput, 7, &value);
        Expect(
            status == STATUS_INVALID_NETWORK_RESPONSE,
            "EXI evicted local compact identifier is permanently invalid");

        const unsigned char currentId[] = { 0x80 };
        HttpExiBitInput currentInput(currentId, sizeof(currentId));
        value = {};
        status = table.ReadLocal(&currentInput, 7, &value);
        Expect(
            NT_SUCCESS(status) &&
                value.Length == 5 &&
                memcmp(value.Data, "three", 5) == 0,
            "EXI later local compact identifier remains addressable after eviction");
    }

    void TestFragmentGrammar()
    {
        const unsigned char encoded[] = {
            0xa0, 0x2e, 0x40, 0x98, 0x70, 0x56, 0xf6, 0xe6,
            0x52, 0x81, 0x31, 0x60, 0xae, 0x8e, 0xed, 0xe4,
            0x0e, 0xe8, 0xd0, 0xe4, 0xca, 0xca, 0xc0
        };
        const char expected[] =
            "<a>one</a><b>two</b><a>three</a>";
        char output[128] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            sizeof(encoded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI fragment grammar decodes multiple root elements and learns root QNames");
    }

    void TestReorderedNamespaceEvents()
    {
        const unsigned char preCompression[] = {
            0xa0, 0x00, 0xc0, 0xf8, 0x00, 0x08, 0x75, 0x72,
            0x6e, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x05, 0x72,
            0x6f, 0x6f, 0x74, 0x02, 0x04, 0x01, 0x70, 0x01,
            0x01, 0x04, 0x02, 0x61, 0x01, 0x04, 0x00, 0x03,
            0x78, 0x06, 0x74, 0x65, 0x78, 0x74
        };
        const unsigned char compression[] = {
            0xa0, 0x09, 0xe1, 0x40, 0x63, 0xe0, 0x28, 0x2d,
            0xca, 0xb3, 0x2a, 0x49, 0x2d, 0x2e, 0x61, 0x2d,
            0xca, 0xcf, 0x2f, 0x61, 0x62, 0x61, 0x2c, 0x60,
            0x64, 0x64, 0x61, 0x4a, 0x64, 0x64, 0x61, 0x60,
            0xae, 0x60, 0x2b, 0x49, 0xad, 0x28, 0x01, 0x00
        };
        const char expected[] =
            "<p:root xmlns:p=\"urn:test\" p:a=\"x\">text</p:root>";
        const unsigned char* streams[] = { preCompression, compression };
        const size_t lengths[] = { sizeof(preCompression), sizeof(compression) };
        const char* messages[] = {
            "EXI pre-compression namespace structure event decodes",
            "EXI compression namespace structure event decodes"
        };
        for (size_t index = 0; index < 2; ++index) {
            char output[160] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                NT_SUCCESS(status) &&
                    outputLength == sizeof(expected) - 1 &&
                    memcmp(output, expected, sizeof(expected) - 1) == 0,
                messages[index]);
        }
    }

    void TestMultipleCompressionBlocks()
    {
        const unsigned char preCompression[] = {
            0xa0, 0x00, 0xc4, 0x06, 0x01, 0x05, 0x72, 0x6f,
            0x6f, 0x74, 0x02, 0x01, 0x02, 0x61, 0x03, 0x05,
            0x6f, 0x6e, 0x65, 0x00, 0x01, 0x00, 0x01, 0x02,
            0x62, 0x03, 0x05, 0x74, 0x77, 0x6f, 0x00, 0x02,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0x74, 0x68,
            0x72, 0x65, 0x65, 0x00, 0x02
        };
        const unsigned char compression[] = {
            0xa0, 0x10, 0x08, 0x50, 0x63, 0x64, 0x2d, 0xca,
            0xcf, 0x2f, 0x61, 0x62, 0x64, 0x4a, 0x64, 0x66,
            0xcd, 0xcf, 0x4b, 0x05, 0x00, 0x63, 0x60, 0x64,
            0x60, 0x64, 0x4a, 0x62, 0x66, 0x2d, 0x29, 0xcf,
            0x07, 0x00, 0x63, 0x60, 0x62, 0x60, 0x04, 0x42,
            0xf6, 0x92, 0x8c, 0xa2, 0xd4, 0x54, 0x00, 0x63,
            0x60, 0x02, 0x00
        };
        const char expected[] =
            "<root><a>one</a><b>two</b><a>three</a></root>";
        const unsigned char* streams[] = { preCompression, compression };
        const size_t lengths[] = { sizeof(preCompression), sizeof(compression) };
        const char* messages[] = {
            "EXI pre-compression keeps grammar and value state across blocks",
            "EXI compression decodes concatenated raw-DEFLATE block streams"
        };
        for (size_t index = 0; index < 2; ++index) {
            char output[160] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                NT_SUCCESS(status) &&
                    outputLength == sizeof(expected) - 1 &&
                    memcmp(output, expected, sizeof(expected) - 1) == 0,
                messages[index]);
        }
    }

    void TestFidelityEvents()
    {
        const unsigned char bitPacked[] = {
            0xa0, 0x08, 0x4d, 0x02, 0x39, 0x37, 0xb7, 0xba,
            0x00, 0x03, 0xba, 0xb9, 0x37, 0x1d, 0x39, 0xbc,
            0xb9, 0x8a, 0x9e, 0x10, 0xa2, 0xa7, 0x2a, 0x24,
            0xaa, 0x2c, 0x90, 0x32, 0xb7, 0x3a, 0x10, 0x11,
            0x3b, 0x30, 0xb6, 0x3a, 0xb2, 0x91, 0x1f, 0x60,
            0x66, 0x26, 0x56, 0x66, 0xf7, 0x26, 0x5e, 0x06,
            0xe0, 0xe4, 0xca, 0x08, 0xc8, 0xc2, 0xe8, 0xc2,
            0x41, 0x5c, 0x9b, 0xdb, 0xdd, 0x28, 0x19, 0xa5,
            0xb9, 0xcd, 0xa5, 0x91, 0x97, 0xc1, 0x5a, 0x5b,
            0x9b, 0x99, 0x5c, 0x81, 0x5d, 0x98, 0x5b, 0x1d,
            0x59, 0x70, 0x1b, 0x2b, 0x73, 0xa2, 0x05, 0x61,
            0x66, 0x74, 0x65, 0x72, 0xc1, 0x1c, 0x1b, 0xdc,
            0xdd, 0x01, 0x19, 0x1b, 0xdb, 0x99, 0x40
        };
        const unsigned char preCompression[] = {
            0xa0, 0x00, 0xc0, 0x26, 0x01, 0x00, 0x04, 0x72,
            0x6f, 0x6f, 0x74, 0x00, 0x07, 0x75, 0x72, 0x6e,
            0x3a, 0x73, 0x79, 0x73, 0x15, 0x3c, 0x21, 0x45,
            0x4e, 0x54, 0x49, 0x54, 0x59, 0x20, 0x65, 0x6e,
            0x74, 0x20, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65,
            0x22, 0x3e, 0x01, 0x01, 0x00, 0x06, 0x62, 0x65,
            0x66, 0x6f, 0x72, 0x65, 0x01, 0x01, 0x01, 0x03,
            0x70, 0x72, 0x65, 0x04, 0x64, 0x61, 0x74, 0x61,
            0x00, 0x01, 0x05, 0x72, 0x6f, 0x6f, 0x74, 0x05,
            0x00, 0x06, 0x69, 0x6e, 0x73, 0x69, 0x64, 0x65,
            0x01, 0x03, 0x01, 0x05, 0x69, 0x6e, 0x6e, 0x65,
            0x72, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x01,
            0x02, 0x03, 0x65, 0x6e, 0x74, 0x00, 0x01, 0x00,
            0x05, 0x61, 0x66, 0x74, 0x65, 0x72, 0x01, 0x01,
            0x04, 0x70, 0x6f, 0x73, 0x74, 0x04, 0x64, 0x6f,
            0x6e, 0x65, 0x00
        };
        const char expected[] =
            "<!DOCTYPE root SYSTEM \"urn:sys\" [<!ENTITY ent \"value\">]>"
            "<!--before--><?pre data?><root><!--inside--><?inner value?>"
            "&ent;</root><!--after--><?post done?>";
        const unsigned char* streams[] = { bitPacked, preCompression };
        const size_t lengths[] = { sizeof(bitPacked), sizeof(preCompression) };
        const char* messages[] = {
            "EXI bit-packed DTD, comment, PI, and entity events decode",
            "EXI pre-compression fidelity structure events decode"
        };
        for (size_t index = 0; index < 2; ++index) {
            char output[320] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                NT_SUCCESS(status) &&
                    outputLength == sizeof(expected) - 1 &&
                    memcmp(output, expected, sizeof(expected) - 1) == 0,
                messages[index]);
        }
    }

    void TestLargeAndSmallCompressionChannels()
    {
        const unsigned char encoded[] = {
            0xa0, 0x25, 0x63, 0x64, 0x2d, 0xca, 0xcf, 0x2f,
            0x61, 0x62, 0x64, 0xcb, 0x49, 0x2c, 0x4a, 0x4f,
            0x65, 0x66, 0x60, 0x64, 0x60, 0x64, 0x2b, 0xce,
            0x4d, 0xcc, 0xc9, 0x01, 0x32, 0xd3, 0x2b, 0xe8,
            0x01, 0x98, 0x2b, 0x01
        };
        char expected[192] = {};
        size_t expectedLength = 0;
        const char prefix[] = "<root><large>";
        const char suffix[] = "</large><small>y</small></root>";
        memcpy(expected + expectedLength, prefix, sizeof(prefix) - 1);
        expectedLength += sizeof(prefix) - 1;
        for (size_t index = 0; index < 101; ++index) {
            expected[expectedLength++] = 'x';
        }
        memcpy(expected + expectedLength, suffix, sizeof(suffix) - 1);
        expectedLength += sizeof(suffix) - 1;

        char output[192] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            sizeof(encoded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == expectedLength &&
                memcmp(output, expected, expectedLength) == 0,
            "EXI compression separates small and greater-than-100 value channels");
    }

    void TestXsiTypeQNameValue()
    {
        const unsigned char bitPacked[] = {
            0xa0, 0x09, 0xf2, 0x0a, 0xe4, 0xde, 0xde, 0xe8,
            0xb9, 0x04, 0x0d, 0x0e, 0x8e, 0x8e, 0x07, 0x45,
            0xe5, 0xee, 0xee, 0xee, 0xe5, 0xce, 0xe6, 0x65,
            0xcd, 0xee, 0x4c, 0xe5, 0xe6, 0x46, 0x06, 0x06,
            0x25, 0xeb, 0x09, 0xa9, 0x8a, 0x6c, 0x6d, 0x0c,
            0xad, 0xac, 0x20, 0x6f, 0x0e, 0x6c, 0x82, 0xc0,
            0x30, 0x1d, 0xcd, 0xd1, 0xc9, 0xa5, 0xb9, 0x9e,
            0x00
        };
        const unsigned char preCompression[] = {
            0xa0, 0x00, 0xc0, 0xf8, 0x01, 0x05, 0x72, 0x6f,
            0x6f, 0x74, 0x02, 0x03, 0x01, 0x00, 0x02, 0x00,
            0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
            0x77, 0x77, 0x77, 0x2e, 0x77, 0x33, 0x2e, 0x6f,
            0x72, 0x67, 0x2f, 0x32, 0x30, 0x30, 0x31, 0x2f,
            0x58, 0x4d, 0x4c, 0x53, 0x63, 0x68, 0x65, 0x6d,
            0x61, 0x03, 0x78, 0x73, 0x64, 0x00, 0x01, 0x03,
            0x00, 0x01, 0x04, 0x07, 0x73, 0x74, 0x72, 0x69,
            0x6e, 0x67, 0x01, 0x00
        };
        const char expected[] =
            "<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
            "xsi:type=\"xsd:string\"></root>";
        const unsigned char* streams[] = { bitPacked, preCompression };
        const size_t lengths[] = { sizeof(bitPacked), sizeof(preCompression) };
        const char* messages[] = {
            "EXI bit-packed xsi:type QName value decodes",
            "EXI pre-compression xsi:type QName value channel decodes"
        };
        for (size_t index = 0; index < 2; ++index) {
            char output[256] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                NT_SUCCESS(status) &&
                    outputLength == sizeof(expected) - 1 &&
                    memcmp(output, expected, sizeof(expected) - 1) == 0,
                messages[index]);
        }
    }

    void TestSelfContainedElementsResetAndRestoreState()
    {
        const unsigned char bitPacked[] = {
            0xa0, 0x01, 0xe9, 0x05, 0x72, 0x6f, 0x6f, 0x74,
            0x68, 0x2b, 0x4b, 0xa3, 0x2b, 0x6a, 0x20, 0xad,
            0x2e, 0x8c, 0xad, 0xb0, 0x15, 0xbd, 0xb9, 0x95,
            0x00, 0x90, 0x0a, 0x20, 0xad, 0x2e, 0x8c, 0xad,
            0xb0, 0x15, 0xd1, 0xdd, 0xbd, 0x00, 0x40
        };
        const unsigned char byteAligned[] = {
            0xa0, 0x00, 0x0e, 0x80, 0x01, 0x05, 0x72, 0x6f,
            0x6f, 0x74, 0x03, 0x01, 0x05, 0x69, 0x74, 0x65,
            0x6d, 0x02, 0x00, 0x01, 0x05, 0x69, 0x74, 0x65,
            0x6d, 0x04, 0x05, 0x6f, 0x6e, 0x65, 0x00, 0x02,
            0x01, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x01,
            0x05, 0x69, 0x74, 0x65, 0x6d, 0x04, 0x05, 0x74,
            0x77, 0x6f, 0x00, 0x02, 0x01
        };
        const char expected[] =
            "<root><item>one</item><item>two</item></root>";
        const unsigned char* streams[] = { bitPacked, byteAligned };
        const size_t lengths[] = { sizeof(bitPacked), sizeof(byteAligned) };
        const char* messages[] = {
            "EXI bit-packed selfContained element resets and restores learned state",
            "EXI byte-aligned selfContained element resets and restores learned state"
        };
        for (size_t index = 0; index < 2; ++index) {
            char output[160] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                NT_SUCCESS(status) &&
                    outputLength == sizeof(expected) - 1 &&
                    memcmp(output, expected, sizeof(expected) - 1) == 0,
                messages[index]);
        }
    }

    void TestBuiltInXmlSchemaTypedValues()
    {
        const unsigned char booleanValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x01, 0xe8
        };
        const unsigned char booleanByteAligned[] = {
            0xa0, 0x00, 0x40, 0xf2, 0x01, 0x40, 0x01, 0x05,
            0x72, 0x6f, 0x6f, 0x74, 0x02, 0x03, 0x01, 0x00,
            0x02, 0x04, 0x03, 0x78, 0x73, 0x64, 0x00, 0x01,
            0x03, 0x00, 0x01, 0x04, 0x00, 0x0f, 0x00, 0x01,
            0x00
        };
        const unsigned char booleanPreCompression[] = {
            0xa0, 0x00, 0xc0, 0xf2, 0x01, 0x40, 0x01, 0x05,
            0x72, 0x6f, 0x6f, 0x74, 0x02, 0x03, 0x01, 0x00,
            0x02, 0x04, 0x03, 0x78, 0x73, 0x64, 0x00, 0x01,
            0x03, 0x00, 0x01, 0x04, 0x00, 0x0f, 0x00, 0x00,
            0x01
        };
        const unsigned char booleanCompression[] = {
            0xa0, 0x09, 0xe0, 0x80, 0xa0, 0x63, 0x64, 0x2d,
            0xca, 0xcf, 0x2f, 0x61, 0x62, 0x66, 0x64, 0x60,
            0x62, 0x61, 0xae, 0x28, 0x4e, 0x61, 0x60, 0x64,
            0x66, 0x60, 0x64, 0x61, 0xe0, 0x67, 0x60, 0x60,
            0x04, 0x00
        };
        const unsigned char integerValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x03, 0xc9, 0x48
        };
        const unsigned char decimalValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x02, 0x68, 0x61, 0x58
        };
        const unsigned char floatValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x02, 0xc3, 0xdc, 0x04
        };
        const unsigned char base64Value[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x01, 0xc0, 0x40, 0x00, 0x10, 0x2f,
            0xf0
        };
        const unsigned char hexValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x03, 0x80, 0x40, 0x00, 0x10, 0x2f,
            0xf0
        };
        const unsigned char stringValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x04, 0xe0, 0x76, 0x86, 0x56, 0xc6,
            0xc6, 0xf0
        };
        const unsigned char intValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x03, 0xa9, 0x48
        };
        const unsigned char unsignedIntValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x05, 0x62, 0xa0
        };
        const unsigned char byteValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x02, 0x05, 0x60
        };
        const unsigned char nonNegativeIntegerValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x04, 0x42, 0xa0
        };
        const unsigned char dateTimeValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x02, 0x40, 0xc2, 0x98, 0xe4, 0x13,
            0xc1, 0x02, 0xb8, 0x00
        };
        const unsigned char dateValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x02, 0x20, 0xc2, 0x9a, 0xe0, 0x00
        };
        const unsigned char timeValue[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6,
            0xf7, 0x44, 0xe5, 0x00, 0xde, 0x1c, 0xd9, 0x05,
            0x80, 0x60, 0x05, 0x03, 0x90, 0x4a, 0xe0, 0x00
        };
        const unsigned char* streams[] = {
            booleanValue,
            booleanByteAligned,
            booleanPreCompression,
            booleanCompression,
            integerValue,
            decimalValue,
            floatValue,
            base64Value,
            hexValue,
            stringValue,
            intValue,
            unsignedIntValue,
            byteValue,
            nonNegativeIntegerValue,
            dateTimeValue,
            dateValue,
            timeValue
        };
        const size_t lengths[] = {
            sizeof(booleanValue),
            sizeof(booleanByteAligned),
            sizeof(booleanPreCompression),
            sizeof(booleanCompression),
            sizeof(integerValue),
            sizeof(decimalValue),
            sizeof(floatValue),
            sizeof(base64Value),
            sizeof(hexValue),
            sizeof(stringValue),
            sizeof(intValue),
            sizeof(unsignedIntValue),
            sizeof(byteValue),
            sizeof(nonNegativeIntegerValue),
            sizeof(dateTimeValue),
            sizeof(dateValue),
            sizeof(timeValue)
        };
        const char* typeNames[] = {
            "boolean", "boolean", "boolean", "boolean", "integer", "decimal",
            "float", "base64Binary", "hexBinary", "string", "int", "unsignedInt",
            "byte", "nonNegativeInteger", "dateTime", "date", "time"
        };
        const char* lexicalValues[] = {
            "true", "true", "true", "true", "-42", "-12.34", "123E-2",
            "AAEC/w==", "000102FF", "hello", "-42", "42", "-42", "42",
            "2024-05-06T07:08:09.123Z", "2024-05-06Z", "07:08:09Z"
        };
        const char* messages[] = {
            "EXI built-in xsd:boolean typed value decodes",
            "EXI byte-aligned built-in xsd:boolean typed value decodes",
            "EXI pre-compression built-in xsd:boolean typed value decodes",
            "EXI compression built-in xsd:boolean typed value decodes",
            "EXI built-in xsd:integer typed value decodes",
            "EXI built-in xsd:decimal typed value decodes",
            "EXI built-in xsd:float typed value decodes",
            "EXI built-in xsd:base64Binary typed value decodes",
            "EXI built-in xsd:hexBinary typed value decodes",
            "EXI built-in xsd:string typed value uses value partitions",
            "EXI built-in xsd:int bounded value decodes",
            "EXI built-in xsd:unsignedInt bounded value decodes",
            "EXI built-in xsd:byte bounded value decodes",
            "EXI built-in xsd:nonNegativeInteger value decodes",
            "EXI built-in xsd:dateTime value decodes",
            "EXI built-in xsd:date value decodes",
            "EXI built-in xsd:time value decodes"
        };
        for (size_t index = 0; index < sizeof(streams) / sizeof(streams[0]); ++index) {
            char expected[320] = {};
            const int expectedLength = snprintf(
                expected,
                sizeof(expected),
                "<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
                "xsi:type=\"xsd:%s\">%s</root>",
                typeNames[index],
                lexicalValues[index]);
            char output[320] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                expectedLength > 0 &&
                    NT_SUCCESS(status) &&
                    outputLength == static_cast<SIZE_T>(expectedLength) &&
                    memcmp(output, expected, outputLength) == 0,
                messages[index]);
        }
    }

    void TestSchemaLessDatatypeRepresentationMapIsConsumed()
    {
        const unsigned char encoded[] = {
            0xa0, 0x04, 0x80, 0x09, 0x94, 0x02, 0x23, 0x48,
            0x2b, 0x93, 0x7b, 0x7b, 0xa6, 0x10, 0x62, 0x64,
            0x5c, 0x66, 0x68, 0x60
        };
        const char expected[] = "<root>12.340</root>";
        char output[96] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            sizeof(encoded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI schema-less stream consumes and ignores datatype representation map");
    }

    void TestPreservedLexicalBooleanValue()
    {
        const unsigned char encoded[] = {
            0xa0, 0x09, 0x29, 0x00, 0xa4, 0x15, 0xc9, 0xbd,
            0xbd, 0xd1, 0x39, 0x40, 0x37, 0x87, 0x36, 0x41,
            0x60, 0x10, 0xd7, 0x87, 0x36, 0x43, 0xa6, 0x26,
            0xf6, 0xf6, 0xc6, 0x56, 0x16, 0xe0, 0x1a, 0x80
        };
        const char expected[] =
            "<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
            "xsi:type=\"xsd:boolean\">1</root>";
        char output[256] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodeExiContent(
            encoded,
            sizeof(encoded),
            output,
            sizeof(output),
            &outputLength);
        Expect(
            NT_SUCCESS(status) &&
                outputLength == sizeof(expected) - 1 &&
                memcmp(output, expected, sizeof(expected) - 1) == 0,
            "EXI lexicalValues preserves the boolean lexical form instead of canonicalizing it");
    }

    void TestPreservedLexicalRestrictedCharacterSets()
    {
        const unsigned char decimalValue[] = {
            0xa0, 0x09, 0x29, 0x00, 0xa4, 0x15, 0xc9, 0xbd, 0xbd, 0xd1,
            0x39, 0x40, 0x37, 0x87, 0x36, 0x41, 0x60, 0x10, 0xd7, 0x87,
            0x36, 0x43, 0xa6, 0x46, 0x56, 0x36, 0x96, 0xd6, 0x16, 0xc0,
            0x59, 0x0e, 0x74, 0x19, 0x2a, 0x39, 0xc0
        };
        const unsigned char doubleValue[] = {
            0xa0, 0x09, 0x29, 0x00, 0xa4, 0x15, 0xc9, 0xbd, 0xbd, 0xd1,
            0x39, 0x40, 0x37, 0x87, 0x36, 0x41, 0x60, 0x10, 0xc7, 0x87,
            0x36, 0x43, 0xa6, 0x46, 0xf7, 0x56, 0x26, 0xc6, 0x50, 0x31,
            0x67, 0x49, 0x00
        };
        const unsigned char dateTimeValue[] = {
            0xa0, 0x09, 0x29, 0x00, 0xa4, 0x15, 0xc9, 0xbd, 0xbd, 0xd1,
            0x39, 0x40, 0x37, 0x87, 0x36, 0x41, 0x60, 0x10, 0xe7, 0x87,
            0x36, 0x43, 0xa6, 0x46, 0x17, 0x46, 0x55, 0x46, 0x96, 0xd6,
            0x50, 0xb2, 0x4e, 0x95, 0x94, 0xec, 0x29, 0xdb, 0x23, 0xba,
            0x27, 0x7c, 0x4f, 0x09, 0x80
        };
        const unsigned char integerValue[] = {
            0xa0, 0x09, 0x29, 0x00, 0xa4, 0x15, 0xc9, 0xbd, 0xbd, 0xd1,
            0x39, 0x40, 0x37, 0x87, 0x36, 0x41, 0x60, 0x10, 0xd7, 0x87,
            0x36, 0x43, 0xa6, 0x96, 0xe7, 0x46, 0x56, 0x76, 0x57, 0x20,
            0x41, 0x0c, 0x63, 0x29, 0x00
        };
        const unsigned char base64Value[] = {
            0xa0, 0x09, 0x29, 0x00, 0xa4, 0x15, 0xc9, 0xbd, 0xbd, 0xd1,
            0x39, 0x40, 0x37, 0x87, 0x36, 0x41, 0x60, 0x11, 0x27, 0x87,
            0x36, 0x43, 0xa6, 0x26, 0x17, 0x36, 0x53, 0x63, 0x44, 0x26,
            0x96, 0xe6, 0x17, 0x27, 0x90, 0x51, 0x12, 0x25, 0x49, 0x85,
            0x82, 0x40, 0x80
        };
        const unsigned char hexValue[] = {
            0xa0, 0x09, 0x29, 0x00, 0xa4, 0x15, 0xc9, 0xbd, 0xbd, 0xd1,
            0x39, 0x40, 0x37, 0x87, 0x36, 0x41, 0x60, 0x10, 0xf7, 0x87,
            0x36, 0x43, 0xa6, 0x86, 0x57, 0x84, 0x26, 0x96, 0xe6, 0x17,
            0x27, 0x90, 0x31, 0x09, 0x9c, 0x80
        };
        const unsigned char* streams[] = {
            decimalValue, doubleValue, dateTimeValue, integerValue, base64Value, hexValue
        };
        const SIZE_T lengths[] = {
            sizeof(decimalValue), sizeof(doubleValue), sizeof(dateTimeValue),
            sizeof(integerValue), sizeof(base64Value), sizeof(hexValue)
        };
        const char* typeNames[] = {
            "decimal", "double", "dateTime", "integer", "base64Binary", "hexBinary"
        };
        const char* values[] = {
            "+001.2300", "-INF", "2024-05-06T07:08:09Z", "+00042", "AAEC/w==", "00ff"
        };
        for (SIZE_T index = 0; index < sizeof(streams) / sizeof(streams[0]); ++index) {
            char expected[320] = {};
            const int expectedLength = snprintf(
                expected,
                sizeof(expected),
                "<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
                "xsi:type=\"xsd:%s\">%s</root>",
                typeNames[index],
                values[index]);
            char output[320] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                expectedLength > 0 && NT_SUCCESS(status) &&
                    outputLength == static_cast<SIZE_T>(expectedLength) &&
                    memcmp(output, expected, outputLength) == 0,
                "EXI lexicalValues decodes the built-in restricted character set");
        }
    }

    void TestXsiNilBuiltInGrammar()
    {
        const unsigned char bitPacked[] = {
            0xa0, 0x09, 0xe4, 0x02, 0x90, 0x57, 0x26, 0xf6, 0xf7, 0x44,
            0xe2, 0xc0, 0x00, 0xce, 0x8e, 0x4e, 0xac, 0xb0
        };
        const unsigned char preCompression[] = {
            0xa0, 0x00, 0xc0, 0xf2, 0x01, 0x40, 0x01, 0x05, 0x72, 0x6f,
            0x6f, 0x74, 0x02, 0x03, 0x01, 0x00, 0x01, 0x03, 0x00, 0x00,
            0x01, 0x00, 0x06, 0x74, 0x72, 0x75, 0x65
        };
        const unsigned char byteAligned[] = {
            0xa0, 0x00, 0x40, 0xf2, 0x01, 0x40, 0x01, 0x05, 0x72, 0x6f,
            0x6f, 0x74, 0x02, 0x03, 0x01, 0x00, 0x01, 0x03, 0x00, 0x00,
            0x06, 0x74, 0x72, 0x75, 0x65, 0x01, 0x00
        };
        const unsigned char compression[] = {
            0xa0, 0x09, 0xe0, 0x80, 0xa0, 0x63, 0x64, 0x2d, 0xca, 0xcf,
            0x2f, 0x61, 0x62, 0x66, 0x64, 0x60, 0x64, 0x66, 0x60, 0x60,
            0x64, 0x60, 0x2b, 0x29, 0x2a, 0x4d, 0x05, 0x00
        };
        const unsigned char* streams[] = {
            bitPacked, byteAligned, preCompression, compression
        };
        const SIZE_T lengths[] = {
            sizeof(bitPacked), sizeof(byteAligned), sizeof(preCompression), sizeof(compression)
        };
        const char expected[] =
            "<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
            "xsi:nil=\"true\"></root>";
        const char* messages[] = {
            "EXI bit-packed xsi:nil built-in grammar decodes",
            "EXI byte-aligned xsi:nil built-in grammar decodes",
            "EXI pre-compression xsi:nil value channel decodes",
            "EXI compression xsi:nil value channel decodes"
        };
        for (SIZE_T index = 0; index < sizeof(streams) / sizeof(streams[0]); ++index) {
            char output[192] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodeExiContent(
                streams[index],
                lengths[index],
                output,
                sizeof(output),
                &outputLength);
            Expect(
                NT_SUCCESS(status) &&
                    outputLength == sizeof(expected) - 1 &&
                    memcmp(output, expected, sizeof(expected) - 1) == 0,
                messages[index]);
        }
    }

    void TestOfflineExificientCorpus()
    {
        struct Fixture final
        {
            const char* Name;
            const char* Expected;
            const char* Sha256;
        };
        const Fixture fixtures[] = {
            { "basic-bit-packed.exi", "basic.expected.xml", "80a2093d5fe146977034a75659445656c34a24675832c9d00448bced09279829" },
            { "basic-byte-aligned.exi", "basic.expected.xml", "3d3db91ae422d607dceec06084668fa744ee84d1fdb3bd1b2230ddca0e010c58" },
            { "basic-pre-compression.exi", "basic.expected.xml", "ab05714b2ed333428ee17f69d42cee1a953e722fa69ebafc1997d77cdeb6811d" },
            { "basic-compression.exi", "basic.expected.xml", "a250ea98c2a41c55640de9b6b31cce75f69d87d0cb285e21bd9aaeb565910878" },
            { "xsi-nil-true-bit-packed.exi", "xsi-nil-true.expected.xml", "d50c44689d5dad40f3cc9f733977cc3e03de0b991ab3a5ecc0264132ab60b046" },
            { "xsi-nil-true-byte-aligned.exi", "xsi-nil-true.expected.xml", "62287f52459633def2dd1ac9237b89b6f52a0c985a5d13e7adf0e403ab497730" },
            { "xsi-nil-true-pre-compression.exi", "xsi-nil-true.expected.xml", "71aadaf8e9049847f0e5648246bc5a7084199baad7d3cb78ae5c0248c6509b06" },
            { "xsi-nil-true-compression.exi", "xsi-nil-true.expected.xml", "87bf682bf908877e66f7552307d8d44a50328f6526b03ec16cc02d80525b3957" },
            { "xsi-nil-false-bit-packed.exi", "xsi-nil-false.expected.xml", "d62f21d81f78aee084c222a654172b9958630df579bd07ce1eb5ed018bf777c5" },
            { "xsi-nil-false-byte-aligned.exi", "xsi-nil-false.expected.xml", "fe68089848b90ee56d62dd05c11fe2a95a8770d9fc9dc248e93f8c17f1bf9d34" },
            { "xsi-nil-false-pre-compression.exi", "xsi-nil-false.expected.xml", "15f4ba0facc7c8b87dd464dae39da754e0c31576ce7461cab53c5d0904ad9a1c" },
            { "xsi-nil-false-compression.exi", "xsi-nil-false.expected.xml", "8d3f0279b8df14ac55f04f776231866031d9ac097e0cf784c0653de728371b1e" },
        };
        for (SIZE_T index = 0; index < sizeof(fixtures) / sizeof(fixtures[0]); ++index) {
            Expect(
                DecodeExiFixture(
                    fixtures[index].Name,
                    fixtures[index].Expected,
                    fixtures[index].Sha256),
                "EXIficient offline EXI corpus decodes with recorded SHA-256");
        }
        const Fixture invalidFixtures[] = {
            { "xsi-nil-invalid-content-bit-packed.exi", nullptr, "6e9f499077e5c67f7b70f4bbaf23d99e55f183be107252904dc3ea165e9b6eef" },
            { "xsi-nil-invalid-content-byte-aligned.exi", nullptr, "d02e783e92f4c939e5edefbde2c148ec447d383c20069ddc6c6e6b434f22ee1e" },
            { "xsi-nil-invalid-content-pre-compression.exi", nullptr, "05c0bf819082e05d4ce9ee7f7fdb402c64e7ab3140b9eff2c4afb62af55f1d2c" },
            { "xsi-nil-invalid-content-compression.exi", nullptr, "137cbe6891347d70ff0aa92faded51f02d7c2c2b8deca2bad7d4fbebdf890ba3" },
        };
        for (SIZE_T index = 0;
             index < sizeof(invalidFixtures) / sizeof(invalidFixtures[0]);
             ++index) {
            Expect(
                RejectExiFixture(invalidFixtures[index].Name, invalidFixtures[index].Sha256),
                "EXI xsi:nil=true content is rejected with recorded SHA-256");
        }
    }
}

int main()
{
    TestUnsignedIntegerRemainsBitPacked();
    TestLiteralStringDecodesUnicodeCodePoints();
    TestXmlWriterAcceptsUnicodeNamesAndEntities();
    TestSchemaLessBitPackedDocument();
    TestCookieOptionsAndByteAlignment();
    TestReorderedAlignmentsAreParsed();
    TestBuiltInGrammarLearning();
    TestPreservedNamespaceAndAttribute();
    TestSynthesizedNamespacePrefix();
    TestLocalAndGlobalValuePartitions();
    TestBoundedValuePartitionsAndValueMaxLength();
    TestEvictedLocalValueIdentifierIsInvalid();
    TestFragmentGrammar();
    TestReorderedNamespaceEvents();
    TestMultipleCompressionBlocks();
    TestFidelityEvents();
    TestLargeAndSmallCompressionChannels();
    TestXsiTypeQNameValue();
    TestSelfContainedElementsResetAndRestoreState();
    TestBuiltInXmlSchemaTypedValues();
    TestSchemaLessDatatypeRepresentationMapIsConsumed();
    TestPreservedLexicalBooleanValue();
    TestPreservedLexicalRestrictedCharacterSets();
    TestXsiNilBuiltInGrammar();
    TestOfflineExificientCorpus();

    if (g_failed) {
        return 1;
    }
    printf("PASS: EXI decoder tests\n");
    return 0;
}
