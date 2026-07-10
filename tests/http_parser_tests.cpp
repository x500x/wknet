#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/http/HttpParser.h>
#include <KernelHttp/http/HttpRequest.h>
#include <KernelHttp/http/HttpCachePolicy.h>
#include <KernelHttp/http/HttpContentEncoding.h>

#include "../src/KernelHttpLib/http/HttpXmlWriter.h"
#include "../src/KernelHttpLib/http/HttpExiEventReader.h"
#include "../src/KernelHttpLib/http/HttpExiGrammar.h"
#include "../src/KernelHttpLib/http/HttpExiGrammarTable.h"
#include "../src/KernelHttpLib/http/HttpExiQNameReader.h"
#include "../src/KernelHttpLib/http/HttpExiStringTable.h"
#include "../src/KernelHttpLib/http/HttpExiValueDecoder.h"
#include "../src/KernelHttpLib/http/HttpPack200BandCodec.h"
#include "../src/KernelHttpLib/http/HttpPack200BandParser.h"
#include "../src/KernelHttpLib/http/HttpPack200Bands.h"
#include "../src/KernelHttpLib/http/HttpPack200ClassWriter.h"
#include "../src/KernelHttpLib/http/HttpPack200Codec.h"
#include "../src/KernelHttpLib/http/HttpPack200Decoder.h"
#include "../src/KernelHttpLib/http/HttpPack200JarWriter.h"

#include <stdio.h>
#include <string.h>

using KernelHttp::http::HeaderValueHasToken;
using KernelHttp::http::HttpBodyKind;
using KernelHttp::http::HttpConnectionDirective;
using KernelHttp::http::HttpHeader;
using KernelHttp::http::HttpMethod;
using KernelHttp::http::HttpParseOptions;
using KernelHttp::http::HttpParser;
using KernelHttp::http::HttpRequestBuilder;
using KernelHttp::http::HttpRequestBodyMode;
using KernelHttp::http::HttpRequestBuildOptions;
using KernelHttp::http::HttpResponse;
using KernelHttp::http::HttpText;
using KernelHttp::http::MakeText;
using KernelHttp::http::TextEqualsIgnoreCase;
using KernelHttp::http::HttpCacheControl;
using KernelHttp::http::HttpCacheMetadata;
using KernelHttp::http::HttpByteRange;
using KernelHttp::http::HttpAcceptEncodingEntry;
using KernelHttp::http::HttpAcceptEncodingRules;
using KernelHttp::http::HttpContentEncoding;
using KernelHttp::http::HttpXmlName;
using KernelHttp::http::HttpXmlText;
using KernelHttp::http::HttpXmlWriter;
using KernelHttp::http::HttpPack200BandReader;
using KernelHttp::http::HttpPack200AttributeBands;
using KernelHttp::http::HttpPack200ClassBands;
using KernelHttp::http::HttpPack200CodeBands;
using KernelHttp::http::HttpPack200CodingFor;
using KernelHttp::http::HttpPack200CodingKind;
using KernelHttp::http::HttpPack200CpBands;
using KernelHttp::http::HttpPack200CpCounts;
using KernelHttp::http::HttpPack200FileBands;
using KernelHttp::http::HttpExiBuiltinProduction;
using KernelHttp::http::HttpExiBitInput;
using KernelHttp::http::HttpExiEventKind;
using KernelHttp::http::HttpExiGrammarKind;
using KernelHttp::http::HttpExiEventCode;
using KernelHttp::http::HttpExiGrammarTable;
using KernelHttp::http::HttpExiLearnedProduction;
using KernelHttp::http::HttpExiProduction;
using KernelHttp::http::HttpExiQNameEntry;
using KernelHttp::http::HttpExiQNameTable;
using KernelHttp::http::HttpExiNameTables;
using KernelHttp::http::HttpExiDecimalValue;
using KernelHttp::http::HttpExiFloatValue;
using KernelHttp::http::HttpExiStringTable;
using KernelHttp::http::HttpExiLearnQName;
using KernelHttp::http::HttpExiReadQNameLiteral;
using KernelHttp::http::HttpExiResolveQName;
using KernelHttp::http::HttpPack200ClassWriter;
using KernelHttp::http::HttpPack200BandCodec;
using KernelHttp::http::HttpPack200BandCodecKind;
using KernelHttp::http::HttpPack200CodecArena;
using KernelHttp::http::HttpPack200DecodeBand;
using KernelHttp::http::HttpPack200DecodePopulationBand;
using KernelHttp::http::HttpPack200ParseMetaCodec;
using KernelHttp::http::HttpPack200ReadAttributeBands;
using KernelHttp::http::HttpPack200ReadClassBands;
using KernelHttp::http::HttpPack200ReadCodeBands;
using KernelHttp::http::HttpPack200ReadCpBands;
using KernelHttp::http::HttpPack200ReadFileBands;
using KernelHttp::http::HttpPack200JarWriter;
using KernelHttp::http::DecodePack200GzipContent;

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

    bool TextEqualsLiteral(HttpText text, const char* literal)
    {
        const HttpText expected = MakeText(literal);
        return text.Length == expected.Length &&
            text.Data != nullptr &&
            memcmp(text.Data, expected.Data, expected.Length) == 0;
    }

    bool MemoryEqualsLiteral(const char* data, size_t length, const char* literal)
    {
        const size_t literalLength = strlen(literal);
        return data != nullptr &&
            length == literalLength &&
            memcmp(data, literal, literalLength) == 0;
    }

    HttpXmlText XmlText(const char* value)
    {
        HttpXmlText text = {};
        text.Data = value;
        text.Length = value == nullptr ? 0 : strlen(value);
        return text;
    }

    HttpXmlName XmlName(const char* prefix, const char* localName)
    {
        HttpXmlName name = {};
        name.Prefix = XmlText(prefix);
        name.LocalName = XmlText(localName);
        return name;
    }

    bool BuildEncodedResponse(
        const char* encoding,
        const unsigned char* encodedBody,
        size_t encodedBodyLength,
        char* response,
        size_t responseCapacity,
        size_t* responseLength)
    {
        if (encoding == nullptr ||
            encodedBody == nullptr ||
            response == nullptr ||
            responseLength == nullptr) {
            return false;
        }

        const int headerLength = snprintf(
            response,
            responseCapacity,
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: %s\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            encoding,
            encodedBodyLength);
        if (headerLength <= 0 ||
            static_cast<size_t>(headerLength) > responseCapacity ||
            encodedBodyLength > (responseCapacity - static_cast<size_t>(headerLength))) {
            return false;
        }

        memcpy(response + headerLength, encodedBody, encodedBodyLength);
        *responseLength = static_cast<size_t>(headerLength) + encodedBodyLength;
        return true;
    }

    void TestXmlWriterSerializesElementEvents()
    {
        char output[160] = {};
        HttpXmlWriter writer(output, sizeof(output));

        NTSTATUS status = writer.WriteStartElement(XmlName("p", "root"));
        Expect(NT_SUCCESS(status), "xml writer starts prefixed element");
        status = writer.WriteNamespace(XmlText("p"), XmlText("urn:test"));
        Expect(NT_SUCCESS(status), "xml writer writes namespace");
        status = writer.WriteAttribute(XmlName(nullptr, "a"), XmlText("1&\"<\t"));
        Expect(NT_SUCCESS(status), "xml writer writes escaped attribute");
        status = writer.WriteCharacters(XmlText("x<&>y"));
        Expect(NT_SUCCESS(status), "xml writer writes escaped text");
        status = writer.WriteEndElement(XmlName("p", "root"));
        Expect(NT_SUCCESS(status), "xml writer ends prefixed element");

        Expect(
            MemoryEqualsLiteral(
                output,
                writer.Length(),
                "<p:root xmlns:p=\"urn:test\" a=\"1&amp;&quot;&lt;&#x9;\">x&lt;&amp;&gt;y</p:root>"),
            "xml writer output matches expected XML bytes");
    }

    void TestXmlWriterRejectsInvalidEvents()
    {
        char output[64] = {};
        HttpXmlWriter writer(output, sizeof(output));

        NTSTATUS status = writer.WriteStartElement(XmlName(nullptr, "1bad"));
        Expect(status == STATUS_INVALID_PARAMETER, "xml writer rejects invalid element name");

        status = writer.WriteStartElement(XmlName(nullptr, "root"));
        Expect(NT_SUCCESS(status), "xml writer starts element for invalid event checks");
        const char invalidText[] = { 'a', static_cast<char>(0x01), 'b' };
        status = writer.WriteCharacters({ invalidText, sizeof(invalidText) });
        Expect(status == STATUS_INVALID_PARAMETER, "xml writer rejects invalid XML text byte");
    }

    void TestXmlWriterReportsOutputTooSmall()
    {
        char output[8] = {};
        HttpXmlWriter writer(output, sizeof(output));

        NTSTATUS status = writer.WriteStartElement(XmlName(nullptr, "root"));
        Expect(NT_SUCCESS(status), "xml writer starts element in small buffer");
        status = writer.WriteCharacters(XmlText("too long"));
        Expect(status == STATUS_BUFFER_TOO_SMALL, "xml writer reports small output buffer");
    }

    void TestXmlWriterSerializesAuxiliaryEvents()
    {
        char output[96] = {};
        HttpXmlWriter writer(output, sizeof(output));

        NTSTATUS status = writer.WriteComment(XmlText("ok"));
        Expect(NT_SUCCESS(status), "xml writer writes comment");
        status = writer.WriteProcessingInstruction(XmlText("pi"), XmlText("value"));
        Expect(NT_SUCCESS(status), "xml writer writes processing instruction");
        status = writer.WriteComment(XmlText("bad--comment"));
        Expect(status == STATUS_INVALID_PARAMETER, "xml writer rejects invalid comment");

        Expect(
            MemoryEqualsLiteral(output, writer.Length(), "<!--ok--><?pi value?>"),
            "xml writer auxiliary event output matches expected XML bytes");
    }

    void TestPack200BandReaderUnsignedAndSigned()
    {
        const unsigned char bytes[] = {
            0x05,
            0x01,
            0x02
        };
        HttpPack200BandReader reader(bytes, sizeof(bytes));

        ULONG unsignedValue = 0;
        Expect(
            reader.ReadUnsigned(HttpPack200CodingKind::Unsigned5, &unsignedValue) && unsignedValue == 5,
            "pack200 unsigned5 reads single-byte value");

        LONG signedValue = 0;
        Expect(
            reader.ReadInt(HttpPack200CodingFor(HttpPack200CodingKind::Signed5), &signedValue) && signedValue == -1,
            "pack200 signed5 reads negative value");
        Expect(
            reader.ReadInt(HttpPack200CodingFor(HttpPack200CodingKind::Signed5), &signedValue) && signedValue == 1,
            "pack200 signed5 reads positive value");
        Expect(reader.Remaining() == 0, "pack200 band reader consumes expected bytes");
    }

    void TestPack200BandReaderDelta()
    {
        const unsigned char bytes[] = {
            0x02,
            0x04,
            0x01
        };
        HttpPack200BandReader reader(bytes, sizeof(bytes));

        LONG value = 0;
        Expect(
            reader.ReadInt(HttpPack200CodingFor(HttpPack200CodingKind::Delta5), &value) && value == 1,
            "pack200 delta5 reads first delta");
        Expect(
            reader.ReadInt(HttpPack200CodingFor(HttpPack200CodingKind::Delta5), &value) && value == 3,
            "pack200 delta5 accumulates positive delta");
        Expect(
            reader.ReadInt(HttpPack200CodingFor(HttpPack200CodingKind::Delta5), &value) && value == 2,
            "pack200 delta5 accumulates negative delta");
    }

    void TestExiStringAndQNameTables()
    {
        HttpExiStringTable strings = {};
        NTSTATUS status = strings.Initialize(4, 32);
        Expect(NT_SUCCESS(status), "exi string table initializes");

        ULONG uri = 0;
        status = strings.Add(XmlText("urn:test"), &uri);
        Expect(NT_SUCCESS(status) && uri == 0, "exi string table adds URI");
        ULONG duplicate = 0;
        status = strings.Add(XmlText("urn:test"), &duplicate);
        Expect(NT_SUCCESS(status) && duplicate == uri && strings.Count() == 1, "exi string table deduplicates values");

        HttpXmlText stored = {};
        Expect(strings.Get(uri, &stored) && MemoryEqualsLiteral(stored.Data, stored.Length, "urn:test"), "exi string table returns stored text");

        HttpExiQNameTable qnames = {};
        status = qnames.Initialize(2);
        Expect(NT_SUCCESS(status), "exi qname table initializes");
        HttpExiQNameEntry entry = {};
        entry.UriId = uri;
        entry.LocalNameId = 1;
        entry.PrefixId = 2;
        ULONG qname = 0;
        status = qnames.Add(entry, &qname);
        Expect(NT_SUCCESS(status) && qname == 0, "exi qname table adds QName");
        ULONG found = 0;
        Expect(qnames.Find(entry, &found) && found == qname, "exi qname table finds QName");
    }

    void TestExiBuiltinGrammarProductions()
    {
        HttpExiProduction production = {};
        Expect(
            HttpExiBuiltinProduction(
                HttpExiGrammarKind::Document,
                0,
                false,
                false,
                false,
                &production) &&
                production.Event == HttpExiEventKind::StartDocument &&
                production.NextGrammar == HttpExiGrammarKind::DocContent,
            "exi document grammar maps SD production");

        Expect(
            HttpExiBuiltinProduction(
                HttpExiGrammarKind::ElementContent,
                2,
                false,
                false,
                false,
                &production) &&
                production.Event == HttpExiEventKind::EndElement &&
                production.PopGrammar,
            "exi element grammar maps EE production");

        Expect(
            HttpExiBuiltinProduction(
                HttpExiGrammarKind::ElementContent,
                3,
                true,
                false,
                false,
                &production) &&
                production.Event == HttpExiEventKind::Comment,
            "exi fidelity comment production follows base element productions");
    }

    void TestExiEventCodeAndStringValueReader()
    {
        const unsigned char eventBytes[] = { 0xc0 };
        HttpExiBitInput eventInput(eventBytes, sizeof(eventBytes));
        HttpExiEventCode eventCode = {};
        HttpExiProduction production = {};
        NTSTATUS status = KernelHttp::http::HttpExiReadEventCode(
            &eventInput,
            HttpExiGrammarKind::ElementContent,
            false,
            false,
            false,
            false,
            false,
            &eventCode,
            &production);
        Expect(
            NT_SUCCESS(status) &&
                eventCode.Value == 1 &&
                eventCode.Width == 2 &&
                production.Event == HttpExiEventKind::Characters,
            "exi event-code reader maps element CH production");

        const unsigned char stringBytes[] = { 0x03, 'a', 'b', 'c', 0x00 };
        HttpExiBitInput stringInput(stringBytes, sizeof(stringBytes));
        HttpExiStringTable values = {};
        status = values.Initialize(4, 16);
        Expect(NT_SUCCESS(status), "exi value string table initializes");
        HttpXmlText literal = {};
        status = KernelHttp::http::HttpExiReadLiteralString(&stringInput, &values, &literal);
        Expect(
            NT_SUCCESS(status) && MemoryEqualsLiteral(literal.Data, literal.Length, "abc"),
            "exi literal string reader stores string value");

        HttpXmlText referenced = {};
        status = KernelHttp::http::HttpExiReadStringTableReference(&stringInput, values, &referenced);
        Expect(
            NT_SUCCESS(status) && MemoryEqualsLiteral(referenced.Data, referenced.Length, "abc"),
            "exi string table reference reader returns stored value");
    }

    void TestExiGrammarLearningTable()
    {
        HttpExiGrammarTable table = {};
        NTSTATUS status = table.Initialize(4);
        Expect(NT_SUCCESS(status), "exi grammar learning table initializes");

        HttpExiLearnedProduction learned = {};
        learned.Grammar = HttpExiGrammarKind::ElementContent;
        learned.Event = HttpExiEventKind::StartElement;
        learned.QNameId = 7;
        learned.NextGrammar = HttpExiGrammarKind::StartTagContent;
        learned.PushElementGrammar = true;

        ULONG index = 0;
        status = table.Learn(learned, &index);
        Expect(NT_SUCCESS(status) && index == 0 && table.Count() == 1, "exi grammar table learns production");
        status = table.Learn(learned, &index);
        Expect(NT_SUCCESS(status) && index == 0 && table.Count() == 1, "exi grammar table deduplicates production");

        ULONG found = 0;
        Expect(
            table.Find(HttpExiGrammarKind::ElementContent, HttpExiEventKind::StartElement, 7, &found) && found == 0,
            "exi grammar table finds learned production");
    }

    void TestExiQNameReaderLearnsAndResolvesNames()
    {
        HttpExiStringTable uris = {};
        HttpExiStringTable locals = {};
        HttpExiStringTable prefixes = {};
        HttpExiQNameTable qnames = {};
        Expect(NT_SUCCESS(uris.Initialize(8, 32)), "exi URI table initializes for QName reader");
        Expect(NT_SUCCESS(locals.Initialize(8, 32)), "exi local-name table initializes for QName reader");
        Expect(NT_SUCCESS(prefixes.Initialize(8, 32)), "exi prefix table initializes for QName reader");
        Expect(NT_SUCCESS(qnames.Initialize(8)), "exi QName table initializes for QName reader");

        HttpExiNameTables tables = {};
        tables.Uris = &uris;
        tables.LocalNames = &locals;
        tables.Prefixes = &prefixes;
        tables.QNames = &qnames;

        ULONG qnameId = 0;
        HttpXmlName xmlName = {};
        NTSTATUS status = HttpExiLearnQName(
            &tables,
            XmlText("urn:test"),
            XmlText("root"),
            XmlText("p"),
            &qnameId,
            &xmlName);
        Expect(
            NT_SUCCESS(status) &&
                qnameId == 0 &&
                MemoryEqualsLiteral(xmlName.Prefix.Data, xmlName.Prefix.Length, "p") &&
                MemoryEqualsLiteral(xmlName.LocalName.Data, xmlName.LocalName.Length, "root"),
            "exi qname reader learns QName from string tables");

        HttpXmlName resolved = {};
        status = HttpExiResolveQName(tables, qnameId, &resolved);
        Expect(
            NT_SUCCESS(status) &&
                MemoryEqualsLiteral(resolved.Prefix.Data, resolved.Prefix.Length, "p") &&
                MemoryEqualsLiteral(resolved.LocalName.Data, resolved.LocalName.Length, "root"),
            "exi qname reader resolves learned QName");

        // Existing URI selector 1, literal local-name length 1 encoded as 2,
        // code point 'n', and the sole learned prefix 'p'.
        const unsigned char literalBytes[] = { 0x81, 0x37, 0x00 };
        HttpExiBitInput input(literalBytes, sizeof(literalBytes));
        status = HttpExiReadQNameLiteral(&input, &tables, true, &qnameId, &xmlName);
        Expect(
            NT_SUCCESS(status) &&
                qnameId == 1 &&
                MemoryEqualsLiteral(xmlName.Prefix.Data, xmlName.Prefix.Length, "p") &&
                MemoryEqualsLiteral(xmlName.LocalName.Data, xmlName.LocalName.Length, "n"),
            "exi qname reader reads literal QName");
    }

    void TestExiBuiltInValueDecoders()
    {
        const unsigned char booleanBytes[] = { 0x80 };
        HttpExiBitInput booleanInput(booleanBytes, sizeof(booleanBytes));
        bool booleanValue = false;
        NTSTATUS status = KernelHttp::http::HttpExiReadBoolean(&booleanInput, &booleanValue);
        Expect(NT_SUCCESS(status) && booleanValue, "exi boolean decoder reads true bit");

        const unsigned char integerBytes[] = { 0x82, 0x00 };
        HttpExiBitInput integerInput(integerBytes, sizeof(integerBytes));
        LONG integerValue = 0;
        status = KernelHttp::http::HttpExiReadInteger(&integerInput, &integerValue);
        Expect(NT_SUCCESS(status) && integerValue == -5, "exi integer decoder reads negative magnitude minus one");

        const unsigned char decimalBytes[] = { 0x81, 0x01, 0x80 };
        HttpExiBitInput decimalInput(decimalBytes, sizeof(decimalBytes));
        HttpExiDecimalValue decimalValue = {};
        status = KernelHttp::http::HttpExiReadDecimal(&decimalInput, &decimalValue);
        Expect(
            NT_SUCCESS(status) &&
                decimalValue.Negative &&
                decimalValue.Integral == 2 &&
                decimalValue.Fractional == 3,
            "exi decimal decoder reads sign and components");

        const unsigned char floatBytes[] = { 0x02, 0xc0, 0x40 };
        HttpExiBitInput floatInput(floatBytes, sizeof(floatBytes));
        HttpExiFloatValue floatValue = {};
        status = KernelHttp::http::HttpExiReadFloat(&floatInput, &floatValue);
        Expect(
            NT_SUCCESS(status) && floatValue.Mantissa == 5 && floatValue.Exponent == -2,
            "exi float decoder reads mantissa and exponent");
    }

    void TestPack200JarWriterStoredEntries()
    {
        char jar[256] = {};
        HttpPack200JarWriter writer(jar, sizeof(jar));
        NTSTATUS status = writer.Initialize(2);
        Expect(NT_SUCCESS(status), "pack200 jar writer initializes");

        const unsigned char manifest[] = {
            'M', 'a', 'n', 'i', 'f', 'e', 's', 't', '-', 'V', 'e', 'r', 's', 'i', 'o', 'n',
            ':', ' ', '1', '.', '0', '\r', '\n', '\r', '\n'
        };
        status = writer.AddStoredEntry(XmlText("META-INF/MANIFEST.MF"), manifest, sizeof(manifest));
        Expect(NT_SUCCESS(status), "pack200 jar writer writes stored manifest");

        SIZE_T jarLength = 0;
        status = writer.Finish(&jarLength);
        Expect(NT_SUCCESS(status), "pack200 jar writer finishes archive");
        Expect(
            jarLength > 22 &&
                static_cast<unsigned char>(jar[0]) == 0x50 &&
                static_cast<unsigned char>(jar[1]) == 0x4b &&
                static_cast<unsigned char>(jar[2]) == 0x03 &&
                static_cast<unsigned char>(jar[3]) == 0x04,
            "pack200 jar writer output starts with local header");
    }

    void TestPack200ClassWriterConstantPool()
    {
        char classBytes[256] = {};
        HttpPack200ClassWriter writer(classBytes, sizeof(classBytes));
        NTSTATUS status = writer.Begin(0, 52, 4);
        Expect(NT_SUCCESS(status), "pack200 class writer begins classfile");

        USHORT thisName = 0;
        USHORT superName = 0;
        USHORT thisClass = 0;
        status = writer.AddUtf8(XmlText("Example"), &thisName);
        Expect(NT_SUCCESS(status) && thisName == 1, "pack200 class writer adds this class name");
        status = writer.AddUtf8(XmlText("java/lang/Object"), &superName);
        Expect(NT_SUCCESS(status) && superName == 2, "pack200 class writer adds super class name");
        status = writer.AddClass(thisName, &thisClass);
        Expect(NT_SUCCESS(status) && thisClass == 3, "pack200 class writer adds class entry");

        SIZE_T classLength = 0;
        status = writer.FinishHeader(0x0021, thisClass, 0, &classLength);
        Expect(NT_SUCCESS(status), "pack200 class writer finishes minimal class header");
        Expect(
            classLength >= 10 &&
                static_cast<unsigned char>(classBytes[0]) == 0xca &&
                static_cast<unsigned char>(classBytes[1]) == 0xfe &&
                static_cast<unsigned char>(classBytes[2]) == 0xba &&
                static_cast<unsigned char>(classBytes[3]) == 0xbe,
            "pack200 class writer output starts with classfile magic");
    }

    void TestPack200MetaCodecAndRunAdaptiveDecode()
    {
        const unsigned char metaBytes[] = { 26, 0x05 };
        HttpPack200BandReader metaReader(metaBytes, sizeof(metaBytes));
        HttpPack200BandCodec codec = {};
        NTSTATUS status = HttpPack200ParseMetaCodec(&metaReader, &codec);
        Expect(
            NT_SUCCESS(status) && codec.Kind == HttpPack200BandCodecKind::Canonical,
            "pack200 meta codec parses canonical unsigned5");

        LONG value = 0;
        status = HttpPack200DecodeBand(&metaReader, codec, &value, 1);
        Expect(NT_SUCCESS(status) && value == 5, "pack200 canonical codec decodes band value");

        HttpPack200BandCodec unsignedCodec = {};
        unsignedCodec.Kind = HttpPack200BandCodecKind::Canonical;
        unsignedCodec.Canonical = HttpPack200CodingFor(HttpPack200CodingKind::Unsigned5);
        HttpPack200BandCodec signedCodec = {};
        signedCodec.Kind = HttpPack200BandCodecKind::Canonical;
        signedCodec.Canonical = HttpPack200CodingFor(HttpPack200CodingKind::Signed5);

        HttpPack200BandCodec runCodec = {};
        runCodec.Kind = HttpPack200BandCodecKind::Run;
        runCodec.First = &unsignedCodec;
        runCodec.Second = &signedCodec;
        runCodec.FirstCount = 1;

        const unsigned char runBytes[] = { 0x05, 0x01, 0x02 };
        HttpPack200BandReader runReader(runBytes, sizeof(runBytes));
        LONG runValues[3] = {};
        status = HttpPack200DecodeBand(&runReader, runCodec, runValues, sizeof(runValues) / sizeof(runValues[0]));
        Expect(
            NT_SUCCESS(status) && runValues[0] == 5 && runValues[1] == -1 && runValues[2] == 1,
            "pack200 run codec decodes split band");

        HttpPack200BandCodec adaptiveCodec = runCodec;
        adaptiveCodec.Kind = HttpPack200BandCodecKind::Adaptive;
        HttpPack200BandReader adaptiveReader(runBytes, sizeof(runBytes));
        LONG adaptiveValues[3] = {};
        status = HttpPack200DecodeBand(
            &adaptiveReader,
            adaptiveCodec,
            adaptiveValues,
            sizeof(adaptiveValues) / sizeof(adaptiveValues[0]));
        Expect(
            NT_SUCCESS(status) &&
                adaptiveValues[0] == 5 &&
                adaptiveValues[1] == -1 &&
                adaptiveValues[2] == 1,
            "pack200 adaptive codec decodes split band");
    }

    void TestPack200PopulationDecode()
    {
        const LONG favoured[] = { 10, 20 };
        const unsigned char tokenBytes[] = { 0x01, 0x02, 0x01 };
        HttpPack200BandReader tokenReader(tokenBytes, sizeof(tokenBytes));
        LONG values[3] = {};
        NTSTATUS status = HttpPack200DecodePopulationBand(
            &tokenReader,
            favoured,
            sizeof(favoured) / sizeof(favoured[0]),
            values,
            sizeof(values) / sizeof(values[0]));
        Expect(
            NT_SUCCESS(status) && values[0] == 10 && values[1] == 20 && values[2] == 10,
            "pack200 population codec maps favoured tokens");
    }

    void TestPack200BandContainers()
    {
        HttpPack200CpCounts counts = {};
        counts.Utf8 = 2;
        counts.Class = 1;
        HttpPack200CpBands cpBands = {};
        NTSTATUS status = cpBands.Initialize(counts);
        Expect(
            NT_SUCCESS(status) &&
                cpBands.Utf8Count() == 2 &&
                cpBands.ClassCount() == 1 &&
                cpBands.Utf8SuffixLengths() != nullptr &&
                cpBands.Utf8CharOffsets() != nullptr &&
                cpBands.Utf8ByteLengths() != nullptr &&
                cpBands.Utf16CharOffsets() != nullptr &&
                cpBands.Utf16CharLengths() != nullptr &&
                cpBands.ClassNameIndexes() != nullptr,
            "pack200 cp band container initializes counted arrays");

        HttpPack200FileBands fileBands = {};
        status = fileBands.Initialize(1);
        Expect(
            NT_SUCCESS(status) && fileBands.NameIndexes() != nullptr && fileBands.SizesLow() != nullptr,
            "pack200 file band container initializes");

        HttpPack200ClassBands classBands = {};
        status = classBands.Initialize(1);
        Expect(
            NT_SUCCESS(status) &&
                classBands.ThisClassIndexes() != nullptr &&
                classBands.SuperClassIndexes() != nullptr,
            "pack200 class band container initializes");

        HttpPack200CodeBands codeBands = {};
        status = codeBands.Initialize(1);
        Expect(
            NT_SUCCESS(status) && codeBands.MaxStacks() != nullptr && codeBands.MaxLocals() != nullptr,
            "pack200 code band container initializes");

        HttpPack200AttributeBands attributeBands = {};
        status = attributeBands.Initialize(1);
        Expect(
            NT_SUCCESS(status) && attributeBands.LayoutNameIndexes() != nullptr,
            "pack200 attribute band container initializes");
    }

    void TestPack200BandParserFillsContainers()
    {
        HttpPack200BandCodec codec = {};
        codec.Kind = HttpPack200BandCodecKind::Canonical;
        codec.Canonical = HttpPack200CodingFor(HttpPack200CodingKind::Unsigned5);

        const unsigned char cpBytes[] = { 3, 'a', 'b', 'c', 1 };
        HttpPack200BandReader cpReader(cpBytes, sizeof(cpBytes));
        HttpPack200BandReader cpHeaders(nullptr, 0);
        HttpPack200CodecArena cpArena = {};
        NTSTATUS status = cpArena.Initialize(64);
        Expect(NT_SUCCESS(status), "pack200 cp parser codec arena initializes");
        HttpPack200CpCounts counts = {};
        counts.Utf8 = 2;
        counts.Class = 1;
        HttpPack200CpBands cpBands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadCpBands(&cpReader, &cpHeaders, &cpArena, counts, &cpBands);
        }
        Expect(
            NT_SUCCESS(status) &&
                cpBands.Utf8SuffixLengths()[0] == 0 &&
                cpBands.Utf8SuffixLengths()[1] == 3 &&
                cpBands.Utf8CharOffsets()[0] == 0 &&
                cpBands.Utf8CharOffsets()[1] == 0 &&
                cpBands.Utf8ByteLengths()[1] == 3 &&
                cpBands.Utf8CharCount() == 3 &&
                cpBands.Utf8Chars()[0] == 'a' &&
                cpBands.Utf8Chars()[1] == 'b' &&
                cpBands.Utf8Chars()[2] == 'c' &&
                cpBands.ClassNameIndexes()[0] == 1,
            "pack200 band parser fills cp utf8 chars and class bands");

        const unsigned char fileBytes[] = { 4, 5 };
        HttpPack200BandReader fileReader(fileBytes, sizeof(fileBytes));
        HttpPack200BandReader fileHeaders(nullptr, 0);
        HttpPack200CodecArena fileArena = {};
        status = fileArena.Initialize(64);
        Expect(NT_SUCCESS(status), "pack200 file parser codec arena initializes");
        HttpPack200FileBands fileBands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadFileBands(
                &fileReader,
                &fileHeaders,
                &fileArena,
                1,
                false,
                false,
                false,
                &fileBands);
        }
        Expect(
            NT_SUCCESS(status) &&
                fileBands.NameIndexes()[0] == 4 &&
                fileBands.SizesLow()[0] == 5 &&
                fileBands.SizesHigh()[0] == 0 &&
                fileBands.Modtimes()[0] == 0 &&
                fileBands.Options()[0] == 0,
            "pack200 band parser fills file bands");

        const unsigned char classBytes[] = { 6, 7 };
        HttpPack200BandReader classReader(classBytes, sizeof(classBytes));
        HttpPack200ClassBands classBands = {};
        status = HttpPack200ReadClassBands(&classReader, codec, 1, &classBands);
        Expect(
            NT_SUCCESS(status) &&
                classBands.ThisClassIndexes()[0] == 6 &&
                classBands.SuperClassIndexes()[0] == 7,
            "pack200 band parser fills class bands");

        const unsigned char codeBytes[] = { 8, 9 };
        HttpPack200BandReader codeReader(codeBytes, sizeof(codeBytes));
        HttpPack200CodeBands codeBands = {};
        status = HttpPack200ReadCodeBands(&codeReader, codec, 1, &codeBands);
        Expect(
            NT_SUCCESS(status) &&
                codeBands.MaxStacks()[0] == 8 &&
                codeBands.MaxLocals()[0] == 9,
            "pack200 band parser fills code bands");

        const unsigned char attributeBytes[] = { 10 };
        HttpPack200BandReader attributeReader(attributeBytes, sizeof(attributeBytes));
        HttpPack200AttributeBands attributeBands = {};
        status = HttpPack200ReadAttributeBands(&attributeReader, codec, 1, &attributeBands);
        Expect(
            NT_SUCCESS(status) && attributeBands.LayoutNameIndexes()[0] == 10,
            "pack200 band parser fills attribute bands");
    }

    bool BuildChunkedBody(
        const unsigned char* body,
        size_t bodyLength,
        char* destination,
        size_t destinationCapacity,
        size_t* destinationLength)
    {
        if (body == nullptr ||
            destination == nullptr ||
            destinationLength == nullptr) {
            return false;
        }

        const int chunkHeaderLength = snprintf(destination, destinationCapacity, "%zx\r\n", bodyLength);
        if (chunkHeaderLength <= 0 || static_cast<size_t>(chunkHeaderLength) > destinationCapacity) {
            return false;
        }

        size_t cursor = static_cast<size_t>(chunkHeaderLength);
        if (bodyLength > destinationCapacity - cursor) {
            return false;
        }

        memcpy(destination + cursor, body, bodyLength);
        cursor += bodyLength;

        const char trailer[] = "\r\n0\r\n\r\n";
        if (sizeof(trailer) - 1 > destinationCapacity - cursor) {
            return false;
        }

        memcpy(destination + cursor, trailer, sizeof(trailer) - 1);
        cursor += sizeof(trailer) - 1;
        *destinationLength = cursor;
        return true;
    }

    bool BuildTransferEncodedResponse(
        const char* transferEncoding,
        const unsigned char* wireBody,
        size_t wireBodyLength,
        char* response,
        size_t responseCapacity,
        size_t* responseLength)
    {
        if (transferEncoding == nullptr ||
            wireBody == nullptr ||
            response == nullptr ||
            responseLength == nullptr) {
            return false;
        }

        const int headerLength = snprintf(
            response,
            responseCapacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: %s\r\n"
            "\r\n",
            transferEncoding);
        if (headerLength <= 0 ||
            static_cast<size_t>(headerLength) > responseCapacity ||
            wireBodyLength > responseCapacity - static_cast<size_t>(headerLength)) {
            return false;
        }

        memcpy(response + headerLength, wireBody, wireBodyLength);
        *responseLength = static_cast<size_t>(headerLength) + wireBodyLength;
        return true;
    }

    bool BuildChunkedGzipResponse(
        const unsigned char* encodedBody,
        size_t encodedBodyLength,
        char* response,
        size_t responseCapacity,
        size_t* responseLength)
    {
        if (encodedBody == nullptr ||
            response == nullptr ||
            responseLength == nullptr) {
            return false;
        }

        const int headerLength = snprintf(
            response,
            responseCapacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Encoding: gzip\r\n"
            "\r\n"
            "%zx\r\n",
            encodedBodyLength);
        if (headerLength <= 0 || static_cast<size_t>(headerLength) > responseCapacity) {
            return false;
        }

        size_t cursor = static_cast<size_t>(headerLength);
        if (encodedBodyLength > (responseCapacity - cursor)) {
            return false;
        }

        memcpy(response + cursor, encodedBody, encodedBodyLength);
        cursor += encodedBodyLength;

        const char trailer[] = "\r\n0\r\n\r\n";
        if (sizeof(trailer) - 1 > (responseCapacity - cursor)) {
            return false;
        }

        memcpy(response + cursor, trailer, sizeof(trailer) - 1);
        cursor += sizeof(trailer) - 1;
        *responseLength = cursor;
        return true;
    }

    constexpr const char* EncodedBodyLiteral = "encoded response body";

    const unsigned char DeflateRawBody[] = {
        0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49, 0x4d, 0x51,
        0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e,
        0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04, 0x00
    };

    const unsigned char DeflateZlibBody[] = {
        0x78, 0x9c, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49,
        0x4d, 0x51, 0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf,
        0x2b, 0x4e, 0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04,
        0x00, 0x5a, 0x14, 0x08, 0x30
    };

    const unsigned char GzipBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xff, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49,
        0x4d, 0x51, 0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf,
        0x2b, 0x4e, 0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04,
        0x00, 0xec, 0xa9, 0xb0, 0x05, 0x15, 0x00, 0x00,
        0x00
    };

    const unsigned char BrotliBody[] = {
        0x1b, 0x14, 0x00, 0x00, 0x04, 0x26, 0x72, 0xa4,
        0x31, 0xb7, 0xfc, 0xfc, 0x2c, 0xc4, 0x11, 0x55,
        0x2a, 0x03, 0xbd, 0x1b, 0xc2, 0xb8, 0x0e
    };

    const unsigned char ZstdBody[] = {
        0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x15, 0xa9, 0x00,
        0x00, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64,
        0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
        0x65, 0x20, 0x62, 0x6f, 0x64, 0x79
    };

    const unsigned char ZstdDictionary[] = {
        0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x20,
        0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
        0x20
    };

    const unsigned char DczBody[] = {
        0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x15, 0x55, 0x00,
        0x00, 0x20, 0x62, 0x6f, 0x64, 0x79, 0x01, 0x00,
        0x34, 0x4f, 0x20
    };

    const unsigned char Aes128GcmIkm[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    const unsigned char Aes128GcmBody[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00, 0x00, 0x10, 0x00, 0x00, 0xb0, 0x66, 0x4c,
        0xef, 0x4f, 0x27, 0x76, 0xe8, 0x71, 0xf4, 0x4a,
        0xd4, 0xa8, 0xc8, 0x7d, 0x06, 0x76, 0x62, 0x54,
        0x41, 0xef, 0x5c, 0x1a, 0x21, 0x42, 0x83, 0x09,
        0x96, 0x69, 0x29, 0x61, 0x35, 0xa4, 0x44, 0xe7,
        0xdf, 0x9e, 0x02
    };

    const unsigned char ExiBody[] = {
        0x24, 0x45, 0x58, 0x49, 0xa0, 0x00, 0x4a, 0x01,
        0x05, 0x72, 0x6f, 0x6f, 0x74, 0x03, 0x06, 0x74,
        0x65, 0x78, 0x74, 0x00
    };

    const unsigned char SimpleExiBody[] = {
        0x24, 0x45, 0x58, 0x49, 0x80, 0x41, 0x5c, 0x9b,
        0xdb, 0xdd, 0x30, 0x67, 0x46, 0x57, 0x87, 0x40
    };

    const unsigned char Pack200GzipBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0x3b, 0xf5, 0xef, 0x02, 0x2f, 0xfb,
        0xb4, 0x2b, 0x0c, 0x20, 0xc0, 0xc8, 0xc4, 0x80,
        0x00, 0x7c, 0x29, 0x89, 0x25, 0x89, 0xfa, 0x19,
        0xa9, 0x39, 0x39, 0xf9, 0x7a, 0x25, 0x15, 0x25,
        0x8c, 0xbc, 0x07, 0x3e, 0xde, 0x7f, 0xa2, 0xc4,
        0x00, 0x16, 0x50, 0x28, 0x48, 0x4c, 0xce, 0x36,
        0x32, 0x30, 0x00, 0x00, 0x6a, 0x6d, 0xd6, 0xdb,
        0x3d, 0x00, 0x00, 0x00
    };

    const unsigned char Pack200BareSegmentWithBands[] = {
        0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0e, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x68,
        0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74,
        0x01, 0x0d, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x00,
        0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x70, 0x61,
        0x63, 0x6b, 0x32, 0x30, 0x30
    };

    // UNIX compress .Z stream for "encoded response body" with 16-bit max codes and no block reset.
    const unsigned char CompressBody[] = {
        0x1f, 0x9d, 0x10, 0x65, 0xdc, 0x8c, 0x79, 0x43,
        0xa6, 0x0c, 0x19, 0x10, 0x72, 0xca, 0xcc, 0x81,
        0xf3, 0xc6, 0xcd, 0x9c, 0x32, 0x20, 0xc4, 0xbc,
        0x21, 0x93, 0x07
    };

    // gzip stream for "15\r\nencoded response body\r\n0\r\n\r\n".
    const unsigned char GzipChunkedStreamBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x0a, 0x33, 0x34, 0xe5, 0xe5, 0x4a, 0xcd,
        0x4b, 0xce, 0x4f, 0x49, 0x4d, 0x51, 0x28, 0x4a,
        0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0x55, 0x48,
        0xca, 0x4f, 0xa9, 0xe4, 0xe5, 0x32, 0xe0, 0xe5,
        0xe2, 0xe5, 0x02, 0x00, 0x97, 0xd3, 0x0a, 0x85,
        0x20, 0x00, 0x00, 0x00
    };

    // gzip stream for "15\r\nencoded response body\r\n0\r\n\r\njunk".
    const unsigned char GzipChunkedStreamWithTailBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x0a, 0x33, 0x34, 0xe5, 0xe5, 0x4a, 0xcd,
        0x4b, 0xce, 0x4f, 0x49, 0x4d, 0x51, 0x28, 0x4a,
        0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0x55, 0x48,
        0xca, 0x4f, 0xa9, 0xe4, 0xe5, 0x32, 0xe0, 0xe5,
        0xe2, 0xe5, 0xca, 0x2a, 0xcd, 0xcb, 0x06, 0x00,
        0x68, 0x51, 0x9e, 0xce, 0x24, 0x00, 0x00, 0x00
    };

    void TestBuildGetRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Accept"), MakeText("*/*") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/index.html");
        options.Host = MakeText("example.com");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.Connection = HttpConnectionDirective::KeepAlive;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET /index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Connection: keep-alive\r\n"
            "Accept: */*\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "GET request builds successfully");
        Expect(written == strlen(expected), "GET request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "GET request bytes match expected output");
    }

    void TestBuildConnectRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Connect;
        options.Path = MakeText("example.com:443");
        options.Host = MakeText("example.com:443");
        options.UserAgent = MakeText("KernelHttp/0.1");

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "CONNECT request builds successfully");
        Expect(written == strlen(expected), "CONNECT request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "CONNECT request bytes match expected output");
    }

    void TestBuildTraceRequestRequiresExplicitOptIn()
    {
        char buffer[512] = {};
        size_t written = 0;

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Trace;
        options.Path = MakeText("/debug");
        options.Host = MakeText("example.com");

        NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);
        Expect(status == STATUS_NOT_SUPPORTED, "TRACE request requires explicit opt-in");

        options.AllowTrace = true;
        status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "TRACE /debug HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "TRACE request builds when explicitly enabled");
        Expect(written == strlen(expected), "TRACE request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "TRACE request bytes match expected output");
    }

    void TestTraceRequestRejectsUnsafeInputs()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "unsafe";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Trace;
        options.Path = MakeText("/debug");
        options.Host = MakeText("example.com");
        options.AllowTrace = true;
        options.Body = body;
        options.BodyLength = strlen(body);
        options.IncludeContentLength = true;

        NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);
        Expect(status == STATUS_INVALID_PARAMETER, "TRACE request rejects body");

        const HttpHeader sensitiveHeaders[] = {
            { MakeText("Authorization"), MakeText("Bearer token") },
            { MakeText("Cookie"), MakeText("a=b") },
            { MakeText("Proxy-Authorization"), MakeText("Basic token") }
        };

        for (SIZE_T index = 0; index < sizeof(sensitiveHeaders) / sizeof(sensitiveHeaders[0]); ++index) {
            options = {};
            options.Method = HttpMethod::Trace;
            options.Path = MakeText("/debug");
            options.Host = MakeText("example.com");
            options.AllowTrace = true;
            options.ExtraHeaders = &sensitiveHeaders[index];
            options.ExtraHeaderCount = 1;

            status = HttpRequestBuilder::Build(
                options,
                buffer,
                sizeof(buffer),
                &written);
            Expect(status == STATUS_NOT_SUPPORTED, "TRACE request rejects sensitive headers");
        }
    }

    void TestBuildPostRequest()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.ContentType = MakeText("application/x-www-form-urlencoded");
        options.Connection = HttpConnectionDirective::Close;
        options.Body = body;
        options.BodyLength = strlen(body);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 10\r\n"
            "Connection: close\r\n"
            "\r\n"
            "alpha=beta";

        Expect(status == STATUS_SUCCESS, "POST request builds successfully");
        Expect(written == strlen(expected), "POST request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "POST request bytes match expected output");
    }

    void TestBuildPostRequestHeadersOnly()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.ContentType = MakeText("application/x-www-form-urlencoded");
        options.Connection = HttpConnectionDirective::Close;
        options.Body = body;
        options.BodyLength = strlen(body);

        const NTSTATUS status = HttpRequestBuilder::BuildHeaders(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 10\r\n"
            "Connection: close\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "POST request headers build successfully");
        Expect(written == strlen(expected), "POST request headers report exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "POST request headers match expected output");
    }

    void TestBuildContentLengthRequestBodyOnly()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.Body = body;
        options.BodyLength = strlen(body);

        const NTSTATUS status = HttpRequestBuilder::BuildBody(
            options,
            buffer,
            sizeof(buffer),
            &written);

        Expect(status == STATUS_SUCCESS, "Content-Length request body builds successfully");
        Expect(written == strlen(body), "Content-Length request body reports exact byte count");
        Expect(memcmp(buffer, body, strlen(body)) == 0, "Content-Length request body bytes match");
    }

    void TestBuildChunkedPostRequest()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.ContentType = MakeText("application/x-www-form-urlencoded");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.IncludeContentLength = true;
        options.BodyMode = HttpRequestBodyMode::Chunked;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "a\r\n"
            "alpha=beta\r\n"
            "0\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "chunked POST request builds successfully");
        Expect(written == strlen(expected), "chunked POST request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "chunked POST request bytes match expected output");
    }

    void TestBuildChunkedRequestBodyOnlyWithTrailers()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";
        const HttpHeader trailers[] = {
            { MakeText("X-Checksum"), MakeText("abc123") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.IncludeContentLength = true;
        options.BodyMode = HttpRequestBodyMode::Chunked;
        options.Trailers = trailers;
        options.TrailerCount = sizeof(trailers) / sizeof(trailers[0]);

        const NTSTATUS status = HttpRequestBuilder::BuildBody(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "a\r\n"
            "alpha=beta\r\n"
            "0\r\n"
            "X-Checksum: abc123\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "chunked request body builds successfully");
        Expect(written == strlen(expected), "chunked request body reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "chunked request body bytes match expected output");
    }

    void TestBuildUpgradeRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Sec-WebSocket-Key"), MakeText("dGhlIHNhbXBsZSBub25jZQ==") },
            { MakeText("Sec-WebSocket-Version"), MakeText("13") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/chat");
        options.Host = MakeText("server.example.com");
        options.Connection = HttpConnectionDirective::Upgrade;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = sizeof(extra) / sizeof(extra[0]);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET /chat HTTP/1.1\r\n"
            "Host: server.example.com\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "Upgrade request builds successfully");
        Expect(written == strlen(expected), "Upgrade request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "Upgrade request bytes match expected output");
    }

    void TestRequestBuilderRejectsInjectionText()
    {
        char buffer[512] = {};
        size_t written = 0;

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/safe path");
        options.Host = MakeText("example.com");
        NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects spaces in request target");

        options.Path = MakeText("/safe");
        options.Host = MakeText("example.com\r\nX-Test: yes");
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects CRLF in Host header");

        const HttpHeader badName[] = {
            { MakeText("Bad\rName"), MakeText("value") }
        };
        options.Host = MakeText("example.com");
        options.ExtraHeaders = badName;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects invalid header name");

        const HttpHeader badValue[] = {
            { MakeText("X-Test"), MakeText("ok\r\nInjected: yes") }
        };
        options.ExtraHeaders = badValue;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects invalid header value");

        const HttpHeader controlledConnection[] = {
            { MakeText("Connection"), MakeText("Upgrade") }
        };
        options.ExtraHeaders = controlledConnection;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects caller-supplied Connection header");

        const HttpHeader controlledHost[] = {
            { MakeText("Host"), MakeText("other.example") }
        };
        options.ExtraHeaders = controlledHost;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects caller-supplied Host header");

        const HttpHeader controlledLength[] = {
            { MakeText("Content-Length"), MakeText("10") }
        };
        options.ExtraHeaders = controlledLength;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects caller-supplied Content-Length header");
    }

    void TestRequestBuilderRejectsTransferEncoding()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "upload body";

        const HttpHeader headers[] = {
            { MakeText("Transfer-Encoding"), MakeText("chunked") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/upload");
        options.Host = MakeText("example.com");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.ExtraHeaders = headers;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects request Transfer-Encoding");
        Expect(written == 0, "request builder reports no bytes for rejected Transfer-Encoding");
    }

    void TestRequestBuilderRejectsUnsupportedRequestFraming()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "upload body";

        const HttpHeader teHeader[] = {
            { MakeText("TE"), MakeText("trailers") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/upload");
        options.Host = MakeText("example.com");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.ExtraHeaders = teHeader;
        options.ExtraHeaderCount = 1;

        NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects request TE header");

        const HttpHeader trailerHeader[] = {
            { MakeText("Trailer"), MakeText("Digest") }
        };
        options.ExtraHeaders = trailerHeader;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects request Trailer header");

        const HttpHeader expectHeader[] = {
            { MakeText("Expect"), MakeText("100-continue") }
        };
        options.ExtraHeaders = expectHeader;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects body with Expect: 100-continue");
    }

    void TestBuildRequestAllowsLibraryExpectContinue()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "upload body";
        const HttpHeader expectHeader[] = {
            { MakeText("Expect"), MakeText("100-continue") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/upload");
        options.Host = MakeText("example.com");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.IncludeContentLength = true;
        options.ExtraHeaders = expectHeader;
        options.ExtraHeaderCount = 1;
        options.AllowExpectContinue = true;

        const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        const char expected[] =
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 11\r\n"
            "Expect: 100-continue\r\n"
            "\r\n"
            "upload body";

        Expect(status == STATUS_SUCCESS, "request builder allows library-controlled Expect: 100-continue");
        Expect(written == strlen(expected), "Expect request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "Expect request bytes match expected output");
    }

    void TestBuildChunkedRequestWithTrailers()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        const HttpHeader extra[] = {
            { MakeText("Trailer"), MakeText("Expires, X-Checksum") }
        };
        const HttpHeader trailers[] = {
            { MakeText("Expires"), MakeText("Wed, 21 Oct 2015 07:28:00 GMT") },
            { MakeText("X-Checksum"), MakeText("abc123") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.ContentType = MakeText("application/x-www-form-urlencoded");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.BodyMode = HttpRequestBodyMode::Chunked;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = 1;
        options.Trailers = trailers;
        options.TrailerCount = sizeof(trailers) / sizeof(trailers[0]);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Trailer: Expires, X-Checksum\r\n"
            "\r\n"
            "a\r\n"
            "alpha=beta\r\n"
            "0\r\n"
            "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
            "X-Checksum: abc123\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "chunked request with trailers builds successfully");
        Expect(written == strlen(expected), "chunked trailers request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "chunked trailers request bytes match expected output");
    }

    void TestBuildChunkedRequestWithEmptyBodyTrailers()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader trailers[] = {
            { MakeText("X-Checksum"), MakeText("deadbeef") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.IncludeContentLength = true;
        options.BodyMode = HttpRequestBodyMode::Chunked;
        options.Trailers = trailers;
        options.TrailerCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "X-Checksum: deadbeef\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "empty-body chunked request with trailers builds successfully");
        Expect(written == strlen(expected), "empty-body trailers request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "empty-body trailers request bytes match expected output");
    }

    void TestRequestBuilderTrailerValidation()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions base = {};
        base.Method = HttpMethod::Post;
        base.Path = MakeText("/submit");
        base.Host = MakeText("example.com");
        base.Body = body;
        base.BodyLength = strlen(body);
        base.BodyMode = HttpRequestBodyMode::Chunked;

        const HttpHeader good[] = {
            { MakeText("X-Checksum"), MakeText("abc123") }
        };

        // Trailers require chunked transfer; reject in Content-Length mode.
        {
            HttpRequestBuildOptions options = base;
            options.BodyMode = HttpRequestBodyMode::ContentLength;
            options.Trailers = good;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_NOT_SUPPORTED, "trailers rejected without chunked transfer");
        }

        // Chunked mode but no framing emitted (no body, no Content-Length opt-in).
        {
            HttpRequestBuildOptions options = base;
            options.Body = nullptr;
            options.BodyLength = 0;
            options.Trailers = good;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_NOT_SUPPORTED, "trailers rejected when no chunked framing is emitted");
        }

        // Non-null count with null pointer.
        {
            HttpRequestBuildOptions options = base;
            options.Trailers = nullptr;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_INVALID_PARAMETER, "null trailer pointer with non-zero count rejected");
        }

        // Forbidden trailer fields (framing / auth / cookie).
        const char* forbidden[] = {
            "Content-Length", "Transfer-Encoding", "Host",
            "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"
        };
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
            const HttpHeader trailer[] = {
                { MakeText(forbidden[i]), MakeText("x") }
            };
            HttpRequestBuildOptions options = base;
            options.Trailers = trailer;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_NOT_SUPPORTED, "forbidden trailer field rejected");
        }

        // Invalid trailer name (illegal token character).
        {
            const HttpHeader trailer[] = {
                { MakeText("Bad Name"), MakeText("x") }
            };
            HttpRequestBuildOptions options = base;
            options.Trailers = trailer;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_INVALID_PARAMETER, "invalid trailer name rejected");
        }

        // CRLF injection in a trailer value.
        {
            const HttpHeader trailer[] = {
                { MakeText("X-Checksum"), MakeText("ok\r\nInjected: yes") }
            };
            HttpRequestBuildOptions options = base;
            options.Trailers = trailer;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_INVALID_PARAMETER, "CRLF injection in trailer value rejected");
        }
    }

    void TestRequestBuilderAllowsEmptyHeaderValue()
    {
        char buffer[256] = {};
        size_t written = 0;

        const HttpHeader headers[] = {
            { MakeText("X-Empty"), { "", 0 } }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/");
        options.Host = MakeText("example.com");
        options.ExtraHeaders = headers;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        const char expected[] =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "X-Empty: \r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "request builder accepts an empty header value");
        Expect(written == strlen(expected), "empty header request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "empty header request bytes match expected output");
    }

    void TestBuildPutRequest()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "{\"enabled\":true}";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Put;
        options.Path = MakeText("/put");
        options.Host = MakeText("httpbin.org");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.ContentType = MakeText("application/json");
        options.Connection = HttpConnectionDirective::Close;
        options.Body = body;
        options.BodyLength = strlen(body);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "PUT /put HTTP/1.1\r\n"
            "Host: httpbin.org\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 16\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"enabled\":true}";

        Expect(status == STATUS_SUCCESS, "PUT request builds successfully");
        Expect(written == strlen(expected), "PUT request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "PUT request bytes match expected output");
    }

    void TestBuildRealHostGetRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Accept"), MakeText("*/*") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/");
        options.Host = MakeText("www.baidu.com");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.Connection = HttpConnectionDirective::Close;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET / HTTP/1.1\r\n"
            "Host: www.baidu.com\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Connection: close\r\n"
            "Accept: */*\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "real-host GET request builds successfully");
        Expect(written == strlen(expected), "real-host GET request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "real-host GET request bytes match expected output");
    }

    void TestRequestSizeProbe()
    {
        size_t written = 0;

        HttpRequestBuildOptions options = {};
        options.Path = MakeText("/");
        options.Host = MakeText("example.com");

        const NTSTATUS status = HttpRequestBuilder::Build(options, nullptr, 0, &written);

        const char expected[] =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";

        Expect(status == STATUS_BUFFER_TOO_SMALL, "request builder supports size probe");
        Expect(written == strlen(expected), "request size probe returns required length");
    }

    void TestBuildAcceptEncodingRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Accept"), MakeText("*/*") },
            { MakeText("Accept-Encoding"), MakeText("gzip, deflate, br, zstd, identity") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/brotli");
        options.Host = MakeText("httpbin.org");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.Connection = HttpConnectionDirective::Close;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = sizeof(extra) / sizeof(extra[0]);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET /brotli HTTP/1.1\r\n"
            "Host: httpbin.org\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Connection: close\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: gzip, deflate, br, zstd, identity\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "Accept-Encoding request builds successfully");
        Expect(written == strlen(expected), "Accept-Encoding request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "Accept-Encoding request bytes match expected output");
    }

    void TestAcceptEncodingQValueParsing()
    {
        HttpAcceptEncodingEntry entries[KernelHttp::http::HttpMaxAcceptEncodingEntries] = {};
        HttpAcceptEncodingRules rules = {};
        rules.Entries = entries;
        rules.EntryCapacity = sizeof(entries) / sizeof(entries[0]);

        NTSTATUS status = HttpContentEncoding::ParseAcceptEncoding(
            MakeText("br;q=0.8, gzip;q=1.000, identity;q=0, *;q=0.001"),
            &rules);
        Expect(NT_SUCCESS(status), "Accept-Encoding qvalues parse");

        bool acceptable = false;
        USHORT qvalue = 0;
        status = HttpContentEncoding::IsContentCodingAcceptable(
            &rules,
            MakeText("br"),
            &acceptable,
            &qvalue);
        Expect(NT_SUCCESS(status) && acceptable && qvalue == 800, "br qvalue is exposed");

        status = HttpContentEncoding::IsContentCodingAcceptable(
            &rules,
            MakeText("identity"),
            &acceptable,
            &qvalue);
        Expect(NT_SUCCESS(status) && !acceptable && qvalue == 0, "identity q=0 is rejected");

        status = HttpContentEncoding::IsContentCodingAcceptable(
            &rules,
            MakeText("zstd"),
            &acceptable,
            &qvalue);
        Expect(NT_SUCCESS(status) && acceptable && qvalue == 1, "wildcard qvalue applies to zstd");
    }

    void TestAcceptEncodingRejectsInvalidQValues()
    {
        HttpAcceptEncodingEntry entries[KernelHttp::http::HttpMaxAcceptEncodingEntries] = {};
        HttpAcceptEncodingRules rules = {};
        rules.Entries = entries;
        rules.EntryCapacity = sizeof(entries) / sizeof(entries[0]);

        NTSTATUS status = HttpContentEncoding::ParseAcceptEncoding(MakeText("gzip;q=1.0000"), &rules);
        Expect(status == STATUS_INVALID_PARAMETER, "qvalue with too many digits rejects");

        rules.EntryCount = 0;
        rules.EmptyHeader = false;
        status = HttpContentEncoding::ParseAcceptEncoding(MakeText("gzip, gzip;q=0.5"), &rules);
        Expect(status == STATUS_INVALID_PARAMETER, "duplicate Accept-Encoding token rejects");

        rules.EntryCount = 0;
        rules.EmptyHeader = false;
        status = HttpContentEncoding::ParseAcceptEncoding(MakeText("gzip,,br"), &rules);
        Expect(status == STATUS_INVALID_PARAMETER, "empty Accept-Encoding list element rejects");
    }

    void TestAcceptEncodingNegotiation()
    {
        HttpAcceptEncodingEntry entries[KernelHttp::http::HttpMaxAcceptEncodingEntries] = {};
        HttpAcceptEncodingRules rules = {};
        rules.Entries = entries;
        rules.EntryCapacity = sizeof(entries) / sizeof(entries[0]);

        NTSTATUS status = HttpContentEncoding::ParseAcceptEncoding(
            MakeText("gzip;q=0.5, br;q=0.9, zstd;q=0.9"),
            &rules);
        Expect(NT_SUCCESS(status), "Accept-Encoding negotiation rules parse");

        const HttpText serverCodings[] = {
            MakeText("gzip"),
            MakeText("zstd"),
            MakeText("br")
        };
        HttpText selected = {};
        USHORT qvalue = 0;
        status = HttpContentEncoding::NegotiateContentCoding(
            &rules,
            serverCodings,
            sizeof(serverCodings) / sizeof(serverCodings[0]),
            &selected,
            &qvalue);
        Expect(NT_SUCCESS(status), "content coding negotiation selects an acceptable coding");
        Expect(TextEqualsLiteral(selected, "zstd") && qvalue == 900, "server order breaks equal qvalue ties");

        HttpAcceptEncodingRules emptyRules = {};
        emptyRules.Entries = entries;
        emptyRules.EntryCapacity = sizeof(entries) / sizeof(entries[0]);
        status = HttpContentEncoding::ParseAcceptEncoding(MakeText(""), &emptyRules);
        Expect(NT_SUCCESS(status), "empty Accept-Encoding header parses");
        bool acceptable = true;
        status = HttpContentEncoding::IsContentCodingAcceptable(
            &emptyRules,
            MakeText("gzip"),
            &acceptable,
            nullptr);
        Expect(NT_SUCCESS(status) && !acceptable, "empty Accept-Encoding only accepts identity");
    }

    void TestParseContentLengthResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "hello"
            "next";

        HttpHeader headers[8] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "Content-Length response parses successfully");
        Expect(response.MajorVersion == 1 && response.MinorVersion == 1, "HTTP version is parsed");
        Expect(response.StatusCode == 200, "status code is parsed");
        Expect(TextEqualsLiteral(response.ReasonPhrase, "OK"), "reason phrase is parsed");
        Expect(response.HeaderCount == 2, "header count is parsed");
        Expect(response.BodyKind == HttpBodyKind::ContentLength, "body kind is ContentLength");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "hello"), "body points to Content-Length bytes");
        Expect(response.BytesConsumed == strlen(responseBytes) - strlen("next"), "parser leaves pipelined bytes unread");
        Expect(response.HasHeaderValueToken(MakeText("Connection"), MakeText("keep-alive")), "connection token lookup works");
    }

    void TestParseChunkedResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "4\r\n"
            "Wiki\r\n"
            "5;ext=value\r\n"
            "pedia\r\n"
            "0\r\n"
            "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
            "\r\n"
            "tail";

        HttpHeader headers[8] = {};
        HttpHeader trailers[4] = {};
        char decoded[32] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.Trailers = trailers;
        options.TrailerCapacity = 4;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "chunked response parses successfully");
        Expect(response.BodyKind == HttpBodyKind::Chunked, "body kind is Chunked");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "Wikipedia"), "chunked body is decoded");
        Expect(response.BytesConsumed == strlen(responseBytes) - strlen("tail"), "chunked parser leaves trailing bytes unread");
        Expect(response.HasChunkedTransferEncoding(), "chunked transfer token lookup works");
        Expect(response.TrailerCount == 1, "chunked trailer count is exposed");
        Expect(TextEqualsLiteral(response.Trailers[0].Name, "Expires"), "chunked trailer name is exposed");
        Expect(TextEqualsLiteral(response.Trailers[0].Value, "Wed, 21 Oct 2015 07:28:00 GMT"), "chunked trailer value is exposed");
    }

    void TestParseIdentityContentEncoding()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: identity\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "identity body";

        HttpHeader headers[8] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "identity content encoding parses successfully");
        Expect(response.BodyKind == HttpBodyKind::ContentLength, "identity body keeps ContentLength kind");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "identity body"), "identity body is exposed unchanged");
    }

    void TestParseDeflateZlibContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("deflate", DeflateZlibBody, sizeof(DeflateZlibBody), responseBytes, sizeof(responseBytes), &responseLength),
            "zlib-wrapped deflate response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "zlib-wrapped deflate content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "zlib-wrapped deflate body is decoded");
    }

    void TestParseDeflateRawContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("deflate", DeflateRawBody, sizeof(DeflateRawBody), responseBytes, sizeof(responseBytes), &responseLength),
            "raw deflate response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "raw deflate content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "raw deflate body is decoded");
    }

    void TestParseGzipContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("gzip", GzipBody, sizeof(GzipBody), responseBytes, sizeof(responseBytes), &responseLength),
            "gzip response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "gzip content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "gzip body is decoded");
    }

    void TestParseBrotliContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("br", BrotliBody, sizeof(BrotliBody), responseBytes, sizeof(responseBytes), &responseLength),
            "brotli response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "brotli content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "brotli body is decoded");
    }

    void TestParseZstdContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("zstd", ZstdBody, sizeof(ZstdBody), responseBytes, sizeof(responseBytes), &responseLength),
            "zstd response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "zstd content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "zstd body is decoded");
    }

    void TestDecodeDictionaryCompressedZstdContentEncoding()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("dcz") }
        };
        KernelHttp::http::HttpCodingExternalMaterial material = {};
        material.Coding = KernelHttp::http::HttpCoding::DictionaryCompressedZstd;
        material.Dictionary = ZstdDictionary;
        material.DictionaryLength = sizeof(ZstdDictionary);
        KernelHttp::http::HttpCodingDecodeMaterials materials = {};
        materials.Items = &material;
        materials.ItemCount = 1;

        char decoded[64] = {};
        char scratch[64] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);
        buffers.ScratchBody = scratch;
        buffers.ScratchBodyCapacity = sizeof(scratch);
        buffers.Materials = &materials;

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(DczBody),
            sizeof(DczBody),
            buffers,
            result);

        Expect(status == STATUS_SUCCESS, "dcz content encoding decodes with dictionary material");
        Expect(MemoryEqualsLiteral(result.Body, result.BodyLength, EncodedBodyLiteral), "dcz body is decoded");
    }

    void TestDecodeDictionaryCompressedZstdRequiresDictionary()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("dcz") }
        };
        char decoded[64] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(DczBody),
            sizeof(DczBody),
            buffers,
            result);

        Expect(status == STATUS_NOT_SUPPORTED, "dcz content encoding fails closed without dictionary material");
    }

    void TestDecodeAes128GcmContentEncoding()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("aes128gcm") }
        };
        KernelHttp::http::HttpCodingExternalMaterial material = {};
        material.Coding = KernelHttp::http::HttpCoding::Aes128Gcm;
        material.Aes128GcmKeyingMaterial = Aes128GcmIkm;
        material.Aes128GcmKeyingMaterialLength = sizeof(Aes128GcmIkm);
        KernelHttp::http::HttpCodingDecodeMaterials materials = {};
        materials.Items = &material;
        materials.ItemCount = 1;

        char decoded[64] = {};
        char scratch[64] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);
        buffers.ScratchBody = scratch;
        buffers.ScratchBodyCapacity = sizeof(scratch);
        buffers.Materials = &materials;

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(Aes128GcmBody),
            sizeof(Aes128GcmBody),
            buffers,
            result);

        Expect(status == STATUS_SUCCESS, "aes128gcm content encoding decrypts with keying material");
        Expect(MemoryEqualsLiteral(result.Body, result.BodyLength, EncodedBodyLiteral), "aes128gcm body is decrypted");
    }

    void TestDecodeAes128GcmRejectsWrongKey()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("aes128gcm") }
        };
        unsigned char wrongIkm[sizeof(Aes128GcmIkm)] = {};
        KernelHttp::http::HttpCodingExternalMaterial material = {};
        material.Coding = KernelHttp::http::HttpCoding::Aes128Gcm;
        material.Aes128GcmKeyingMaterial = wrongIkm;
        material.Aes128GcmKeyingMaterialLength = sizeof(wrongIkm);
        KernelHttp::http::HttpCodingDecodeMaterials materials = {};
        materials.Items = &material;
        materials.ItemCount = 1;

        char decoded[64] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);
        buffers.Materials = &materials;

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(Aes128GcmBody),
            sizeof(Aes128GcmBody),
            buffers,
            result);

        Expect(!NT_SUCCESS(status), "aes128gcm rejects incorrect keying material");
    }

    void TestDecodeExiContentEncodingByteAlignment()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("exi") }
        };
        char decoded[64] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(ExiBody),
            sizeof(ExiBody),
            buffers,
            result);

        Expect(
            NT_SUCCESS(status) &&
                result.BodyLength == 17 &&
                memcmp(decoded, "<root>text</root>", 17) == 0,
            "exi content encoding decodes byte-aligned options stream");
    }

    void TestDecodeExiDrivesXmlSinkForBuiltInEvents()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("exi") }
        };
        char decoded[64] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(SimpleExiBody),
            sizeof(SimpleExiBody),
            buffers,
            result);

        Expect(
            NT_SUCCESS(status) &&
                result.BodyLength == 17 &&
                memcmp(decoded, "<root>text</root>", 17) == 0,
            "exi event loop drives XML sink for document, element, characters, and end events");
    }

    void TestDecodeExiRejectsUnsupportedHeader()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("exi") }
        };
        const unsigned char unsupported[] = {
            0x24, 0x45, 0x58, 0x49, 0x00
        };
        char decoded[64] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(unsupported),
            sizeof(unsupported),
            buffers,
            result);

        Expect(!NT_SUCCESS(status), "exi rejects invalid or unsupported EXI stream");
    }

    void TestDecodePack200GzipContentEncodingRebuildsJar()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("pack200-gzip") }
        };
        char decoded[256] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(Pack200GzipBody),
            sizeof(Pack200GzipBody),
            buffers,
            result);

        Expect(
            NT_SUCCESS(status) &&
                result.BodyLength > 4 &&
                static_cast<unsigned char>(decoded[0]) == 0x50 &&
                static_cast<unsigned char>(decoded[1]) == 0x4b &&
                static_cast<unsigned char>(decoded[2]) == 0x03 &&
                static_cast<unsigned char>(decoded[3]) == 0x04,
            "pack200-gzip content encoding rebuilds a JAR from a file-only segment");
    }

    void TestDecodePack200GzipRejectsNonPackSegmentAfterGzip()
    {
        char decoded[256] = {};
        SIZE_T decodedLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            GzipBody,
            sizeof(GzipBody),
            decoded,
            sizeof(decoded),
            &decodedLength);

        Expect(
            status == STATUS_INVALID_NETWORK_RESPONSE && decodedLength == 0,
            "pack200-gzip decodes gzip wrapper and rejects non-Pack200 segment payload");
    }

    void TestDecodePack200BareSegmentRebuildsJar()
    {
        char decoded[256] = {};
        SIZE_T decodedLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            Pack200BareSegmentWithBands,
            sizeof(Pack200BareSegmentWithBands),
            decoded,
            sizeof(decoded),
            &decodedLength);

        Expect(
            NT_SUCCESS(status) &&
                decodedLength > 4 &&
                static_cast<unsigned char>(decoded[0]) == 0x50 &&
                static_cast<unsigned char>(decoded[1]) == 0x4b &&
                static_cast<unsigned char>(decoded[2]) == 0x03 &&
                static_cast<unsigned char>(decoded[3]) == 0x04,
            "pack200 bare segment path rebuilds a JAR from decoded cp and file bands");
    }

    void TestDecodePack200SegmentRejectsTruncatedBands()
    {
        char decoded[256] = {};
        SIZE_T decodedLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            Pack200BareSegmentWithBands,
            sizeof(Pack200BareSegmentWithBands) - 1,
            decoded,
            sizeof(decoded),
            &decodedLength);

        Expect(
            status == STATUS_INVALID_NETWORK_RESPONSE && decodedLength == 0,
            "pack200 segment path rejects truncated cp or file bands");
    }

    void TestDecodePack200GzipRejectsCorruptPack()
    {
        HttpHeader headers[] = {
            { MakeText("Content-Encoding"), MakeText("pack200-gzip") }
        };
        unsigned char corrupt[sizeof(Pack200GzipBody)] = {};
        memcpy(corrupt, Pack200GzipBody, sizeof(corrupt));
        corrupt[sizeof(corrupt) - 5] ^= 0x7f;
        char decoded[256] = {};
        KernelHttp::http::HttpContentDecodeBuffers buffers = {};
        buffers.DecodedBody = decoded;
        buffers.DecodedBodyCapacity = sizeof(decoded);

        KernelHttp::http::HttpContentDecodeResult result = {};
        const NTSTATUS status = HttpContentEncoding::Decode(
            headers,
            sizeof(headers) / sizeof(headers[0]),
            reinterpret_cast<const char*>(corrupt),
            sizeof(corrupt),
            buffers,
            result);

        Expect(!NT_SUCCESS(status), "pack200-gzip rejects corrupt gzip or pack200 stream");
    }

    void TestParseCompressContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("compress", CompressBody, sizeof(CompressBody), responseBytes, sizeof(responseBytes), &responseLength),
            "compress response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "compress content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "compress content body is decoded");

        memset(responseBytes, 0, sizeof(responseBytes));
        responseLength = 0;
        Expect(
            BuildEncodedResponse("x-compress", CompressBody, sizeof(CompressBody), responseBytes, sizeof(responseBytes), &responseLength),
            "x-compress response fixture builds");

        memset(decoded, 0, sizeof(decoded));
        response = {};
        status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "x-compress content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "x-compress content body is decoded");
    }

    void TestParseChunkedGzipContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildChunkedGzipResponse(GzipBody, sizeof(GzipBody), responseBytes, sizeof(responseBytes), &responseLength),
            "chunked gzip response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        char scratch[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "chunked gzip response parses successfully");
        Expect(response.BodyKind == HttpBodyKind::Chunked, "chunked gzip keeps Chunked body kind");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "chunked gzip body is transfer-decoded and decompressed");
    }

    void TestTransferEncodingGzipChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(GzipBody, sizeof(GzipBody), chunked, sizeof(chunked), &chunkedLength),
            "gzip transfer body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "gzip, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "gzip chunked transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "gzip, chunked transfer coding parses");
        Expect(response.BodyKind == HttpBodyKind::Chunked, "gzip, chunked body kind is Chunked");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "gzip transfer coding decodes after chunked framing");
    }

    void TestTransferEncodingDeflateChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(DeflateZlibBody, sizeof(DeflateZlibBody), chunked, sizeof(chunked), &chunkedLength),
            "deflate transfer body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "deflate, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "deflate chunked transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "deflate, chunked transfer coding parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "deflate transfer coding decodes after chunked framing");
    }

    void TestTransferEncodingCompressChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(CompressBody, sizeof(CompressBody), chunked, sizeof(chunked), &chunkedLength),
            "compress transfer body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "compress, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "compress chunked transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "compress, chunked transfer coding parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "compress transfer coding decodes after chunked framing");
    }

    void TestTransferEncodingAliasesChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(GzipBody, sizeof(GzipBody), chunked, sizeof(chunked), &chunkedLength),
            "x-gzip transfer alias body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "x-gzip, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "x-gzip transfer alias response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "x-gzip transfer alias parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "x-gzip transfer alias decodes");

        memset(chunked, 0, sizeof(chunked));
        chunkedLength = 0;
        Expect(
            BuildChunkedBody(CompressBody, sizeof(CompressBody), chunked, sizeof(chunked), &chunkedLength),
            "x-compress transfer alias body is chunked");

        memset(responseBytes, 0, sizeof(responseBytes));
        responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "x-compress, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "x-compress transfer alias response fixture builds");

        memset(decoded, 0, sizeof(decoded));
        memset(scratch, 0, sizeof(scratch));
        response = {};
        status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "x-compress transfer alias parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "x-compress transfer alias decodes");
    }

    void TestTransferEncodingGzipCloseDelimited()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "gzip",
                GzipBody,
                sizeof(GzipBody),
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "close-delimited gzip transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "final non-chunked transfer coding waits for connection close");

        options.MessageCompleteOnConnectionClose = true;
        status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_SUCCESS, "close-delimited gzip transfer coding parses after connection close");
        Expect(response.BodyKind == HttpBodyKind::CloseDelimited, "close-delimited gzip keeps CloseDelimited body kind");
        Expect(response.BytesConsumed == responseLength, "close-delimited gzip consumes all response bytes");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "close-delimited gzip transfer coding decodes");
    }

    void TestTransferEncodingChunkedThenGzipCloseDelimited()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "chunked, gzip",
                GzipChunkedStreamBody,
                sizeof(GzipChunkedStreamBody),
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "chunked then gzip close-delimited transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "chunked, gzip waits for connection close");

        options.MessageCompleteOnConnectionClose = true;
        status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_SUCCESS, "chunked, gzip transfer coding parses after connection close");
        Expect(response.BodyKind == HttpBodyKind::CloseDelimited, "chunked, gzip is close-delimited on the wire");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "chunked, gzip decodes gzip then inner chunked stream");
    }

    void TestTransferEncodingRejectsInnerChunkedTail()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "chunked, gzip",
                GzipChunkedStreamWithTailBody,
                sizeof(GzipChunkedStreamWithTailBody),
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "chunked tail rejection fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);
        options.MessageCompleteOnConnectionClose = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "inner chunked stream must consume all decoded bytes");
    }

    void TestTransferEncodingRejectsEmptyListMember()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(GzipBody, sizeof(GzipBody), chunked, sizeof(chunked), &chunkedLength),
            "gzip transfer body with empty list members is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "gzip,, chunked,",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "empty list member transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "empty transfer-coding list members are rejected");
    }

    void TestUnsupportedContentEncoding()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: unknown-coding\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "data";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_NOT_SUPPORTED, "unsupported content encoding is rejected");
    }

    void TestContentEncodingRequiresCapacity()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("gzip", GzipBody, sizeof(GzipBody), responseBytes, sizeof(responseBytes), &responseLength),
            "gzip small-buffer fixture builds");

        HttpHeader headers[8] = {};
        char decoded[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "content decoder rejects undersized output buffer");
    }

    void TestContentEncodingRejectsTooManyCodings()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: identity, identity, identity, identity, identity, identity, identity, identity, identity\r\n"
            "Content-Length: 1\r\n"
            "\r\n"
            "x";

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        char scratch[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_NOT_SUPPORTED, "content decoder rejects content coding chains beyond the hard parser limit");
    }

    void TestChunkedDecodeRequiresCapacity()
    {
        const char chunkedBody[] =
            "3\r\n"
            "abc\r\n"
            "0\r\n"
            "\r\n";

        char decoded[2] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "chunked decoder rejects undersized output buffer");
        Expect(decodedLength == 0, "chunked decoder does not report a partial body as complete");
        Expect(bytesConsumed == 0, "chunked decoder does not consume partial output on capacity failure");
    }

    void TestChunkedDecodeRejectsBadTerminator()
    {
        const char chunkedBody[] =
            "3\r\n"
            "abc\n"
            "0\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects missing CRLF after data");
    }

    void TestChunkedDecodeRejectsMalformedExtension()
    {
        const char chunkedBody[] =
            "3;=bad\r\n"
            "abc\r\n"
            "0\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects malformed extension");
    }

    void TestChunkedDecodeRejectsMalformedTrailer()
    {
        const char chunkedBody[] =
            "0\r\n"
            "Bad Name: value\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects malformed trailer field name");
        Expect(decodedLength == 0, "malformed trailer does not expose decoded body");
        Expect(bytesConsumed == 0, "malformed trailer does not consume the message");
    }

    void TestChunkedDecodeRejectsForbiddenTrailer()
    {
        const char chunkedBody[] =
            "0\r\n"
            "Content-Length: 7\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects forbidden trailer field");
        Expect(decodedLength == 0, "forbidden trailer does not expose decoded body");
        Expect(bytesConsumed == 0, "forbidden trailer does not consume the message");
    }

    void TestUnsupportedTransferEncoding()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: br, chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_NOT_SUPPORTED, "br transfer coding is rejected while br content coding remains separate");
    }

    void TestTransferEncodingRejectsContentLength()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "Transfer-Encoding plus Content-Length is rejected");
    }

    void TestTransferEncodingRejectsHttp10()
    {
        const char responseBytes[] =
            "HTTP/1.0 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/1.0 Transfer-Encoding is framing faulty");
    }

    void TestTransferEncodingRejectsDuplicateChunked()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked, chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "duplicate chunked transfer coding is rejected");
    }

    void TestTransferEncodingRejectsParameters()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked;foo=bar\r\n"
            "\r\n"
            "3\r\n"
            "abc\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "parameters on chunked transfer coding are rejected");

        const char gzipResponseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: gzip;foo=bar\r\n"
            "\r\n";
        response = {};
        status = HttpParser::ParseResponse(
            gzipResponseBytes,
            strlen(gzipResponseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "parameters on compression transfer coding are rejected");
    }

    void TestTransferEncodingRejectsMalformedParameters()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked;=bad\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "malformed transfer coding parameter is rejected");
    }

    void TestTransferEncodingRejectsIdentity()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: identity, chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "identity is not valid in Transfer-Encoding");
    }

    void TestTransferEncodingRejectsOnlyEmptyList()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: ,,\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "Transfer-Encoding with no effective coding is rejected");
    }

    void TestHeaderCapacityFailure()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";

        HttpHeader headers[1] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 1;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "parser reports header storage exhaustion");
        Expect(response.HeaderCount == 0, "parser clears response on header storage failure");
    }

    void TestResponseRejectsInvalidHeaders()
    {
        const char whitespaceBeforeColon[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length : 5\r\n"
            "\r\n"
            "hello";
        const char invalidFieldName[] =
            "HTTP/1.1 200 OK\r\n"
            "Bad(Header): value\r\n"
            "\r\n";
        const char invalidFieldValue[] =
            "HTTP/1.1 200 OK\r\n"
            "X-Test: bad\001value\r\n"
            "\r\n";

        const char* cases[] = {
            whitespaceBeforeColon,
            invalidFieldName,
            invalidFieldValue
        };

        for (SIZE_T index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            HttpHeader headers[4] = {};
            HttpParseOptions options = {};
            options.Headers = headers;
            options.HeaderCapacity = 4;
            options.MessageCompleteOnConnectionClose = true;

            HttpResponse response = {};
            const NTSTATUS status = HttpParser::ParseResponse(
                cases[index],
                strlen(cases[index]),
                options,
                response);

            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "response parser rejects invalid header syntax");
        }
    }

    void TestResponseRejectsInvalidStatusLines()
    {
        const char unsupportedVersion[] =
            "HTTP/2.0 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        const char zeroStatus[] =
            "HTTP/1.1 000 Invalid\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        const char unsupportedStatus[] =
            "HTTP/1.1 999 Invalid\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        const char* cases[] = {
            unsupportedVersion,
            zeroStatus,
            unsupportedStatus
        };

        for (SIZE_T index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            HttpHeader headers[4] = {};
            HttpParseOptions options = {};
            options.Headers = headers;
            options.HeaderCapacity = 4;

            HttpResponse response = {};
            const NTSTATUS status = HttpParser::ParseResponse(
                cases[index],
                strlen(cases[index]),
                options,
                response);

            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "response parser rejects unsupported status line");
        }
    }

    void TestParseCloseDelimitedResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "close-body";

        HttpHeader headers[2] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 2;
        options.MessageCompleteOnConnectionClose = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "close-delimited response parses when marked complete");
        Expect(response.BodyKind == HttpBodyKind::CloseDelimited, "body kind is CloseDelimited");
        Expect(response.BodyEndsOnConnectionClose, "response records close-delimited completion");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "close-body"), "close-delimited body is exposed");
    }

    void TestParseEmptyCloseDelimitedResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "\r\n";

        HttpHeader headers[2] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 2;
        options.MessageCompleteOnConnectionClose = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "empty close-delimited response parses when EOF completes it");
        Expect(response.BodyKind == HttpBodyKind::None, "empty close-delimited response has no body bytes");
        Expect(response.BodyEndsOnConnectionClose, "empty EOF-delimited response still records close ownership");
    }

    void TestParseHttp10ConnectionDirectives()
    {
        const char keepAliveResponse[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "ok";
        const char closeResponse[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(
            keepAliveResponse,
            strlen(keepAliveResponse),
            options,
            response);
        Expect(status == STATUS_SUCCESS, "HTTP/1.0 keep-alive response parses");
        Expect(response.MajorVersion == 1 && response.MinorVersion == 0, "HTTP/1.0 version is recorded");
        Expect(response.HasConnectionKeepAlive(), "HTTP/1.0 keep-alive token is recorded");

        memset(headers, 0, sizeof(headers));
        response = {};
        status = HttpParser::ParseResponse(
            closeResponse,
            strlen(closeResponse),
            options,
            response);
        Expect(status == STATUS_SUCCESS, "HTTP/1.0 close response parses");
        Expect(response.HasConnectionClose(), "HTTP/1.0 close token is recorded");
    }


    void TestIncompleteResponseNeedsMoreData()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "he";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "incomplete Content-Length body requests more data");
    }

    void TestIncompleteChunkedResponseNeedsMoreData()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "chunked header without body requests more data");
    }

    void TestEmptyResponseNeedsMoreData()
    {
        const char responseBytes[] = "";
        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            0,
            options,
            response);

        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "empty response buffer requests more data");
    }

    void TestDuplicateContentLengthConflict()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "hello!";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "conflicting Content-Length headers are rejected");
    }

    void TestContentLengthEquivalentListRejected()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5, 5\r\n"
            "\r\n"
            "hello"
            "next";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "equivalent Content-Length list is rejected");
    }

    void TestContentLengthListConflict()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5, 6\r\n"
            "\r\n"
            "hello!";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "conflicting Content-Length list is rejected");
    }

    void TestNoBodyStatus()
    {
        const char responseBytes[] =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 10\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "204 response parses successfully");
        Expect(response.BodyKind == HttpBodyKind::None, "204 response ignores message body");
        Expect(response.BodyLength == 0, "204 response body length is zero");
    }

    void TestHeadResponseForbidsBody()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 128\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.ResponseBodyForbidden = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "HEAD response parses without waiting for Content-Length body");
        Expect(response.BodyKind == HttpBodyKind::None, "HEAD response body kind is None");
        Expect(response.BodyLength == 0, "HEAD response body length is zero");
    }

    void TestSwitchingProtocolsLeavesWebSocketBytes()
    {
        const char responseBytes[] =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "\r\n"
            "frame";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.ResponseBodyForbidden = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "101 response parses without treating websocket bytes as HTTP body");
        Expect(response.StatusCode == 101, "101 status code is parsed");
        Expect(response.BodyKind == HttpBodyKind::None, "101 response body kind is None");
        Expect(response.BytesConsumed == strlen(responseBytes) - strlen("frame"), "101 parser leaves upgraded bytes unread");
    }

    void TestHeaderTokenMatching()
    {
        Expect(HeaderValueHasToken(MakeText("gzip, chunked"), MakeText("chunked")), "header token matching handles comma lists");
        Expect(HeaderValueHasToken(MakeText(" keep-alive "), MakeText("KEEP-ALIVE")), "header token matching is case-insensitive");
        Expect(!HeaderValueHasToken(MakeText("notchunked"), MakeText("chunked")), "header token matching does not match substrings");
        Expect(TextEqualsIgnoreCase(MakeText("Content-Length"), MakeText("content-length")), "case-insensitive text matching works");
    }

    void TestObsFoldRejected()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "X-Test: a\r\n"
            " b\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "obs-fold header continuation is rejected");
    }

    void TestContentRangeParsing()
    {
        using KernelHttp::http::HttpContentRange;

        HttpHeader headers[2] = {};
        headers[0].Name = MakeText("Content-Range");
        headers[0].Value = MakeText("bytes 0-499/1234");
        headers[1].Name = MakeText("Content-Length");
        headers[1].Value = MakeText("500");

        HttpResponse response = {};
        response.StatusCode = 206;
        response.Headers = headers;
        response.HeaderCount = 2;

        Expect(response.IsPartialContent(), "206 reports partial content");

        HttpContentRange range = {};
        Expect(response.GetContentRange(&range), "well-formed Content-Range parses");
        Expect(range.HasRange && range.FirstBytePos == 0 && range.LastBytePos == 499, "range bounds parse");
        Expect(range.HasCompleteLength && range.CompleteLength == 1234, "complete length parses");
    }

    void TestContentRangeUnknownAndUnsatisfied()
    {
        using KernelHttp::http::HttpContentRange;

        {
            HttpHeader headers[1] = {};
            headers[0].Name = MakeText("Content-Range");
            headers[0].Value = MakeText("bytes 100-200/*");
            HttpResponse response = {};
            response.Headers = headers;
            response.HeaderCount = 1;

            HttpContentRange range = {};
            Expect(response.GetContentRange(&range), "range with unknown complete length parses");
            Expect(range.HasRange && range.FirstBytePos == 100 && range.LastBytePos == 200, "bounds parse with unknown length");
            Expect(!range.HasCompleteLength, "unknown complete length is flagged");
        }

        {
            HttpHeader headers[1] = {};
            headers[0].Name = MakeText("Content-Range");
            headers[0].Value = MakeText("bytes */1234");
            HttpResponse response = {};
            response.Headers = headers;
            response.HeaderCount = 1;

            HttpContentRange range = {};
            Expect(response.GetContentRange(&range), "unsatisfied range parses");
            Expect(!range.HasRange, "unsatisfied range has no bounds");
            Expect(range.HasCompleteLength && range.CompleteLength == 1234, "unsatisfied range carries complete length");
        }
    }

    void TestContentRangeRejectsMalformed()
    {
        using KernelHttp::http::HttpContentRange;

        const char* badValues[] = {
            "bytes 500-499/1234",
            "bytes 0-1234/1234",
            "items 0-1/2",
            "bytes 0-1",
            "bytes 0500/1234",
            "bytes 0-1/1234  extra",
            "bytes -1/1234",
            ""
        };

        for (size_t i = 0; i < sizeof(badValues) / sizeof(badValues[0]); ++i) {
            HttpHeader headers[1] = {};
            headers[0].Name = MakeText("Content-Range");
            headers[0].Value = MakeText(badValues[i]);
            HttpResponse response = {};
            response.Headers = headers;
            response.HeaderCount = 1;

            HttpContentRange range = {};
            Expect(!response.GetContentRange(&range), "malformed Content-Range is rejected");
        }

        HttpResponse empty = {};
        HttpContentRange range = {};
        Expect(!empty.GetContentRange(&range), "absent Content-Range returns false");
    }

    void TestHttpCachePolicyDateParsing()
    {
        LONGLONG imf = 0;
        LONGLONG rfc850 = 0;
        LONGLONG asctime = 0;
        Expect(KernelHttp::http::ParseHttpDate(MakeText("Sun, 06 Nov 1994 08:49:37 GMT"), &imf), "IMF-fixdate parses");
        Expect(KernelHttp::http::ParseHttpDate(MakeText("Sunday, 06-Nov-94 08:49:37 GMT"), &rfc850), "RFC 850 date parses");
        Expect(KernelHttp::http::ParseHttpDate(MakeText("Sun Nov  6 08:49:37 1994"), &asctime), "asctime date parses");
        Expect(imf == rfc850 && imf == asctime, "HTTP date formats normalize to same second");
        Expect(!KernelHttp::http::ParseHttpDate(MakeText("Sun, 31 Feb 1994 08:49:37 GMT"), &imf), "invalid HTTP date rejects");
    }

    void TestHttpCacheControlParsing()
    {
        HttpCacheControl control = {};
        Expect(KernelHttp::http::ParseCacheControl(
            MakeText("no-cache, max-age=60, s-maxage=\"30\", private=\"Set-Cookie\", only-if-cached, max-stale=10"),
            &control),
            "Cache-Control parses");
        Expect(control.NoCache, "no-cache directive is recorded");
        Expect(control.Private, "private directive is recorded");
        Expect(control.OnlyIfCached, "only-if-cached directive is recorded");
        Expect(control.HasMaxAge && control.MaxAgeSeconds == 60, "max-age parses");
        Expect(control.HasSharedMaxAge && control.SharedMaxAgeSeconds == 30, "s-maxage quoted value parses");
        Expect(control.HasMaxStale && !control.MaxStaleAny && control.MaxStaleSeconds == 10, "max-stale value parses");
    }

    void TestHttpCacheRangeParsing()
    {
        HttpByteRange range = {};
        Expect(KernelHttp::http::ParseSingleByteRange(MakeText("bytes=5-9"), &range), "single byte range parses");
        Expect(range.Valid && !range.Suffix && range.First == 5 && range.Last == 9, "byte range bounds are exposed");
        Expect(KernelHttp::http::ParseSingleByteRange(MakeText("bytes=-128"), &range), "suffix range parses");
        Expect(range.Valid && range.Suffix && range.SuffixLength == 128, "suffix range length is exposed");
        Expect(!KernelHttp::http::ParseSingleByteRange(MakeText("bytes=0-1,4-5"), &range), "multi-range is not treated as single range");
        Expect(!KernelHttp::http::ParseSingleByteRange(MakeText("items=0-1"), &range), "non-byte range rejects");
    }

    void TestHttpCacheFreshnessAndValidationPolicy()
    {
        HttpHeader headers[4] = {};
        headers[0].Name = MakeText("Date");
        headers[0].Value = MakeText("Sun, 06 Nov 1994 08:49:37 GMT");
        headers[1].Name = MakeText("Cache-Control");
        headers[1].Value = MakeText("max-age=60");
        headers[2].Name = MakeText("ETag");
        headers[2].Value = MakeText("\"abc\"");
        headers[3].Name = MakeText("Vary");
        headers[3].Value = MakeText("Accept-Encoding");

        HttpResponse response = {};
        response.StatusCode = 200;
        response.Headers = headers;
        response.HeaderCount = 4;

        HttpCacheMetadata metadata = {};
        Expect(KernelHttp::http::CollectCacheMetadata(response, &metadata), "cache metadata collects");
        Expect(metadata.CacheControl.HasMaxAge && metadata.CacheControl.MaxAgeSeconds == 60, "response max-age is collected");
        Expect(metadata.HasDate && metadata.HasETag, "date and ETag are collected");
        Expect(KernelHttp::http::FreshnessLifetimeSeconds(metadata, 200, KernelHttp::http::HttpCacheScope::Private) == 60, "freshness lifetime uses max-age");

        HttpCacheMetadata requestMetadata = {};
        bool requiresValidation = true;
        Expect(KernelHttp::http::CanUseStoredResponse(
            requestMetadata,
            metadata,
            200,
            metadata.DateSeconds,
            metadata.DateSeconds + 30,
            KernelHttp::http::HttpCacheScope::Private,
            &requiresValidation),
            "fresh response is reusable");
        Expect(!requiresValidation, "fresh response does not require validation");

        Expect(KernelHttp::http::CanUseStoredResponse(
            requestMetadata,
            metadata,
            200,
            metadata.DateSeconds,
            metadata.DateSeconds + 90,
            KernelHttp::http::HttpCacheScope::Private,
            &requiresValidation),
            "stale response can be selected for validation");
        Expect(requiresValidation, "stale response requires validation");
    }
}

int main()
{
    TestXmlWriterSerializesElementEvents();
    TestXmlWriterRejectsInvalidEvents();
    TestXmlWriterReportsOutputTooSmall();
    TestXmlWriterSerializesAuxiliaryEvents();
    TestPack200BandReaderUnsignedAndSigned();
    TestPack200BandReaderDelta();
    TestExiStringAndQNameTables();
    TestExiBuiltinGrammarProductions();
    TestExiEventCodeAndStringValueReader();
    TestExiGrammarLearningTable();
    TestExiQNameReaderLearnsAndResolvesNames();
    TestExiBuiltInValueDecoders();
    TestPack200JarWriterStoredEntries();
    TestPack200ClassWriterConstantPool();
    TestPack200MetaCodecAndRunAdaptiveDecode();
    TestPack200PopulationDecode();
    TestPack200BandContainers();
    TestPack200BandParserFillsContainers();
    TestBuildGetRequest();
    TestBuildConnectRequest();
    TestBuildTraceRequestRequiresExplicitOptIn();
    TestTraceRequestRejectsUnsafeInputs();
    TestBuildPostRequest();
    TestBuildPostRequestHeadersOnly();
    TestBuildContentLengthRequestBodyOnly();
    TestBuildChunkedPostRequest();
    TestBuildChunkedRequestBodyOnlyWithTrailers();
    TestBuildUpgradeRequest();
    TestRequestBuilderRejectsInjectionText();
    TestRequestBuilderRejectsTransferEncoding();
    TestRequestBuilderRejectsUnsupportedRequestFraming();
    TestBuildRequestAllowsLibraryExpectContinue();
    TestBuildChunkedRequestWithTrailers();
    TestBuildChunkedRequestWithEmptyBodyTrailers();
    TestRequestBuilderTrailerValidation();
    TestRequestBuilderAllowsEmptyHeaderValue();
    TestBuildPutRequest();
    TestBuildRealHostGetRequest();
    TestRequestSizeProbe();
    TestBuildAcceptEncodingRequest();
    TestAcceptEncodingQValueParsing();
    TestAcceptEncodingRejectsInvalidQValues();
    TestAcceptEncodingNegotiation();
    TestParseContentLengthResponse();
    TestParseChunkedResponse();
    TestParseIdentityContentEncoding();
    TestParseDeflateZlibContentEncoding();
    TestParseDeflateRawContentEncoding();
    TestParseGzipContentEncoding();
    TestParseBrotliContentEncoding();
    TestParseZstdContentEncoding();
    TestDecodeDictionaryCompressedZstdContentEncoding();
    TestDecodeDictionaryCompressedZstdRequiresDictionary();
    TestDecodeAes128GcmContentEncoding();
    TestDecodeAes128GcmRejectsWrongKey();
    TestDecodeExiContentEncodingByteAlignment();
    TestDecodeExiDrivesXmlSinkForBuiltInEvents();
    TestDecodeExiRejectsUnsupportedHeader();
    TestDecodePack200GzipContentEncodingRebuildsJar();
    TestDecodePack200GzipRejectsNonPackSegmentAfterGzip();
    TestDecodePack200BareSegmentRebuildsJar();
    TestDecodePack200SegmentRejectsTruncatedBands();
    TestDecodePack200GzipRejectsCorruptPack();
    TestParseCompressContentEncoding();
    TestParseChunkedGzipContentEncoding();
    TestTransferEncodingGzipChunked();
    TestTransferEncodingDeflateChunked();
    TestTransferEncodingCompressChunked();
    TestTransferEncodingAliasesChunked();
    TestTransferEncodingGzipCloseDelimited();
    TestTransferEncodingChunkedThenGzipCloseDelimited();
    TestTransferEncodingRejectsInnerChunkedTail();
    TestTransferEncodingRejectsEmptyListMember();
    TestUnsupportedContentEncoding();
    TestContentEncodingRequiresCapacity();
    TestContentEncodingRejectsTooManyCodings();
    TestChunkedDecodeRequiresCapacity();
    TestChunkedDecodeRejectsBadTerminator();
    TestChunkedDecodeRejectsMalformedExtension();
    TestChunkedDecodeRejectsMalformedTrailer();
    TestChunkedDecodeRejectsForbiddenTrailer();
    TestUnsupportedTransferEncoding();
    TestTransferEncodingRejectsContentLength();
    TestTransferEncodingRejectsHttp10();
    TestTransferEncodingRejectsDuplicateChunked();
    TestTransferEncodingRejectsParameters();
    TestTransferEncodingRejectsMalformedParameters();
    TestTransferEncodingRejectsIdentity();
    TestTransferEncodingRejectsOnlyEmptyList();
    TestHeaderCapacityFailure();
    TestResponseRejectsInvalidHeaders();
    TestResponseRejectsInvalidStatusLines();
    TestParseCloseDelimitedResponse();
    TestParseEmptyCloseDelimitedResponse();
    TestParseHttp10ConnectionDirectives();
    TestIncompleteResponseNeedsMoreData();
    TestIncompleteChunkedResponseNeedsMoreData();
    TestEmptyResponseNeedsMoreData();
    TestDuplicateContentLengthConflict();
    TestContentLengthEquivalentListRejected();
    TestContentLengthListConflict();
    TestNoBodyStatus();
    TestHeadResponseForbidsBody();
    TestSwitchingProtocolsLeavesWebSocketBytes();
    TestHeaderTokenMatching();
    TestObsFoldRejected();
    TestContentRangeParsing();
    TestContentRangeUnknownAndUnsatisfied();
    TestContentRangeRejectsMalformed();
    TestHttpCachePolicyDateParsing();
    TestHttpCacheControlParsing();
    TestHttpCacheRangeParsing();
    TestHttpCacheFreshnessAndValidationPolicy();

    if (g_failed) {
        return 1;
    }

    printf("PASS: HTTP parser tests\n");
    return 0;
}
