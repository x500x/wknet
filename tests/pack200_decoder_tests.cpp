#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttpLib/http/HttpPack200BandCodec.h"
#include "../src/KernelHttpLib/http/HttpPack200BandParser.h"
#include "../src/KernelHttpLib/http/HttpPack200Bands.h"
#include "../src/KernelHttpLib/http/HttpPack200Codec.h"
#include "../src/KernelHttpLib/http/HttpPack200Decoder.h"
#include "../src/KernelHttpLib/http/HttpPack200ClassWriter.h"
#include "../src/KernelHttpLib/http/HttpPack200JarWriter.h"
#include "../src/KernelHttpLib/http/HttpDeflateDecoder.h"

#include <stdio.h>
#include <string.h>

using KernelHttp::http::DecodePack200GzipContent;
using KernelHttp::http::HttpPack200BandCodec;
using KernelHttp::http::HttpPack200BandCodecKind;
using KernelHttp::http::HttpPack200BandReader;
using KernelHttp::http::HttpPack200CpBands;
using KernelHttp::http::HttpPack200CpCounts;
using KernelHttp::http::HttpPack200ClassBands;
using KernelHttp::http::HttpPack200CodeBands;
using KernelHttp::http::HttpPack200RelocationKind;
using KernelHttp::http::HttpPack200ClassWriter;
using KernelHttp::http::HttpPack200BootstrapMethod;
using KernelHttp::http::HttpPack200ClassMember;
using KernelHttp::http::HttpPack200FileBands;
using KernelHttp::http::HttpPack200Coding;
using KernelHttp::http::HttpPack200CodecArena;
using KernelHttp::http::HttpPack200DecodeBand;
using KernelHttp::http::HttpPack200DecodeBandWithMeta;
using KernelHttp::http::HttpPack200ParseMetaCodec;
using KernelHttp::http::HttpPack200ReadCpBands;
using KernelHttp::http::HttpPack200ReadAttributeDefinitionBands;
using KernelHttp::http::HttpPack200ReadInnerClassBands;
using KernelHttp::http::HttpPack200ReadBytecodeBands;
using KernelHttp::http::HttpPack200ReadClassBandsWithMeta;
using KernelHttp::http::HttpPack200ReadFileBands;
using KernelHttp::http::HttpPack200JarWriter;
using KernelHttp::http::HttpDecodeRawDeflate;
using KernelHttp::http::HttpXmlText;
using KernelHttp::HeapArray;

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

    SIZE_T CountBytes(const char* data, SIZE_T length, const char* needle, SIZE_T needleLength);

    void TestBhsdContinuationUsesFullByteValue()
    {
        const unsigned char bytes[] = { 0xec, 0x01 };
        HttpPack200BandReader reader(bytes, sizeof(bytes));
        LONG value = 0;
        const HttpPack200Coding unsigned5 = { 5, 64, 0, 0 };
        Expect(
            reader.ReadInt(unsigned5, &value) && value == 300,
            "pack200 BHSD continuation contributes the full byte value");
    }

    void TestCanonicalAndArbitraryMetaCodings()
    {
        const unsigned char canonicalBytes[] = { 115 };
        HttpPack200BandReader canonicalReader(canonicalBytes, sizeof(canonicalBytes));
        HttpPack200BandCodec canonical = {};
        NTSTATUS status = HttpPack200ParseMetaCodec(&canonicalReader, &canonical);
        Expect(
            NT_SUCCESS(status) &&
                canonical.Kind == HttpPack200BandCodecKind::Canonical &&
                canonical.Canonical.B == 4 &&
                canonical.Canonical.H == 248 &&
                canonical.Canonical.S == 1 &&
                canonical.Canonical.D == 1,
            "pack200 parses canonical meta-coding 115");

        // 116, then D=1/S=2/B=3 and H=64.
        const unsigned char arbitraryBytes[] = { 116, 0x15, 0x3f };
        HttpPack200BandReader arbitraryReader(arbitraryBytes, sizeof(arbitraryBytes));
        HttpPack200BandCodec arbitrary = {};
        status = HttpPack200ParseMetaCodec(&arbitraryReader, &arbitrary);
        Expect(
            NT_SUCCESS(status) &&
                arbitrary.Kind == HttpPack200BandCodecKind::Canonical &&
                arbitrary.Canonical.B == 3 &&
                arbitrary.Canonical.H == 64 &&
                arbitrary.Canonical.S == 2 &&
                arbitrary.Canonical.D == 1,
            "pack200 parses arbitrary BHSD meta-coding");
    }

    void TestPublishedPack200VersionsAreRecognized()
    {
        const unsigned char versions[][2] = {
            { 7, 150 },
            { 1, 160 },
            { 1, 170 },
            { 0, 171 }
        };

        for (SIZE_T index = 0; index < sizeof(versions) / sizeof(versions[0]); ++index) {
            const unsigned char segment[] = {
                0xca, 0xfe, 0xd0, 0x0d,
                versions[index][0], versions[index][1], 0
            };
            char output[64] = {};
            SIZE_T outputLength = 0;
            const NTSTATUS status = DecodePack200GzipContent(
                segment,
                sizeof(segment),
                output,
                sizeof(output),
                &outputLength);
            Expect(
                status == STATUS_INVALID_NETWORK_RESPONSE,
                "published Pack200 version reaches header truncation validation");
            Expect(outputLength == 0, "Pack200 failure clears output length");
        }

        const unsigned char unsupported[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0, 172, 0
        };
        char output[64] = {};
        SIZE_T outputLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            unsupported,
            sizeof(unsupported),
            output,
            sizeof(output),
            &outputLength);
        Expect(status == STATUS_NOT_SUPPORTED, "unknown Pack200 version is reported as unsupported");
        Expect(outputLength == 0, "unsupported Pack200 version clears output length");
    }

    void TestRunMetaCoding()
    {
        // Run K=2, with explicit BYTE1 A and B codings.
        const unsigned char metaBytes[] = { 121, 1, 1, 1 };
        HttpPack200BandReader metaReader(metaBytes, sizeof(metaBytes));
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(8);
        Expect(NT_SUCCESS(status), "pack200 run codec arena initializes");

        const HttpPack200BandCodec* codec = nullptr;
        status = HttpPack200ParseMetaCodec(
            &metaReader,
            { 1, 256, 0, 0 },
            4,
            &arena,
            &codec);
        Expect(
            NT_SUCCESS(status) &&
                codec != nullptr &&
                codec->Kind == HttpPack200BandCodecKind::Run &&
                codec->FirstCount == 2 &&
                metaReader.Remaining() == 0,
            "pack200 parses recursive run meta-coding");

        const unsigned char bandBytes[] = { 10, 20, 30, 40 };
        HttpPack200BandReader bandReader(bandBytes, sizeof(bandBytes));
        LONG values[4] = {};
        status = codec != nullptr ?
            HttpPack200DecodeBand(&bandReader, *codec, values, 4) :
            STATUS_INVALID_NETWORK_RESPONSE;
        Expect(
            NT_SUCCESS(status) &&
                values[0] == 10 && values[1] == 20 &&
                values[2] == 30 && values[3] == 40 &&
                bandReader.Remaining() == 0,
            "pack200 decodes run A and B sub-bands");

        const unsigned char nestedRun[] = { 117, 117 };
        HttpPack200BandReader nestedReader(nestedRun, sizeof(nestedRun));
        HttpPack200CodecArena nestedArena = {};
        status = nestedArena.Initialize(8);
        codec = nullptr;
        if (NT_SUCCESS(status)) {
            status = HttpPack200ParseMetaCodec(
                &nestedReader,
                { 1, 256, 0, 0 },
                10,
                &nestedArena,
                &codec);
        }
        Expect(
            status == STATUS_INVALID_NETWORK_RESPONSE,
            "pack200 rejects directly nested run coding in ACode");
    }

    void TestPopulationMetaCoding()
    {
        // F and U use the default BYTE1 coding. T uses implicit L=1 coding.
        const unsigned char metaBytes[] = { 148 };
        HttpPack200BandReader metaReader(metaBytes, sizeof(metaBytes));
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(8);
        Expect(NT_SUCCESS(status), "pack200 population codec arena initializes");

        const HttpPack200BandCodec* codec = nullptr;
        status = HttpPack200ParseMetaCodec(
            &metaReader,
            { 1, 256, 0, 0 },
            4,
            &arena,
            &codec);
        Expect(
            NT_SUCCESS(status) &&
                codec != nullptr &&
                codec->Kind == HttpPack200BandCodecKind::Population &&
                codec->TokenDefL == 1 &&
                metaReader.Remaining() == 0,
            "pack200 parses population F/T/U meta-coding");

        const unsigned char bandBytes[] = {
            10, 20, 20,
            1, 2, 0, 1,
            99
        };
        HttpPack200BandReader bandReader(bandBytes, sizeof(bandBytes));
        LONG values[4] = {};
        status = codec != nullptr ?
            HttpPack200DecodeBand(&bandReader, *codec, values, 4) :
            STATUS_INVALID_NETWORK_RESPONSE;
        Expect(
            NT_SUCCESS(status) &&
                values[0] == 10 && values[1] == 20 &&
                values[2] == 99 && values[3] == 10 &&
                bandReader.Remaining() == 0,
            "pack200 decodes population favoured tokens and unfavoured values");
    }

    void TestBandEscapeUsesSeparateBandHeaders()
    {
        // UNSIGNED5 escape X=L+1 selects canonical coding 1 (BYTE1).
        const unsigned char canonicalBand[] = { 0xc1, 0x00, 7, 8 };
        HttpPack200BandReader canonicalReader(canonicalBand, sizeof(canonicalBand));
        HttpPack200BandReader emptyHeaders(nullptr, 0);
        HttpPack200CodecArena canonicalArena = {};
        NTSTATUS status = canonicalArena.Initialize(8);
        LONG canonicalValues[2] = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200DecodeBandWithMeta(
                &canonicalReader,
                &emptyHeaders,
                { 5, 64, 0, 0 },
                canonicalValues,
                2,
                &canonicalArena);
        }
        Expect(
            NT_SUCCESS(status) &&
                canonicalValues[0] == 7 && canonicalValues[1] == 8 &&
                canonicalReader.Remaining() == 0 &&
                emptyHeaders.Remaining() == 0,
            "pack200 band escape selects inline canonical meta-coding");

        // UNSIGNED5 escape X=L+121 selects run coding 121; its remaining
        // parameters and child codings come from the independent band_headers band.
        const unsigned char runBand[] = { 0xf9, 0x01, 10, 20, 30, 40 };
        const unsigned char runHeaders[] = { 1, 1, 1 };
        HttpPack200BandReader runReader(runBand, sizeof(runBand));
        HttpPack200BandReader headerReader(runHeaders, sizeof(runHeaders));
        HttpPack200CodecArena runArena = {};
        status = runArena.Initialize(8);
        LONG runValues[4] = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200DecodeBandWithMeta(
                &runReader,
                &headerReader,
                { 5, 64, 0, 0 },
                runValues,
                4,
                &runArena);
        }
        Expect(
            NT_SUCCESS(status) &&
                runValues[0] == 10 && runValues[1] == 20 &&
                runValues[2] == 30 && runValues[3] == 40 &&
                runReader.Remaining() == 0 &&
                headerReader.Remaining() == 0,
            "pack200 composite meta-coding consumes parameters from band_headers");
    }

    void TestConstantPoolNumericBands()
    {
        const unsigned char encoded[] = { 42, 0, 0, 0, 0, 0 };
        HttpPack200BandReader reader(encoded, sizeof(encoded));
        HttpPack200BandReader bandHeaders(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        Expect(NT_SUCCESS(status), "Pack200 constant-pool codec arena initializes");

        HttpPack200CpCounts counts = {};
        counts.Utf8 = 1;
        counts.Int = 1;
        counts.Float = 1;
        counts.Long = 1;
        counts.Double = 1;
        HttpPack200CpBands bands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadCpBands(
                &reader,
                &bandHeaders,
                &arena,
                counts,
                &bands);
        }
        Expect(
            NT_SUCCESS(status) &&
                reader.Remaining() == 0 &&
                bands.IntCount() == 1 &&
                bands.FloatCount() == 1 &&
                bands.LongCount() == 1 &&
                bands.DoubleCount() == 1 &&
                bands.IntBits()[0] == 42 &&
                bands.FloatBits()[0] == 0 &&
                bands.LongHighBits()[0] == 0 &&
                bands.LongLowBits()[0] == 0 &&
                bands.DoubleHighBits()[0] == 0 &&
                bands.DoubleLowBits()[0] == 0,
            "Pack200 numeric constant-pool bands decode in specification order");
    }

    void TestJava7ConstantPoolBands()
    {
        const unsigned char encoded[] = {
            1, 'I',
            42,
            1,
            2,
            0, 0,
            0, 0,
            2, 0,
            0,
            0, 1, 0,
            0, 0
        };
        HttpPack200BandReader reader(encoded, sizeof(encoded));
        HttpPack200BandReader bandHeaders(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        Expect(NT_SUCCESS(status), "Pack200 Java 7 constant-pool codec arena initializes");

        HttpPack200CpCounts counts = {};
        counts.Utf8 = 2;
        counts.Int = 1;
        counts.Class = 1;
        counts.Signature = 1;
        counts.Descriptor = 1;
        counts.Field = 1;
        counts.MethodHandle = 1;
        counts.MethodType = 1;
        counts.BootstrapMethod = 1;
        counts.InvokeDynamic = 1;
        HttpPack200CpBands bands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadCpBands(
                &reader,
                &bandHeaders,
                &arena,
                counts,
                &bands);
        }
        Expect(
            NT_SUCCESS(status) &&
                reader.Remaining() == 0 &&
                bands.MethodHandleCount() == 1 &&
                bands.MethodHandleReferenceKinds()[0] == 1 &&
                bands.MethodHandleMemberIndexes()[0] == 0 &&
                bands.MethodTypeSignatureIndexes()[0] == 0 &&
                bands.BootstrapMethodReferenceIndexes()[0] == 0 &&
                bands.BootstrapMethodArgumentCounts()[0] == 1 &&
                bands.BootstrapMethodArgumentIndexes()[0] == 0 &&
                bands.InvokeDynamicBootstrapIndexes()[0] == 0 &&
                bands.InvokeDynamicDescriptorIndexes()[0] == 0,
            "Pack200 Java 7 extra constant-pool bands decode in specification order");
    }

    void TestAttributeDefinitionAndInnerClassBands()
    {
        const unsigned char attributeBytes[] = { 4, 1, 2 };
        HttpPack200BandReader attributeReader(attributeBytes, sizeof(attributeBytes));
        HttpPack200BandReader emptyHeaders(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(32);
        KernelHttp::http::HttpPack200AttributeDefinitionBands definitions = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadAttributeDefinitionBands(
                &attributeReader,
                &emptyHeaders,
                &arena,
                1,
                3,
                &definitions);
        }
        Expect(
            NT_SUCCESS(status) && attributeReader.Remaining() == 0 &&
                definitions.Headers()[0] == 4 &&
                definitions.NameIndexes()[0] == 1 &&
                definitions.LayoutIndexes()[0] == 2,
            "Pack200 attribute definition header, name and layout bands decode");

        const unsigned char innerBytes[] = { 1, 0xc1, 0xfd, 0x0c, 2, 4 };
        HttpPack200BandReader innerReader(innerBytes, sizeof(innerBytes));
        HttpPack200BandReader innerHeaders(nullptr, 0);
        KernelHttp::http::HttpPack200InnerClassBands inner = {};
        status = HttpPack200ReadInnerClassBands(
            &innerReader,
            &innerHeaders,
            &arena,
            1,
            4,
            4,
            &inner);
        Expect(
            NT_SUCCESS(status) && innerReader.Remaining() == 0 &&
                inner.ThisClassIndexes()[0] == 1 &&
                inner.Flags()[0] == 0x00010001UL &&
                inner.OuterClassIndexes()[0] == 1 &&
                inner.NameIndexes()[0] == 2,
            "Pack200 global inner-class bands decode explicit outer and name references");
    }

    void TestJava7AndJava8BytecodeReferenceBands()
    {
        const unsigned char encoded[] = {
            240, 241, 186, 242, 243, 177, 0xff,
            0, 2,
            0, 2,
            0
        };
        HttpPack200BandReader reader(encoded, sizeof(encoded));
        HttpPack200BandReader headers(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        HttpPack200CodeBands bands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadBytecodeBands(
                &reader,
                &headers,
                &arena,
                1,
                &bands);
        }
        const unsigned char expected[] = {
            18, 0,
            19, 0, 0,
            186, 0, 0, 0, 0,
            183, 0, 0,
            184, 0, 0,
            177
        };
        Expect(
            NT_SUCCESS(status) && reader.Remaining() == 0 &&
                bands.CodeCount() == 1 && bands.RelocationCount() == 5 &&
                bands.CodeLengths()[0] == sizeof(expected) &&
                memcmp(bands.CodeBytes(), expected, sizeof(expected)) == 0 &&
                bands.Relocations()[0].Kind == HttpPack200RelocationKind::LoadableValue &&
                bands.Relocations()[0].ReferenceIndex == 0 &&
                bands.Relocations()[1].Kind == HttpPack200RelocationKind::LoadableValue &&
                bands.Relocations()[1].ReferenceIndex == 1 &&
                bands.Relocations()[2].Kind == HttpPack200RelocationKind::InvokeDynamic &&
                bands.Relocations()[3].Kind == HttpPack200RelocationKind::InterfaceMethod &&
                bands.Relocations()[4].Kind == HttpPack200RelocationKind::InterfaceMethod,
            "Pack200 qldc, invokedynamic and Java 8 interface invoke bands reconstruct bytecodes");
    }

    SIZE_T CountBytes(const char* data, SIZE_T length, const char* needle, SIZE_T needleLength)
    {
        if (data == nullptr || needle == nullptr || needleLength == 0 || needleLength > length) {
            return 0;
        }
        SIZE_T count = 0;
        for (SIZE_T offset = 0; offset <= length - needleLength; ++offset) {
            if (memcmp(data + offset, needle, needleLength) == 0) {
                ++count;
            }
        }
        return count;
    }

    void TestInnerClassPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x31, 0x02, 0x00, 0x18, 0x10, 0x0c, 0x06, 0x6a, 0x61,
            0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x4f, 0x75, 0x74, 0x65, 0x72, 0x24, 0x49, 0x6e, 0x6e, 0x65, 0x72,
            0x01, 0x01, 0x01, 0x02, 0x09, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21,
            0x21, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x00, 0x02, 0x02
        };
        char jar[4096] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        Expect(
            NT_SUCCESS(status) &&
                CountBytes(jar, jarLength, "sample/Outer.class", 18) >= 2 &&
                CountBytes(jar, jarLength, "sample/Outer$Inner.class", 24) >= 2 &&
                CountBytes(jar, jarLength, "InnerClasses", 12) >= 2,
            "Pack200 global inner-class tuples rebuild InnerClasses attributes in both class files");
    }

    void TestSignatureAttributePack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x02,
            0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x06, 0x07, 0x08, 0x02, 0x03, 0x08, 0x10, 0x0e, 0x05, 0x28, 0x4c, 0x3b, 0x29, 0x4c, 0x3b,
            0x54, 0x54, 0x3b, 0x29, 0x54, 0x54, 0x3b, 0x3c, 0x54, 0x3a, 0x4c, 0x3b, 0x3e, 0x4c, 0x3b, 0x4c,
            0x3b, 0x54, 0x54, 0x3b, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x6a, 0x61, 0x76, 0x61,
            0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2f, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x07,
            0x01, 0x0a, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x05, 0x01, 0x03, 0x02,
            0x00, 0x00, 0x02, 0x02, 0x00, 0xc1, 0xfd, 0x7c, 0x00, 0x01, 0xc1, 0xcd, 0x7d, 0x03, 0xe1, 0xcd,
            0x7d, 0x02, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        char jar[4096] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        Expect(
            NT_SUCCESS(status) &&
                CountBytes(jar, jarLength, "Signature", 9) >= 1 &&
                CountBytes(jar, jarLength, "<T:Ljava/lang/Object;>Ljava/lang/Object;", 40) >= 1 &&
                CountBytes(jar, jarLength, "(TT;)TT;", 8) >= 1,
            "Pack200 class, field and method Signature layouts rebuild classfile attributes");
    }

    void TestMinimalClassBands()
    {
        const unsigned char encoded[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0xc1, 0x15 };
        HttpPack200BandReader reader(encoded, sizeof(encoded));
        HttpPack200BandReader bandHeaders(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        HttpPack200ClassBands bands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadClassBandsWithMeta(
                &reader,
                &bandHeaders,
                &arena,
                1,
                false,
                false,
                false,
                false,
                false,
                &bands);
        }
        Expect(
            NT_SUCCESS(status) &&
                reader.Remaining() == 0 &&
                bands.ThisClassIndexes()[0] == 1 &&
                bands.SuperClassIndexes()[0] == 0 &&
                bands.InterfaceCounts()[0] == 0 &&
                bands.FieldCounts()[0] == 0 &&
                bands.MethodCounts()[0] == 0 &&
                bands.FlagsLow()[0] == 0x0601,
            "Pack200 minimal class bands decode in specification order");
    }

    void TestDeprecatedAttributeFlags()
    {
        const unsigned char encoded[] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0xc1, 0xd5, 0xfd, 0x00
        };
        HttpPack200BandReader reader(encoded, sizeof(encoded));
        HttpPack200BandReader bandHeaders(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        HttpPack200ClassBands bands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadClassBandsWithMeta(
                &reader,
                &bandHeaders,
                &arena,
                1,
                false,
                false,
                false,
                false,
                false,
                &bands);
        }
        Expect(
            NT_SUCCESS(status) && reader.Remaining() == 0 &&
                bands.FlagsLow()[0] == ((1UL << 20) | 0x0601UL),
            "Pack200 class Deprecated layout flag is accepted without extra bands");
    }

    void TestEnclosingMethodAttributeBands()
    {
        const unsigned char encoded[] = {
            0x02, 0x00, 0x00, 0x00, 0x00,
            0xc1, 0xd5, 0x3d,
            0x01,
            0x00
        };
        HttpPack200BandReader reader(encoded, sizeof(encoded));
        HttpPack200BandReader bandHeaders(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        HttpPack200ClassBands bands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadClassBandsWithMeta(
                &reader,
                &bandHeaders,
                &arena,
                1,
                false,
                false,
                false,
                false,
                false,
                &bands);
        }
        Expect(
            NT_SUCCESS(status) && reader.Remaining() == 0 &&
                bands.FlagsLow()[0] == ((1UL << 18) | 0x0601UL) &&
                bands.EnclosingMethodClassIndexes()[0] == 1 &&
                bands.EnclosingMethodDescriptorIndexes()[0] == 0,
            "Pack200 EnclosingMethod class and nullable descriptor bands decode in order");
    }

    void TestClassOnlyBandSequence()
    {
        const unsigned char encoded[] = {
            0x00, 0x10, 0x0d, 0x6a, 0x61, 0x76, 0x61, 0x2f,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a,
            0x65, 0x63, 0x74, 0x73, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2f, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x72,
            0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc1,
            0x15, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22,
            0x02
        };
        HttpPack200BandReader reader(encoded, sizeof(encoded));
        HttpPack200BandReader bandHeaders(nullptr, 0);
        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        HttpPack200CpCounts counts = {};
        counts.Utf8 = 3;
        counts.Class = 2;
        HttpPack200CpBands cpBands = {};
        HttpPack200ClassBands classBands = {};
        HttpPack200FileBands fileBands = {};
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadCpBands(
                &reader,
                &bandHeaders,
                &arena,
                counts,
                &cpBands);
        }
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadClassBandsWithMeta(
                &reader,
                &bandHeaders,
                &arena,
                1,
                false,
                false,
                false,
                false,
                false,
                &classBands);
        }
        if (NT_SUCCESS(status)) {
            status = HttpPack200ReadFileBands(
                &reader,
                &bandHeaders,
                &arena,
                1,
                false,
                true,
                true,
                &fileBands);
        }
        Expect(
            NT_SUCCESS(status) &&
                reader.Remaining() == 0 &&
                fileBands.NameIndexes()[0] == 0 &&
                fileBands.SizesLow()[0] == 0 &&
                fileBands.Options()[0] == 2,
            "Pack200 class-only CP, class, and file bands consume the reference segment body");
        HttpXmlText thisName = {};
        HttpXmlText superName = {};
        const ULONG* classNames = cpBands.ClassNameIndexes();
        const ULONG* thisClasses = classBands.ThisClassIndexes();
        const ULONG* superClasses = classBands.SuperClassIndexes();
        const bool namesValid = classNames != nullptr &&
            thisClasses != nullptr &&
            superClasses != nullptr &&
            thisClasses[0] < cpBands.ClassCount() &&
            superClasses[0] < cpBands.ClassCount() &&
            cpBands.GetUtf8(classNames[thisClasses[0]], &thisName) &&
            cpBands.GetUtf8(classNames[superClasses[0]], &superName);
        Expect(
            namesValid &&
                thisName.Length == 13 &&
                memcmp(thisName.Data, "sample/Marker", 13) == 0 &&
                superName.Length == 16 &&
                memcmp(superName.Data, "java/lang/Object", 16) == 0,
            "Pack200 class-only references resolve this and super class names");
        Expect(
            fileBands.Modtimes()[0] == 315561600,
            "Pack200 class-only file modification time band decodes");
        HeapArray<char> classBytes(128);
        SIZE_T classLength = 0;
        NTSTATUS classStatus = classBytes.IsValid() ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
        if (NT_SUCCESS(classStatus) && namesValid) {
            HttpPack200ClassWriter classWriter(classBytes.Get(), classBytes.Count());
            USHORT thisUtf8 = 0;
            USHORT thisClass = 0;
            USHORT superUtf8 = 0;
            USHORT superClass = 0;
            classStatus = classWriter.Begin(0, 49, 5);
            if (NT_SUCCESS(classStatus)) classStatus = classWriter.AddUtf8(thisName, &thisUtf8);
            if (NT_SUCCESS(classStatus)) classStatus = classWriter.AddClass(thisUtf8, &thisClass);
            if (NT_SUCCESS(classStatus)) classStatus = classWriter.AddUtf8(superName, &superUtf8);
            if (NT_SUCCESS(classStatus)) classStatus = classWriter.AddClass(superUtf8, &superClass);
            if (NT_SUCCESS(classStatus)) {
                classStatus = classWriter.FinishHeader(0x0601, thisClass, superClass, &classLength);
            }
        }
        Expect(
            NT_SUCCESS(classStatus) && classLength == 65,
            "Pack200 minimal class writer rebuilds the reference interface classfile");
    }

    void TestClassWriterMethodHandleAndMethodTypeConstants()
    {
        char classBytes[256] = {};
        HttpPack200ClassWriter writer(classBytes, sizeof(classBytes));
        NTSTATUS status = writer.Begin(0, 51, 9);
        USHORT classNameUtf8 = 0;
        USHORT classIndex = 0;
        USHORT methodNameUtf8 = 0;
        USHORT descriptorUtf8 = 0;
        USHORT nameAndType = 0;
        USHORT methodReference = 0;
        USHORT methodHandle = 0;
        USHORT methodType = 0;
        if (NT_SUCCESS(status)) {
            status = writer.AddUtf8({ "sample/Owner", 12 }, &classNameUtf8);
        }
        if (NT_SUCCESS(status)) status = writer.AddClass(classNameUtf8, &classIndex);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "target", 6 }, &methodNameUtf8);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "()V", 3 }, &descriptorUtf8);
        if (NT_SUCCESS(status)) {
            status = writer.AddNameAndType(methodNameUtf8, descriptorUtf8, &nameAndType);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddMethodref(classIndex, nameAndType, &methodReference);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddMethodHandle(6, methodReference, &methodHandle);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddMethodType(descriptorUtf8, &methodType);
        }
        SIZE_T classLength = 0;
        if (NT_SUCCESS(status)) {
            status = writer.FinishHeader(0x0021, classIndex, classIndex, &classLength);
        }
        Expect(
            NT_SUCCESS(status) && classLength != 0 && methodHandle == 7 && methodType == 8 &&
                CountBytes(classBytes, classLength, "\x0f\x06", 2) == 1 &&
                CountBytes(classBytes, classLength, "\x10", 1) >= 1,
            "Pack200 class writer emits CONSTANT_MethodHandle and CONSTANT_MethodType entries");
    }

    void TestClassWriterInvokeDynamicAndBootstrapMethods()
    {
        char classBytes[256] = {};
        HttpPack200ClassWriter writer(classBytes, sizeof(classBytes));
        NTSTATUS status = writer.Begin(0, 51, 15);
        USHORT classNameUtf8 = 0;
        USHORT classIndex = 0;
        USHORT bootstrapNameUtf8 = 0;
        USHORT bootstrapDescriptorUtf8 = 0;
        USHORT bootstrapNameAndType = 0;
        USHORT bootstrapReference = 0;
        USHORT bootstrapHandle = 0;
        USHORT callNameUtf8 = 0;
        USHORT callDescriptorUtf8 = 0;
        USHORT callNameAndType = 0;
        USHORT invokeDynamic = 0;
        USHORT attributeName = 0;
        USHORT argumentUtf8 = 0;
        USHORT argumentString = 0;
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "sample/Owner", 12 }, &classNameUtf8);
        if (NT_SUCCESS(status)) status = writer.AddClass(classNameUtf8, &classIndex);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "bootstrap", 9 }, &bootstrapNameUtf8);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "()V", 3 }, &bootstrapDescriptorUtf8);
        if (NT_SUCCESS(status)) {
            status = writer.AddNameAndType(
                bootstrapNameUtf8,
                bootstrapDescriptorUtf8,
                &bootstrapNameAndType);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddMethodref(
                classIndex,
                bootstrapNameAndType,
                &bootstrapReference);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddMethodHandle(6, bootstrapReference, &bootstrapHandle);
        }
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "call", 4 }, &callNameUtf8);
        if (NT_SUCCESS(status)) {
            status = writer.AddUtf8(
                { "()Ljava/lang/String;", 20 },
                &callDescriptorUtf8);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddNameAndType(
                callNameUtf8,
                callDescriptorUtf8,
                &callNameAndType);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddInvokeDynamic(0, callNameAndType, &invokeDynamic);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddUtf8({ "BootstrapMethods", 16 }, &attributeName);
        }
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "argument", 8 }, &argumentUtf8);
        if (NT_SUCCESS(status)) status = writer.AddString(argumentUtf8, &argumentString);

        const USHORT arguments[] = { argumentString };
        const HttpPack200BootstrapMethod bootstrapMethods[] = {
            { bootstrapHandle, arguments, 1 }
        };
        SIZE_T classLength = 0;
        if (NT_SUCCESS(status)) {
            status = writer.FinishClass(
                0x0021,
                classIndex,
                classIndex,
                nullptr,
                0,
                nullptr,
                0,
                nullptr,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                attributeName,
                bootstrapMethods,
                1,
                0,
                nullptr,
                0,
                nullptr,
                0,
                &classLength);
        }
        const unsigned char expectedMethodHandle[] = { 0x0f, 0x06, 0x00, 0x06 };
        const unsigned char expectedInvokeDynamic[] = { 0x12, 0x00, 0x00, 0x00, 0x0a };
        const unsigned char expectedClassTail[] = {
            0x00, 0x21, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c,
            0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x07,
            0x00, 0x01, 0x00, 0x0e
        };
        Expect(
            NT_SUCCESS(status) && classLength == 161 && bootstrapHandle == 7 &&
                callNameAndType == 10 && invokeDynamic == 11 && attributeName == 12 &&
                argumentString == 14 &&
                memcmp(classBytes + 56, expectedMethodHandle, sizeof(expectedMethodHandle)) == 0 &&
                memcmp(classBytes + 95, expectedInvokeDynamic, sizeof(expectedInvokeDynamic)) == 0 &&
                memcmp(classBytes + 133, expectedClassTail, sizeof(expectedClassTail)) == 0,
            "Pack200 class writer emits CONSTANT_InvokeDynamic and BootstrapMethods attributes");
    }

    void TestClassWriterDeprecatedAttributes()
    {
        char classBytes[256] = {};
        HttpPack200ClassWriter writer(classBytes, sizeof(classBytes));
        NTSTATUS status = writer.Begin(0, 49, 8);
        USHORT className = 0;
        USHORT classIndex = 0;
        HttpPack200ClassMember field = {};
        HttpPack200ClassMember method = {};
        USHORT deprecatedName = 0;
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "sample/Old", 10 }, &className);
        if (NT_SUCCESS(status)) status = writer.AddClass(className, &classIndex);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "value", 5 }, &field.NameIndex);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "I", 1 }, &field.DescriptorIndex);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "run", 3 }, &method.NameIndex);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "()V", 3 }, &method.DescriptorIndex);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "Deprecated", 10 }, &deprecatedName);
        field.DeprecatedAttributeNameIndex = deprecatedName;
        method.DeprecatedAttributeNameIndex = deprecatedName;
        SIZE_T classLength = 0;
        if (NT_SUCCESS(status)) {
            status = writer.FinishClass(
                0x0021,
                classIndex,
                classIndex,
                nullptr,
                0,
                &field,
                1,
                &method,
                1,
                0,
                0,
                0,
                0,
                deprecatedName,
                0,
                0,
                0,
                0,
                nullptr,
                0,
                0,
                nullptr,
                0,
                nullptr,
                0,
                &classLength);
        }
        const char deprecatedAttribute[] = { 0x00, 0x07, 0x00, 0x00, 0x00, 0x00 };
        Expect(
            NT_SUCCESS(status) && classLength != 0 &&
                CountBytes(
                    classBytes,
                    classLength,
                    deprecatedAttribute,
                    sizeof(deprecatedAttribute)) == 3,
            "Pack200 class writer emits class, field and method Deprecated attributes");
    }

    void TestClassWriterEnclosingMethodAttribute()
    {
        char classBytes[256] = {};
        HttpPack200ClassWriter writer(classBytes, sizeof(classBytes));
        NTSTATUS status = writer.Begin(0, 49, 9);
        USHORT className = 0;
        USHORT classIndex = 0;
        USHORT enclosingClassName = 0;
        USHORT enclosingClass = 0;
        USHORT methodName = 0;
        USHORT methodDescriptor = 0;
        USHORT enclosingMethod = 0;
        USHORT attributeName = 0;
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "sample/Local", 12 }, &className);
        if (NT_SUCCESS(status)) status = writer.AddClass(className, &classIndex);
        if (NT_SUCCESS(status)) {
            status = writer.AddUtf8({ "sample/Owner", 12 }, &enclosingClassName);
        }
        if (NT_SUCCESS(status)) status = writer.AddClass(enclosingClassName, &enclosingClass);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "make", 4 }, &methodName);
        if (NT_SUCCESS(status)) status = writer.AddUtf8({ "()V", 3 }, &methodDescriptor);
        if (NT_SUCCESS(status)) {
            status = writer.AddNameAndType(methodName, methodDescriptor, &enclosingMethod);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddUtf8({ "EnclosingMethod", 15 }, &attributeName);
        }
        SIZE_T classLength = 0;
        if (NT_SUCCESS(status)) {
            status = writer.FinishClass(
                0x0021,
                classIndex,
                classIndex,
                nullptr,
                0,
                nullptr,
                0,
                nullptr,
                0,
                0,
                0,
                0,
                0,
                0,
                attributeName,
                enclosingClass,
                enclosingMethod,
                0,
                nullptr,
                0,
                0,
                nullptr,
                0,
                nullptr,
                0,
                &classLength);
        }
        const char expectedAttribute[] = {
            0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x07
        };
        Expect(
            NT_SUCCESS(status) && classLength != 0 &&
                CountBytes(
                    classBytes,
                    classLength,
                    expectedAttribute,
                    sizeof(expectedAttribute)) == 1,
            "Pack200 class writer emits EnclosingMethod class and NameAndType indexes");
    }

    USHORT ReadLe16(const unsigned char* value)
    {
        return static_cast<USHORT>(
            static_cast<USHORT>(value[0]) |
            (static_cast<USHORT>(value[1]) << 8));
    }

    ULONG ReadLe32(const unsigned char* value)
    {
        return static_cast<ULONG>(ReadLe16(value)) |
            (static_cast<ULONG>(ReadLe16(value + 2)) << 16);
    }

    ULONGLONG ReadLe64(const unsigned char* value)
    {
        return static_cast<ULONGLONG>(ReadLe32(value)) |
            (static_cast<ULONGLONG>(ReadLe32(value + 4)) << 32);
    }

    void ExpectFileOnlyJar(const char* jar, SIZE_T jarLength, const char* sourceDescription)
    {
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
        const char expectedName[] = "data/hello.txt";
        const unsigned char expectedContent[] = {
            'h', 'e', 'l', 'l', 'o', ' ', 'p', 'a', 'c', 'k', '2', '0', '0'
        };
        const SIZE_T expectedNameLength = sizeof(expectedName) - 1;
        const SIZE_T localContentOffset = 30 + expectedNameLength;
        const SIZE_T centralOffset = localContentOffset + sizeof(expectedContent);
        const SIZE_T eocdOffset = centralOffset + 46 + expectedNameLength;
        const bool matches =
            jarLength == eocdOffset + 22 &&
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 6) == 0x0800 &&
                ReadLe16(bytes + 8) == 0 &&
                ReadLe16(bytes + 10) == 0x4000 &&
                ReadLe16(bytes + 12) == 0x0021 &&
                ReadLe32(bytes + 14) == 0xc3c9de61UL &&
                ReadLe32(bytes + 18) == sizeof(expectedContent) &&
                ReadLe32(bytes + 22) == sizeof(expectedContent) &&
                ReadLe16(bytes + 26) == expectedNameLength &&
                ReadLe16(bytes + 28) == 0 &&
                memcmp(bytes + 30, expectedName, expectedNameLength) == 0 &&
                memcmp(bytes + localContentOffset, expectedContent, sizeof(expectedContent)) == 0 &&
                ReadLe32(bytes + centralOffset) == 0x02014b50UL &&
                ReadLe16(bytes + centralOffset + 28) == expectedNameLength &&
                memcmp(bytes + centralOffset + 46, expectedName, expectedNameLength) == 0 &&
                ReadLe32(bytes + eocdOffset) == 0x06054b50UL &&
                ReadLe16(bytes + eocdOffset + 8) == 1 &&
                ReadLe16(bytes + eocdOffset + 10) == 1;
        if (!matches) {
            printf(
                "Pack200 JAR mismatch: length=%zu flags=%04x method=%u time=%04x date=%04x "
                "crc=%08lx size=%lu nameLength=%u central=%08lx eocd=%08lx\n",
                jarLength,
                ReadLe16(bytes + 6),
                ReadLe16(bytes + 8),
                ReadLe16(bytes + 10),
                ReadLe16(bytes + 12),
                static_cast<unsigned long>(ReadLe32(bytes + 14)),
                static_cast<unsigned long>(ReadLe32(bytes + 22)),
                ReadLe16(bytes + 26),
                static_cast<unsigned long>(ReadLe32(bytes + centralOffset)),
                static_cast<unsigned long>(ReadLe32(bytes + eocdOffset)));
        }
        Expect(matches, sourceDescription);
    }

    void TestFileOnlyPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0e, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x68,
            0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74,
            0x01, 0x0d, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x00,
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x70, 0x61,
            0x63, 0x6b, 0x32, 0x30, 0x30
        };
        const unsigned char gzipPacked[] = {
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

        char jar[512] = {};
        SIZE_T jarLength = 0;
        NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        Expect(NT_SUCCESS(status), "raw Pack200 file-only segment decodes successfully");
        if (NT_SUCCESS(status)) {
            ExpectFileOnlyJar(jar, jarLength, "raw Pack200 reconstructs the expected JAR entry");
        }

        RtlZeroMemory(jar, sizeof(jar));
        jarLength = 0;
        status = DecodePack200GzipContent(
            gzipPacked,
            sizeof(gzipPacked),
            jar,
            sizeof(jar),
            &jarLength);
        Expect(NT_SUCCESS(status), "gzip Pack200 file-only segment decodes successfully");
        if (NT_SUCCESS(status)) {
            ExpectFileOnlyJar(jar, jarLength, "gzip Pack200 reconstructs the expected JAR entry");
        }

        jarLength = 99;
        status = DecodePack200GzipContent(
            packed,
            sizeof(packed) - 1,
            jar,
            sizeof(jar),
            &jarLength);
        Expect(
            status == STATUS_INVALID_NETWORK_RESPONSE && jarLength == 0,
            "truncated Pack200 file bits fail without exposing a partial JAR");
    }

    void TestClassOnlyPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x10, 0x0d, 0x6a, 0x61, 0x76, 0x61,
            0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62,
            0x6a, 0x65, 0x63, 0x74, 0x73, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2f, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x72,
            0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc1,
            0x15, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22,
            0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x05, 0x01, 0x00, 0x0d, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x4d, 0x61, 0x72, 0x6b,
            0x65, 0x72, 0x07, 0x00, 0x01, 0x01, 0x00, 0x10,
            0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
            0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
            0x07, 0x00, 0x03, 0x06, 0x01, 0x00, 0x02, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00
        };
        const char expectedName[] = "sample/Marker.class";

        char jar[512] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 class-only segment reconstructs a valid reference classfile JAR entry");
    }

    void TestAbstractMethodPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x03,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x14, 0x13, 0x05, 0x07, 0x10,
            0x06, 0x0f, 0x28, 0x49, 0x29, 0x4c, 0x3b, 0x63,
            0x6f, 0x6e, 0x76, 0x65, 0x72, 0x74, 0x6a, 0x61,
            0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f,
            0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x74,
            0x72, 0x69, 0x6e, 0x67, 0x73, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x72,
            0x61, 0x63, 0x74, 0x03, 0x01, 0x01, 0x02, 0x01,
            0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00,
            0xc1, 0x0d, 0xc1, 0x15, 0x00, 0x00, 0xc0, 0xf1,
            0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x07, 0x01, 0x00, 0x0f, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x43, 0x6f, 0x6e, 0x74,
            0x72, 0x61, 0x63, 0x74, 0x07, 0x00, 0x01, 0x01,
            0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
            0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65,
            0x63, 0x74, 0x07, 0x00, 0x03, 0x01, 0x00, 0x07,
            0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x74, 0x01,
            0x00, 0x15, 0x28, 0x49, 0x29, 0x4c, 0x6a, 0x61,
            0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f,
            0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x06,
            0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x04, 0x01, 0x00, 0x05, 0x00,
            0x06, 0x00, 0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/Contract.class";

        char jar[768] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 abstract method descriptors and flags rebuild a valid classfile");
    }

    void TestMemberOnlyPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x09, 0x00, 0x04,
            0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x0a, 0x0a, 0x13, 0x00, 0x00,
            0x04, 0x01, 0x14, 0x0b, 0x06, 0x04, 0x0c, 0x05,
            0x28, 0x29, 0x4c, 0x3b, 0x49, 0x6a, 0x61, 0x76,
            0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x53, 0x65, 0x72,
            0x69, 0x61, 0x6c, 0x69, 0x7a, 0x61, 0x62, 0x6c,
            0x65, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62,
            0x6a, 0x65, 0x63, 0x74, 0x53, 0x74, 0x72, 0x69,
            0x6e, 0x67, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x4d, 0x6f, 0x64,
            0x65, 0x6c, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x03,
            0x01, 0x01, 0x02, 0x04, 0x01, 0x02, 0x10, 0x03,
            0x00, 0x01, 0x06, 0x02, 0x02, 0x00, 0x02, 0x02,
            0x00, 0x01, 0x01, 0xc1, 0x0d, 0xe1, 0x0d, 0x00,
            0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x0b, 0x01, 0x00, 0x0c, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x4d, 0x6f, 0x64, 0x65,
            0x6c, 0x07, 0x00, 0x01, 0x01, 0x00, 0x10, 0x6a,
            0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67,
            0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x07,
            0x00, 0x03, 0x01, 0x00, 0x14, 0x6a, 0x61, 0x76,
            0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x53, 0x65, 0x72,
            0x69, 0x61, 0x6c, 0x69, 0x7a, 0x61, 0x62, 0x6c,
            0x65, 0x07, 0x00, 0x05, 0x01, 0x00, 0x05, 0x76,
            0x61, 0x6c, 0x75, 0x65, 0x01, 0x00, 0x01, 0x49,
            0x01, 0x00, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x01,
            0x00, 0x14, 0x28, 0x29, 0x4c, 0x6a, 0x61, 0x76,
            0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53,
            0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x04, 0x21,
            0x00, 0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x06,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x00, 0x09,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/Model.class";

        char jar[1024] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 interfaces, fields, and abstract methods rebuild a valid classfile");
    }

    void TestSimpleCodePack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x02,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x00, 0x03, 0x06, 0x10, 0x0d,
            0x28, 0x29, 0x49, 0x61, 0x6e, 0x73, 0x77, 0x65,
            0x72, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61,
            0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63,
            0x74, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f,
            0x41, 0x6e, 0x73, 0x77, 0x65, 0x72, 0x03, 0x01,
            0x02, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0xc9, 0xfd, 0x1c, 0x21, 0x02, 0x00, 0x10,
            0xac, 0xff, 0x07, 0x00, 0x00, 0xc0, 0xf1, 0xdf,
            0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x08, 0x01, 0x00, 0x0d, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x41, 0x6e, 0x73, 0x77,
            0x65, 0x72, 0x07, 0x00, 0x01, 0x01, 0x00, 0x10,
            0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
            0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
            0x07, 0x00, 0x03, 0x01, 0x00, 0x06, 0x61, 0x6e,
            0x73, 0x77, 0x65, 0x72, 0x01, 0x00, 0x03, 0x28,
            0x29, 0x49, 0x01, 0x00, 0x04, 0x43, 0x6f, 0x64,
            0x65, 0x00, 0x21, 0x00, 0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, 0x00,
            0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x07, 0x00,
            0x00, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x03, 0x10, 0x07, 0xac, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/Answer.class";

        char jar[1024] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 code headers and byte operands rebuild a valid Code attribute");
    }

    void TestBranchCodePack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x02,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x02, 0x04, 0x10, 0x0d, 0x05,
            0x28, 0x49, 0x29, 0x49, 0x6a, 0x61, 0x76, 0x61,
            0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62,
            0x6a, 0x65, 0x63, 0x74, 0x73, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2f, 0x42, 0x72, 0x61, 0x6e, 0x63,
            0x68, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x02, 0x01,
            0x02, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0xc9, 0xfd, 0x1c, 0x21, 0x02, 0x00, 0x1a,
            0x99, 0x04, 0xac, 0x03, 0xac, 0xff, 0x04, 0x00,
            0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x08, 0x01, 0x00, 0x0d, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x42, 0x72, 0x61, 0x6e,
            0x63, 0x68, 0x07, 0x00, 0x01, 0x01, 0x00, 0x10,
            0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
            0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
            0x07, 0x00, 0x03, 0x01, 0x00, 0x06, 0x73, 0x65,
            0x6c, 0x65, 0x63, 0x74, 0x01, 0x00, 0x04, 0x28,
            0x49, 0x29, 0x49, 0x01, 0x00, 0x04, 0x43, 0x6f,
            0x64, 0x65, 0x00, 0x21, 0x00, 0x02, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09,
            0x00, 0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x08, 0x1a, 0x99, 0x00, 0x05,
            0x04, 0xac, 0x03, 0xac, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        };
        const char expectedName[] = "sample/Branch.class";

        char jar[1024] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 branch labels are remapped from instruction indexes to JVM byte offsets");
    }

    void TestTableSwitchPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x02,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x00, 0x04, 0x10, 0x03, 0x12,
            0x28, 0x49, 0x29, 0x49, 0x6a, 0x61, 0x76, 0x61,
            0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62,
            0x6a, 0x65, 0x63, 0x74, 0x6d, 0x61, 0x70, 0x73,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x54, 0x61,
            0x62, 0x6c, 0x65, 0x53, 0x77, 0x69, 0x74, 0x63,
            0x68, 0x02, 0x02, 0x02, 0x06, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x02, 0x00, 0xc9, 0xfd, 0x1c, 0x21,
            0x02, 0x00, 0x1a, 0xaa, 0x10, 0xac, 0x10, 0xac,
            0x10, 0xac, 0x02, 0xac, 0xff, 0x03, 0x00, 0x0a,
            0x14, 0x1e, 0x09, 0x01, 0x04, 0x06, 0x00, 0x00,
            0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x08, 0x01, 0x00, 0x12, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x54, 0x61, 0x62, 0x6c,
            0x65, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x07,
            0x00, 0x01, 0x01, 0x00, 0x10, 0x6a, 0x61, 0x76,
            0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f,
            0x62, 0x6a, 0x65, 0x63, 0x74, 0x07, 0x00, 0x03,
            0x01, 0x00, 0x03, 0x6d, 0x61, 0x70, 0x01, 0x00,
            0x04, 0x28, 0x49, 0x29, 0x49, 0x01, 0x00, 0x04,
            0x43, 0x6f, 0x64, 0x65, 0x00, 0x21, 0x00, 0x02,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x09, 0x00, 0x05, 0x00, 0x06, 0x00, 0x01,
            0x00, 0x07, 0x00, 0x00, 0x00, 0x33, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x27, 0x1a, 0xaa,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x1b, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00,
            0x00, 0x21, 0x10, 0x0a, 0xac, 0x10, 0x14, 0xac,
            0x10, 0x1e, 0xac, 0x02, 0xac, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/TableSwitch.class";

        char jar[1280] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 tableswitch bands rebuild aligned JVM switch operands");
    }

    void TestConstructorPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x02,
            0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x00, 0x03, 0x06, 0x10, 0x0b,
            0x28, 0x29, 0x56, 0x3c, 0x69, 0x6e, 0x69, 0x74,
            0x3e, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61,
            0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63,
            0x74, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f,
            0x43, 0x74, 0x6f, 0x72, 0x03, 0x01, 0x02, 0x04,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
            0x00, 0xc1, 0xfd, 0x1c, 0x21, 0x02, 0x00, 0xe4,
            0xb1, 0xff, 0x00, 0x00, 0x00, 0xc0, 0xf1, 0xdf,
            0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x0e, 0x01, 0x00, 0x0b, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x43, 0x74, 0x6f, 0x72,
            0x07, 0x00, 0x01, 0x01, 0x00, 0x10, 0x6a, 0x61,
            0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f,
            0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x07, 0x00,
            0x03, 0x01, 0x00, 0x06, 0x3c, 0x69, 0x6e, 0x69,
            0x74, 0x3e, 0x01, 0x00, 0x03, 0x28, 0x29, 0x56,
            0x01, 0x00, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x01,
            0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
            0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65,
            0x63, 0x74, 0x07, 0x00, 0x08, 0x01, 0x00, 0x06,
            0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e, 0x01, 0x00,
            0x03, 0x28, 0x29, 0x56, 0x0c, 0x00, 0x0a, 0x00,
            0x0b, 0x0a, 0x00, 0x09, 0x00, 0x0c, 0x00, 0x21,
            0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x05, 0x00, 0x06,
            0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x11,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
            0x2a, 0xb7, 0x00, 0x0d, 0xb1, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/Ctor.class";

        char jar[1280] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 super-method pseudo opcodes rebuild constructor method references");
    }

    void TestExceptionHandlerPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x03,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x14, 0x13, 0x00, 0x03, 0x10, 0x10,
            0x03, 0x0e, 0x28, 0x29, 0x49, 0x6a, 0x61, 0x76,
            0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f,
            0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x75, 0x6e,
            0x74, 0x69, 0x6d, 0x65, 0x45, 0x78, 0x63, 0x65,
            0x70, 0x74, 0x69, 0x6f, 0x6e, 0x72, 0x75, 0x6e,
            0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x43,
            0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x02, 0x01,
            0x02, 0x02, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x02, 0x00, 0xc9, 0xfd, 0x1c, 0x21, 0x92, 0x00,
            0x02, 0x00, 0x02, 0x00, 0x04, 0xac, 0x02, 0xac,
            0xff, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22,
            0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x0a, 0x01, 0x00, 0x0e, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x43, 0x61, 0x74, 0x63,
            0x68, 0x65, 0x72, 0x07, 0x00, 0x01, 0x01, 0x00,
            0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61,
            0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63,
            0x74, 0x07, 0x00, 0x03, 0x01, 0x00, 0x03, 0x72,
            0x75, 0x6e, 0x01, 0x00, 0x03, 0x28, 0x29, 0x49,
            0x01, 0x00, 0x1a, 0x6a, 0x61, 0x76, 0x61, 0x2f,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x52, 0x75, 0x6e,
            0x74, 0x69, 0x6d, 0x65, 0x45, 0x78, 0x63, 0x65,
            0x70, 0x74, 0x69, 0x6f, 0x6e, 0x07, 0x00, 0x07,
            0x01, 0x00, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x00,
            0x21, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x09, 0x00, 0x05, 0x00,
            0x06, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x04, 0xac, 0x02, 0xac, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/Catcher.class";

        char jar[1280] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 exception handler bands rebuild JVM exception table PCs and catch type");
    }

    void TestIntegerLdcPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd6, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x31, 0x01, 0x00, 0x00, 0x00,
            0x03, 0x10, 0x11, 0x05, 0x28, 0x29, 0x49, 0x6a,
            0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67,
            0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x49, 0x6e,
            0x74, 0x65, 0x67, 0x65, 0x72, 0x4c, 0x64, 0x63,
            0x76, 0x61, 0x6c, 0x75, 0x65, 0xe0, 0xd7, 0x15,
            0x02, 0x01, 0x02, 0x08, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x02, 0x00, 0xc9, 0xfd, 0x1c, 0x21, 0x02,
            0x00, 0xea, 0xac, 0xff, 0x00, 0x00, 0x00, 0xc0,
            0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x09, 0x01, 0x00, 0x11, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x49, 0x6e, 0x74, 0x65,
            0x67, 0x65, 0x72, 0x4c, 0x64, 0x63, 0x07, 0x00,
            0x01, 0x01, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61,
            0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62,
            0x6a, 0x65, 0x63, 0x74, 0x07, 0x00, 0x03, 0x01,
            0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x01,
            0x00, 0x03, 0x28, 0x29, 0x49, 0x01, 0x00, 0x04,
            0x43, 0x6f, 0x64, 0x65, 0x03, 0x00, 0x01, 0x86,
            0xa0, 0x00, 0x21, 0x00, 0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, 0x00,
            0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x07, 0x00,
            0x00, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x03, 0x12, 0x08, 0xac, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/IntegerLdc.class";

        char jar[1280] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 integer ldc references rebuild numeric constants and local CP indexes");
    }

    void TestMethodReferencePack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x00, 0x03,
            0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x14, 0x13, 0x00, 0x03, 0x11,
            0x10, 0x06, 0x03, 0x10, 0x28, 0x29, 0x4a, 0x63,
            0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x54, 0x69,
            0x6d, 0x65, 0x4d, 0x69, 0x6c, 0x6c, 0x69, 0x73,
            0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
            0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x6e, 0x6f,
            0x77, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f,
            0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x52, 0x65,
            0x66, 0x03, 0x01, 0x02, 0x02, 0x04, 0x06, 0x00,
            0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
            0x01, 0xc9, 0xfd, 0x1c, 0x21, 0x03, 0x00, 0xb8,
            0xad, 0xff, 0x00, 0x00, 0x00, 0xc0, 0xf1, 0xdf,
            0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x0e, 0x01, 0x00, 0x10, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x4d, 0x65, 0x74, 0x68,
            0x6f, 0x64, 0x52, 0x65, 0x66, 0x07, 0x00, 0x01,
            0x01, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a,
            0x65, 0x63, 0x74, 0x07, 0x00, 0x03, 0x01, 0x00,
            0x03, 0x6e, 0x6f, 0x77, 0x01, 0x00, 0x03, 0x28,
            0x29, 0x4a, 0x01, 0x00, 0x04, 0x43, 0x6f, 0x64,
            0x65, 0x01, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61,
            0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x79,
            0x73, 0x74, 0x65, 0x6d, 0x07, 0x00, 0x08, 0x01,
            0x00, 0x11, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e,
            0x74, 0x54, 0x69, 0x6d, 0x65, 0x4d, 0x69, 0x6c,
            0x6c, 0x69, 0x73, 0x01, 0x00, 0x03, 0x28, 0x29,
            0x4a, 0x0c, 0x00, 0x0a, 0x00, 0x0b, 0x0a, 0x00,
            0x09, 0x00, 0x0c, 0x00, 0x21, 0x00, 0x02, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x09, 0x00, 0x05, 0x00, 0x06, 0x00, 0x01, 0x00,
            0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x04, 0xb8, 0x00, 0x0d,
            0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/MethodRef.class";

        char jar[1536] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 method reference bands rebuild Methodref constants and invokestatic operands");
    }

    void TestFieldReferencePack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x03,
            0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x00, 0x14, 0x13, 0x00, 0x03,
            0x01, 0x09, 0x11, 0x06, 0x03, 0x0f, 0x28, 0x29,
            0x49, 0x49, 0x4d, 0x41, 0x58, 0x5f, 0x56, 0x41,
            0x4c, 0x55, 0x45, 0x6a, 0x61, 0x76, 0x61, 0x2f,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x49, 0x6e, 0x74,
            0x65, 0x67, 0x65, 0x72, 0x4f, 0x62, 0x6a, 0x65,
            0x63, 0x74, 0x6d, 0x61, 0x78, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x46, 0x69, 0x65, 0x6c,
            0x64, 0x52, 0x65, 0x66, 0x04, 0x01, 0x02, 0x04,
            0x01, 0x06, 0x06, 0x00, 0x01, 0x00, 0x00, 0x04,
            0x02, 0x00, 0x00, 0x02, 0x01, 0xc9, 0xfd, 0x1c,
            0x21, 0x02, 0x00, 0xb2, 0xac, 0xff, 0x00, 0x00,
            0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x0e, 0x01, 0x00, 0x0f, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x46, 0x69, 0x65, 0x6c,
            0x64, 0x52, 0x65, 0x66, 0x07, 0x00, 0x01, 0x01,
            0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
            0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65,
            0x63, 0x74, 0x07, 0x00, 0x03, 0x01, 0x00, 0x03,
            0x6d, 0x61, 0x78, 0x01, 0x00, 0x03, 0x28, 0x29,
            0x49, 0x01, 0x00, 0x04, 0x43, 0x6f, 0x64, 0x65,
            0x01, 0x00, 0x11, 0x6a, 0x61, 0x76, 0x61, 0x2f,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x49, 0x6e, 0x74,
            0x65, 0x67, 0x65, 0x72, 0x07, 0x00, 0x08, 0x01,
            0x00, 0x09, 0x4d, 0x41, 0x58, 0x5f, 0x56, 0x41,
            0x4c, 0x55, 0x45, 0x01, 0x00, 0x01, 0x49, 0x0c,
            0x00, 0x0a, 0x00, 0x0b, 0x09, 0x00, 0x09, 0x00,
            0x0c, 0x00, 0x21, 0x00, 0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, 0x00,
            0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x07, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0xb2, 0x00, 0x0d, 0xac, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00
        };
        const char expectedName[] = "sample/FieldRef.class";

        char jar[1536] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 field reference bands rebuild Fieldref constants and getstatic operands");
    }

    void TestConstantValuePack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd6, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x31, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x05, 0x10, 0x14, 0x49, 0x56, 0x41, 0x4c,
            0x55, 0x45, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
            0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65,
            0x63, 0x74, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x2f, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e,
            0x74, 0x46, 0x69, 0x65, 0x6c, 0x64, 0xc0, 0xc6,
            0x1b, 0x03, 0x01, 0x02, 0x04, 0x00, 0x02, 0x00,
            0x00, 0x02, 0x00, 0x00, 0xd9, 0xfd, 0x1c, 0x00,
            0x21, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22,
            0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x09, 0x01, 0x00, 0x14, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x43, 0x6f, 0x6e, 0x73,
            0x74, 0x61, 0x6e, 0x74, 0x46, 0x69, 0x65, 0x6c,
            0x64, 0x07, 0x00, 0x01, 0x01, 0x00, 0x10, 0x6a,
            0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67,
            0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x07,
            0x00, 0x03, 0x01, 0x00, 0x05, 0x56, 0x41, 0x4c,
            0x55, 0x45, 0x01, 0x00, 0x01, 0x49, 0x03, 0x00,
            0x01, 0xe2, 0x40, 0x01, 0x00, 0x0d, 0x43, 0x6f,
            0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x56, 0x61,
            0x6c, 0x75, 0x65, 0x00, 0x21, 0x00, 0x02, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x19, 0x00,
            0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x00
        };
        const char expectedName[] = "sample/ConstantField.class";

        char jar[1280] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 ConstantValue bands rebuild typed field constants and attributes");
    }

    void TestDeclaredExceptionsPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x03,
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x0a, 0x09, 0x00, 0x03, 0x13, 0x0b,
            0x03, 0x0d, 0x28, 0x29, 0x56, 0x6a, 0x61, 0x76,
            0x61, 0x2f, 0x69, 0x6f, 0x2f, 0x49, 0x4f, 0x45,
            0x78, 0x63, 0x65, 0x70, 0x74, 0x69, 0x6f, 0x6e,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a,
            0x65, 0x63, 0x74, 0x72, 0x75, 0x6e, 0x73, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x54, 0x68, 0x72,
            0x6f, 0x77, 0x73, 0x02, 0x01, 0x02, 0x02, 0x08,
            0x00, 0x04, 0x02, 0x00, 0x00, 0x02, 0x00, 0xc1,
            0xcd, 0x3d, 0x01, 0x00, 0xe1, 0x0d, 0x00, 0x00,
            0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x0a, 0x01, 0x00, 0x0d, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x54, 0x68, 0x72, 0x6f,
            0x77, 0x73, 0x07, 0x00, 0x01, 0x01, 0x00, 0x10,
            0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
            0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
            0x07, 0x00, 0x03, 0x01, 0x00, 0x03, 0x72, 0x75,
            0x6e, 0x01, 0x00, 0x03, 0x28, 0x29, 0x56, 0x01,
            0x00, 0x13, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x69,
            0x6f, 0x2f, 0x49, 0x4f, 0x45, 0x78, 0x63, 0x65,
            0x70, 0x74, 0x69, 0x6f, 0x6e, 0x07, 0x00, 0x07,
            0x01, 0x00, 0x0a, 0x45, 0x78, 0x63, 0x65, 0x70,
            0x74, 0x69, 0x6f, 0x6e, 0x73, 0x04, 0x21, 0x00,
            0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x04, 0x01, 0x00, 0x05, 0x00, 0x06, 0x00,
            0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x00
        };
        const char expectedName[] = "sample/Throws.class";

        char jar[1280] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 method Exceptions bands rebuild declared exception attributes");
    }

    void TestSourceFilePack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x0d, 0x10, 0x12, 0x45, 0x78,
            0x70, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x2e, 0x6a,
            0x61, 0x76, 0x61, 0x6a, 0x61, 0x76, 0x61, 0x2f,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a,
            0x65, 0x63, 0x74, 0x73, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2f, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65,
            0x4e, 0x61, 0x6d, 0x65, 0x64, 0x02, 0x01, 0x02,
            0x00, 0x00, 0x00, 0x00, 0xe1, 0xfd, 0x1c, 0x02,
            0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        const unsigned char expectedClass[] = {
            0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x31,
            0x00, 0x07, 0x01, 0x00, 0x12, 0x73, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2f, 0x53, 0x6f, 0x75, 0x72,
            0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x64, 0x07,
            0x00, 0x01, 0x01, 0x00, 0x10, 0x6a, 0x61, 0x76,
            0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f,
            0x62, 0x6a, 0x65, 0x63, 0x74, 0x07, 0x00, 0x03,
            0x01, 0x00, 0x0d, 0x45, 0x78, 0x70, 0x6c, 0x69,
            0x63, 0x69, 0x74, 0x2e, 0x6a, 0x61, 0x76, 0x61,
            0x01, 0x00, 0x0a, 0x53, 0x6f, 0x75, 0x72, 0x63,
            0x65, 0x46, 0x69, 0x6c, 0x65, 0x00, 0x21, 0x00,
            0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x05
        };
        const char expectedName[] = "sample/SourceNamed.class";

        char jar[1280] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed,
            sizeof(packed),
            jar,
            sizeof(jar),
            &jarLength);
        bool matches = false;
        if (NT_SUCCESS(status) && jarLength >= 30) {
            const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
            const SIZE_T nameLength = ReadLe16(bytes + 26);
            const SIZE_T contentLength = ReadLe32(bytes + 22);
            const SIZE_T contentOffset = 30 + nameLength;
            matches =
                ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 8) == 0 &&
                nameLength == sizeof(expectedName) - 1 &&
                contentLength == sizeof(expectedClass) &&
                contentOffset <= jarLength &&
                sizeof(expectedClass) <= jarLength - contentOffset &&
                memcmp(bytes + 30, expectedName, nameLength) == 0 &&
                memcmp(bytes + contentOffset, expectedClass, sizeof(expectedClass)) == 0;
        }
        Expect(
            NT_SUCCESS(status) && matches,
            "Pack200 SourceFile RUNH bands rebuild class-level source attributes");
    }

    void ExpectMultiSegmentJar(const char* jar, SIZE_T jarLength, const char* message)
    {
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
        SIZE_T offset = 0;
        bool valid = true;
        for (SIZE_T index = 0; index < 3; ++index) {
            char expectedName[32] = {};
            char expectedContent[16] = {};
            const int nameLength = snprintf(
                expectedName,
                sizeof(expectedName),
                "data/segment-%zu.txt",
                index);
            const int contentLength = snprintf(
                expectedContent,
                sizeof(expectedContent),
                "segment-%zu",
                index);
            if (nameLength <= 0 || contentLength <= 0 || offset > jarLength || jarLength - offset < 30) {
                valid = false;
                break;
            }
            const USHORT actualNameLength = ReadLe16(bytes + offset + 26);
            const ULONG actualContentLength = ReadLe32(bytes + offset + 22);
            const SIZE_T entryLength =
                30 + static_cast<SIZE_T>(actualNameLength) + static_cast<SIZE_T>(actualContentLength);
            if (ReadLe32(bytes + offset) != 0x04034b50UL ||
                ReadLe16(bytes + offset + 8) != 0 ||
                actualNameLength != static_cast<USHORT>(nameLength) ||
                actualContentLength != static_cast<ULONG>(contentLength) ||
                entryLength > jarLength - offset ||
                memcmp(bytes + offset + 30, expectedName, actualNameLength) != 0 ||
                memcmp(
                    bytes + offset + 30 + actualNameLength,
                    expectedContent,
                    actualContentLength) != 0) {
                valid = false;
                break;
            }
            offset += entryLength;
        }
        valid = valid &&
            jarLength >= 22 &&
            ReadLe32(bytes + jarLength - 22) == 0x06054b50UL &&
            ReadLe16(bytes + jarLength - 22 + 8) == 3 &&
            ReadLe16(bytes + jarLength - 22 + 10) == 3;
        Expect(valid, message);
    }

    void TestMultiSegmentPack200Interoperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x12, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x73,
            0x65, 0x67, 0x6d, 0x65, 0x6e, 0x74, 0x2d, 0x30,
            0x2e, 0x74, 0x78, 0x74, 0x01, 0x09, 0xc0, 0xf1,
            0xdf, 0xe4, 0x22, 0x00, 0x73, 0x65, 0x67, 0x6d,
            0x65, 0x6e, 0x74, 0x2d, 0x30,
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x1a, 0x12, 0x05, 0x64, 0x61, 0x74, 0x61,
            0x2f, 0x73, 0x65, 0x67, 0x6d, 0x65, 0x6e, 0x74,
            0x2d, 0x31, 0x2e, 0x74, 0x78, 0x74, 0x32, 0x2e,
            0x74, 0x78, 0x74, 0x01, 0x02, 0x09, 0x09, 0xc4,
            0xf1, 0xdf, 0xe4, 0x22, 0x04, 0x00, 0x00, 0x73,
            0x65, 0x67, 0x6d, 0x65, 0x6e, 0x74, 0x2d, 0x31,
            0x73, 0x65, 0x67, 0x6d, 0x65, 0x6e, 0x74, 0x2d,
            0x32
        };
        const unsigned char gzipPacked[] = {
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xff, 0x3b, 0xf5, 0xef, 0x02, 0x2f, 0xfb,
            0xb4, 0x2b, 0x0c, 0x20, 0xc0, 0xc8, 0xc4, 0x80,
            0x00, 0x42, 0x29, 0x89, 0x25, 0x89, 0xfa, 0xc5,
            0xa9, 0xe9, 0xb9, 0xa9, 0x79, 0x25, 0xba, 0x06,
            0x7a, 0x25, 0x15, 0x25, 0x8c, 0x9c, 0x07, 0x3e,
            0xde, 0x7f, 0xa2, 0xc4, 0x00, 0x17, 0x3c, 0x85,
            0xa4, 0x99, 0x89, 0x19, 0x49, 0xb3, 0x94, 0x10,
            0x2b, 0x8a, 0x76, 0x43, 0x90, 0x76, 0x23, 0xb0,
            0x19, 0x4c, 0x9c, 0x9c, 0x47, 0x40, 0xa6, 0xb0,
            0x30, 0xc0, 0xcd, 0x31, 0x84, 0x31, 0x8c, 0x00,
            0x3c, 0x80, 0xe9, 0x99, 0x8e, 0x00, 0x00, 0x00
        };

        const unsigned char* streams[] = { packed, gzipPacked };
        const SIZE_T lengths[] = { sizeof(packed), sizeof(gzipPacked) };
        const char* successMessages[] = {
            "raw Pack200 concatenated segments decode successfully",
            "gzip Pack200 concatenated segments decode successfully"
        };
        const char* jarMessages[] = {
            "raw Pack200 preserves file order across segments",
            "gzip Pack200 preserves file order across segments"
        };
        for (SIZE_T index = 0; index < 2; ++index) {
            char jar[1024] = {};
            SIZE_T jarLength = 0;
            const NTSTATUS status = DecodePack200GzipContent(
                streams[index],
                lengths[index],
                jar,
                sizeof(jar),
                &jarLength);
            Expect(NT_SUCCESS(status), successMessages[index]);
            if (NT_SUCCESS(status)) {
                ExpectMultiSegmentJar(jar, jarLength, jarMessages[index]);
            }
        }
    }

    void TestJarWriterZip64EntryCountBoundary()
    {
        constexpr SIZE_T EntryCount = 65536;
        constexpr SIZE_T JarCapacity = 8 * 1024 * 1024;
        HeapArray<char> jar(JarCapacity);
        Expect(jar.IsValid(), "Pack200 ZIP64 test buffer allocates on the heap");
        if (!jar.IsValid()) {
            return;
        }

        HttpPack200JarWriter writer(jar.Get(), jar.Count());
        NTSTATUS status = writer.Initialize(EntryCount);
        Expect(NT_SUCCESS(status), "Pack200 ZIP64 writer initializes 65536 entries");
        for (SIZE_T index = 0; NT_SUCCESS(status) && index < EntryCount; ++index) {
            char name[8] = {};
            const int nameLength = snprintf(name, sizeof(name), "f%05zu", index);
            if (nameLength <= 0) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }
            status = writer.AddStoredEntry(
                { name, static_cast<SIZE_T>(nameLength) },
                nullptr,
                0);
        }
        Expect(NT_SUCCESS(status), "Pack200 ZIP64 writer adds 65536 empty entries");

        SIZE_T jarLength = 0;
        if (NT_SUCCESS(status)) {
            status = writer.Finish(&jarLength);
        }
        Expect(NT_SUCCESS(status), "Pack200 ZIP64 writer finishes entry-count boundary archive");
        if (!NT_SUCCESS(status) || jarLength < 98) {
            return;
        }

        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar.Get());
        const SIZE_T legacyEndOffset = jarLength - 22;
        const SIZE_T locatorOffset = legacyEndOffset - 20;
        const SIZE_T zip64EndOffset = locatorOffset - 56;
        Expect(
            ReadLe32(bytes + zip64EndOffset) == 0x06064b50UL &&
                ReadLe64(bytes + zip64EndOffset + 4) == 44 &&
                ReadLe64(bytes + zip64EndOffset + 24) == EntryCount &&
                ReadLe64(bytes + zip64EndOffset + 32) == EntryCount &&
                ReadLe32(bytes + locatorOffset) == 0x07064b50UL &&
                ReadLe64(bytes + locatorOffset + 8) == zip64EndOffset &&
                ReadLe32(bytes + legacyEndOffset) == 0x06054b50UL &&
                ReadLe16(bytes + legacyEndOffset + 8) == 0xffffU &&
                ReadLe16(bytes + legacyEndOffset + 10) == 0xffffU,
            "Pack200 JAR emits ZIP64 EOCD, locator, and saturated legacy counts");
    }

    void TestJarWriterRawDeflateEntry()
    {
        char jar[1024] = {};
        HttpPack200JarWriter writer(jar, sizeof(jar));
        NTSTATUS status = writer.Initialize(2);
        Expect(NT_SUCCESS(status), "pack200 JAR writer initializes");

        const char nameBytes[] = {
            'd', 'i', 'r', '/', static_cast<char>(0xc3), static_cast<char>(0xa9),
            '.', 't', 'x', 't'
        };
        const unsigned char content[] = { 'h', 'e', 'l', 'l', 'o' };
        HttpXmlText name = { nameBytes, sizeof(nameBytes) };
        status = writer.AddEntry(name, content, sizeof(content), true, 315532800UL);
        Expect(NT_SUCCESS(status), "pack200 JAR writer adds UTF-8 deflated entry");

        SIZE_T jarLength = 0;
        status = writer.Finish(&jarLength);
        Expect(NT_SUCCESS(status) && jarLength != 0, "pack200 JAR writer finishes archive");
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
        const USHORT nameLength = ReadLe16(bytes + 26);
        const ULONG compressedLength = ReadLe32(bytes + 18);
        const SIZE_T compressedOffset = 30 + nameLength;
        Expect(
            ReadLe32(bytes) == 0x04034b50UL &&
                ReadLe16(bytes + 6) == 0x0800 &&
                ReadLe16(bytes + 8) == 8 &&
                ReadLe16(bytes + 10) == 0 &&
                ReadLe16(bytes + 12) == 0x0021 &&
                compressedLength == 10 &&
                ReadLe32(bytes + 22) == sizeof(content),
            "pack200 JAR local header carries UTF-8, method, size, and DOS time metadata");

        char decoded[16] = {};
        SIZE_T decodedLength = 0;
        status = HttpDecodeRawDeflate(
            bytes + compressedOffset,
            compressedLength,
            decoded,
            sizeof(decoded),
            &decodedLength);
        Expect(
            NT_SUCCESS(status) &&
                decodedLength == sizeof(content) &&
                memcmp(decoded, content, sizeof(content)) == 0,
            "pack200 JAR method 8 payload is valid raw-DEFLATE stored blocks");
    }

    bool ContainsBytes(const unsigned char* value, SIZE_T valueLength, const char* needle)
    {
        const SIZE_T needleLength = strlen(needle);
        if (value == nullptr || needleLength == 0 || needleLength > valueLength) {
            return false;
        }
        for (SIZE_T index = 0; index <= valueLength - needleLength; ++index) {
            if (memcmp(value + index, needle, needleLength) == 0) {
                return true;
            }
        }
        return false;
    }

    void TestDebugCodeAttributesInteroperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x31, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, 0x07, 0x08, 0x02, 0x03, 0x04, 0x10, 0x10, 0x05, 0x28, 0x4c,
            0x3b, 0x29, 0x4c, 0x3b, 0x54, 0x54, 0x3b, 0x29, 0x54, 0x54, 0x3b,
            0x3c, 0x54, 0x3a, 0x4c, 0x3b, 0x3e, 0x4c, 0x3b, 0x4c, 0x3b, 0x54,
            0x54, 0x3b, 0x65, 0x63, 0x68, 0x6f, 0x6a, 0x61, 0x76, 0x61, 0x2f,
            0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
            0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x44, 0x65, 0x62, 0x75,
            0x67, 0x49, 0x6e, 0x66, 0x6f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x07,
            0x01, 0x0a, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0c, 0x04, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0xc9, 0xfd, 0x9c,
            0x03, 0xe1, 0xfd, 0x7c, 0x02, 0x02, 0x0e, 0x01, 0x00, 0x2a, 0x01,
            0x00, 0x02, 0x09, 0x01, 0x00, 0x01, 0x00, 0x02, 0x09, 0x00, 0x00,
            0x2a, 0xb0, 0xff, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        char jar[8192] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed, sizeof(packed), jar, sizeof(jar), &jarLength);
        bool valid = NT_SUCCESS(status) && jarLength > 30;
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
        SIZE_T contentOffset = 0;
        SIZE_T contentLength = 0;
        if (valid) {
            contentOffset = 30 + ReadLe16(bytes + 26) + ReadLe16(bytes + 28);
            contentLength = ReadLe32(bytes + 22);
            valid = contentOffset <= jarLength && contentLength <= jarLength - contentOffset;
        }
        Expect(
            valid &&
                ContainsBytes(bytes + contentOffset, contentLength, "LineNumberTable") &&
                ContainsBytes(bytes + contentOffset, contentLength, "LocalVariableTable") &&
                ContainsBytes(bytes + contentOffset, contentLength, "LocalVariableTypeTable") &&
                ContainsBytes(bytes + contentOffset, contentLength, "value"),
            "Pack200 code debug attribute bands rebuild LNT, LVT, and LVTT attributes");
    }

    void TestAnnotationAttributesInteroperability()
    {
        const unsigned char packed[] = {
            0xca, 0xfe, 0xd0, 0x0d, 0x07, 0x96, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x0c, 0x00, 0x03, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x0d, 0x04,
            0x01, 0x02, 0x05, 0x05, 0x10, 0x06, 0x09, 0x10, 0x06, 0x05, 0x28, 0x49,
            0x29, 0x56, 0x49, 0x4c, 0x3b, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x66, 0x69,
            0x65, 0x6c, 0x64, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67,
            0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x6d, 0x65, 0x74, 0x68, 0x6f,
            0x64, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x41, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74,
            0x65, 0x64, 0x4d, 0x61, 0x72, 0x6b, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x75,
            0x65, 0x06, 0x03, 0x01, 0x04, 0x02, 0x03, 0x02, 0x0a, 0x04, 0x00, 0x02,
            0x02, 0x00, 0x00, 0x02, 0x02, 0x00, 0xc1, 0xfd, 0xfc, 0x04, 0x00, 0x01,
            0x01, 0x01, 0x0b, 0x73, 0x05, 0x01, 0xc9, 0xfd, 0xdc, 0x25, 0x00, 0x00,
            0x01, 0x01, 0x01, 0x0b, 0x73, 0x07, 0x01, 0x01, 0x01, 0x01, 0x0b, 0x73,
            0x08, 0xe1, 0xfd, 0xfc, 0x04, 0x00, 0x01, 0x01, 0x01, 0x0b, 0x73, 0x04,
            0x01, 0x00, 0xb1, 0xff, 0x00, 0x00, 0xc0, 0xf1, 0xdf, 0xe4, 0x22, 0x02
        };
        char jar[12288] = {};
        SIZE_T jarLength = 0;
        const NTSTATUS status = DecodePack200GzipContent(
            packed, sizeof(packed), jar, sizeof(jar), &jarLength);
        bool valid = NT_SUCCESS(status) && jarLength > 30;
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(jar);
        SIZE_T contentOffset = 0;
        SIZE_T contentLength = 0;
        if (valid) {
            contentOffset = 30 + ReadLe16(bytes + 26) + ReadLe16(bytes + 28);
            contentLength = ReadLe32(bytes + 22);
            valid = contentOffset <= jarLength && contentLength <= jarLength - contentOffset;
        }
        Expect(
            valid &&
                ContainsBytes(bytes + contentOffset, contentLength, "RuntimeVisibleAnnotations") &&
                ContainsBytes(bytes + contentOffset, contentLength, "RuntimeVisibleParameterAnnotations") &&
                ContainsBytes(bytes + contentOffset, contentLength, "Lsample/Marker;") &&
                ContainsBytes(bytes + contentOffset, contentLength, "parameter"),
            "Pack200 metadata bands rebuild class, field, method, and parameter annotations");
    }
}

int main()
{
    TestBhsdContinuationUsesFullByteValue();
    TestCanonicalAndArbitraryMetaCodings();
    TestPublishedPack200VersionsAreRecognized();
    TestRunMetaCoding();
    TestPopulationMetaCoding();
    TestBandEscapeUsesSeparateBandHeaders();
    TestConstantPoolNumericBands();
    TestJava7ConstantPoolBands();
    TestAttributeDefinitionAndInnerClassBands();
    TestJava7AndJava8BytecodeReferenceBands();
    TestInnerClassPack200Interoperability();
    TestSignatureAttributePack200Interoperability();
    TestMinimalClassBands();
    TestDeprecatedAttributeFlags();
    TestEnclosingMethodAttributeBands();
    TestClassOnlyBandSequence();
    TestClassWriterMethodHandleAndMethodTypeConstants();
    TestClassWriterInvokeDynamicAndBootstrapMethods();
    TestClassWriterDeprecatedAttributes();
    TestClassWriterEnclosingMethodAttribute();
    TestJarWriterRawDeflateEntry();
    TestDebugCodeAttributesInteroperability();
    TestAnnotationAttributesInteroperability();
    TestFileOnlyPack200Interoperability();
    TestClassOnlyPack200Interoperability();
    TestAbstractMethodPack200Interoperability();
    TestMemberOnlyPack200Interoperability();
    TestSimpleCodePack200Interoperability();
    TestBranchCodePack200Interoperability();
    TestTableSwitchPack200Interoperability();
    TestConstructorPack200Interoperability();
    TestExceptionHandlerPack200Interoperability();
    TestIntegerLdcPack200Interoperability();
    TestMethodReferencePack200Interoperability();
    TestFieldReferencePack200Interoperability();
    TestConstantValuePack200Interoperability();
    TestDeclaredExceptionsPack200Interoperability();
    TestSourceFilePack200Interoperability();
    TestMultiSegmentPack200Interoperability();
    TestJarWriterZip64EntryCountBoundary();

    if (g_failed) {
        return 1;
    }
    printf("PASS: Pack200 decoder tests\n");
    return 0;
}
