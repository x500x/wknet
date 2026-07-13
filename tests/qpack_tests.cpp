#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "qpack/QpackHuffman.h"
#include "qpack/QpackInteger.h"
#include "qpack/QpackDecoder.h"
#include "qpack/QpackDynamicTable.h"
#include "qpack/QpackEncoder.h"
#include "qpack/QpackStaticTable.h"
#include <stdio.h>
#include <string.h>

namespace
{
bool failed = false;

void Expect(bool condition, const char *message)
{
    if (!condition)
    {
        failed = true;
        printf("FAIL: %s\n", message);
    }
}

wknet::qpack::QpackStringView View(const char *value)
{
    SIZE_T length = 0;
    while (value[length] != '\0')
    {
        ++length;
    }
    return {reinterpret_cast<const UCHAR *>(value), length};
}

bool Equals(const wknet::qpack::QpackStringView &value, const char *expected)
{
    const wknet::qpack::QpackStringView expectedView = View(expected);
    return value.Length == expectedView.Length &&
           (value.Length == 0 || memcmp(value.Data, expectedView.Data, value.Length) == 0);
}

void TestDynamicTable()
{
    using namespace wknet::qpack;

    QpackDynamicTable table;
    QpackDynamicTable oversized;
    Expect(oversized.Initialize(wknet::WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES + 1) == STATUS_INVALID_PARAMETER,
           "dynamic table rejects a capacity above the local NonPaged hard limit");
    Expect(NT_SUCCESS(table.Initialize(256)), "dynamic table initializes with a bounded NonPaged budget");
    Expect(NT_SUCCESS(table.SetCapacity(128)), "dynamic table accepts a capacity within its maximum");

    ULONGLONG first = 0;
    ULONGLONG second = 0;
    ULONGLONG third = 0;
    ULONGLONG fourth = 0;
    Expect(NT_SUCCESS(table.Insert(View("a").Data, 1, View("1").Data, 1, &first)) && first == 0,
           "first dynamic entry receives absolute index zero");
    Expect(NT_SUCCESS(table.Insert(View("b").Data, 1, View("2").Data, 1, &second)) && second == 1,
           "second dynamic entry increments the absolute index");
    Expect(NT_SUCCESS(table.Insert(View("c").Data, 1, View("3").Data, 1, &third)) && third == 2,
           "third dynamic entry fits before eviction");
    Expect(NT_SUCCESS(table.Insert(View("d").Data, 1, View("4").Data, 1, &fourth)) && fourth == 3,
           "fourth dynamic entry evicts the oldest entry");

    QpackDynamicEntryView entry = {};
    Expect(table.LookupAbsolute(first, &entry) == STATUS_NOT_FOUND, "eviction removes the oldest absolute index");
    Expect(NT_SUCCESS(table.LookupRelative(table.InsertCount(), 0, &entry)) && Equals(entry.Name, "d"),
           "relative index zero resolves the newest entry");
    Expect(NT_SUCCESS(table.LookupPostBase(3, 0, &entry)) && Equals(entry.Name, "d"),
           "post-base index resolves an absolute entry after Base");

    ULONGLONG duplicate = 0;
    Expect(NT_SUCCESS(table.DuplicateRelative(0, &duplicate)) && duplicate == 4,
           "Duplicate inserts a new entry with a new absolute index");
    Expect(NT_SUCCESS(table.LookupAbsolute(duplicate, &entry)) && Equals(entry.Name, "d") && Equals(entry.Value, "4"),
           "Duplicate preserves name and value bytes across eviction and compaction");

    Expect(NT_SUCCESS(table.AddReference(duplicate)), "dynamic entry reference is tracked");
    Expect(table.SetCapacity(0) == STATUS_DEVICE_BUSY && table.Capacity() == 128,
           "capacity reduction is delayed when it would evict a referenced entry");
    Expect(NT_SUCCESS(table.ReleaseReference(duplicate)), "dynamic entry reference releases");
    Expect(NT_SUCCESS(table.SetCapacity(0)) && table.EntryCount() == 0 && table.CurrentSize() == 0,
           "capacity zero evicts every unreferenced entry");
    Expect(table.Insert(View("x").Data, 1, View("y").Data, 1) == STATUS_INSUFFICIENT_RESOURCES,
           "capacity zero rejects insertion without allocating outside the bound");
}

void TestRequiredInsertCount()
{
    using namespace wknet::qpack;

    ULONGLONG encoded = 0;
    ULONGLONG decoded = 0;
    Expect(NT_SUCCESS(QpackDecoder::EncodeRequiredInsertCount(0, 256, &encoded)) && encoded == 0,
           "zero Required Insert Count encodes as zero");
    Expect(NT_SUCCESS(QpackDecoder::EncodeRequiredInsertCount(9, 256, &encoded)) && encoded == 10,
           "Required Insert Count uses RFC modulo encoding");
    Expect(NT_SUCCESS(QpackDecoder::DecodeRequiredInsertCount(encoded, 9, 256, &decoded)) && decoded == 9,
           "Required Insert Count reconstructs against the current insert count");
    Expect(NT_SUCCESS(QpackDecoder::EncodeRequiredInsertCount(17, 256, &encoded)) && encoded == 2,
           "Required Insert Count wraps across two MaxEntries ranges");
    Expect(NT_SUCCESS(QpackDecoder::DecodeRequiredInsertCount(encoded, 17, 256, &decoded)) && decoded == 17,
           "wrapped Required Insert Count reconstructs without ambiguity");
    Expect(QpackDecoder::DecodeRequiredInsertCount(17, 256, 256, &decoded) == STATUS_INVALID_NETWORK_RESPONSE,
           "encoded Required Insert Count larger than FullRange is rejected");
}

void TestInstructionStreamsAndFieldSections()
{
    using namespace wknet::qpack;

    QpackEncoder encoder;
    QpackDecoder decoder;
    Expect(NT_SUCCESS(encoder.Initialize(wknet::WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES * 2, 32)) &&
               encoder.EffectiveMaximumCapacity() == wknet::WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES &&
               encoder.EffectiveBlockedStreams() == wknet::WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS,
           "peer SETTINGS are reduced by local QPACK hard limits");
    encoder.Reset();
    Expect(NT_SUCCESS(encoder.Initialize(256, 4)), "encoder initializes with peer budgets");
    Expect(NT_SUCCESS(decoder.Initialize(256, 4, 1024, 16)), "decoder initializes with local SETTINGS budgets");

    UCHAR instruction[256] = {};
    SIZE_T instructionLength = 0;
    SIZE_T consumed = 0;
    ULONGLONG applicationError = 0;
    Expect(NT_SUCCESS(encoder.SetCapacity(256, instruction, sizeof(instruction), &instructionLength)) &&
               instructionLength == 3 && instruction[0] == 0x3f && instruction[1] == 0xe1 && instruction[2] == 0x01,
           "encoder writes Set Dynamic Table Capacity");
    Expect(decoder.ProcessEncoderInstructions(instruction, 1, &consumed, &applicationError) ==
                   STATUS_MORE_PROCESSING_REQUIRED &&
               consumed == 0 && applicationError == 0 && decoder.Table().Capacity() == 0,
           "fragmented encoder instruction waits for continuation bytes without mutating the table");
    Expect(
        NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &applicationError)) &&
            consumed == instructionLength && decoder.Table().Capacity() == 256,
        "decoder applies Set Dynamic Table Capacity");

    ULONGLONG authorityIndex = 0;
    Expect(NT_SUCCESS(encoder.InsertWithNameReference(true, 0, View("example.com").Data, View("example.com").Length,
                                                      false, instruction, sizeof(instruction), &instructionLength,
                                                      &authorityIndex)),
           "encoder writes Insert With Name Reference");
    Expect(instructionLength == 13 && instruction[0] == 0xc0 && instruction[1] == 11,
           "Insert With Name Reference matches the RFC 9204 instruction bit layout");
    Expect(NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &applicationError)),
           "decoder processes Insert With Name Reference");

    ULONGLONG literalIndex = 0;
    Expect(NT_SUCCESS(encoder.InsertWithLiteralName(View("x-test").Data, View("x-test").Length, true, View("one").Data,
                                                    View("one").Length, true, instruction, sizeof(instruction),
                                                    &instructionLength, &literalIndex)),
           "encoder writes Huffman Insert With Literal Name");
    Expect(NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &applicationError)),
           "decoder processes Huffman Insert With Literal Name");

    ULONGLONG dynamicNameIndex = 0;
    Expect(
        NT_SUCCESS(encoder.InsertWithNameReference(false, 0, View("two").Data, View("two").Length, false, instruction,
                                                   sizeof(instruction), &instructionLength, &dynamicNameIndex)),
        "encoder writes Insert With Dynamic Name Reference");
    Expect(NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &applicationError)),
           "decoder resolves a relative dynamic name in the encoder stream");

    ULONGLONG duplicateIndex = 0;
    Expect(NT_SUCCESS(encoder.Duplicate(0, instruction, sizeof(instruction), &instructionLength, &duplicateIndex)),
           "encoder writes Duplicate");
    Expect(
        NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &applicationError)) &&
            decoder.Table().InsertCount() == 4,
        "decoder processes Duplicate and advances Insert Count");

    QpackDynamicEntryView duplicated = {};
    Expect(NT_SUCCESS(decoder.Table().LookupAbsolute(duplicateIndex, &duplicated)) &&
               Equals(duplicated.Name, "x-test") && Equals(duplicated.Value, "two"),
           "instruction stream tables remain synchronized");

    UCHAR decoderInstruction[32] = {};
    SIZE_T decoderInstructionLength = 0;
    Expect(NT_SUCCESS(decoder.WriteInsertCountIncrement(2, decoderInstruction, sizeof(decoderInstruction),
                                                        &decoderInstructionLength)),
           "decoder writes Insert Count Increment");
    Expect(NT_SUCCESS(encoder.ProcessDecoderInstructions(decoderInstruction, decoderInstructionLength, &consumed,
                                                         &applicationError)) &&
               encoder.KnownReceivedCount() == 2,
           "encoder applies Insert Count Increment");

    QpackFieldView fields[4] = {};
    fields[0] = {View(":authority"), View("example.com"), false};
    fields[1] = {View("authorization"), View("Bearer secret"), false};
    fields[2] = {View("x-literal"), View("value"), false};
    fields[3] = {View("x-test"), View("different"), false};
    UCHAR fieldSection[512] = {};
    SIZE_T fieldSectionLength = 0;
    Expect(NT_SUCCESS(encoder.EncodeFieldSection(4, fields, 4, fieldSection, sizeof(fieldSection), &fieldSectionLength,
                                                 &applicationError)) &&
               encoder.OutstandingSectionCount() == 1 && encoder.BlockedStreamCount() == 1,
           "encoder emits a field section and tracks a blocked dynamic reference");
    Expect(fieldSectionLength > 2 && (fieldSection[3] & 0x60U) == 0x60U,
           "Authorization uses a literal name reference with the never-index bit");

    QpackFieldView decodedFields[5] = {};
    UCHAR fieldBuffer[512] = {};
    SIZE_T decodedFieldCount = 0;
    SIZE_T fieldBufferUsed = 0;
    Expect(NT_SUCCESS(decoder.DecodeFieldSection(4, fieldSection, fieldSectionLength, decodedFields, 5,
                                                 &decodedFieldCount, fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed,
                                                 decoderInstruction, sizeof(decoderInstruction),
                                                 &decoderInstructionLength, &applicationError)) &&
               decodedFieldCount == 4 && decoderInstructionLength != 0,
           "decoder resolves dynamic/static/literal field lines and emits Section Ack");
    Expect(Equals(decodedFields[0].Name, ":authority") && Equals(decodedFields[0].Value, "example.com"),
           "decoded dynamic indexed field is copied to caller storage");
    Expect(decodedFields[1].Sensitive && Equals(decodedFields[1].Name, "authorization") &&
               Equals(decodedFields[1].Value, "Bearer secret"),
           "never-index survives decoding for sensitive fields");
    Expect(Equals(decodedFields[2].Name, "x-literal") && Equals(decodedFields[2].Value, "value"),
           "literal name field round-trips");
    Expect(Equals(decodedFields[3].Name, "x-test") && Equals(decodedFields[3].Value, "different"),
           "literal with dynamic name reference round-trips");

    Expect(NT_SUCCESS(encoder.ProcessDecoderInstructions(decoderInstruction, decoderInstructionLength, &consumed,
                                                         &applicationError)) &&
               encoder.OutstandingSectionCount() == 0,
           "Section Ack releases the oldest outstanding section for the stream");

    Expect(encoder.KnownReceivedCount() == 4 && decoder.ReportedInsertCount() == 4,
           "Section Ack advances both peers to the section Required Insert Count");
    Expect(decoder.WriteInsertCountIncrement(1, decoderInstruction, sizeof(decoderInstruction),
                                             &decoderInstructionLength) == STATUS_INVALID_PARAMETER,
           "Insert Count Increment cannot exceed unreported inserts");

    Expect(encoder.ProcessDecoderInstructions(reinterpret_cast<const UCHAR *>("\x81"), 1, &consumed,
                                              &applicationError) == STATUS_INVALID_NETWORK_RESPONSE &&
               applicationError == QpackDecoderStreamError,
           "Section Ack for an unknown stream is a decoder stream error");
    const UCHAR partialDecoderInstruction[] = {0xff};
    applicationError = 0;
    Expect(encoder.ProcessDecoderInstructions(partialDecoderInstruction, sizeof(partialDecoderInstruction), &consumed,
                                              &applicationError) == STATUS_MORE_PROCESSING_REQUIRED &&
               consumed == 0 && applicationError == 0,
           "fragmented decoder instruction waits for continuation bytes without raising a stream error");
    Expect(QpackEncoder::IsSensitiveName(View("Authorization").Data, View("Authorization").Length) &&
               QpackEncoder::IsSensitiveName(View("Proxy-Authorization").Data, View("Proxy-Authorization").Length) &&
               QpackEncoder::IsSensitiveName(View("Cookie").Data, View("Cookie").Length),
           "sensitive-name policy covers authorization, proxy authorization, and cookie case-insensitively");

    QpackFieldView sensitiveLiteral = {View("x-private"), View("hidden"), true};
    Expect(NT_SUCCESS(encoder.EncodeFieldSection(16, &sensitiveLiteral, 1, fieldSection, sizeof(fieldSection),
                                                 &fieldSectionLength, &applicationError)) &&
               fieldSectionLength > 2 && (fieldSection[2] & 0x30U) == 0x30U,
           "caller-marked sensitive literal names use the never-index representation");
    Expect(NT_SUCCESS(decoder.DecodeFieldSection(16, fieldSection, fieldSectionLength, decodedFields, 5,
                                                 &decodedFieldCount, fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed,
                                                 decoderInstruction, sizeof(decoderInstruction),
                                                 &decoderInstructionLength, &applicationError)) &&
               decodedFieldCount == 1 && decodedFields[0].Sensitive,
           "explicit never-index survives literal-name decoding");
}

void TestRelativeAndPostBaseDecoding()
{
    using namespace wknet::qpack;

    QpackEncoder encoder;
    QpackDecoder decoder;
    Expect(NT_SUCCESS(encoder.Initialize(256, 4)) && NT_SUCCESS(decoder.Initialize(256, 4, 256, 8)),
           "relative index fixtures initialize");
    UCHAR instruction[128] = {};
    SIZE_T instructionLength = 0;
    SIZE_T consumed = 0;
    ULONGLONG error = 0;
    Expect(NT_SUCCESS(encoder.SetCapacity(128, instruction, sizeof(instruction), &instructionLength)) &&
               NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &error)),
           "relative fixture capacity synchronizes");
    Expect(NT_SUCCESS(encoder.InsertWithLiteralName(View("first").Data, 5, false, View("1").Data, 1, false, instruction,
                                                    sizeof(instruction), &instructionLength)) &&
               NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &error)),
           "relative fixture inserts first entry");
    Expect(NT_SUCCESS(encoder.InsertWithLiteralName(View("second").Data, 6, false, View("2").Data, 1, false,
                                                    instruction, sizeof(instruction), &instructionLength)) &&
               NT_SUCCESS(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &error)),
           "relative fixture inserts second entry");

    const UCHAR relativeSection[] = {3, 0, 0x80};
    const UCHAR postBaseSection[] = {3, 0x80, 0x10};
    const UCHAR postBaseNameSection[] = {3, 0x80, 0x08, 1, 'v'};
    QpackFieldView fields[2] = {};
    UCHAR fieldBuffer[64] = {};
    UCHAR decoderInstruction[16] = {};
    SIZE_T fieldCount = 0;
    SIZE_T fieldBufferUsed = 0;
    SIZE_T decoderInstructionLength = 0;
    Expect(NT_SUCCESS(decoder.DecodeFieldSection(4, relativeSection, sizeof(relativeSection), fields, 2, &fieldCount,
                                                 fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed, decoderInstruction,
                                                 sizeof(decoderInstruction), &decoderInstructionLength, &error)) &&
               fieldCount == 1 && Equals(fields[0].Name, "second"),
           "relative dynamic index resolves Base minus index minus one");
    Expect(NT_SUCCESS(decoder.DecodeFieldSection(8, postBaseSection, sizeof(postBaseSection), fields, 2, &fieldCount,
                                                 fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed, decoderInstruction,
                                                 sizeof(decoderInstruction), &decoderInstructionLength, &error)) &&
               fieldCount == 1 && Equals(fields[0].Name, "second"),
           "post-base dynamic index resolves Base plus index");
    Expect(NT_SUCCESS(decoder.DecodeFieldSection(12, postBaseNameSection, sizeof(postBaseNameSection), fields, 2,
                                                 &fieldCount, fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed,
                                                 decoderInstruction, sizeof(decoderInstruction),
                                                 &decoderInstructionLength, &error)) &&
               fieldCount == 1 && fields[0].Sensitive && Equals(fields[0].Name, "second") &&
               Equals(fields[0].Value, "v"),
           "literal post-base name reference resolves and retains never-index");
}

void TestBlockedStreamsAndCancellation()
{
    using namespace wknet::qpack;

    QpackEncoder encoder;
    QpackDecoder decoder;
    Expect(NT_SUCCESS(encoder.Initialize(128, 1)) && NT_SUCCESS(decoder.Initialize(128, 1, 256, 8)),
           "blocked stream fixtures initialize with one-stream limits");
    UCHAR capacityInstruction[32] = {};
    SIZE_T capacityInstructionLength = 0;
    SIZE_T consumed = 0;
    ULONGLONG error = 0;
    Expect(NT_SUCCESS(encoder.SetCapacity(128, capacityInstruction, sizeof(capacityInstruction),
                                          &capacityInstructionLength)) &&
               NT_SUCCESS(decoder.ProcessEncoderInstructions(capacityInstruction, capacityInstructionLength, &consumed,
                                                             &error)),
           "blocked stream decoder receives capacity before inserts");

    UCHAR insertInstruction[128] = {};
    SIZE_T insertInstructionLength = 0;
    Expect(NT_SUCCESS(encoder.InsertWithLiteralName(View("blocked").Data, 7, false, View("one").Data, 3, false,
                                                    insertInstruction, sizeof(insertInstruction),
                                                    &insertInstructionLength)),
           "encoder creates an insert withheld from the decoder");
    QpackFieldView sourceField = {View("blocked"), View("one"), false};
    UCHAR section[128] = {};
    SIZE_T sectionLength = 0;
    Expect(NT_SUCCESS(encoder.EncodeFieldSection(4, &sourceField, 1, section, sizeof(section), &sectionLength, &error)),
           "encoder creates a section that requires the withheld insert");

    QpackFieldView decoded[2] = {};
    UCHAR fieldBuffer[64] = {};
    UCHAR decoderInstruction[16] = {};
    SIZE_T fieldCount = 0;
    SIZE_T fieldBufferUsed = 0;
    SIZE_T decoderInstructionLength = 0;
    Expect(decoder.DecodeFieldSection(
               4, section, sectionLength, decoded, 2, &fieldCount, fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed,
               decoderInstruction, sizeof(decoderInstruction), &decoderInstructionLength, &error) == STATUS_PENDING &&
               decoder.BlockedStreamCount() == 1 && decoder.BlockedBytes() == sectionLength,
           "decoder stores a bounded blocked field section");
    Expect(decoder.DecodeFieldSection(8, section, sectionLength, decoded, 2, &fieldCount, fieldBuffer,
                                      sizeof(fieldBuffer), &fieldBufferUsed, decoderInstruction,
                                      sizeof(decoderInstruction), &decoderInstructionLength,
                                      &error) == STATUS_INSUFFICIENT_RESOURCES,
           "decoder enforces the unique blocked-stream limit");

    Expect(
        NT_SUCCESS(decoder.ProcessEncoderInstructions(insertInstruction, insertInstructionLength, &consumed, &error)),
        "withheld encoder instruction advances the decoder table");
    Expect(NT_SUCCESS(decoder.ResumeBlockedFieldSection(
               4, decoded, 2, &fieldCount, fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed, decoderInstruction,
               sizeof(decoderInstruction), &decoderInstructionLength, &error)) &&
               fieldCount == 1 && Equals(decoded[0].Name, "blocked") && decoder.BlockedStreamCount() == 0,
           "blocked field section resumes after the required insert arrives");
    Expect(
        NT_SUCCESS(encoder.ProcessDecoderInstructions(decoderInstruction, decoderInstructionLength, &consumed, &error)),
        "resumed section acknowledgment releases encoder references");

    Expect(
        NT_SUCCESS(encoder.EncodeFieldSection(20, &sourceField, 1, section, sizeof(section), &sectionLength, &error)) &&
            NT_SUCCESS(
                encoder.EncodeFieldSection(20, &sourceField, 1, section, sizeof(section), &sectionLength, &error)) &&
            encoder.OutstandingSectionCount() == 2,
        "encoder keeps multiple ordered outstanding sections for one stream");
    UCHAR manualCancellation[16] = {};
    SIZE_T manualCancellationLength = 0;
    Expect(NT_SUCCESS(QpackEncodeInteger(20, 0x40, 6, manualCancellation, sizeof(manualCancellation),
                                         &manualCancellationLength)) &&
               NT_SUCCESS(encoder.ProcessDecoderInstructions(manualCancellation, manualCancellationLength, &consumed,
                                                             &error)) &&
               encoder.OutstandingSectionCount() == 0,
           "Stream Cancellation clears every outstanding section for the stream");

    UCHAR secondInsert[128] = {};
    SIZE_T secondInsertLength = 0;
    Expect(NT_SUCCESS(encoder.InsertWithLiteralName(View("cancelled").Data, 9, false, View("two").Data, 3, false,
                                                    secondInsert, sizeof(secondInsert), &secondInsertLength)),
           "second withheld insert is created for cancellation");
    sourceField = {View("cancelled"), View("two"), false};
    Expect(
        NT_SUCCESS(encoder.EncodeFieldSection(12, &sourceField, 1, section, sizeof(section), &sectionLength, &error)),
        "cancel fixture field section is encoded");
    Expect(decoder.DecodeFieldSection(12, section, sectionLength, decoded, 2, &fieldCount, fieldBuffer,
                                      sizeof(fieldBuffer), &fieldBufferUsed, decoderInstruction,
                                      sizeof(decoderInstruction), &decoderInstructionLength, &error) == STATUS_PENDING,
           "cancel fixture becomes blocked");
    Expect(NT_SUCCESS(
               decoder.CancelStream(12, decoderInstruction, sizeof(decoderInstruction), &decoderInstructionLength)) &&
               decoder.BlockedStreamCount() == 0,
           "Stream Cancellation removes blocked bytes before emitting the instruction");
    Expect(NT_SUCCESS(
               encoder.ProcessDecoderInstructions(decoderInstruction, decoderInstructionLength, &consumed, &error)) &&
               encoder.OutstandingSectionCount() == 0,
           "encoder applies Stream Cancellation to all sections on the stream");
}

void TestCapacityDelayAndMalformedStreams()
{
    using namespace wknet::qpack;

    QpackEncoder encoder;
    QpackDecoder decoder;
    Expect(NT_SUCCESS(encoder.Initialize(128, 1)) && NT_SUCCESS(decoder.Initialize(64, 1, 128, 4)),
           "capacity delay fixtures initialize");
    UCHAR instruction[128] = {};
    SIZE_T instructionLength = 0;
    SIZE_T consumed = 0;
    ULONGLONG error = 0;
    Expect(NT_SUCCESS(encoder.SetCapacity(128, instruction, sizeof(instruction), &instructionLength)),
           "encoder capacity is established");
    Expect(decoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &error) ==
                   STATUS_INVALID_NETWORK_RESPONSE &&
               error == QpackEncoderStreamError,
           "decoder rejects capacity above its advertised SETTINGS value");

    QpackDecoder synchronizedDecoder;
    Expect(NT_SUCCESS(synchronizedDecoder.Initialize(128, 1, 128, 4)) &&
               NT_SUCCESS(
                   synchronizedDecoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &error)),
           "capacity delay decoder synchronizes");
    Expect(NT_SUCCESS(encoder.InsertWithLiteralName(View("hold").Data, 4, false, View("reference").Data, 9, false,
                                                    instruction, sizeof(instruction), &instructionLength)),
           "capacity delay entry inserts");
    Expect(
        NT_SUCCESS(synchronizedDecoder.ProcessEncoderInstructions(instruction, instructionLength, &consumed, &error)),
        "capacity delay decoder receives the entry");
    QpackFieldView field = {View("hold"), View("reference"), false};
    UCHAR section[128] = {};
    SIZE_T sectionLength = 0;
    Expect(NT_SUCCESS(encoder.EncodeFieldSection(4, &field, 1, section, sizeof(section), &sectionLength, &error)),
           "capacity delay section references the entry");
    Expect(encoder.SetCapacity(0, instruction, sizeof(instruction), &instructionLength) == STATUS_PENDING &&
               instructionLength == 0,
           "encoder records a pending capacity reduction instead of evicting a referenced entry");
    Expect(encoder.InsertWithLiteralName(View("delayed").Data, 7, false, View("insert").Data, 6, false, instruction,
                                         sizeof(instruction), &instructionLength) == STATUS_DEVICE_BUSY &&
               instructionLength == 0,
           "encoder delays new inserts while a referenced capacity reduction is pending");

    QpackFieldView decoded[1] = {};
    UCHAR fieldBuffer[64] = {};
    UCHAR decoderInstruction[16] = {};
    SIZE_T fieldCount = 0;
    SIZE_T fieldBufferUsed = 0;
    SIZE_T decoderInstructionLength = 0;
    Expect(NT_SUCCESS(synchronizedDecoder.DecodeFieldSection(
               4, section, sectionLength, decoded, 1, &fieldCount, fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed,
               decoderInstruction, sizeof(decoderInstruction), &decoderInstructionLength, &error)) &&
               NT_SUCCESS(
                   encoder.ProcessDecoderInstructions(decoderInstruction, decoderInstructionLength, &consumed, &error)),
           "Section Ack releases the reference protecting pending capacity");
    Expect(NT_SUCCESS(encoder.DrainPendingCapacity(instruction, sizeof(instruction), &instructionLength)) &&
               encoder.Table().Capacity() == 0,
           "pending capacity reduction drains after references release");

    const UCHAR invalidDuplicate[] = {0};
    QpackDecoder emptyDecoder;
    Expect(NT_SUCCESS(emptyDecoder.Initialize(128, 1, 128, 4)), "empty decoder initializes");
    Expect(emptyDecoder.ProcessEncoderInstructions(invalidDuplicate, sizeof(invalidDuplicate), &consumed, &error) ==
                   STATUS_INVALID_NETWORK_RESPONSE &&
               error == QpackEncoderStreamError,
           "Duplicate of a missing dynamic entry is an encoder stream error");

    const UCHAR invalidFieldSection[] = {2, 0};
    QpackFieldView invalidFields[1] = {};
    Expect(emptyDecoder.DecodeFieldSection(4, invalidFieldSection, sizeof(invalidFieldSection), invalidFields, 1,
                                           &fieldCount, fieldBuffer, sizeof(fieldBuffer), &fieldBufferUsed,
                                           decoderInstruction, sizeof(decoderInstruction), &decoderInstructionLength,
                                           &error) == STATUS_PENDING,
           "future Required Insert Count blocks instead of being decoded prematurely");
    Expect(emptyDecoder.CancelStream(4, decoderInstruction, sizeof(decoderInstruction), &decoderInstructionLength) ==
               STATUS_SUCCESS,
           "blocked malformed/future section can be cancelled without retaining bytes");
}
} // namespace

int main()
{
    UCHAR integer[16] = {};
    SIZE_T written = 0;
    Expect(NT_SUCCESS(wknet::qpack::QpackEncodeInteger(10, 0, 5, integer, sizeof(integer), &written)) && written == 1 &&
               integer[0] == 10,
           "prefixed integer encodes a value below the prefix maximum");
    Expect(NT_SUCCESS(wknet::qpack::QpackEncodeInteger(1337, 0, 5, integer, sizeof(integer), &written)) &&
               written == 3 && integer[0] == 0x1f && integer[1] == 0x9a && integer[2] == 0x0a,
           "prefixed integer matches the RFC continuation example");
    ULONGLONG decodedInteger = 0;
    SIZE_T consumed = 0;
    Expect(NT_SUCCESS(wknet::qpack::QpackDecodeInteger(integer, written, 5, &decodedInteger, &consumed)) &&
               decodedInteger == 1337 && consumed == written,
           "prefixed integer round-trips");
    const UCHAR overflowInteger[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    Expect(wknet::qpack::QpackDecodeInteger(overflowInteger, sizeof(overflowInteger), 8, &decodedInteger, &consumed) ==
               STATUS_INTEGER_OVERFLOW,
           "prefixed integer rejects values above the local 62-bit bound");

    const UCHAR huffmanInput[] = "www.example.com";
    const UCHAR expectedHuffman[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    UCHAR huffmanEncoded[64] = {};
    SIZE_T huffmanEncodedLength = 0;
    Expect(wknet::qpack::QpackHuffmanEncodedLength(huffmanInput, sizeof(huffmanInput) - 1) == sizeof(expectedHuffman),
           "QPACK Huffman length uses the RFC 7541 codebook");
    Expect(NT_SUCCESS(wknet::qpack::QpackHuffmanEncode(huffmanInput, sizeof(huffmanInput) - 1, huffmanEncoded,
                                                       sizeof(huffmanEncoded), &huffmanEncodedLength)) &&
               huffmanEncodedLength == sizeof(expectedHuffman) &&
               memcmp(huffmanEncoded, expectedHuffman, sizeof(expectedHuffman)) == 0,
           "QPACK Huffman encode matches the RFC vector");
    UCHAR huffmanDecoded[64] = {};
    SIZE_T huffmanDecodedLength = 0;
    Expect(NT_SUCCESS(wknet::qpack::QpackHuffmanDecode(huffmanEncoded, huffmanEncodedLength, huffmanDecoded,
                                                       sizeof(huffmanDecoded), &huffmanDecodedLength)) &&
               huffmanDecodedLength == sizeof(huffmanInput) - 1 &&
               memcmp(huffmanDecoded, huffmanInput, huffmanDecodedLength) == 0,
           "QPACK Huffman round-trips into a caller-owned buffer");
    const UCHAR badPadding[] = {0x00};
    Expect(wknet::qpack::QpackHuffmanDecode(badPadding, sizeof(badPadding), huffmanDecoded, sizeof(huffmanDecoded),
                                            &huffmanDecodedLength) == STATUS_INVALID_NETWORK_RESPONSE,
           "QPACK Huffman rejects non-EOS-prefix padding");
    const UCHAR eos[] = {0xff, 0xff, 0xff, 0xff};
    Expect(wknet::qpack::QpackHuffmanDecode(eos, sizeof(eos), huffmanDecoded, sizeof(huffmanDecoded),
                                            &huffmanDecodedLength) == STATUS_INVALID_NETWORK_RESPONSE,
           "QPACK Huffman rejects the EOS symbol");

    wknet::qpack::QpackStaticEntryView entry = {};
    Expect(NT_SUCCESS(wknet::qpack::QpackStaticTableLookup(0, &entry)) && entry.Name.Length == 10 &&
               memcmp(entry.Name.Data, ":authority", 10) == 0 && entry.Value.Length == 0,
           "QPACK static table index zero is :authority");
    Expect(NT_SUCCESS(wknet::qpack::QpackStaticTableLookup(98, &entry)) && entry.Name.Length == 15 &&
               memcmp(entry.Name.Data, "x-frame-options", 15) == 0 && entry.Value.Length == 10 &&
               memcmp(entry.Value.Data, "sameorigin", 10) == 0,
           "QPACK static table final index matches RFC 9204");
    Expect(wknet::qpack::QpackStaticTableLookup(99, &entry) == STATUS_INVALID_NETWORK_RESPONSE,
           "QPACK static table rejects an out-of-range index");

    TestDynamicTable();
    TestRequiredInsertCount();
    TestInstructionStreamsAndFieldSections();
    TestRelativeAndPostBaseDecoding();
    TestBlockedStreamsAndCancellation();
    TestCapacityDelayAndMalformedStreams();

    if (failed)
    {
        printf("QPACK TESTS FAILED\n");
        return 1;
    }
    printf("QPACK TESTS PASSED\n");
    return 0;
}
