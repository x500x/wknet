#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "quic/QuicAttemptValidation.h"
#include "quic/QuicPacket.h"

#include <stdio.h>
#include <string.h>

namespace
{
bool g_failed = false;

void Expect(bool condition, const char *message) noexcept
{
    if (!condition)
    {
        g_failed = true;
        printf("FAIL: %s\n", message);
    }
}

SIZE_T BuildInitial(UCHAR *packet, SIZE_T capacity, UCHAR cidSeed) noexcept
{
    if (capacity < 48)
    {
        return 0;
    }
    SIZE_T offset = 0;
    packet[offset++] = 0xc0;
    packet[offset++] = 0;
    packet[offset++] = 0;
    packet[offset++] = 0;
    packet[offset++] = 1;
    packet[offset++] = 8;
    for (UCHAR index = 0; index < 8; ++index)
        packet[offset++] = static_cast<UCHAR>(cidSeed + index);
    packet[offset++] = 8;
    for (UCHAR index = 0; index < 8; ++index)
        packet[offset++] = static_cast<UCHAR>(cidSeed + 16 + index);
    packet[offset++] = 0;
    packet[offset++] = 0x19;
    packet[offset++] = 0;
    for (UCHAR index = 0; index < 24; ++index)
        packet[offset++] = index;
    return offset;
}
} // namespace

int main()
{
    UCHAR packet[128] = {};
    const SIZE_T packetLength = BuildInitial(packet, sizeof(packet), 1);
    wknet::quic::QuicPacketHeader header = {};
    Expect(NT_SUCCESS(wknet::quic::QuicParsePacketHeader(packet, packetLength, 0, &header)), "Initial header parses");
    Expect(header.Type == wknet::quic::QuicPacketType::Initial, "Initial type is identified");
    Expect(header.Version == wknet::quic::QuicVersion1, "v1 is parsed");
    Expect(header.DestinationConnectionId.Length == 8 && header.SourceConnectionId.Length == 8, "CID views are parsed");
    Expect(header.Token.Length == 0 && header.PacketNumberLength == 1, "Initial token and PN length are parsed");
    Expect(header.PacketLength == packetLength, "long-header length bounds packet");

    UCHAR versionNegotiation[] = {0x85, 0, 0, 0,    0,    4,    1,    2,    3,    4,    4,   5,
                                  6,    7, 8, 0x0a, 0x0a, 0x0a, 0x0a, 0x6b, 0x33, 0x43, 0xcf};
    Expect(NT_SUCCESS(wknet::quic::QuicParsePacketHeader(versionNegotiation, sizeof(versionNegotiation), 0, &header)),
           "Version Negotiation header parses when the randomized Fixed Bit is zero");
    Expect(header.Type == wknet::quic::QuicPacketType::VersionNegotiation && header.VersionList.Length == 8,
           "VN version list is exposed");
    const UCHAR odcid[] = {5, 6, 7, 8};
    const UCHAR clientScid[] = {1, 2, 3, 4};
    wknet::quic::QuicAttemptValidation vnAttempt;
    Expect(NT_SUCCESS(vnAttempt.Initialize(wknet::quic::QuicVersion1, {odcid, sizeof(odcid)},
                                           {clientScid, sizeof(clientScid)})),
           "VN attempt initializes");
    const ULONG v1Only[] = {wknet::quic::QuicVersion1};
    ULONG selectedVersion = 0;
    Expect(vnAttempt.ValidateVersionNegotiation(header, v1Only, 1, &selectedVersion) == STATUS_NOT_SUPPORTED,
           "valid VN with no different supported version terminates v1 attempt");
    Expect(vnAttempt.VersionNegotiationAccepted() && selectedVersion == 0, "valid no-common-version VN is remembered");
    wknet::quic::QuicAttemptValidation selectableAttempt;
    (void)selectableAttempt.Initialize(wknet::quic::QuicVersion1, {odcid, sizeof(odcid)},
                                       {clientScid, sizeof(clientScid)});
    const ULONG injectedVersions[] = {wknet::quic::QuicVersion1, 0x6b3343cfUL};
    Expect(NT_SUCCESS(selectableAttempt.ValidateVersionNegotiation(header, injectedVersions, 2, &selectedVersion)) &&
               selectedVersion == 0x6b3343cfUL,
           "test-only supported set exercises different-version selection");

    UCHAR retry[64] = {};
    SIZE_T retryLength = 0;
    retry[retryLength++] = 0xf0;
    retry[retryLength++] = 0;
    retry[retryLength++] = 0;
    retry[retryLength++] = 0;
    retry[retryLength++] = 1;
    retry[retryLength++] = 4;
    retry[retryLength++] = 1;
    retry[retryLength++] = 2;
    retry[retryLength++] = 3;
    retry[retryLength++] = 4;
    retry[retryLength++] = 4;
    retry[retryLength++] = 5;
    retry[retryLength++] = 6;
    retry[retryLength++] = 7;
    retry[retryLength++] = 8;
    retry[retryLength++] = 9;
    retry[retryLength++] = 10;
    retryLength += wknet::quic::QuicRetryIntegrityTagLength;
    Expect(NT_SUCCESS(wknet::quic::QuicParsePacketHeader(retry, retryLength, 0, &header)), "Retry header parses");
    Expect(header.Type == wknet::quic::QuicPacketType::Retry && header.Token.Length == 2,
           "Retry token excludes integrity tag");

    UCHAR shortPacket[] = {0x43, 1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    Expect(NT_SUCCESS(wknet::quic::QuicParsePacketHeader(shortPacket, sizeof(shortPacket), 4, &header)),
           "short header parses");
    Expect(header.Type == wknet::quic::QuicPacketType::OneRtt && header.PacketNumberLength == 4 &&
               header.PacketNumberOffset == 5,
           "short header DCID and PN views are bounded");

    UCHAR pn[4] = {};
    SIZE_T pnWritten = 0;
    Expect(NT_SUCCESS(wknet::quic::QuicEncodePacketNumber(0x123456, 3, pn, sizeof(pn), &pnWritten)),
           "packet number encodes");
    Expect(pnWritten == 3 && pn[0] == 0x12 && pn[1] == 0x34 && pn[2] == 0x56, "packet number uses network byte order");
    ULONGLONG reconstructed = 0;
    Expect(NT_SUCCESS(wknet::quic::QuicReconstructPacketNumber(0x9b32, 2, 0xa82f30eaULL, &reconstructed)),
           "packet number reconstructs");
    Expect(reconstructed == 0xa82f9b32ULL, "RFC packet number reconstruction example matches");

    const UCHAR encodeDcid[] = {1, 2, 3, 4};
    const UCHAR encodeScid[] = {5, 6, 7, 8};
    const UCHAR encodeToken[] = {9, 10};
    wknet::quic::QuicLongHeaderEncodeOptions longOptions = {};
    longOptions.Type = wknet::quic::QuicPacketType::Initial;
    longOptions.DestinationConnectionId = {encodeDcid, sizeof(encodeDcid)};
    longOptions.SourceConnectionId = {encodeScid, sizeof(encodeScid)};
    longOptions.Token = {encodeToken, sizeof(encodeToken)};
    longOptions.PacketNumber = 0x1234;
    longOptions.PacketNumberLength = 2;
    longOptions.ProtectedPayloadLength = 22;
    SIZE_T packetNumberOffset = 0;
    SIZE_T encodedHeaderLength = 0;
    Expect(NT_SUCCESS(wknet::quic::QuicEncodeLongPacketHeader(longOptions, packet, sizeof(packet), &packetNumberOffset,
                                                              &encodedHeaderLength)),
           "Initial long header encodes");
    memset(packet + encodedHeaderLength, 0, 20);
    Expect(NT_SUCCESS(wknet::quic::QuicParsePacketHeader(packet, encodedHeaderLength + 20, 0, &header)) &&
               header.PacketNumberOffset == packetNumberOffset && header.PacketNumberLength == 2 &&
               header.Token.Length == 2,
           "encoded Initial long header parses");

    wknet::quic::QuicShortHeaderEncodeOptions shortOptions = {};
    shortOptions.DestinationConnectionId = {encodeDcid, sizeof(encodeDcid)};
    shortOptions.PacketNumber = 0x123456;
    shortOptions.PacketNumberLength = 3;
    shortOptions.KeyPhase = true;
    Expect(NT_SUCCESS(wknet::quic::QuicEncodeShortPacketHeader(shortOptions, packet, sizeof(packet),
                                                               &packetNumberOffset, &encodedHeaderLength)),
           "1-RTT short header encodes");
    memset(packet + encodedHeaderLength, 0, 20);
    Expect(
        NT_SUCCESS(wknet::quic::QuicParsePacketHeader(packet, encodedHeaderLength + 20, sizeof(encodeDcid), &header)) &&
            header.PacketNumberOffset == packetNumberOffset && header.PacketNumberLength == 3 &&
            (packet[0] & 0x04U) != 0,
        "encoded 1-RTT short header parses with key phase");

    UCHAR coalesced[128] = {};
    const SIZE_T firstLength = BuildInitial(coalesced, sizeof(coalesced), 1);
    const SIZE_T secondLength = BuildInitial(coalesced + firstLength, sizeof(coalesced) - firstLength, 32);
    wknet::quic::QuicPacketIterator iterator = {};
    wknet::quic::QuicPacketIteratorInitialize(&iterator, coalesced, firstLength + secondLength, 0);
    wknet::quic::QuicBufferView view = {};
    Expect(NT_SUCCESS(wknet::quic::QuicPacketIteratorNext(&iterator, &header, &view)) && view.Length == firstLength,
           "coalesced iterator returns first packet");
    Expect(NT_SUCCESS(wknet::quic::QuicPacketIteratorNext(&iterator, &header, &view)) && view.Length == secondLength,
           "coalesced iterator returns second packet");
    Expect(wknet::quic::QuicPacketIteratorNext(&iterator, &header, &view) == STATUS_NOT_FOUND,
           "coalesced iterator terminates exactly");

    Expect(wknet::quic::QuicValidateInitialDatagramLength(1199) == STATUS_INVALID_PARAMETER,
           "client Initial datagram below 1200 is rejected");
    Expect(NT_SUCCESS(wknet::quic::QuicValidateInitialDatagramLength(1200)), "1200-byte Initial datagram is accepted");

    const UCHAR malformed[] = {0xc0, 0, 0, 0, 1, 21};
    Expect(wknet::quic::QuicParsePacketHeader(malformed, sizeof(malformed), 0, &header) ==
               STATUS_INVALID_NETWORK_RESPONSE,
           "CID length above 20 is rejected without allocation");

    if (g_failed)
    {
        printf("QUIC PACKET TESTS FAILED\n");
        return 1;
    }
    printf("QUIC PACKET TESTS PASSED\n");
    return 0;
}
