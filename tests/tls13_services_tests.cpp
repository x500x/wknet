#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "tls/Tls13HandshakeMessages.h"
#include "tls/Tls13KeySchedule.h"
#include "tls/TlsTranscriptHash.h"

#include <stdio.h>
#include <string.h>

using wknet::crypto::HashAlgorithm;
using wknet::tls::Tls13HandshakeMessages;
using wknet::tls::Tls13KeySchedule;
using wknet::tls::TlsCipherSuite;
using wknet::tls::TlsTranscriptHash;

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

    void ExpectStatus(NTSTATUS actual, NTSTATUS expected, const char* message)
    {
        if (actual != expected) {
            g_failed = true;
            printf(
                "FAIL: %s (actual=0x%08X expected=0x%08X)\n",
                message,
                static_cast<unsigned int>(actual),
                static_cast<unsigned int>(expected));
        }
    }

    void TestHkdfLabelEncoding()
    {
        const UCHAR expected[] = {
            0x00, 0x10,
            0x09,
            't', 'l', 's', '1', '3', ' ', 'k', 'e', 'y',
            0x00
        };
        UCHAR encoded[32] = {};
        SIZE_T written = 0;
        NTSTATUS status = Tls13KeySchedule::BuildHkdfLabel(
            "key",
            nullptr,
            0,
            16,
            encoded,
            sizeof(encoded),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 HKDF label encodes");
        Expect(written == sizeof(expected), "TLS 1.3 HKDF label length matches");
        Expect(memcmp(encoded, expected, sizeof(expected)) == 0, "TLS 1.3 HKDF label bytes match RFC 8446");

        written = 0;
        status = Tls13KeySchedule::BuildHkdfLabel(
            "key",
            nullptr,
            0,
            16,
            encoded,
            sizeof(expected) - 1,
            &written);
        ExpectStatus(status, STATUS_BUFFER_TOO_SMALL, "TLS 1.3 HKDF label reports capacity");
        Expect(written == sizeof(expected), "TLS 1.3 HKDF label reports required length");
    }

    void TestTranscriptSnapshotAndMessageHash()
    {
        static const UCHAR data[] = { 'a', 'b', 'c' };
        static const UCHAR expectedSha256[] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
        UCHAR snapshot[sizeof(expectedSha256)] = {};
        SIZE_T written = 0;

        TlsTranscriptHash transcript;
        NTSTATUS status = transcript.Initialize(HashAlgorithm::Sha256);
        ExpectStatus(status, STATUS_SUCCESS, "TLS transcript initializes");
        status = transcript.Update(data, sizeof(data));
        ExpectStatus(status, STATUS_SUCCESS, "TLS transcript updates");
        status = transcript.Snapshot(snapshot, sizeof(snapshot), &written);
        ExpectStatus(status, STATUS_SUCCESS, "TLS transcript snapshots");
        Expect(written == sizeof(snapshot), "TLS transcript snapshot length matches");
        Expect(memcmp(snapshot, expectedSha256, sizeof(snapshot)) == 0, "TLS transcript snapshot matches SHA-256");

        status = transcript.ReplaceWithMessageHash(snapshot, sizeof(snapshot));
        ExpectStatus(status, STATUS_SUCCESS, "TLS transcript replaces state with synthetic message_hash");
    }

    void TestHandshakeMessageServiceMetadata()
    {
        Expect(
            Tls13HandshakeMessages::HashForCipherSuite(TlsCipherSuite::TlsAes128GcmSha256) ==
                HashAlgorithm::Sha256,
            "TLS 1.3 AES-128 uses SHA-256");
        Expect(
            Tls13HandshakeMessages::HashForCipherSuite(TlsCipherSuite::TlsAes256GcmSha384) ==
                HashAlgorithm::Sha384,
            "TLS 1.3 AES-256 uses SHA-384");
    }
}

int main()
{
    TestHkdfLabelEncoding();
    TestTranscriptSnapshotAndMessageHash();
    TestHandshakeMessageServiceMetadata();

    if (g_failed) {
        return 1;
    }

    printf("PASS: TLS 1.3 service tests\n");
    return 0;
}
