#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/Trace.h>
#include <wknet/crypto/Aead.h>

#include "qpack/QpackDynamicTable.h"
#include "quic/QuicAttemptValidation.h"
#include "quic/QuicPacket.h"
#include "session/UrlParser.h"

#include <stdio.h>
#include <string.h>

namespace
{
    bool g_failed = false;
    char g_log[128 * 1024] = {};
    SIZE_T g_logLength = 0;

    constexpr const char* SensitiveMarkers[] = {"PACKET_MARKER_6D4F",
                                                "HEADER_MARKER_27A1",
                                                "BODY_MARKER_901C",
                                                "KEY_MARKER_4B28",
                                                "SECRET_MARKER_119E",
                                                "IV_MARKER_7F32",
                                                "NONCE_MARKER_A830",
                                                "HP_SAMPLE_MARKER_55D0",
                                                "TICKET_MARKER_2C19",
                                                "RETRY_TOKEN_MARKER_8A44",
                                                "NEW_TOKEN_MARKER_F137",
                                                "RESET_TOKEN_MARKER_3E91",
                                                "CID_MARKER_74B2",
                                                "QUERY_MARKER_08F5",
                                                "CREDENTIAL_MARKER_49D3",
                                                "CERTIFICATE_MARKER_E622",
                                                "ADDRESS_MARKER_FFFF800012340000"};

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition)
        {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void CaptureTrace(void*, wknet::TraceLevel, ULONG, const char* message) noexcept
    {
        if (message == nullptr || g_logLength >= sizeof(g_log) - 1)
        {
            return;
        }
        const SIZE_T remaining = sizeof(g_log) - g_logLength;
        const int written = snprintf(g_log + g_logLength, remaining, "%s\n", message);
        if (written > 0)
        {
            const SIZE_T appended = static_cast<SIZE_T>(written);
            g_logLength += appended < remaining ? appended : remaining - 1;
        }
    }

    void ExerciseUrlQuery() noexcept
    {
        wknet::session::Request request = {};
        constexpr char url[] = "https://example.test/path?token=QUERY_MARKER_08F5";
        Expect(NT_SUCCESS(wknet::session::ParseUrlIntoRequest(request, url, sizeof(url) - 1)),
               "URL marker input parses");
    }

    void ExerciseQpackMarkers() noexcept
    {
        wknet::qpack::QpackDynamicTable table;
        Expect(NT_SUCCESS(table.Initialize(4096, 4096)), "QPACK marker table initializes");
        constexpr UCHAR name[] = "authorization";
        for (const char* marker : SensitiveMarkers)
        {
            const SIZE_T length = strlen(marker);
            Expect(NT_SUCCESS(table.Insert(name, sizeof(name) - 1, reinterpret_cast<const UCHAR*>(marker), length)),
                   "QPACK marker insert succeeds");
        }
    }

    void ExerciseCryptoMarkers() noexcept
    {
        const UCHAR keyBytes[16] = {'K', 'E', 'Y', '_', 'M', 'A', 'R', 'K', 'E', 'R', '_', '4', 'B', '2', '8', '!'};
        const UCHAR nonce[12] = {'N', 'O', 'N', 'C', 'E', '_', 'A', '8', '3', '0', '!', '!'};
        constexpr UCHAR plaintext[] = "BODY_MARKER_901C PACKET_MARKER_6D4F SECRET_MARKER_119E";
        wknet::crypto::AeadKey key = {};
        key.Algorithm = wknet::crypto::AeadAlgorithm::Aes128Gcm;
        key.Key = keyBytes;
        key.KeyLength = sizeof(keyBytes);
        wknet::crypto::AeadParameters parameters = {};
        parameters.Nonce = {nonce, sizeof(nonce)};
        UCHAR ciphertext[sizeof(plaintext)] = {};
        UCHAR tag[16] = {};
        SIZE_T written = 0;
        Expect(NT_SUCCESS(wknet::crypto::Aead::Encrypt(nullptr, key, parameters, plaintext, sizeof(plaintext) - 1,
                                                       ciphertext, sizeof(ciphertext), tag, sizeof(tag), &written)),
               "crypto marker input encrypts");
    }

    void ExerciseQuicMarkers() noexcept
    {
        const UCHAR originalDestinationConnectionId[] = {'C', 'I', 'D', '_', 'M', 'A', 'R', 'K', 'E', 'R'};
        const UCHAR sourceConnectionId[] = {'S', 'R', 'C', '_', 'C', 'I', 'D'};
        const UCHAR versionList[] = {0x6b, 0x33, 0x43, 0xcf};
        wknet::quic::QuicAttemptValidation attempt;
        Expect(NT_SUCCESS(attempt.Initialize(wknet::quic::QuicVersion1,
                                             {originalDestinationConnectionId, sizeof(originalDestinationConnectionId)},
                                             {sourceConnectionId, sizeof(sourceConnectionId)})),
               "QUIC marker attempt initializes");
        wknet::quic::QuicPacketHeader header = {};
        header.Type = wknet::quic::QuicPacketType::VersionNegotiation;
        header.DestinationConnectionId = {sourceConnectionId, sizeof(sourceConnectionId)};
        header.SourceConnectionId = {originalDestinationConnectionId, sizeof(originalDestinationConnectionId)};
        header.VersionList = {versionList, sizeof(versionList)};
        const ULONG supported[] = {0x6b3343cfUL};
        Expect(NT_SUCCESS(attempt.ValidateVersionNegotiation(header, supported, 1, nullptr)),
               "QUIC CID marker validation succeeds");
    }
} // namespace

int main()
{
    wknet::TraceSetSink(CaptureTrace, nullptr);
    wknet::TraceSetComponents(wknet::ComponentAll);
    wknet::TraceSetLevel(wknet::TraceLevel::Max);

    ExerciseUrlQuery();
    ExerciseQpackMarkers();
    ExerciseCryptoMarkers();
    ExerciseQuicMarkers();

    Expect(g_logLength != 0, "protocol operations emitted auditable logs");
    for (const char* marker : SensitiveMarkers)
    {
        if (strstr(g_log, marker) != nullptr)
        {
            g_failed = true;
            printf("FAIL: sensitive marker leaked: %s\n", marker);
        }
    }

    wknet::TraceSetSink(nullptr, nullptr);
    if (g_failed)
    {
        printf("PROTOCOL LOG SAFETY TESTS FAILED\n");
        return 1;
    }
    printf("PROTOCOL LOG SAFETY TESTS PASSED\n");
    return 0;
}
