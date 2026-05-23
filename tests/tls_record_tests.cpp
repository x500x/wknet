#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/tls/TlsContext.h"
#include "../src/KernelHttp/tls/CertificateStore.h"
#include "../src/KernelHttp/tls/CertificateValidator.h"
#include "../src/KernelHttp/tls/TlsHandshake12.h"
#include "../src/KernelHttp/tls/TlsRecord.h"

#include <stdio.h>
#include <string.h>

using KernelHttp::crypto::HashAlgorithm;
using KernelHttp::tls::CertificateAuthorityBundle;
using KernelHttp::tls::CertificateChainView;
using KernelHttp::tls::CertificatePin;
using KernelHttp::tls::CertificateStore;
using KernelHttp::tls::CertificateStoreOptions;
using KernelHttp::tls::CertificateTrustAnchor;
using KernelHttp::tls::CertificateValidationOptions;
using KernelHttp::tls::CertificateValidationResult;
using KernelHttp::tls::CertificateValidator;
using KernelHttp::tls::TlsAeadCipherState;
using KernelHttp::tls::CertificateSha256ThumbprintLength;
using KernelHttp::tls::TlsCipherSuite;
using KernelHttp::tls::TlsCertificateListView;
using KernelHttp::tls::TlsAesGcmExplicitNonceLength;
using KernelHttp::tls::TlsAesGcmFixedIvLength;
using KernelHttp::tls::TlsAesGcmTagLength;
using KernelHttp::tls::TlsClientHelloOptions;
using KernelHttp::tls::TlsRecordHeaderLength;
using KernelHttp::tls::TlsContentType;
using KernelHttp::tls::TlsContext;
using KernelHttp::tls::TlsHandshake12;
using KernelHttp::tls::TlsHandshakeMessageView;
using KernelHttp::tls::TlsHandshakeState;
using KernelHttp::tls::TlsHandshakeType;
using KernelHttp::tls::TlsMutablePlaintextRecord;
using KernelHttp::tls::TlsNamedGroup;
using KernelHttp::tls::TlsPlaintextRecord;
using KernelHttp::tls::TlsProtocolVersion;
using KernelHttp::tls::TlsRecordLayer;
using KernelHttp::tls::TlsRecordView;
using KernelHttp::tls::TlsServerHelloView;
using KernelHttp::tls::TlsServerKeyExchangeView;
using KernelHttp::tls::TlsSignatureScheme;
using KernelHttp::tls::TlsSessionSecrets;
using KernelHttp::tls::TlsTranscriptHash;
using KernelHttp::tls::TlsVerifyDataLength;

namespace
{
    constexpr SIZE_T TestMaxPemCertificateLength = 4096;
    constexpr SIZE_T TestMaxDerCertificateLength = 2048;
    constexpr SIZE_T TestMaxCertificateListLength = TestMaxDerCertificateLength + 3;
    const char LocalhostCertificatePath[] = "tests\\testdata\\localhost.cert.pem";
    const char PemCertificateBegin[] = "-----BEGIN CERTIFICATE-----";
    const char PemCertificateEnd[] = "-----END CERTIFICATE-----";

    bool g_failed = false;

    void Expect(bool condition, const char* message)
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    bool ReadFileBytes(const char* path, UCHAR* buffer, SIZE_T bufferCapacity, SIZE_T* bytesRead)
    {
        if (bytesRead != nullptr) {
            *bytesRead = 0;
        }

        if (path == nullptr || buffer == nullptr || bytesRead == nullptr || bufferCapacity == 0) {
            return false;
        }

        FILE* file = nullptr;
        if (fopen_s(&file, path, "rb") != 0 || file == nullptr) {
            return false;
        }

        bool ok = false;
        if (fseek(file, 0, SEEK_END) == 0) {
            const long fileLength = ftell(file);
            if (fileLength > 0 && static_cast<SIZE_T>(fileLength) <= bufferCapacity && fseek(file, 0, SEEK_SET) == 0) {
                const SIZE_T expectedLength = static_cast<SIZE_T>(fileLength);
                const SIZE_T actualLength = fread(buffer, 1, expectedLength, file);
                ok = actualLength == expectedLength && ferror(file) == 0;
                if (ok) {
                    *bytesRead = actualLength;
                }
            }
        }

        fclose(file);
        return ok;
    }

    bool MatchAscii(const UCHAR* data, SIZE_T dataLength, const char* text, SIZE_T textLength)
    {
        if (data == nullptr || text == nullptr || dataLength != textLength) {
            return false;
        }

        for (SIZE_T index = 0; index < dataLength; ++index) {
            if (data[index] != static_cast<UCHAR>(text[index])) {
                return false;
            }
        }

        return true;
    }

    bool FindAscii(
        const UCHAR* data,
        SIZE_T dataLength,
        const char* text,
        SIZE_T textLength,
        SIZE_T start,
        SIZE_T* foundAt)
    {
        if (foundAt != nullptr) {
            *foundAt = 0;
        }

        if (data == nullptr ||
            text == nullptr ||
            foundAt == nullptr ||
            textLength == 0 ||
            start > dataLength ||
            textLength > dataLength - start) {
            return false;
        }

        for (SIZE_T index = start; index <= dataLength - textLength; ++index) {
            if (MatchAscii(data + index, textLength, text, textLength)) {
                *foundAt = index;
                return true;
            }
        }

        return false;
    }

    bool DecodeBase64Char(UCHAR input, UCHAR* value)
    {
        if (value == nullptr) {
            return false;
        }

        if (input >= 'A' && input <= 'Z') {
            *value = static_cast<UCHAR>(input - 'A');
            return true;
        }

        if (input >= 'a' && input <= 'z') {
            *value = static_cast<UCHAR>(input - 'a' + 26);
            return true;
        }

        if (input >= '0' && input <= '9') {
            *value = static_cast<UCHAR>(input - '0' + 52);
            return true;
        }

        if (input == '+') {
            *value = 62;
            return true;
        }

        if (input == '/') {
            *value = 63;
            return true;
        }

        return false;
    }

    bool DecodePemCertificate(
        const UCHAR* pem,
        SIZE_T pemLength,
        UCHAR* der,
        SIZE_T derCapacity,
        SIZE_T* derLength)
    {
        if (derLength != nullptr) {
            *derLength = 0;
        }

        if (pem == nullptr || der == nullptr || derLength == nullptr) {
            return false;
        }

        SIZE_T begin = 0;
        if (!FindAscii(pem, pemLength, PemCertificateBegin, sizeof(PemCertificateBegin) - 1, 0, &begin)) {
            return false;
        }

        const SIZE_T bodyStart = begin + sizeof(PemCertificateBegin) - 1;
        SIZE_T end = 0;
        if (!FindAscii(pem, pemLength, PemCertificateEnd, sizeof(PemCertificateEnd) - 1, bodyStart, &end)) {
            return false;
        }

        UCHAR quartet[4] = {};
        bool padding[4] = {};
        SIZE_T quartetLength = 0;
        bool completed = false;

        for (SIZE_T index = bodyStart; index < end; ++index) {
            const UCHAR input = pem[index];
            if (input == ' ' || input == '\r' || input == '\n' || input == '\t') {
                continue;
            }

            if (completed) {
                return false;
            }

            UCHAR value = 0;
            bool isPadding = false;
            if (input == '=') {
                isPadding = true;
            }
            else if (!DecodeBase64Char(input, &value)) {
                return false;
            }

            quartet[quartetLength] = value;
            padding[quartetLength] = isPadding;
            ++quartetLength;

            if (quartetLength == 4) {
                if (padding[0] || padding[1] || (padding[2] && !padding[3])) {
                    return false;
                }

                const SIZE_T bytesToWrite = padding[2] ? 1 : (padding[3] ? 2 : 3);
                if (*derLength > derCapacity || bytesToWrite > derCapacity - *derLength) {
                    return false;
                }

                const ULONG decoded =
                    (static_cast<ULONG>(quartet[0]) << 18) |
                    (static_cast<ULONG>(quartet[1]) << 12) |
                    (static_cast<ULONG>(quartet[2]) << 6) |
                    quartet[3];

                der[(*derLength)++] = static_cast<UCHAR>((decoded >> 16) & 0xff);
                if (bytesToWrite > 1) {
                    der[(*derLength)++] = static_cast<UCHAR>((decoded >> 8) & 0xff);
                }
                if (bytesToWrite > 2) {
                    der[(*derLength)++] = static_cast<UCHAR>(decoded & 0xff);
                }

                completed = padding[2] || padding[3];
                memset(quartet, 0, sizeof(quartet));
                memset(padding, 0, sizeof(padding));
                quartetLength = 0;
            }
        }

        return quartetLength == 0 && *derLength != 0;
    }

    bool LoadLocalhostCertificate(
        UCHAR* pem,
        SIZE_T pemCapacity,
        SIZE_T* pemLength,
        UCHAR* der,
        SIZE_T derCapacity,
        SIZE_T* derLength,
        UCHAR* certificateList,
        SIZE_T certificateListCapacity,
        SIZE_T* certificateListLength)
    {
        if (certificateListLength != nullptr) {
            *certificateListLength = 0;
        }

        if (!ReadFileBytes(LocalhostCertificatePath, pem, pemCapacity, pemLength) ||
            !DecodePemCertificate(pem, *pemLength, der, derCapacity, derLength) ||
            *derLength > 0x00ffffff ||
            certificateList == nullptr ||
            certificateListLength == nullptr ||
            certificateListCapacity < *derLength + 3) {
            return false;
        }

        certificateList[0] = static_cast<UCHAR>((*derLength >> 16) & 0xff);
        certificateList[1] = static_cast<UCHAR>((*derLength >> 8) & 0xff);
        certificateList[2] = static_cast<UCHAR>(*derLength & 0xff);
        memcpy(certificateList + 3, der, *derLength);
        *certificateListLength = *derLength + 3;
        return true;
    }

    void TestPlainRecordRoundTrip()
    {
        const UCHAR body[] = { 1, 2, 3, 4 };
        UCHAR encoded[32] = {};
        SIZE_T written = 0;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::Handshake;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        NTSTATUS status = TlsRecordLayer::EncodePlaintext(
            plain,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "plaintext record encodes");
        Expect(written == 9, "plaintext record length includes header");
        Expect(encoded[0] == 22 && encoded[3] == 0 && encoded[4] == sizeof(body), "plaintext header is written");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);

        Expect(status == STATUS_SUCCESS, "plaintext record parses");
        Expect(parsed.ContentType == TlsContentType::Handshake, "content type parses");
        Expect(parsed.FragmentLength == sizeof(body), "fragment length parses");
        Expect(memcmp(parsed.Fragment, body, sizeof(body)) == 0, "fragment bytes parse");
    }

    void TestRecordNeedsMoreData()
    {
        const UCHAR partial[] = { 22, 3, 3, 0 };
        TlsRecordView parsed = {};
        const NTSTATUS status = TlsRecordLayer::Parse(partial, sizeof(partial), parsed);
        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "short record asks for more data");
    }

    void TestRecordRejectsInvalidHeader()
    {
        const UCHAR invalidType[] = { 99, 3, 3, 0, 0 };
        TlsRecordView parsed = {};
        NTSTATUS status = TlsRecordLayer::Parse(invalidType, sizeof(invalidType), parsed);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "record parser rejects invalid content type");

        const UCHAR invalidVersion[] = { 22, 3, 4, 0, 0 };
        status = TlsRecordLayer::Parse(invalidVersion, sizeof(invalidVersion), parsed);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "record parser rejects unsupported protocol version");
    }

    void TestPlainRecordSizeProbe()
    {
        const UCHAR body[] = { 1, 2, 3 };
        SIZE_T written = 0;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        const NTSTATUS status = TlsRecordLayer::EncodePlaintext(
            plain,
            nullptr,
            0,
            &written);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "plaintext record supports size probe");
        Expect(written == TlsRecordHeaderLength + sizeof(body), "plaintext size probe reports exact bytes");
    }

    void TestSequenceNumberEncoding()
    {
        UCHAR encoded[TlsAesGcmExplicitNonceLength] = {};
        TlsRecordLayer::WriteSequenceNumber(0x0102030405060708ULL, encoded);

        const UCHAR expected[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        Expect(memcmp(encoded, expected, sizeof(expected)) == 0, "sequence number is encoded big-endian");
    }

    void TestAesGcmRecordProtection()
    {
        const UCHAR body[] = { 'h', 'e', 'l', 'l', 'o' };
        UCHAR encoded[128] = {};
        UCHAR decoded[32] = {};
        SIZE_T written = 0;

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(index + 1);
            readState.Key[index] = static_cast<UCHAR>(index + 1);
        }

        writeState.KeyLength = 16;
        readState.KeyLength = 16;
        writeState.FixedIvLength = 4;
        readState.FixedIvLength = 4;
        writeState.FixedIv[0] = 0x11;
        readState.FixedIv[0] = 0x11;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "AES-GCM record protects");
        Expect(writeState.SequenceNumber == 1, "write sequence increments");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "protected record parses");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_SUCCESS, "AES-GCM record unprotects");
        Expect(readState.SequenceNumber == 1, "read sequence increments");
        Expect(output.FragmentLength == sizeof(body), "unprotected length matches");
        Expect(memcmp(output.Fragment, body, sizeof(body)) == 0, "unprotected bytes match");
    }

    void TestAesGcmRejectsSmallPlaintextBuffer()
    {
        const UCHAR body[] = { 'd', 'a', 't', 'a' };
        UCHAR encoded[128] = {};
        UCHAR decoded[2] = {};
        SIZE_T written = 0;

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0x20 + index);
            readState.Key[index] = static_cast<UCHAR>(0x20 + index);
        }

        writeState.KeyLength = 16;
        readState.KeyLength = 16;
        writeState.FixedIvLength = TlsAesGcmFixedIvLength;
        readState.FixedIvLength = TlsAesGcmFixedIvLength;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);
        Expect(status == STATUS_SUCCESS, "AES-GCM record protects for buffer-size test");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "protected record parses for buffer-size test");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "AES-GCM unprotect rejects undersized plaintext buffer");
        Expect(readState.SequenceNumber == 0, "failed AES-GCM unprotect does not advance sequence");
    }

    void TestAesGcmRejectsTruncatedCiphertext()
    {
        const UCHAR fragment[TlsAesGcmExplicitNonceLength + TlsAesGcmTagLength - 1] = {};
        UCHAR decoded[16] = {};

        TlsRecordView encrypted = {};
        encrypted.ContentType = TlsContentType::ApplicationData;
        encrypted.Version = { 3, 3 };
        encrypted.Fragment = fragment;
        encrypted.FragmentLength = sizeof(fragment);

        TlsAeadCipherState readState = {};
        readState.Key[0] = 1;
        readState.KeyLength = 16;
        readState.FixedIvLength = TlsAesGcmFixedIvLength;

        TlsMutablePlaintextRecord output = {};
        const NTSTATUS status = TlsRecordLayer::UnprotectAesGcm(
            encrypted,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_INVALID_PARAMETER, "AES-GCM unprotect rejects fragments smaller than nonce plus tag");
    }

    void TestClientHello()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS context initializes");

        UCHAR message[512] = {};
        SIZE_T written = 0;

        TlsClientHelloOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);

        status = TlsHandshake12::EncodeClientHello(
            context,
            options,
            message,
            sizeof(message),
            &written);

        Expect(status == STATUS_SUCCESS, "ClientHello encodes");
        Expect(context.State() == TlsHandshakeState::ClientHelloSent, "ClientHello updates state");
        Expect(written > 40, "ClientHello has body");

        TlsHandshakeMessageView parsed = {};
        status = TlsHandshake12::ParseMessage(message, written, parsed);

        Expect(status == STATUS_SUCCESS, "ClientHello parses as handshake message");
        Expect(parsed.Type == TlsHandshakeType::ClientHello, "ClientHello type parses");
        Expect(parsed.BodyLength == written - 4, "ClientHello length parses");
    }

    bool ClientHelloHasExtension(const UCHAR* body, SIZE_T bodyLength, USHORT extensionType)
    {
        if (body == nullptr || bodyLength < 42) {
            return false;
        }

        SIZE_T offset = 34;
        if (offset >= bodyLength) {
            return false;
        }

        const SIZE_T sessionIdLength = body[offset++];
        if (sessionIdLength > bodyLength - offset) {
            return false;
        }

        offset += sessionIdLength;
        if (bodyLength - offset < 2) {
            return false;
        }

        const SIZE_T cipherSuiteBytes =
            (static_cast<SIZE_T>(body[offset]) << 8) | body[offset + 1];
        offset += 2;
        if (cipherSuiteBytes > bodyLength - offset) {
            return false;
        }

        offset += cipherSuiteBytes;
        if (offset >= bodyLength) {
            return false;
        }

        const SIZE_T compressionMethodBytes = body[offset++];
        if (compressionMethodBytes > bodyLength - offset || bodyLength - offset < compressionMethodBytes + 2) {
            return false;
        }

        offset += compressionMethodBytes;
        const SIZE_T extensionBytes =
            (static_cast<SIZE_T>(body[offset]) << 8) | body[offset + 1];
        offset += 2;
        if (extensionBytes != bodyLength - offset) {
            return false;
        }

        const SIZE_T extensionEnd = offset + extensionBytes;
        while (extensionEnd - offset >= 4) {
            const USHORT currentType = static_cast<USHORT>(
                (static_cast<USHORT>(body[offset]) << 8) | body[offset + 1]);
            const SIZE_T currentLength =
                (static_cast<SIZE_T>(body[offset + 2]) << 8) | body[offset + 3];
            offset += 4;
            if (currentLength > extensionEnd - offset) {
                return false;
            }

            if (currentType == extensionType) {
                return true;
            }

            offset += currentLength;
        }

        return false;
    }

    void TestClientHelloAdvertisesSessionTicket()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS context initializes for session ticket extension");

        UCHAR message[512] = {};
        SIZE_T written = 0;

        TlsClientHelloOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);

        status = TlsHandshake12::EncodeClientHello(
            context,
            options,
            message,
            sizeof(message),
            &written);

        Expect(status == STATUS_SUCCESS, "ClientHello with session ticket extension encodes");

        TlsHandshakeMessageView parsed = {};
        status = TlsHandshake12::ParseMessage(message, written, parsed);
        Expect(status == STATUS_SUCCESS, "ClientHello with session ticket extension parses");
        Expect(ClientHelloHasExtension(parsed.Body, parsed.BodyLength, 35), "ClientHello advertises session_ticket");
    }

    void TestParseNewSessionTicketMessage()
    {
        const UCHAR message[] = {
            4, 0, 0, 6,
            0, 0, 0, 0, 0, 0
        };

        TlsHandshakeMessageView parsed = {};
        const NTSTATUS status = TlsHandshake12::ParseMessage(message, sizeof(message), parsed);

        Expect(status == STATUS_SUCCESS, "NewSessionTicket handshake parses");
        Expect(parsed.Type == TlsHandshakeType::NewSessionTicket, "NewSessionTicket type parses");
        Expect(parsed.BodyLength == 6, "NewSessionTicket body length parses");
    }

    void TestParseServerHello()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "context initializes for ServerHello");

        UCHAR body[96] = {};
        SIZE_T offset = 0;
        body[offset++] = 3;
        body[offset++] = 3;
        for (SIZE_T index = 0; index < 32; ++index) {
            body[offset++] = static_cast<UCHAR>(0x40 + index);
        }
        body[offset++] = 0;
        body[offset++] = 0xC0;
        body[offset++] = 0x2F;
        body[offset++] = 0;
        body[offset++] = 0;
        body[offset++] = 0;

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = body;
        message.BodyLength = offset;

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context, message, serverHello);

        Expect(status == STATUS_SUCCESS, "ServerHello parses");
        Expect(context.State() == TlsHandshakeState::ServerHelloReceived, "ServerHello updates state");
        Expect(context.CipherSuite() == TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256, "cipher suite is selected");
        Expect(serverHello.RandomLength == 32, "server random is exposed");
    }

    void TestParseServerKeyExchange()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "context initializes for ServerKeyExchange");

        UCHAR point[65] = {};
        point[0] = 4;
        for (SIZE_T index = 1; index < sizeof(point); ++index) {
            point[index] = static_cast<UCHAR>(index);
        }

        UCHAR body[160] = {};
        SIZE_T offset = 0;
        body[offset++] = 3;
        body[offset++] = 0;
        body[offset++] = static_cast<UCHAR>(TlsNamedGroup::Secp256r1);
        body[offset++] = sizeof(point);
        memcpy(body + offset, point, sizeof(point));
        offset += sizeof(point);
        body[offset++] = 0x04;
        body[offset++] = 0x01;
        body[offset++] = 0;
        body[offset++] = 4;
        body[offset++] = 1;
        body[offset++] = 2;
        body[offset++] = 3;
        body[offset++] = 4;

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::ServerKeyExchange;
        message.Body = body;
        message.BodyLength = offset;

        TlsServerKeyExchangeView keyExchange = {};
        status = TlsHandshake12::ParseServerKeyExchange(context, message, keyExchange);

        Expect(status == STATUS_SUCCESS, "ServerKeyExchange parses");
        Expect(context.State() == TlsHandshakeState::ServerKeyExchangeReceived, "ServerKeyExchange updates state");
        Expect(keyExchange.NamedGroup == TlsNamedGroup::Secp256r1, "named group parses");
        Expect(keyExchange.SignatureScheme == TlsSignatureScheme::RsaPkcs1Sha256, "signature scheme parses");
        Expect(keyExchange.EcPointLength == sizeof(point), "EC point parses");
        Expect(keyExchange.SignatureLength == 4, "signature parses");
    }

    void TestParseCertificateListState()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "context initializes for Certificate");

        const UCHAR cert[] = { 0x30, 0x03, 1, 2, 3 };
        UCHAR body[16] = {};
        SIZE_T offset = 0;
        body[offset++] = 0;
        body[offset++] = 0;
        body[offset++] = 8;
        body[offset++] = 0;
        body[offset++] = 0;
        body[offset++] = sizeof(cert);
        memcpy(body + offset, cert, sizeof(cert));
        offset += sizeof(cert);

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::Certificate;
        message.Body = body;
        message.BodyLength = offset;

        TlsCertificateListView certificates = {};
        status = TlsHandshake12::ParseCertificateList(context, message, certificates);

        Expect(status == STATUS_SUCCESS, "Certificate list parses");
        Expect(certificates.CertificateCount == 1, "Certificate count parses");
        Expect(context.State() == TlsHandshakeState::ServerCertificateReceived, "Certificate list updates state");
    }

    void TestCertificateStoreTrustAndPin()
    {
        UCHAR spki[CertificateSha256ThumbprintLength] = {};
        for (SIZE_T index = 0; index < sizeof(spki); ++index) {
            spki[index] = static_cast<UCHAR>(0x40 + index);
        }

        const UCHAR subject[] = { 0x30, 0x03, 1, 2, 3 };
        CertificateTrustAnchor anchor = {};
        anchor.SubjectName = subject;
        anchor.SubjectNameLength = sizeof(subject);
        memcpy(anchor.SubjectPublicKeySha256, spki, sizeof(spki));
        anchor.MatchSubjectPublicKey = true;

        CertificatePin pin = {};
        pin.HostName = "example.com";
        pin.HostNameLength = strlen(pin.HostName);
        memcpy(pin.LeafSubjectPublicKeySha256, spki, sizeof(spki));

        CertificateStoreOptions options = {};
        options.TrustAnchors = &anchor;
        options.TrustAnchorCount = 1;
        options.Pins = &pin;
        options.PinCount = 1;

        CertificateStore store;
        NTSTATUS status = store.Initialize(options);
        Expect(status == STATUS_SUCCESS, "certificate store initializes");
        Expect(store.IsTrustedAnchor(subject, sizeof(subject), spki, sizeof(spki)), "trust anchor matches subject and SPKI");
        Expect(store.MatchesPin("EXAMPLE.com", strlen("EXAMPLE.com"), spki, sizeof(spki)), "pin host match is case-insensitive");

        UCHAR otherSpki[CertificateSha256ThumbprintLength] = {};
        Expect(!store.MatchesPin("example.com", strlen("example.com"), otherSpki, sizeof(otherSpki)), "mismatched pin is rejected");
        Expect(store.MatchesPin("other.example", strlen("other.example"), otherSpki, sizeof(otherSpki)), "host without configured pin is allowed by pin policy");
    }

    void TestCertificateValidationCanSkipVerification()
    {
        UCHAR pem[TestMaxPemCertificateLength] = {};
        UCHAR der[TestMaxDerCertificateLength] = {};
        UCHAR certificateList[TestMaxCertificateListLength] = {};
        SIZE_T pemLength = 0;
        SIZE_T derLength = 0;
        SIZE_T certificateListLength = 0;

        const bool loaded = LoadLocalhostCertificate(
            pem,
            sizeof(pem),
            &pemLength,
            der,
            sizeof(der),
            &derLength,
            certificateList,
            sizeof(certificateList),
            &certificateListLength);
        Expect(loaded, "localhost certificate fixture loads for skipped verification");
        if (!loaded) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions options = {};
        options.VerifyCertificate = false;

        CertificateValidationResult result = {};
        const NTSTATUS status = CertificateValidator::ValidateChain(chain, options, &result);

        Expect(status == STATUS_SUCCESS, "certificate validation skip succeeds without trust store");
        Expect(result.Leaf.DerLength == derLength, "skipped verification leaf length matches DER");
        Expect(result.Leaf.Der != nullptr && memcmp(result.Leaf.Der, der, derLength) == 0, "skipped verification still parses the leaf certificate");
    }

    void TestCertificateValidationRequiresTrustMaterial()
    {
        UCHAR pem[TestMaxPemCertificateLength] = {};
        UCHAR der[TestMaxDerCertificateLength] = {};
        UCHAR certificateList[TestMaxCertificateListLength] = {};
        SIZE_T pemLength = 0;
        SIZE_T derLength = 0;
        SIZE_T certificateListLength = 0;

        const bool loaded = LoadLocalhostCertificate(
            pem,
            sizeof(pem),
            &pemLength,
            der,
            sizeof(der),
            &derLength,
            certificateList,
            sizeof(certificateList),
            &certificateListLength);
        Expect(loaded, "localhost certificate fixture loads for missing trust test");
        if (!loaded) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions options = {};
        options.HostName = "localhost";
        options.HostNameLength = strlen(options.HostName);

        const NTSTATUS status = CertificateValidator::ValidateChain(chain, options);
        Expect(status == STATUS_TRUST_FAILURE, "verified validation fails without external trust material");
    }

    void TestCertificateValidationAcceptsExternalPemBundle()
    {
        UCHAR pem[TestMaxPemCertificateLength] = {};
        UCHAR der[TestMaxDerCertificateLength] = {};
        UCHAR certificateList[TestMaxCertificateListLength] = {};
        SIZE_T pemLength = 0;
        SIZE_T derLength = 0;
        SIZE_T certificateListLength = 0;

        const bool loaded = LoadLocalhostCertificate(
            pem,
            sizeof(pem),
            &pemLength,
            der,
            sizeof(der),
            &derLength,
            certificateList,
            sizeof(certificateList),
            &certificateListLength);
        Expect(loaded, "localhost certificate fixture loads for external bundle test");
        if (!loaded) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = pem;
        bundle.DataLength = pemLength;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;

        CertificateStore store;
        NTSTATUS status = store.Initialize(storeOptions);
        Expect(status == STATUS_SUCCESS, "certificate store accepts external PEM bundle");
        Expect(store.AuthorityBundleCount() == 1, "certificate store exposes external bundle count");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions options = {};
        options.HostName = "localhost";
        options.HostNameLength = strlen(options.HostName);
        options.Store = &store;

        CertificateValidationResult result = {};
        status = CertificateValidator::ValidateChain(chain, options, &result);

        Expect(status == STATUS_SUCCESS, "verified validation trusts external PEM bundle");
        Expect(result.Leaf.DerLength == derLength, "external bundle validation leaf length matches DER");
        Expect(result.Leaf.Der != nullptr && memcmp(result.Leaf.Der, der, derLength) == 0, "external bundle validation returns the leaf certificate");
    }

    void TestEncodeClientKeyExchange()
    {
        const UCHAR publicKey[] = { 4, 1, 2, 3, 4 };
        UCHAR message[32] = {};
        SIZE_T written = 0;

        const NTSTATUS status = TlsHandshake12::EncodeClientKeyExchange(
            publicKey,
            sizeof(publicKey),
            message,
            sizeof(message),
            &written);

        Expect(status == STATUS_SUCCESS, "ClientKeyExchange encodes");
        Expect(written == 4 + 1 + sizeof(publicKey), "ClientKeyExchange length matches");
        Expect(message[0] == static_cast<UCHAR>(TlsHandshakeType::ClientKeyExchange), "ClientKeyExchange type is written");
        Expect(message[4] == sizeof(publicKey), "ClientKeyExchange public key length is written");
    }

    void TestFinishedVerifyData()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS context initializes for Finished");

        UCHAR serverRandom[32] = {};
        for (SIZE_T index = 0; index < sizeof(serverRandom); ++index) {
            serverRandom[index] = static_cast<UCHAR>(0x80 + index);
        }

        status = context.SetServerRandom(serverRandom);
        Expect(status == STATUS_SUCCESS, "server random sets");

        const UCHAR premaster[] = {
            0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15
        };

        status = context.DeriveMasterSecret(premaster, sizeof(premaster));
        Expect(status == STATUS_SUCCESS, "master secret derives");

        UCHAR transcriptHash[32] = {};
        for (SIZE_T index = 0; index < sizeof(transcriptHash); ++index) {
            transcriptHash[index] = static_cast<UCHAR>(index);
        }

        UCHAR finished[64] = {};
        SIZE_T written = 0;
        status = TlsHandshake12::EncodeFinished(
            context,
            true,
            transcriptHash,
            sizeof(transcriptHash),
            finished,
            sizeof(finished),
            &written);

        Expect(status == STATUS_SUCCESS, "Finished encodes");
        Expect(written == 4 + TlsVerifyDataLength, "Finished length matches");

        status = TlsHandshake12::VerifyFinished(
            context,
            true,
            transcriptHash,
            sizeof(transcriptHash),
            finished + 4,
            TlsVerifyDataLength);

        Expect(status == STATUS_SUCCESS, "Finished verify data validates");
    }

    void TestTranscriptHash()
    {
        TlsTranscriptHash transcript;
        UCHAR digest[48] = {};
        SIZE_T written = 0;

        NTSTATUS status = transcript.Initialize(HashAlgorithm::Sha256);
        Expect(status == STATUS_SUCCESS, "transcript initializes");

        const UCHAR first[] = { 1, 2, 3 };
        const UCHAR second[] = { 4, 5 };

        status = transcript.Update(first, sizeof(first));
        Expect(status == STATUS_SUCCESS, "transcript updates first message");

        status = transcript.Update(second, sizeof(second));
        Expect(status == STATUS_SUCCESS, "transcript updates second message");

        status = transcript.Finish(digest, sizeof(digest), &written);
        Expect(status == STATUS_SUCCESS, "transcript finishes");
        Expect(written == 32, "SHA-256 transcript length is 32");
    }
}

int main()
{
    TestPlainRecordRoundTrip();
    TestRecordNeedsMoreData();
    TestRecordRejectsInvalidHeader();
    TestPlainRecordSizeProbe();
    TestSequenceNumberEncoding();
    TestAesGcmRecordProtection();
    TestAesGcmRejectsSmallPlaintextBuffer();
    TestAesGcmRejectsTruncatedCiphertext();
    TestClientHello();
    TestClientHelloAdvertisesSessionTicket();
    TestParseNewSessionTicketMessage();
    TestParseServerHello();
    TestParseServerKeyExchange();
    TestParseCertificateListState();
    TestCertificateStoreTrustAndPin();
    TestCertificateValidationCanSkipVerification();
    TestCertificateValidationRequiresTrustMaterial();
    TestCertificateValidationAcceptsExternalPemBundle();
    TestEncodeClientKeyExchange();
    TestFinishedVerifyData();
    TestTranscriptHash();

    if (g_failed) {
        return 1;
    }

    printf("PASS: TLS record tests\n");
    return 0;
}
