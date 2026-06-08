#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/tls/TlsContext.h>
#include <KernelHttp/tls/CertificateStore.h>
#include <KernelHttp/tls/CertificateValidator.h>
#include <KernelHttp/tls/TlsHandshake12.h>
#include <KernelHttp/tls/TlsHandshake13.h>
#include <KernelHttp/tls/TlsConnection.h>
#include <KernelHttp/tls/TlsRecord.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::crypto::HashAlgorithm;
using KernelHttp::HeapArray;
using KernelHttp::tls::CertificateAuthorityBundle;
using KernelHttp::tls::CertificateChainView;
using KernelHttp::tls::CertificatePin;
using KernelHttp::tls::CertificateStore;
using KernelHttp::tls::CertificateStoreOptions;
using KernelHttp::tls::CertificateTrustAnchor;
using KernelHttp::tls::CertificateValidationOptions;
using KernelHttp::tls::CertificateValidationResult;
using KernelHttp::tls::CertificateValidator;
using KernelHttp::tls::ParsedCertificate;
using KernelHttp::tls::TlsAeadCipherState;
using KernelHttp::tls::CertificateSha256ThumbprintLength;
using KernelHttp::tls::TlsCipherSuite;
using KernelHttp::tls::TlsCertificateListView;
using KernelHttp::tls::TlsAesGcmExplicitNonceLength;
using KernelHttp::tls::TlsAesGcmFixedIvLength;
using KernelHttp::tls::TlsAesGcmTls13IvLength;
using KernelHttp::tls::TlsAesGcmTagLength;
using KernelHttp::tls::TlsApplicationBufferLength;
using KernelHttp::tls::Tls12NewSessionTicketView;
using KernelHttp::tls::TlsClientHelloOptions;
using KernelHttp::tls::TlsRecordHeaderLength;
using KernelHttp::tls::TlsContentType;
using KernelHttp::tls::TlsContext;
using KernelHttp::tls::TlsHandshake12;
using KernelHttp::tls::TlsHandshake13;
using KernelHttp::tls::TlsHandshakeMessageView;
using KernelHttp::tls::TlsHandshakeState;
using KernelHttp::tls::TlsHandshakeType;
using KernelHttp::tls::TlsMaxPlaintextLength;
using KernelHttp::tls::Tls13ClientHelloOptions;
using KernelHttp::tls::Tls13CertificateVerifyInputMaxLength;
using KernelHttp::tls::Tls13EncryptedExtensionsView;
using KernelHttp::tls::Tls13KeyShareEntry;
using KernelHttp::tls::Tls13MaxTicketIdentityLength;
using KernelHttp::tls::Tls13NewSessionTicketView;
using KernelHttp::tls::Tls13ServerHelloView;
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

    void TestAesGcmRejectsSequenceNumberExhaustion()
    {
        const UCHAR body[] = { 's', 'e', 'q' };
        UCHAR encoded[128] = {};
        UCHAR decoded[32] = {};
        SIZE_T written = 0;

        TlsAeadCipherState exhaustedWrite = {};
        TlsAeadCipherState normalWrite = {};
        TlsAeadCipherState exhaustedRead = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            exhaustedWrite.Key[index] = static_cast<UCHAR>(0x21 + index);
            normalWrite.Key[index] = static_cast<UCHAR>(0x21 + index);
            exhaustedRead.Key[index] = static_cast<UCHAR>(0x21 + index);
        }
        exhaustedWrite.KeyLength = 16;
        normalWrite.KeyLength = 16;
        exhaustedRead.KeyLength = 16;
        exhaustedWrite.FixedIvLength = TlsAesGcmFixedIvLength;
        normalWrite.FixedIvLength = TlsAesGcmFixedIvLength;
        exhaustedRead.FixedIvLength = TlsAesGcmFixedIvLength;
        exhaustedWrite.SequenceNumber = ~0ull;
        exhaustedRead.SequenceNumber = ~0ull;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm(
            plain,
            exhaustedWrite,
            encoded,
            sizeof(encoded),
            &written);
        Expect(status == STATUS_INVALID_DEVICE_STATE, "AES-GCM protect rejects exhausted sequence number");
        Expect(exhaustedWrite.SequenceNumber == ~0ull, "failed AES-GCM protect keeps exhausted sequence number");
        Expect(written == 0, "failed AES-GCM protect reports no bytes written");

        status = TlsRecordLayer::ProtectAesGcm(
            plain,
            normalWrite,
            encoded,
            sizeof(encoded),
            &written);
        Expect(status == STATUS_SUCCESS, "AES-GCM fixture protects before exhausted read test");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "AES-GCM fixture parses before exhausted read test");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm(
            parsed,
            exhaustedRead,
            decoded,
            sizeof(decoded),
            output);
        Expect(status == STATUS_INVALID_DEVICE_STATE, "AES-GCM unprotect rejects exhausted sequence number");
        Expect(exhaustedRead.SequenceNumber == ~0ull, "failed AES-GCM unprotect keeps exhausted sequence number");
    }

    void TestHkdfExtractExpand()
    {
        const UCHAR salt[] = { 1, 2, 3, 4 };
        const UCHAR ikm[] = { 5, 6, 7, 8, 9 };
        UCHAR prk[48] = {};
        SIZE_T prkLength = 0;

        NTSTATUS status = KernelHttp::crypto::CngProvider::HkdfExtract(
            HashAlgorithm::Sha256,
            salt,
            sizeof(salt),
            ikm,
            sizeof(ikm),
            prk,
            sizeof(prk),
            &prkLength);

        Expect(status == STATUS_SUCCESS, "HKDF extract succeeds");
        Expect(prkLength == 32, "HKDF extract reports SHA-256 digest length");

        const UCHAR info[] = { 't', 'l', 's', '1', '3' };
        UCHAR okm[42] = {};
        status = KernelHttp::crypto::CngProvider::HkdfExpand(
            HashAlgorithm::Sha256,
            prk,
            prkLength,
            info,
            sizeof(info),
            okm,
            sizeof(okm));

        Expect(status == STATUS_SUCCESS, "HKDF expand succeeds");
        Expect(okm[0] != okm[sizeof(okm) - 1] || okm[0] != 0, "HKDF expand writes output");
    }

    void TestTls13EarlySecretUsesZeroPsk()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for zero PSK early secret");

        status = context.SetCipherSuite(TlsCipherSuite::TlsAes128GcmSha256);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 SHA-256 cipher suite sets for zero PSK");
        status = context.DeriveTls13EarlySecret(nullptr, 0);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 SHA-256 zero PSK early secret derives");

        const UCHAR expectedSha256[] = {
            0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
            0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
            0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
            0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a
        };
        Expect(context.Tls13Secrets().SecretLength == sizeof(expectedSha256), "TLS 1.3 SHA-256 early secret length matches digest");
        Expect(memcmp(context.Tls13Secrets().EarlySecret, expectedSha256, sizeof(expectedSha256)) == 0,
            "TLS 1.3 SHA-256 early secret uses digest-length zero PSK");

        status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context reinitializes for SHA-384 zero PSK");
        status = context.SetCipherSuite(TlsCipherSuite::TlsAes256GcmSha384);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 SHA-384 cipher suite sets for zero PSK");
        status = context.DeriveTls13EarlySecret(nullptr, 0);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 SHA-384 zero PSK early secret derives");

        Expect(context.Tls13Secrets().SecretLength == 48, "TLS 1.3 SHA-384 early secret length matches digest");
    }

    void TestTls13ApplicationMasterSecretUsesZeroIkm()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for application secret test");
        status = context.SetCipherSuite(TlsCipherSuite::TlsAes128GcmSha256);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 application secret cipher suite sets");

        UCHAR sharedSecret[32] = {};
        UCHAR serverHelloHash[32] = {};
        UCHAR serverFinishedHash[32] = {};
        for (SIZE_T index = 0; index < sizeof(sharedSecret); ++index) {
            sharedSecret[index] = static_cast<UCHAR>(0x10 + index);
            serverHelloHash[index] = static_cast<UCHAR>(0x40 + index);
            serverFinishedHash[index] = static_cast<UCHAR>(0x80 + index);
        }

        status = context.DeriveTls13EarlySecret(nullptr, 0);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 early secret derives for application secret test");
        status = context.DeriveTls13HandshakeSecrets(
            sharedSecret,
            sizeof(sharedSecret),
            serverHelloHash,
            sizeof(serverHelloHash));
        Expect(status == STATUS_SUCCESS, "TLS 1.3 handshake secrets derive for application secret test");
        status = context.DeriveTls13ApplicationSecrets(serverFinishedHash, sizeof(serverFinishedHash));
        Expect(status == STATUS_SUCCESS, "TLS 1.3 application secrets derive");

        const UCHAR expectedMasterSecret[] = {
            0xdf, 0xc3, 0x05, 0xa3, 0x33, 0x07, 0x34, 0xea,
            0xef, 0x4b, 0xe9, 0xf2, 0xf8, 0x57, 0x84, 0x6c,
            0x0b, 0x76, 0x5e, 0x4c, 0xfd, 0x42, 0xfd, 0xf2,
            0x43, 0x94, 0xcd, 0xda, 0x92, 0x14, 0xca, 0x84
        };

        Expect(context.Tls13Secrets().SecretLength == sizeof(expectedMasterSecret),
            "TLS 1.3 master secret length matches digest");
        Expect(memcmp(context.Tls13Secrets().MasterSecret, expectedMasterSecret, sizeof(expectedMasterSecret)) == 0,
            "TLS 1.3 master secret uses digest-length zero IKM");
    }

    void TestTls13AesGcmRecordProtection()
    {
        const UCHAR body[] = { 't', 'l', 's', '1', '3' };
        UCHAR encoded[128] = {};
        UCHAR decoded[32] = {};
        SIZE_T written = 0;

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0x30 + index);
            readState.Key[index] = static_cast<UCHAR>(0x30 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            writeState.FixedIv[index] = static_cast<UCHAR>(0x50 + index);
            readState.FixedIv[index] = static_cast<UCHAR>(0x50 + index);
        }
        writeState.KeyLength = 16;
        readState.KeyLength = 16;
        writeState.FixedIvLength = TlsAesGcmTls13IvLength;
        readState.FixedIvLength = TlsAesGcmTls13IvLength;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM record protects");
        Expect(writeState.SequenceNumber == 1, "TLS 1.3 write sequence increments");
        Expect(encoded[0] == static_cast<UCHAR>(TlsContentType::ApplicationData), "TLS 1.3 outer content type is application_data");
        Expect(encoded[1] == 3 && encoded[2] == 3, "TLS 1.3 outer version is legacy 1.2");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 protected record parses");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm13(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM record unprotects");
        Expect(readState.SequenceNumber == 1, "TLS 1.3 read sequence increments");
        Expect(output.ContentType == TlsContentType::ApplicationData, "TLS 1.3 inner content type recovers");
        Expect(output.FragmentLength == sizeof(body), "TLS 1.3 unprotected length matches");
        Expect(memcmp(output.Fragment, body, sizeof(body)) == 0, "TLS 1.3 unprotected bytes match");
    }

    void TestTls13AesGcmAllowsEmptyApplicationData()
    {
        UCHAR encoded[64] = {};
        UCHAR decoded[32] = {};
        SIZE_T written = 0;

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0x40 + index);
            readState.Key[index] = static_cast<UCHAR>(0x40 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            writeState.FixedIv[index] = static_cast<UCHAR>(0x60 + index);
            readState.FixedIv[index] = static_cast<UCHAR>(0x60 + index);
        }
        writeState.KeyLength = 16;
        readState.KeyLength = 16;
        writeState.FixedIvLength = TlsAesGcmTls13IvLength;
        readState.FixedIvLength = TlsAesGcmTls13IvLength;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = nullptr;
        plain.FragmentLength = 0;

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 empty application_data protects");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 empty application_data parses");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm13(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 empty application_data unprotects");
        Expect(output.ContentType == TlsContentType::ApplicationData, "TLS 1.3 empty application_data content type recovers");
        Expect(output.FragmentLength == 0, "TLS 1.3 empty application_data has zero plaintext length");
    }

    void TestTls13AesGcmProtectsMaxPlaintextRecord()
    {
        static UCHAR body[TlsMaxPlaintextLength] = {};
        static UCHAR encoded[TlsRecordHeaderLength + TlsMaxPlaintextLength + 1 + TlsAesGcmTagLength] = {};
        static UCHAR decoded[TlsMaxPlaintextLength + 1] = {};

        for (SIZE_T index = 0; index < sizeof(body); ++index) {
            body[index] = static_cast<UCHAR>(index & 0xff);
        }

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0x70 + index);
            readState.Key[index] = static_cast<UCHAR>(0x70 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            writeState.FixedIv[index] = static_cast<UCHAR>(0x90 + index);
            readState.FixedIv[index] = static_cast<UCHAR>(0x90 + index);
        }
        writeState.KeyLength = 16;
        readState.KeyLength = 16;
        writeState.FixedIvLength = TlsAesGcmTls13IvLength;
        readState.FixedIvLength = TlsAesGcmTls13IvLength;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        SIZE_T written = 0;
        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM max record protects");
        Expect(written == sizeof(encoded), "TLS 1.3 AES-GCM max record writes full encoded length");
        Expect(writeState.SequenceNumber == 1, "TLS 1.3 AES-GCM max record increments write sequence");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM max record parses");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm13(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM max record unprotects");
        Expect(readState.SequenceNumber == 1, "TLS 1.3 AES-GCM max record increments read sequence");
        Expect(output.ContentType == TlsContentType::ApplicationData, "TLS 1.3 AES-GCM max record content type recovers");
        Expect(output.FragmentLength == sizeof(body), "TLS 1.3 AES-GCM max record plaintext length matches");
        Expect(memcmp(output.Fragment, body, sizeof(body)) == 0, "TLS 1.3 AES-GCM max record plaintext bytes match");
        Expect(TlsApplicationBufferLength >= TlsMaxPlaintextLength + 1, "TLS connection receive buffer fits max TLS 1.3 inner plaintext");
    }

    void TestTls13AesGcmProtectsWithHeapScratch()
    {
        HeapArray<UCHAR> scratch(TlsMaxPlaintextLength + 1);
        Expect(scratch.IsValid(), "TLS 1.3 AES-GCM scratch allocates");
        if (!scratch.IsValid()) {
            return;
        }

        UCHAR encoded[128] = {};
        const UCHAR body[] = { 'h', 'e', 'a', 'p' };

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0xd0 + index);
            readState.Key[index] = static_cast<UCHAR>(0xd0 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            writeState.FixedIv[index] = static_cast<UCHAR>(0xe0 + index);
            readState.FixedIv[index] = static_cast<UCHAR>(0xe0 + index);
        }
        writeState.KeyLength = 16;
        readState.KeyLength = 16;
        writeState.FixedIvLength = TlsAesGcmTls13IvLength;
        readState.FixedIvLength = TlsAesGcmTls13IvLength;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        SIZE_T written = 0;
        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13WithScratch(
            plain,
            writeState,
            scratch.Get(),
            scratch.Count(),
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM heap scratch protects");
        Expect(writeState.SequenceNumber == 1, "TLS 1.3 AES-GCM heap scratch increments write sequence");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM heap scratch parses");

        UCHAR decoded[32] = {};
        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm13(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM heap scratch unprotects");
        Expect(output.FragmentLength == sizeof(body), "TLS 1.3 AES-GCM heap scratch plaintext length matches");
        Expect(memcmp(output.Fragment, body, sizeof(body)) == 0, "TLS 1.3 AES-GCM heap scratch plaintext bytes match");
    }

    void TestTls13AesGcmProtectsOverlappingDestination()
    {
        UCHAR encoded[128] = {};
        const UCHAR body[] = { 'o', 'v', 'e', 'r', 'l', 'a', 'p' };
        RtlCopyMemory(encoded, body, sizeof(body));

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0xa0 + index);
            readState.Key[index] = static_cast<UCHAR>(0xa0 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            writeState.FixedIv[index] = static_cast<UCHAR>(0xc0 + index);
            readState.FixedIv[index] = static_cast<UCHAR>(0xc0 + index);
        }
        writeState.KeyLength = 16;
        readState.KeyLength = 16;
        writeState.FixedIvLength = TlsAesGcmTls13IvLength;
        readState.FixedIvLength = TlsAesGcmTls13IvLength;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = encoded;
        plain.FragmentLength = sizeof(body);

        SIZE_T written = 0;
        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM wrapper allocates scratch for overlapping record");
        Expect(writeState.SequenceNumber == 1, "TLS 1.3 AES-GCM wrapper increments write sequence");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM wrapper overlapping record parses");

        UCHAR decoded[32] = {};
        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm13(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM wrapper overlapping record unprotects");
        Expect(output.FragmentLength == sizeof(body), "TLS 1.3 AES-GCM wrapper overlapping plaintext length matches");
        Expect(memcmp(output.Fragment, body, sizeof(body)) == 0, "TLS 1.3 AES-GCM wrapper overlapping plaintext bytes match");
    }

    void TestTls13AesGcmRejectsSequenceNumberExhaustion()
    {
        const UCHAR body[] = { 't', 'l', 's', '1', '3' };
        UCHAR encoded[128] = {};
        UCHAR decoded[32] = {};
        SIZE_T written = 0;

        TlsAeadCipherState exhaustedWrite = {};
        TlsAeadCipherState normalWrite = {};
        TlsAeadCipherState exhaustedRead = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            exhaustedWrite.Key[index] = static_cast<UCHAR>(0xb0 + index);
            normalWrite.Key[index] = static_cast<UCHAR>(0xb0 + index);
            exhaustedRead.Key[index] = static_cast<UCHAR>(0xb0 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            exhaustedWrite.FixedIv[index] = static_cast<UCHAR>(0xd0 + index);
            normalWrite.FixedIv[index] = static_cast<UCHAR>(0xd0 + index);
            exhaustedRead.FixedIv[index] = static_cast<UCHAR>(0xd0 + index);
        }
        exhaustedWrite.KeyLength = 16;
        normalWrite.KeyLength = 16;
        exhaustedRead.KeyLength = 16;
        exhaustedWrite.FixedIvLength = TlsAesGcmTls13IvLength;
        normalWrite.FixedIvLength = TlsAesGcmTls13IvLength;
        exhaustedRead.FixedIvLength = TlsAesGcmTls13IvLength;
        exhaustedWrite.SequenceNumber = ~0ull;
        exhaustedRead.SequenceNumber = ~0ull;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            exhaustedWrite,
            encoded,
            sizeof(encoded),
            &written);
        Expect(status == STATUS_INVALID_DEVICE_STATE, "TLS 1.3 AES-GCM protect rejects exhausted sequence number");
        Expect(exhaustedWrite.SequenceNumber == ~0ull, "failed TLS 1.3 AES-GCM protect keeps exhausted sequence number");
        Expect(written == 0, "failed TLS 1.3 AES-GCM protect reports no bytes written");

        status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            normalWrite,
            encoded,
            sizeof(encoded),
            &written);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM fixture protects before exhausted read test");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM fixture parses before exhausted read test");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm13(
            parsed,
            exhaustedRead,
            decoded,
            sizeof(decoded),
            output);
        Expect(status == STATUS_INVALID_DEVICE_STATE, "TLS 1.3 AES-GCM unprotect rejects exhausted sequence number");
        Expect(exhaustedRead.SequenceNumber == ~0ull, "failed TLS 1.3 AES-GCM unprotect keeps exhausted sequence number");
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

    bool FindClientHelloExtension(
        const UCHAR* body,
        SIZE_T bodyLength,
        USHORT extensionType,
        const UCHAR** extension,
        SIZE_T* extensionLength)
    {
        if (extension != nullptr) {
            *extension = nullptr;
        }
        if (extensionLength != nullptr) {
            *extensionLength = 0;
        }
        if (body == nullptr || extension == nullptr || extensionLength == nullptr || bodyLength < 42) {
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
                *extension = body + offset;
                *extensionLength = currentLength;
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

    void TestTls13ClientHelloExtensions()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes");

        const UCHAR publicKey[] = {
            4,
            1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
            33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63, 64
        };
        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::Secp256r1;
        keyShare.KeyExchange = publicKey;
        keyShare.KeyExchangeLength = sizeof(publicKey);

        const KernelHttp::tls::TlsAlpnProtocol alpn[] = {
            { "h2", 2 },
            { "http/1.1", 8 }
        };

        Tls13ClientHelloOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;
        options.AlpnProtocols = alpn;
        options.AlpnProtocolCount = sizeof(alpn) / sizeof(alpn[0]);

        UCHAR message[1024] = {};
        SIZE_T written = 0;
        status = TlsHandshake13::EncodeClientHello(context, options, message, sizeof(message), &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 ClientHello encodes");
        Expect(context.State() == TlsHandshakeState::ClientHelloSent, "TLS 1.3 ClientHello updates state");

        TlsHandshakeMessageView parsed = {};
        status = TlsHandshake12::ParseMessage(message, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 ClientHello parses as handshake");
        Expect(parsed.Type == TlsHandshakeType::ClientHello, "TLS 1.3 ClientHello type parses");
        Expect(ClientHelloHasExtension(parsed.Body, parsed.BodyLength, 43), "TLS 1.3 ClientHello has supported_versions");
        Expect(ClientHelloHasExtension(parsed.Body, parsed.BodyLength, 51), "TLS 1.3 ClientHello has key_share");
        Expect(ClientHelloHasExtension(parsed.Body, parsed.BodyLength, 45), "TLS 1.3 ClientHello has psk_key_exchange_modes");
        Expect(ClientHelloHasExtension(parsed.Body, parsed.BodyLength, 16), "TLS 1.3 ClientHello has ALPN");
    }

    void TestParseTls13ServerHello()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for ServerHello");

        UCHAR body[160] = {};
        SIZE_T offset = 0;
        body[offset++] = 3;
        body[offset++] = 3;
        for (SIZE_T index = 0; index < 32; ++index) {
            body[offset++] = static_cast<UCHAR>(0x60 + index);
        }
        body[offset++] = 0;
        body[offset++] = 0x13;
        body[offset++] = 0x01;
        body[offset++] = 0;
        const SIZE_T extensionsLengthOffset = offset;
        body[offset++] = 0;
        body[offset++] = 0;
        const SIZE_T extensionsStart = offset;
        body[offset++] = 0;
        body[offset++] = 43;
        body[offset++] = 0;
        body[offset++] = 2;
        body[offset++] = 3;
        body[offset++] = 4;
        body[offset++] = 0;
        body[offset++] = 51;
        body[offset++] = 0;
        body[offset++] = 8;
        body[offset++] = 0;
        body[offset++] = static_cast<UCHAR>(TlsNamedGroup::Secp256r1);
        body[offset++] = 0;
        body[offset++] = 4;
        body[offset++] = 4;
        body[offset++] = 1;
        body[offset++] = 2;
        body[offset++] = 3;
        const SIZE_T extensionsLength = offset - extensionsStart;
        body[extensionsLengthOffset] = static_cast<UCHAR>((extensionsLength >> 8) & 0xff);
        body[extensionsLengthOffset + 1] = static_cast<UCHAR>(extensionsLength & 0xff);

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = body;
        message.BodyLength = offset;

        Tls13ServerHelloView serverHello = {};
        status = TlsHandshake13::ParseServerHello(context, message, serverHello);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 ServerHello parses");
        Expect(context.CipherSuite() == TlsCipherSuite::TlsAes128GcmSha256, "TLS 1.3 cipher suite is selected");
        Expect(serverHello.SelectedVersion.Minor == 4, "TLS 1.3 selected version parses");
        Expect(serverHello.KeyShare.KeyExchangeLength == 4, "TLS 1.3 key share parses");
    }

    void TestParseTls13HelloRetryRequest()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for HRR");

        const UCHAR hrrRandom[] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };

        UCHAR body[128] = {};
        SIZE_T offset = 0;
        body[offset++] = 3;
        body[offset++] = 3;
        memcpy(body + offset, hrrRandom, sizeof(hrrRandom));
        offset += sizeof(hrrRandom);
        body[offset++] = 0;
        body[offset++] = 0x13;
        body[offset++] = 0x01;
        body[offset++] = 0;
        const SIZE_T extensionsLengthOffset = offset;
        body[offset++] = 0;
        body[offset++] = 0;
        const SIZE_T extensionsStart = offset;
        body[offset++] = 0;
        body[offset++] = 43;
        body[offset++] = 0;
        body[offset++] = 2;
        body[offset++] = 3;
        body[offset++] = 4;
        body[offset++] = 0;
        body[offset++] = 51;
        body[offset++] = 0;
        body[offset++] = 2;
        body[offset++] = 0;
        body[offset++] = static_cast<UCHAR>(TlsNamedGroup::Secp384r1);
        const SIZE_T extensionsLength = offset - extensionsStart;
        body[extensionsLengthOffset] = static_cast<UCHAR>((extensionsLength >> 8) & 0xff);
        body[extensionsLengthOffset + 1] = static_cast<UCHAR>(extensionsLength & 0xff);

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = body;
        message.BodyLength = offset;

        Tls13ServerHelloView serverHello = {};
        status = TlsHandshake13::ParseServerHello(context, message, serverHello);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 HelloRetryRequest parses");
        Expect(serverHello.IsHelloRetryRequest, "TLS 1.3 HRR is detected");
        Expect(serverHello.RetryGroup == TlsNamedGroup::Secp384r1, "TLS 1.3 HRR retry group parses");
    }

    void TestParseTls13EncryptedExtensions()
    {
        const UCHAR body[] = {
            0, 13,
            0, 16, 0, 5,
            0, 3, 2, 'h', '2',
            0, 42, 0, 0
        };

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::EncryptedExtensions;
        message.Body = body;
        message.BodyLength = sizeof(body);

        Tls13EncryptedExtensionsView parsed = {};
        const NTSTATUS status = TlsHandshake13::ParseEncryptedExtensions(message, parsed);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 EncryptedExtensions parses");
        Expect(parsed.AlpnLength == 2 && memcmp(parsed.Alpn, "h2", 2) == 0, "TLS 1.3 ALPN parses");
        Expect(parsed.EarlyDataAccepted, "TLS 1.3 early_data extension parses");
    }

    void TestParseTls13NewSessionTicket()
    {
        const UCHAR body[] = {
            0, 0, 0, 10,
            1, 2, 3, 4,
            2, 0xaa, 0xbb,
            0, 3, 'p', 's', 'k',
            0, 8,
            0, 42, 0, 4, 0, 0, 4, 0
        };

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::NewSessionTicket;
        message.Body = body;
        message.BodyLength = sizeof(body);

        Tls13NewSessionTicketView ticket = {};
        const NTSTATUS status = TlsHandshake13::ParseNewSessionTicket(message, ticket);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 NewSessionTicket parses");
        Expect(ticket.LifetimeSeconds == 10, "TLS 1.3 ticket lifetime parses");
        Expect(ticket.NonceLength == 2, "TLS 1.3 ticket nonce parses");
        Expect(ticket.TicketLength == 3, "TLS 1.3 ticket identity parses");
        Expect(ticket.MaxEarlyDataSize == 1024, "TLS 1.3 ticket early data size parses");
    }

    void TestParseTls13NewSessionTicketAllowsLargeIdentity()
    {
        constexpr SIZE_T TicketLength = Tls13MaxTicketIdentityLength + 1;
        constexpr SIZE_T BodyLength = 4 + 4 + 1 + 2 + TicketLength + 2;
        UCHAR body[BodyLength] = {};
        body[3] = 10;
        body[7] = 1;
        body[9] = static_cast<UCHAR>((TicketLength >> 8) & 0xff);
        body[10] = static_cast<UCHAR>(TicketLength & 0xff);
        memset(body + 11, 0x5a, TicketLength);

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::NewSessionTicket;
        message.Body = body;
        message.BodyLength = sizeof(body);

        Tls13NewSessionTicketView ticket = {};
        const NTSTATUS status = TlsHandshake13::ParseNewSessionTicket(message, ticket);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 NewSessionTicket parser accepts large ticket identity");
        Expect(ticket.TicketLength == TicketLength, "TLS 1.3 large ticket identity length parses");
    }

    void TestParseMultipleTls13NewSessionTicketsFromOneRecord()
    {
        const UCHAR tickets[] = {
            4, 0, 0, 14,
            0, 0, 0, 10,
            1, 2, 3, 4,
            0,
            0, 1, 'a',
            0, 0,
            4, 0, 0, 15,
            0, 0, 0, 20,
            5, 6, 7, 8,
            1, 0x33,
            0, 1, 'b',
            0, 0
        };

        SIZE_T offset = 0;
        Tls13NewSessionTicketView first = {};
        NTSTATUS status = TlsHandshake13::ParseNextNewSessionTicket(
            tickets,
            sizeof(tickets),
            &offset,
            first);

        Expect(status == STATUS_SUCCESS, "first TLS 1.3 post-handshake ticket parses");
        Expect(first.LifetimeSeconds == 10, "first TLS 1.3 post-handshake ticket lifetime parses");
        Expect(first.TicketLength == 1 && first.Ticket[0] == 'a', "first TLS 1.3 post-handshake ticket identity parses");
        Expect(offset == 18, "first TLS 1.3 post-handshake ticket advances offset");

        Tls13NewSessionTicketView second = {};
        status = TlsHandshake13::ParseNextNewSessionTicket(
            tickets,
            sizeof(tickets),
            &offset,
            second);

        Expect(status == STATUS_SUCCESS, "second TLS 1.3 post-handshake ticket parses from same record");
        Expect(second.LifetimeSeconds == 20, "second TLS 1.3 post-handshake ticket lifetime parses");
        Expect(second.NonceLength == 1 && second.Nonce[0] == 0x33, "second TLS 1.3 post-handshake ticket nonce parses");
        Expect(second.TicketLength == 1 && second.Ticket[0] == 'b', "second TLS 1.3 post-handshake ticket identity parses");
        Expect(offset == sizeof(tickets), "TLS 1.3 post-handshake ticket parser consumes the whole record");
    }

    void TestParseTls13PostHandshakeRejectsUnexpectedType()
    {
        const UCHAR unexpected[] = {
            static_cast<UCHAR>(TlsHandshakeType::CertificateRequest), 0, 0, 0
        };

        SIZE_T offset = 0;
        Tls13NewSessionTicketView ticket = {};
        const NTSTATUS status = TlsHandshake13::ParseNextNewSessionTicket(
            unexpected,
            sizeof(unexpected),
            &offset,
            ticket);

        Expect(status == STATUS_NOT_SUPPORTED, "TLS 1.3 post-handshake parser rejects non-ticket messages");
        Expect(offset == 0, "TLS 1.3 post-handshake parser does not advance offset on unexpected type");
    }

    void TestTls13FinishedVerifyData()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for Finished");
        status = context.SetCipherSuite(TlsCipherSuite::TlsAes128GcmSha256);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 cipher suite sets");

        const UCHAR sharedSecret[] = {
            1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15, 16
        };
        UCHAR transcriptHash[32] = {};
        for (SIZE_T index = 0; index < sizeof(transcriptHash); ++index) {
            transcriptHash[index] = static_cast<UCHAR>(0x20 + index);
        }

        status = context.DeriveTls13EarlySecret(nullptr, 0);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 early secret derives");
        status = context.DeriveTls13HandshakeSecrets(sharedSecret, sizeof(sharedSecret), transcriptHash, sizeof(transcriptHash));
        Expect(status == STATUS_SUCCESS, "TLS 1.3 handshake secrets derive");

        UCHAR finished[96] = {};
        SIZE_T written = 0;
        status = TlsHandshake13::EncodeFinished(context, true, transcriptHash, sizeof(transcriptHash), finished, sizeof(finished), &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 Finished encodes");
        Expect(written == 4 + context.Tls13Secrets().SecretLength, "TLS 1.3 Finished length matches hash length");

        status = TlsHandshake13::VerifyFinished(
            context,
            true,
            transcriptHash,
            sizeof(transcriptHash),
            finished + 4,
            written - 4);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 Finished verifies");
    }

    void TestTls13CertificateVerifyInputCapacity()
    {
        UCHAR transcriptHash[48] = {};
        for (SIZE_T index = 0; index < sizeof(transcriptHash); ++index) {
            transcriptHash[index] = static_cast<UCHAR>(0x40 + index);
        }

        UCHAR tooSmall[128] = {};
        SIZE_T written = 0;
        NTSTATUS status = TlsHandshake13::BuildCertificateVerifyInput(
            true,
            transcriptHash,
            sizeof(transcriptHash),
            tooSmall,
            sizeof(tooSmall),
            &written);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "TLS 1.3 CertificateVerify rejects old 128-byte scratch");
        Expect(written == Tls13CertificateVerifyInputMaxLength, "TLS 1.3 CertificateVerify reports max input length");

        UCHAR input[Tls13CertificateVerifyInputMaxLength] = {};
        written = 0;
        status = TlsHandshake13::BuildCertificateVerifyInput(
            true,
            transcriptHash,
            sizeof(transcriptHash),
            input,
            sizeof(input),
            &written);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 CertificateVerify fits max scratch");
        Expect(written == sizeof(input), "TLS 1.3 CertificateVerify uses full max scratch for SHA-384");
    }

    void TestTls13PskBinderComputes()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for binder");
        status = context.SetCipherSuite(TlsCipherSuite::TlsAes128GcmSha256);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 cipher suite sets for binder");

        UCHAR resumptionSecret[32] = {};
        UCHAR partialHash[32] = {};
        for (SIZE_T index = 0; index < sizeof(resumptionSecret); ++index) {
            resumptionSecret[index] = static_cast<UCHAR>(0x70 + index);
            partialHash[index] = static_cast<UCHAR>(0x90 + index);
        }

        UCHAR binder[48] = {};
        SIZE_T binderLength = 0;
        status = TlsHandshake13::ComputePskBinder(
            context,
            resumptionSecret,
            sizeof(resumptionSecret),
            partialHash,
            sizeof(partialHash),
            binder,
            sizeof(binder),
            &binderLength);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 PSK binder computes");
        Expect(binderLength == 32, "TLS 1.3 PSK binder length matches hash");
        const UCHAR expected[] = {
            0x38, 0x64, 0x34, 0xae, 0x1f, 0xd2, 0x8f, 0xbb,
            0x55, 0x0f, 0xa8, 0x0f, 0x8e, 0x8c, 0x1e, 0xa7,
            0x64, 0xf1, 0x01, 0xae, 0x81, 0xa4, 0x1a, 0xb2,
            0x7b, 0x2f, 0xbf, 0x71, 0x92, 0xfa, 0x89, 0x2d
        };
        Expect(memcmp(binder, expected, sizeof(expected)) == 0, "TLS 1.3 PSK binder matches HKDF-Expand-Label vector");
    }

    void TestTls13ClientHelloPskBinderTranscriptLength()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for PSK ClientHello");

        const UCHAR publicKey[] = {
            4,
            1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
            33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63, 64
        };
        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::Secp256r1;
        keyShare.KeyExchange = publicKey;
        keyShare.KeyExchangeLength = sizeof(publicKey);

        const UCHAR identityBytes[] = { 't', 'i', 'c', 'k', 'e', 't' };
        UCHAR binder[32] = {};
        for (SIZE_T index = 0; index < sizeof(binder); ++index) {
            binder[index] = static_cast<UCHAR>(0xa0 + index);
        }
        KernelHttp::tls::Tls13PskIdentity identity = {};
        identity.Identity = identityBytes;
        identity.IdentityLength = sizeof(identityBytes);
        identity.ObfuscatedTicketAge = 1234;
        identity.Binder = binder;
        identity.BinderLength = sizeof(binder);

        Tls13ClientHelloOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;
        options.PskIdentities = &identity;
        options.PskIdentityCount = 1;
        options.OfferEarlyData = true;

        UCHAR message[1024] = {};
        SIZE_T written = 0;
        status = TlsHandshake13::EncodeClientHello(context, options, message, sizeof(message), &written);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 PSK ClientHello encodes");

        TlsHandshakeMessageView parsed = {};
        status = TlsHandshake12::ParseMessage(message, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 PSK ClientHello parses");

        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        const bool found = FindClientHelloExtension(parsed.Body, parsed.BodyLength, 41, &extension, &extensionLength);
        Expect(found, "TLS 1.3 PSK ClientHello has pre_shared_key extension");
        if (!found) {
            return;
        }

        const UCHAR* pskExtensionEnd = extension + extensionLength;
        Expect(pskExtensionEnd == parsed.Body + parsed.BodyLength, "TLS 1.3 pre_shared_key is final ClientHello extension");

        SIZE_T binderTranscriptLength = 0;
        status = TlsHandshake13::FindPskBinderTranscriptLength(message, written, &binderTranscriptLength);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 PSK binder transcript boundary is found");

        SIZE_T pskOffset = 0;
        const SIZE_T identitiesLength =
            (static_cast<SIZE_T>(extension[pskOffset]) << 8) | extension[pskOffset + 1];
        pskOffset += 2 + identitiesLength;
        const SIZE_T bindersLengthFieldBodyOffset =
            static_cast<SIZE_T>((extension + pskOffset) - parsed.Body);
        Expect(
            binderTranscriptLength == 4 + bindersLengthFieldBodyOffset,
            "TLS 1.3 PSK binder transcript excludes binders vector length and entries");
    }

    void TestTls13PskBinderRejectsWrongHashLength()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for invalid binder");

        UCHAR resumptionSecret[32] = {};
        UCHAR partialHash[16] = {};
        UCHAR binder[48] = {};
        SIZE_T binderLength = 0;
        status = TlsHandshake13::ComputePskBinder(
            context,
            resumptionSecret,
            sizeof(resumptionSecret),
            partialHash,
            sizeof(partialHash),
            binder,
            sizeof(binder),
            &binderLength);

        Expect(status == STATUS_INVALID_PARAMETER, "TLS 1.3 PSK binder rejects non-digest transcript hash length");
    }

    void TestParseNewSessionTicketMessage()
    {
        const UCHAR message[] = {
            4, 0, 0, 9,
            0, 0, 0, 10,
            0, 3, 't', 'k', 't'
        };

        TlsHandshakeMessageView parsed = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(message, sizeof(message), parsed);

        Expect(status == STATUS_SUCCESS, "NewSessionTicket handshake parses");
        Expect(parsed.Type == TlsHandshakeType::NewSessionTicket, "NewSessionTicket type parses");
        Expect(parsed.BodyLength == 9, "NewSessionTicket body length parses");

        Tls12NewSessionTicketView ticket = {};
        status = TlsHandshake12::ParseNewSessionTicket(parsed, ticket);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 NewSessionTicket payload parses");
        Expect(ticket.LifetimeHintSeconds == 10, "TLS 1.2 NewSessionTicket lifetime parses");
        Expect(ticket.TicketLength == 3, "TLS 1.2 NewSessionTicket ticket length parses");
        Expect(ticket.Ticket != nullptr && memcmp(ticket.Ticket, "tkt", 3) == 0, "TLS 1.2 NewSessionTicket ticket parses");
    }

    void TestParseNewSessionTicketRejectsUnexpectedType()
    {
        const UCHAR message[] = {
            static_cast<UCHAR>(TlsHandshakeType::ServerHelloDone), 0, 0, 0
        };

        TlsHandshakeMessageView parsed = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(message, sizeof(message), parsed);
        Expect(status == STATUS_SUCCESS, "unexpected TLS 1.2 handshake message parses generically");

        Tls12NewSessionTicketView ticket = {};
        status = TlsHandshake12::ParseNewSessionTicket(parsed, ticket);
        Expect(status == STATUS_NOT_SUPPORTED, "TLS 1.2 NewSessionTicket parser rejects non-ticket messages");
    }

    void TestParseNewSessionTicketRejectsBadLength()
    {
        const UCHAR message[] = {
            4, 0, 0, 7,
            0, 0, 0, 10,
            0, 4, 't'
        };

        TlsHandshakeMessageView parsed = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(message, sizeof(message), parsed);
        Expect(status == STATUS_SUCCESS, "malformed TLS 1.2 NewSessionTicket parses generically");

        Tls12NewSessionTicketView ticket = {};
        status = TlsHandshake12::ParseNewSessionTicket(parsed, ticket);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 NewSessionTicket parser rejects mismatched ticket length");
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

    void TestCertificateStoreRejectsEmptyTrustAnchor()
    {
        CertificateTrustAnchor anchor = {};
        CertificateStoreOptions options = {};
        options.TrustAnchors = &anchor;
        options.TrustAnchorCount = 1;

        CertificateStore store;
        const NTSTATUS status = store.Initialize(options);
        Expect(status == STATUS_INVALID_PARAMETER, "certificate store rejects an empty trust anchor");
    }

    void TestCertificateStoreRejectsDnOnlyTrustAnchor()
    {
        const UCHAR subject[] = { 0x30, 0x03, 1, 2, 3 };
        CertificateTrustAnchor anchor = {};
        anchor.SubjectName = subject;
        anchor.SubjectNameLength = sizeof(subject);
        anchor.MatchSubjectPublicKey = false;

        CertificateStoreOptions options = {};
        options.TrustAnchors = &anchor;
        options.TrustAnchorCount = 1;

        CertificateStore store;
        const NTSTATUS status = store.Initialize(options);
        Expect(status == STATUS_INVALID_PARAMETER, "certificate store rejects DN-only trust anchors without SPKI matching");
    }

    void TestCertificateParserRejectsInvalidCalendarDate()
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
        Expect(loaded, "localhost certificate fixture loads for invalid date test");
        if (!loaded) {
            return;
        }

        const char notBefore[] = "260521022604Z";
        SIZE_T timeOffset = 0;
        const bool foundTime = FindAscii(der, derLength, notBefore, sizeof(notBefore) - 1, 0, &timeOffset);
        Expect(foundTime, "localhost certificate notBefore time is found");
        if (!foundTime) {
            return;
        }

        der[timeOffset + 2] = '0';
        der[timeOffset + 3] = '2';
        der[timeOffset + 4] = '3';
        der[timeOffset + 5] = '0';

        ParsedCertificate parsed = {};
        const NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects February 30 validity time");
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
    TestAesGcmRejectsSequenceNumberExhaustion();
    TestHkdfExtractExpand();
    TestTls13EarlySecretUsesZeroPsk();
    TestTls13ApplicationMasterSecretUsesZeroIkm();
    TestTls13AesGcmRecordProtection();
    TestTls13AesGcmAllowsEmptyApplicationData();
    TestTls13AesGcmProtectsMaxPlaintextRecord();
    TestTls13AesGcmProtectsWithHeapScratch();
    TestTls13AesGcmProtectsOverlappingDestination();
    TestTls13AesGcmRejectsSequenceNumberExhaustion();
    TestClientHello();
    TestClientHelloAdvertisesSessionTicket();
    TestTls13ClientHelloExtensions();
    TestParseTls13ServerHello();
    TestParseTls13HelloRetryRequest();
    TestParseTls13EncryptedExtensions();
    TestParseTls13NewSessionTicket();
    TestParseTls13NewSessionTicketAllowsLargeIdentity();
    TestParseMultipleTls13NewSessionTicketsFromOneRecord();
    TestParseTls13PostHandshakeRejectsUnexpectedType();
    TestTls13FinishedVerifyData();
    TestTls13CertificateVerifyInputCapacity();
    TestTls13PskBinderComputes();
    TestTls13ClientHelloPskBinderTranscriptLength();
    TestTls13PskBinderRejectsWrongHashLength();
    TestParseNewSessionTicketMessage();
    TestParseNewSessionTicketRejectsUnexpectedType();
    TestParseNewSessionTicketRejectsBadLength();
    TestParseServerHello();
    TestParseServerKeyExchange();
    TestParseCertificateListState();
    TestCertificateStoreTrustAndPin();
    TestCertificateStoreRejectsEmptyTrustAnchor();
    TestCertificateStoreRejectsDnOnlyTrustAnchor();
    TestCertificateParserRejectsInvalidCalendarDate();
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
