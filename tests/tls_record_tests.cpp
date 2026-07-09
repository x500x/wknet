#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/tls/TlsContext.h>
#include <KernelHttp/tls/CertificateStore.h>
#include <KernelHttp/tls/CertificateValidator.h>
#include <KernelHttp/tls/TlsCapabilities.h>
#include <KernelHttp/tls/TlsHandshake12.h>
#include <KernelHttp/tls/TlsHandshake13.h>
#include <KernelHttp/tls/TlsConnection.h>
#include <KernelHttp/tls/TlsPolicy.h>
#include <KernelHttp/tls/TlsRecord.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

using KernelHttp::crypto::HashAlgorithm;
using KernelHttp::crypto::AeadAlgorithm;
using KernelHttp::HeapArray;
using KernelHttp::tls::CertificateAuthorityBundle;
using KernelHttp::tls::CertificateChainView;
using KernelHttp::tls::CertificatePin;
using KernelHttp::tls::CertificateRevocationEntry;
using KernelHttp::tls::CertificateRevocationMode;
using KernelHttp::tls::CertificateRevocationProviderQuery;
using KernelHttp::tls::CertificateRevocationSource;
using KernelHttp::tls::CertificateRevocationStatus;
using KernelHttp::tls::CertificateStore;
using KernelHttp::tls::CertificateStoreOptions;
using KernelHttp::tls::CertificateTrustAnchor;
using KernelHttp::tls::CertificateValidationOptions;
using KernelHttp::tls::CertificateValidationResult;
using KernelHttp::tls::CertificateValidator;
using KernelHttp::tls::ParsedCertificate;
using KernelHttp::tls::TlsAeadCipherState;
using KernelHttp::tls::TlsAlpnProtocol;
using KernelHttp::tls::TlsAlert;
using KernelHttp::tls::TlsAlertDescription;
using KernelHttp::tls::TlsAlertLevel;
using KernelHttp::tls::CertificateSha256ThumbprintLength;
using KernelHttp::tls::TlsCipherSuite;
using KernelHttp::tls::TlsCertificateListView;
using KernelHttp::tls::TlsAesGcmExplicitNonceLength;
using KernelHttp::tls::TlsAesGcmFixedIvLength;
using KernelHttp::tls::TlsAesGcmTls13IvLength;
using KernelHttp::tls::TlsAesGcmTagLength;
using KernelHttp::tls::TlsApplicationBufferLength;
using KernelHttp::tls::Tls12Session;
using KernelHttp::tls::Tls12SessionCache;
using KernelHttp::tls::Tls12CertificateStatusView;
using KernelHttp::tls::Tls12NewSessionTicketView;
using KernelHttp::tls::TlsClientHelloOptions;
using KernelHttp::tls::TlsRecordHeaderLength;
using KernelHttp::tls::TlsContentType;
using KernelHttp::tls::TlsContext;
using KernelHttp::tls::Tls12KeyExchangeKind;
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
using KernelHttp::tls::Tls13KeyUpdateRequest;
using KernelHttp::tls::Tls13KeyUpdateView;
using KernelHttp::tls::Tls13MaxRecordPaddingLength;
using KernelHttp::tls::Tls13MaxTicketIdentityLength;
using KernelHttp::tls::Tls13NewSessionTicketView;
using KernelHttp::tls::Tls13SessionCache;
using KernelHttp::tls::Tls13SessionTicket;
using KernelHttp::tls::Tls13ServerHelloView;
using KernelHttp::tls::TlsClientConnectionOptions;
using KernelHttp::tls::TlsConnection;
using KernelHttp::tls::TlsHandshakeFailureCategory;
using KernelHttp::tls::TlsMutablePlaintextRecord;
using KernelHttp::tls::TlsNamedGroup;
using KernelHttp::tls::TlsPlaintextRecord;
using KernelHttp::tls::TlsProtocol;
using KernelHttp::tls::TlsProtocolVersion;
using KernelHttp::tls::TlsRecordLayer;
using KernelHttp::tls::TlsRecordView;
using KernelHttp::tls::TlsServerHelloView;
using KernelHttp::tls::TlsServerKeyExchangeView;
using KernelHttp::tls::TlsSignatureScheme;
using KernelHttp::tls::TlsMasterSecretLength;
using KernelHttp::tls::TlsSessionSecrets;
using KernelHttp::tls::TlsPolicy;
using KernelHttp::tls::TlsSecurityProfile;
using KernelHttp::tls::TlsTranscriptHash;
using KernelHttp::tls::TlsVerifyDataLength;

namespace
{
    constexpr SIZE_T TestMaxPemCertificateLength = 4096;
    constexpr SIZE_T TestMaxDerCertificateLength = 2048;
    constexpr SIZE_T TestMaxCertificateListLength = (TestMaxDerCertificateLength + 3) * 4;
    const char LocalhostCertificatePath[] = "tests\\testdata\\localhost.cert.pem";
    const char PkiRootCertificatePath[] = "tests\\testdata\\pki\\root.cert.pem";
    const char PkiIntermediateCertificatePath[] = "tests\\testdata\\pki\\intermediate.cert.pem";
    const char PkiLeafCertificatePath[] = "tests\\testdata\\pki\\leaf.cert.pem";
    const char PkiBadLeafCertificatePath[] = "tests\\testdata\\pki\\bad-leaf.cert.pem";
    const char PkiIdnaLeafCertificatePath[] = "tests\\testdata\\pki\\idna-leaf.cert.pem";
    const char PkiCrossTrustedRootCertificatePath[] = "tests\\testdata\\pki\\cross\\trusted-root.cert.pem";
    const char PkiCrossIntermediateByTrustedCertificatePath[] =
        "tests\\testdata\\pki\\cross\\intermediate-by-trusted.cert.pem";
    const char PkiCrossIntermediateByUntrustedCertificatePath[] =
        "tests\\testdata\\pki\\cross\\intermediate-by-untrusted.cert.pem";
    const char PkiCrossLeafCertificatePath[] = "tests\\testdata\\pki\\cross\\leaf.cert.pem";
    const char WsPostmanEchoServerKeyExchangePath[] =
        "tests\\testdata\\tls\\ws-postman-echo-server-key-exchange.bin";
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

    bool FindBytes(
        const UCHAR* data,
        SIZE_T dataLength,
        const UCHAR* pattern,
        SIZE_T patternLength,
        SIZE_T start,
        SIZE_T* foundAt)
    {
        if (foundAt != nullptr) {
            *foundAt = 0;
        }

        if (data == nullptr ||
            pattern == nullptr ||
            foundAt == nullptr ||
            patternLength == 0 ||
            start > dataLength ||
            patternLength > dataLength - start) {
            return false;
        }

        for (SIZE_T index = start; index <= dataLength - patternLength; ++index) {
            if (memcmp(data + index, pattern, patternLength) == 0) {
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

    bool LoadPemCertificate(
        const char* path,
        UCHAR* pem,
        SIZE_T pemCapacity,
        SIZE_T* pemLength,
        UCHAR* der,
        SIZE_T derCapacity,
        SIZE_T* derLength)
    {
        return ReadFileBytes(path, pem, pemCapacity, pemLength) &&
            DecodePemCertificate(pem, *pemLength, der, derCapacity, derLength);
    }

    bool AppendCertificateToList(
        const UCHAR* der,
        SIZE_T derLength,
        UCHAR* certificateList,
        SIZE_T certificateListCapacity,
        SIZE_T* certificateListLength)
    {
        if (der == nullptr ||
            derLength == 0 ||
            derLength > 0x00ffffff ||
            certificateList == nullptr ||
            certificateListLength == nullptr ||
            *certificateListLength > certificateListCapacity ||
            derLength + 3 > certificateListCapacity - *certificateListLength) {
            return false;
        }

        UCHAR* target = certificateList + *certificateListLength;
        target[0] = static_cast<UCHAR>((derLength >> 16) & 0xff);
        target[1] = static_cast<UCHAR>((derLength >> 8) & 0xff);
        target[2] = static_cast<UCHAR>(derLength & 0xff);
        memcpy(target + 3, der, derLength);
        *certificateListLength += derLength + 3;
        return true;
    }

    bool RebuildCertificateList(
        const UCHAR* der,
        SIZE_T derLength,
        UCHAR* certificateList,
        SIZE_T certificateListCapacity,
        SIZE_T* certificateListLength)
    {
        if (certificateListLength != nullptr) {
            *certificateListLength = 0;
        }
        if (der == nullptr ||
            derLength == 0 ||
            derLength > 0x00ffffff ||
            certificateList == nullptr ||
            certificateListLength == nullptr ||
            certificateListCapacity < derLength + 3) {
            return false;
        }

        certificateList[0] = static_cast<UCHAR>((derLength >> 16) & 0xff);
        certificateList[1] = static_cast<UCHAR>((derLength >> 8) & 0xff);
        certificateList[2] = static_cast<UCHAR>(derLength & 0xff);
        memcpy(certificateList + 3, der, derLength);
        *certificateListLength = derLength + 3;
        return true;
    }

    bool InsertBytes(
        UCHAR* data,
        SIZE_T dataCapacity,
        SIZE_T* dataLength,
        SIZE_T offset,
        const UCHAR* source,
        SIZE_T sourceLength)
    {
        if (data == nullptr ||
            dataLength == nullptr ||
            offset > *dataLength ||
            sourceLength > dataCapacity - *dataLength ||
            (source == nullptr && sourceLength != 0)) {
            return false;
        }

        if (sourceLength != 0) {
            memmove(data + offset + sourceLength, data + offset, *dataLength - offset);
            memcpy(data + offset, source, sourceLength);
            *dataLength += sourceLength;
        }
        return true;
    }

    USHORT ReadBigEndian16(const UCHAR* data, SIZE_T offset)
    {
        return static_cast<USHORT>(
            (static_cast<USHORT>(data[offset]) << 8) |
            data[offset + 1]);
    }

    void WriteBigEndian16(UCHAR* data, SIZE_T offset, USHORT value)
    {
        data[offset] = static_cast<UCHAR>((value >> 8) & 0xff);
        data[offset + 1] = static_cast<UCHAR>(value & 0xff);
    }

    bool IncreaseBigEndian16(UCHAR* data, SIZE_T dataLength, SIZE_T offset, USHORT delta)
    {
        if (data == nullptr || offset + 1 >= dataLength) {
            return false;
        }

        const USHORT value = ReadBigEndian16(data, offset);
        if (value > static_cast<USHORT>(0xffffU - delta)) {
            return false;
        }

        WriteBigEndian16(data, offset, static_cast<USHORT>(value + delta));
        return true;
    }

    bool IncreaseLengthByte(UCHAR* data, SIZE_T dataLength, SIZE_T offset, UCHAR delta)
    {
        if (data == nullptr || offset >= dataLength || data[offset] > static_cast<UCHAR>(0xffU - delta)) {
            return false;
        }

        data[offset] = static_cast<UCHAR>(data[offset] + delta);
        return true;
    }

    bool FindFixtureExtensionsHeader(
        const UCHAR* der,
        SIZE_T derLength,
        SIZE_T beforeOffset,
        SIZE_T* extensionsOffset)
    {
        if (extensionsOffset != nullptr) {
            *extensionsOffset = 0;
        }
        if (der == nullptr || extensionsOffset == nullptr || beforeOffset > derLength || beforeOffset < 6) {
            return false;
        }

        bool found = false;
        for (SIZE_T index = 0; index + 5 < beforeOffset; ++index) {
            if (der[index] == 0xa3 &&
                der[index + 1] == 0x81 &&
                der[index + 3] == 0x30 &&
                der[index + 4] == 0x81) {
                *extensionsOffset = index;
                found = true;
            }
        }
        return found;
    }

    bool PatchSubjectAltNameAsCertificatePolicies(
        UCHAR* der,
        SIZE_T derCapacity,
        SIZE_T* derLength,
        bool critical,
        bool malformedPolicyValue)
    {
        static const UCHAR subjectAltNameOid[] = { 0x55, 0x1d, 0x11 };
        static const UCHAR certificatePoliciesOid[] = { 0x55, 0x1d, 0x20 };
        static const UCHAR criticalExtension[] = { 0x01, 0x01, 0xff };
        constexpr UCHAR CriticalExtensionLength = static_cast<UCHAR>(sizeof(criticalExtension));
        constexpr USHORT CriticalExtensionLength16 = static_cast<USHORT>(sizeof(criticalExtension));
        static const UCHAR validPolicies[] = {
            0x30, 0x23,
            0x30, 0x09, 0x06, 0x07, 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a
        };

        if (der == nullptr || derLength == nullptr) {
            return false;
        }

        SIZE_T sanOidOffset = 0;
        if (!FindBytes(
            der,
            *derLength,
            subjectAltNameOid,
            sizeof(subjectAltNameOid),
            0,
            &sanOidOffset) ||
            sanOidOffset < 4) {
            return false;
        }

        const SIZE_T extensionStart = sanOidOffset - 4;
        const SIZE_T octetStringOffset = sanOidOffset + sizeof(subjectAltNameOid);
        if (octetStringOffset + 2 > *derLength ||
            der[extensionStart] != 0x30 ||
            der[extensionStart + 1] < 2 ||
            der[octetStringOffset] != 0x04) {
            return false;
        }

        const SIZE_T policyValueLength = der[octetStringOffset + 1];
        if (policyValueLength != sizeof(validPolicies) ||
            octetStringOffset + 2 + policyValueLength > *derLength) {
            return false;
        }

        memcpy(der + sanOidOffset, certificatePoliciesOid, sizeof(certificatePoliciesOid));
        UCHAR* policyValue = der + octetStringOffset + 2;
        if (malformedPolicyValue) {
            memset(policyValue, 0, policyValueLength);
            policyValue[0] = 0x31;
            policyValue[1] = static_cast<UCHAR>(policyValueLength - 2);
        }
        else {
            memcpy(policyValue, validPolicies, sizeof(validPolicies));
        }

        if (!critical) {
            return true;
        }

        SIZE_T extensionsOffset = 0;
        if (!FindFixtureExtensionsHeader(der, *derLength, extensionStart, &extensionsOffset) ||
            !InsertBytes(
                der,
                derCapacity,
                derLength,
                octetStringOffset,
                criticalExtension,
                sizeof(criticalExtension))) {
            return false;
        }

        return IncreaseBigEndian16(der, *derLength, 2, CriticalExtensionLength16) &&
            IncreaseBigEndian16(der, *derLength, 6, CriticalExtensionLength16) &&
            IncreaseLengthByte(der, *derLength, extensionsOffset + 2, CriticalExtensionLength) &&
            IncreaseLengthByte(der, *derLength, extensionsOffset + 5, CriticalExtensionLength) &&
            IncreaseLengthByte(der, *derLength, extensionStart + 1, CriticalExtensionLength);
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

    void TestAlertParsing()
    {
        const UCHAR closeNotifyBytes[] = {
            static_cast<UCHAR>(TlsAlertLevel::Warning),
            static_cast<UCHAR>(TlsAlertDescription::CloseNotify)
        };
        TlsAlert alert = {};
        NTSTATUS status = TlsRecordLayer::DecodeAlert(closeNotifyBytes, sizeof(closeNotifyBytes), alert);
        Expect(status == STATUS_SUCCESS, "close_notify alert parses");
        Expect(alert.Level == TlsAlertLevel::Warning, "close_notify level is warning");
        Expect(alert.Description == TlsAlertDescription::CloseNotify, "close_notify description parses");
        Expect(alert.CloseNotify, "close_notify is marked clean close");

        const UCHAR protocolVersionBytes[] = {
            static_cast<UCHAR>(TlsAlertLevel::Fatal),
            static_cast<UCHAR>(TlsAlertDescription::ProtocolVersion)
        };
        status = TlsRecordLayer::DecodeAlert(protocolVersionBytes, sizeof(protocolVersionBytes), alert);
        Expect(status == STATUS_SUCCESS, "protocol_version alert parses");
        Expect(alert.Level == TlsAlertLevel::Fatal, "protocol_version level is fatal");
        Expect(alert.Description == TlsAlertDescription::ProtocolVersion, "protocol_version description parses");
        Expect(!alert.CloseNotify, "fatal protocol_version is not clean close");

        const UCHAR badCertificateBytes[] = {
            static_cast<UCHAR>(TlsAlertLevel::Fatal),
            static_cast<UCHAR>(TlsAlertDescription::BadCertificate)
        };
        status = TlsRecordLayer::DecodeAlert(badCertificateBytes, sizeof(badCertificateBytes), alert);
        Expect(status == STATUS_SUCCESS, "bad_certificate alert parses");
        Expect(alert.Description == TlsAlertDescription::BadCertificate, "bad_certificate description parses");

        const UCHAR unknownFatalBytes[] = {
            static_cast<UCHAR>(TlsAlertLevel::Fatal),
            255
        };
        status = TlsRecordLayer::DecodeAlert(unknownFatalBytes, sizeof(unknownFatalBytes), alert);
        Expect(status == STATUS_SUCCESS, "unknown fatal alert parses");
        Expect(alert.Level == TlsAlertLevel::Fatal, "unknown fatal level parses");
        Expect(static_cast<UCHAR>(alert.Description) == 255, "unknown fatal description is preserved");

        const UCHAR invalidLevelBytes[] = { 3, 0 };
        status = TlsRecordLayer::DecodeAlert(invalidLevelBytes, sizeof(invalidLevelBytes), alert);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "invalid alert level is rejected");
    }

    class ScriptedTlsTransport final : public KernelHttp::core::ITransport
    {
    public:
        ScriptedTlsTransport(const UCHAR* receiveBytes, SIZE_T receiveLength) noexcept :
            receiveBytes_(receiveBytes),
            receiveLength_(receiveLength)
        {
        }

        NTSTATUS Send(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept override
        {
            if (data == nullptr && length != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (sendCalls_ < 2 && length <= sizeof(sentRecords_[0])) {
                memcpy(sentRecords_[sendCalls_], data, length);
                sentRecordLengths_[sendCalls_] = length;
            }
            ++sendCalls_;
            if (bytesSent != nullptr) {
                *bytesSent = length;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS Receive(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept override
        {
            return ReceiveWithTimeout(buffer, length, bytesReceived, 0);
        }

        NTSTATUS ReceiveWithTimeout(
            void* buffer,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override
        {
            UNREFERENCED_PARAMETER(timeoutMilliseconds);
            if ((buffer == nullptr && length != 0) || bytesReceived == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *bytesReceived = 0;
            if (receiveOffset_ >= receiveLength_) {
                return STATUS_CONNECTION_DISCONNECTED;
            }

            const SIZE_T available = receiveLength_ - receiveOffset_;
            const SIZE_T copyLength = length < available ? length : available;
            if (copyLength != 0) {
                memcpy(buffer, receiveBytes_ + receiveOffset_, copyLength);
            }
            receiveOffset_ += copyLength;
            *bytesReceived = copyLength;
            return STATUS_SUCCESS;
        }

        SIZE_T SendCalls() const noexcept
        {
            return sendCalls_;
        }

        const UCHAR* SentRecord(SIZE_T index) const noexcept
        {
            return index < 2 && sentRecordLengths_[index] != 0 ? sentRecords_[index] : nullptr;
        }

        SIZE_T SentRecordLength(SIZE_T index) const noexcept
        {
            return index < 2 ? sentRecordLengths_[index] : 0;
        }

    private:
        const UCHAR* receiveBytes_ = nullptr;
        SIZE_T receiveLength_ = 0;
        SIZE_T receiveOffset_ = 0;
        SIZE_T sendCalls_ = 0;
        UCHAR sentRecords_[2][4096] = {};
        SIZE_T sentRecordLengths_[2] = {};
    };

    void TestTlsHandshakeFailureRecordsLocalPolicy()
    {
        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.HandshakeReceiveTimeoutMilliseconds = 1000;

        const NTSTATUS status = connection.Connect(transport, options);
        Expect(status == STATUS_INVALID_PARAMETER, "TLS connect rejects invalid local policy options");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::LocalPolicy,
            "TLS failure category records local policy failure");
        Expect(failure.Status == STATUS_INVALID_PARAMETER, "TLS failure records local policy NTSTATUS");
        Expect(!failure.HasPeerAlert, "TLS local policy failure has no peer alert");
    }

    void TestTlsHandshakeFailureRecordsProtocolVersionAlert()
    {
        const UCHAR protocolVersionAlertRecord[] = {
            static_cast<UCHAR>(TlsContentType::Alert),
            3,
            3,
            0,
            2,
            static_cast<UCHAR>(TlsAlertLevel::Fatal),
            static_cast<UCHAR>(TlsAlertDescription::ProtocolVersion)
        };

        ScriptedTlsTransport transport(protocolVersionAlertRecord, sizeof(protocolVersionAlertRecord));
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_INVALID_NETWORK_RESPONSE,
            "TLS connect returns the alert decode status for protocol_version");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::VersionNegotiation,
            "TLS protocol_version alert records version negotiation failure");
        Expect(failure.HasPeerAlert, "TLS protocol_version failure records the peer alert");
        Expect(
            failure.PeerAlert.Description == TlsAlertDescription::ProtocolVersion,
            "TLS protocol_version failure preserves alert description");
    }

    void TestTlsHandshakeFailureRecordsTls13HandshakeFailureAsVersionCandidate()
    {
        const UCHAR handshakeFailureAlertRecord[] = {
            static_cast<UCHAR>(TlsContentType::Alert),
            3,
            3,
            0,
            2,
            static_cast<UCHAR>(TlsAlertLevel::Fatal),
            static_cast<UCHAR>(TlsAlertDescription::HandshakeFailure)
        };

        ScriptedTlsTransport transport(handshakeFailureAlertRecord, sizeof(handshakeFailureAlertRecord));
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_INVALID_NETWORK_RESPONSE,
            "TLS connect returns the alert decode status for early handshake_failure");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::VersionNegotiation,
            "TLS early handshake_failure is a TLS1.2 confirmation candidate when both versions are allowed");
        Expect(failure.HasPeerAlert, "TLS early handshake_failure preserves peer alert metadata");
        Expect(
            failure.PeerAlert.Description == TlsAlertDescription::HandshakeFailure,
            "TLS early handshake_failure preserves alert description");
    }

    void TestTlsHandshakeFailureDoesNotClassifyTls13OnlyHandshakeFailure()
    {
        const UCHAR handshakeFailureAlertRecord[] = {
            static_cast<UCHAR>(TlsContentType::Alert),
            3,
            3,
            0,
            2,
            static_cast<UCHAR>(TlsAlertLevel::Fatal),
            static_cast<UCHAR>(TlsAlertDescription::HandshakeFailure)
        };

        ScriptedTlsTransport transport(handshakeFailureAlertRecord, sizeof(handshakeFailureAlertRecord));
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls13;
        options.MaximumProtocol = TlsProtocol::Tls13;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_INVALID_NETWORK_RESPONSE,
            "TLS1.3-only connect returns the alert decode status for handshake_failure");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::PeerAlert,
            "TLS1.3-only handshake_failure remains a peer alert");
    }

    void TestTlsHandshakeFailureRecordsTls13CloseNotifyAsVersionCandidate()
    {
        const UCHAR closeNotifyAlertRecord[] = {
            static_cast<UCHAR>(TlsContentType::Alert),
            3,
            3,
            0,
            2,
            static_cast<UCHAR>(TlsAlertLevel::Warning),
            static_cast<UCHAR>(TlsAlertDescription::CloseNotify)
        };

        ScriptedTlsTransport transport(closeNotifyAlertRecord, sizeof(closeNotifyAlertRecord));
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_INVALID_NETWORK_RESPONSE,
            "TLS connect returns the alert decode status for early close_notify");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::VersionNegotiation,
            "TLS early close_notify is a TLS1.2 confirmation candidate when both versions are allowed");
        Expect(failure.HasPeerAlert, "TLS early close_notify preserves peer alert metadata");
        Expect(failure.PeerAlert.CloseNotify, "TLS early close_notify preserves close_notify marker");
    }

    void TestTlsHandshakeFailureDoesNotClassifyTls13OnlyCloseNotify()
    {
        const UCHAR closeNotifyAlertRecord[] = {
            static_cast<UCHAR>(TlsContentType::Alert),
            3,
            3,
            0,
            2,
            static_cast<UCHAR>(TlsAlertLevel::Warning),
            static_cast<UCHAR>(TlsAlertDescription::CloseNotify)
        };

        ScriptedTlsTransport transport(closeNotifyAlertRecord, sizeof(closeNotifyAlertRecord));
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls13;
        options.MaximumProtocol = TlsProtocol::Tls13;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_INVALID_NETWORK_RESPONSE,
            "TLS1.3-only connect returns the alert decode status for close_notify");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::PeerAlert,
            "TLS1.3-only close_notify remains a peer alert");
    }

    void TestTlsHandshakeFailureMarksTls13FirstServerHelloNetworkIo()
    {
        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_CONNECTION_DISCONNECTED,
            "TLS connect returns first ServerHello transport disconnect");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::NetworkIo,
            "TLS first ServerHello disconnect records network I/O failure");
        Expect(
            failure.BeforeTls13FirstServerHello,
            "TLS first ServerHello disconnect is marked as TLS1.2 confirmation stage");
    }

    void TestTlsHandshakeFailureDoesNotMarkTls13OnlyFirstServerHelloNetworkIo()
    {
        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls13;
        options.MaximumProtocol = TlsProtocol::Tls13;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_CONNECTION_DISCONNECTED,
            "TLS1.3-only connect returns first ServerHello transport disconnect");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::NetworkIo,
            "TLS1.3-only first ServerHello disconnect records network I/O failure");
        Expect(
            !failure.BeforeTls13FirstServerHello,
            "TLS1.3-only first ServerHello disconnect is not a TLS1.2 confirmation candidate");
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

    void InitializeCbcEtmState(TlsAeadCipherState& state)
    {
        state = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            state.Key[index] = static_cast<UCHAR>(0x30 + index);
        }
        for (SIZE_T index = 0; index < 32; ++index) {
            state.MacKey[index] = static_cast<UCHAR>(0x80 + index);
        }
        state.KeyLength = 16;
        state.MacKeyLength = 32;
        state.MacAlgorithm = HashAlgorithm::Sha256;
        state.EncryptThenMac = true;
    }

    void WriteSequenceForTest(unsigned long long sequenceNumber, UCHAR* destination)
    {
        destination[0] = static_cast<UCHAR>((sequenceNumber >> 56) & 0xff);
        destination[1] = static_cast<UCHAR>((sequenceNumber >> 48) & 0xff);
        destination[2] = static_cast<UCHAR>((sequenceNumber >> 40) & 0xff);
        destination[3] = static_cast<UCHAR>((sequenceNumber >> 32) & 0xff);
        destination[4] = static_cast<UCHAR>((sequenceNumber >> 24) & 0xff);
        destination[5] = static_cast<UCHAR>((sequenceNumber >> 16) & 0xff);
        destination[6] = static_cast<UCHAR>((sequenceNumber >> 8) & 0xff);
        destination[7] = static_cast<UCHAR>(sequenceNumber & 0xff);
    }

    void TestAesCbcEncryptThenMacRecordProtection()
    {
        const UCHAR body[] = { 'c', 'b', 'c', '-', 'e', 't', 'm' };
        UCHAR encoded[256] = {};
        UCHAR decoded[128] = {};
        SIZE_T written = 0;

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        InitializeCbcEtmState(writeState);
        InitializeCbcEtmState(readState);

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);

        NTSTATUS status = TlsRecordLayer::ProtectAesCbcEncryptThenMac(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CBC EtM record protects");
        Expect(writeState.SequenceNumber == 1, "AES-CBC EtM write sequence increments");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CBC EtM record parses");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesCbcEncryptThenMac(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CBC EtM record unprotects");
        Expect(readState.SequenceNumber == 1, "AES-CBC EtM read sequence increments");
        Expect(output.FragmentLength == sizeof(body), "AES-CBC EtM unprotected length matches");
        Expect(memcmp(output.Fragment, body, sizeof(body)) == 0, "AES-CBC EtM unprotected bytes match");

        UCHAR tamperedMac[256] = {};
        memcpy(tamperedMac, encoded, written);
        tamperedMac[written - 1] ^= 1;
        status = TlsRecordLayer::Parse(tamperedMac, written, parsed);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CBC EtM tampered MAC record parses");
        InitializeCbcEtmState(readState);
        status = TlsRecordLayer::UnprotectAesCbcEncryptThenMac(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);
        ExpectStatus(status, STATUS_INVALID_SIGNATURE, "AES-CBC EtM rejects tampered MAC before decrypt");
        Expect(readState.SequenceNumber == 0, "AES-CBC EtM MAC failure does not advance sequence");

        UCHAR tamperedPadding[256] = {};
        memcpy(tamperedPadding, encoded, written);
        TlsRecordView paddingParsed = {};
        status = TlsRecordLayer::Parse(tamperedPadding, written, paddingParsed);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CBC EtM padding tamper base record parses");
        if (!NT_SUCCESS(status) || paddingParsed.FragmentLength <= 32) {
            return;
        }

        const SIZE_T macLength = 32;
        const SIZE_T encryptedPartLength = paddingParsed.FragmentLength - macLength;
        tamperedPadding[TlsRecordHeaderLength + encryptedPartLength - 1] ^= 0x7f;

        UCHAR macInput[13 + 256] = {};
        WriteSequenceForTest(0, macInput);
        macInput[8] = static_cast<UCHAR>(paddingParsed.ContentType);
        macInput[9] = paddingParsed.Version.Major;
        macInput[10] = paddingParsed.Version.Minor;
        macInput[11] = static_cast<UCHAR>((encryptedPartLength >> 8) & 0xff);
        macInput[12] = static_cast<UCHAR>(encryptedPartLength & 0xff);
        memcpy(macInput + 13, tamperedPadding + TlsRecordHeaderLength, encryptedPartLength);

        UCHAR mac[32] = {};
        SIZE_T macWritten = 0;
        status = KernelHttp::crypto::CngProvider::Hmac(
            HashAlgorithm::Sha256,
            readState.MacKey,
            readState.MacKeyLength,
            macInput,
            13 + encryptedPartLength,
            mac,
            sizeof(mac),
            &macWritten);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CBC EtM test recomputes HMAC for padding tamper");
        Expect(macWritten == macLength, "AES-CBC EtM test HMAC length matches");
        memcpy(tamperedPadding + TlsRecordHeaderLength + encryptedPartLength, mac, macLength);

        status = TlsRecordLayer::Parse(tamperedPadding, written, paddingParsed);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CBC EtM padding-tampered record parses");
        InitializeCbcEtmState(readState);
        status = TlsRecordLayer::UnprotectAesCbcEncryptThenMac(
            paddingParsed,
            readState,
            decoded,
            sizeof(decoded),
            output);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "AES-CBC EtM rejects invalid padding after valid MAC");
        Expect(readState.SequenceNumber == 0, "AES-CBC EtM padding failure does not advance sequence");
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

    void TestTls13ExporterAndTrafficUpdate()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for exporter test");
        status = context.SetCipherSuite(TlsCipherSuite::TlsAes128CcmSha256);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-CCM cipher suite sets");

        UCHAR sharedSecret[32] = {};
        UCHAR serverHelloHash[32] = {};
        UCHAR serverFinishedHash[32] = {};
        for (SIZE_T index = 0; index < sizeof(sharedSecret); ++index) {
            sharedSecret[index] = static_cast<UCHAR>(0x21 + index);
            serverHelloHash[index] = static_cast<UCHAR>(0x51 + index);
            serverFinishedHash[index] = static_cast<UCHAR>(0x91 + index);
        }

        status = context.DeriveTls13EarlySecret(nullptr, 0);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 early secret derives for exporter test");
        status = context.DeriveTls13HandshakeSecrets(
            sharedSecret,
            sizeof(sharedSecret),
            serverHelloHash,
            sizeof(serverHelloHash));
        Expect(status == STATUS_SUCCESS, "TLS 1.3 handshake secrets derive for exporter test");
        status = context.DeriveTls13ApplicationSecrets(serverFinishedHash, sizeof(serverFinishedHash));
        Expect(status == STATUS_SUCCESS, "TLS 1.3 application secrets derive for exporter test");

        UCHAR exporterA[32] = {};
        UCHAR exporterB[32] = {};
        const UCHAR exporterContextA[] = { 1, 2, 3 };
        const UCHAR exporterContextB[] = { 1, 2, 4 };
        status = context.DeriveTls13Exporter(
            "EXPORTER-kernel-http-test",
            exporterContextA,
            sizeof(exporterContextA),
            exporterA,
            sizeof(exporterA));
        Expect(status == STATUS_SUCCESS, "TLS 1.3 exporter derives");
        status = context.DeriveTls13Exporter(
            "EXPORTER-kernel-http-test",
            exporterContextB,
            sizeof(exporterContextB),
            exporterB,
            sizeof(exporterB));
        Expect(status == STATUS_SUCCESS, "TLS 1.3 exporter derives with alternate context");
        Expect(memcmp(exporterA, exporterB, sizeof(exporterA)) != 0, "TLS 1.3 exporter is context-bound");

        TlsAeadCipherState clientState = {};
        TlsAeadCipherState serverState = {};
        status = context.ConfigureTls13ApplicationAesGcmStates(clientState, serverState);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 application states configure for AES-CCM");
        Expect(clientState.Algorithm == AeadAlgorithm::Aes128Ccm, "TLS 1.3 AES-CCM state selects CCM AEAD");

        UCHAR previousKey[sizeof(clientState.Key)] = {};
        RtlCopyMemory(previousKey, clientState.Key, sizeof(previousKey));
        clientState.SequenceNumber = 17;
        status = context.UpdateTls13ApplicationTrafficSecret(true, clientState);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 client traffic secret updates");
        Expect(clientState.SequenceNumber == 0, "TLS 1.3 traffic update resets sequence number");
        Expect(memcmp(previousKey, clientState.Key, clientState.KeyLength) != 0, "TLS 1.3 traffic update changes key material");
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

    void TestTls13AesGcmProtectsWithExplicitPadding()
    {
        UCHAR encoded[128] = {};
        UCHAR decoded[32] = {};
        const UCHAR body[] = { 'p', 'a', 'd' };
        constexpr SIZE_T PaddingLength = 7;

        TlsAeadCipherState writeState = {};
        TlsAeadCipherState readState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0x44 + index);
            readState.Key[index] = static_cast<UCHAR>(0x44 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            writeState.FixedIv[index] = static_cast<UCHAR>(0x66 + index);
            readState.FixedIv[index] = static_cast<UCHAR>(0x66 + index);
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
        plain.Tls13PaddingLength = PaddingLength;

        SIZE_T written = 0;
        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM explicit padding protects");
        Expect(
            written == TlsRecordHeaderLength + sizeof(body) + 1 + PaddingLength + TlsAesGcmTagLength,
            "TLS 1.3 AES-GCM explicit padding increases encrypted length");

        TlsRecordView parsed = {};
        status = TlsRecordLayer::Parse(encoded, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM explicit padding parses");

        TlsMutablePlaintextRecord output = {};
        status = TlsRecordLayer::UnprotectAesGcm13(
            parsed,
            readState,
            decoded,
            sizeof(decoded),
            output);

        Expect(status == STATUS_SUCCESS, "TLS 1.3 AES-GCM explicit padding unprotects");
        Expect(output.FragmentLength == sizeof(body), "TLS 1.3 AES-GCM explicit padding is stripped");
        Expect(memcmp(output.Fragment, body, sizeof(body)) == 0, "TLS 1.3 AES-GCM explicit padding preserves plaintext");
    }

    void TestTls13AesGcmRejectsOversizedPadding()
    {
        UCHAR encoded[64] = {};
        const UCHAR body[] = { 'x', 'x' };

        TlsAeadCipherState writeState = {};
        for (SIZE_T index = 0; index < 16; ++index) {
            writeState.Key[index] = static_cast<UCHAR>(0x88 + index);
        }
        for (SIZE_T index = 0; index < TlsAesGcmTls13IvLength; ++index) {
            writeState.FixedIv[index] = static_cast<UCHAR>(0xaa + index);
        }
        writeState.KeyLength = 16;
        writeState.FixedIvLength = TlsAesGcmTls13IvLength;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::ApplicationData;
        plain.Version = { 3, 3 };
        plain.Fragment = body;
        plain.FragmentLength = sizeof(body);
        plain.Tls13PaddingLength = Tls13MaxRecordPaddingLength;

        SIZE_T written = 99;
        const NTSTATUS status = TlsRecordLayer::ProtectAesGcm13(
            plain,
            writeState,
            encoded,
            sizeof(encoded),
            &written);

        Expect(status == STATUS_INVALID_PARAMETER, "TLS 1.3 AES-GCM rejects oversized padding");
        Expect(written == 0, "TLS 1.3 AES-GCM oversized padding reports no bytes written");
        Expect(writeState.SequenceNumber == 0, "TLS 1.3 AES-GCM oversized padding does not advance sequence");
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

    bool ClientHelloOffersCipherSuite(const UCHAR* body, SIZE_T bodyLength, TlsCipherSuite cipherSuite)
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
        if ((cipherSuiteBytes % 2) != 0 || cipherSuiteBytes > bodyLength - offset) {
            return false;
        }

        for (SIZE_T index = 0; index < cipherSuiteBytes; index += 2) {
            const USHORT current = static_cast<USHORT>(
                (static_cast<USHORT>(body[offset + index]) << 8) |
                body[offset + index + 1]);
            if (current == static_cast<USHORT>(cipherSuite)) {
                return true;
            }
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

    bool ClientHelloSessionIdEquals(
        const UCHAR* body,
        SIZE_T bodyLength,
        const UCHAR* expected,
        SIZE_T expectedLength)
    {
        if (body == nullptr || (expected == nullptr && expectedLength != 0) || bodyLength < 35) {
            return false;
        }

        SIZE_T offset = 34;
        const SIZE_T sessionIdLength = body[offset++];
        if (sessionIdLength > bodyLength - offset || sessionIdLength != expectedLength) {
            return false;
        }

        return expectedLength == 0 ||
            memcmp(body + offset, expected, expectedLength) == 0;
    }

    bool ClientHelloExtensionPayloadEquals(
        const UCHAR* body,
        SIZE_T bodyLength,
        USHORT extensionType,
        const UCHAR* expected,
        SIZE_T expectedLength)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindClientHelloExtension(body, bodyLength, extensionType, &extension, &extensionLength) ||
            extensionLength != expectedLength) {
            return false;
        }

        return expectedLength == 0 ||
            (expected != nullptr && memcmp(extension, expected, expectedLength) == 0);
    }

    bool ParseSentClientHello(
        const ScriptedTlsTransport& transport,
        SIZE_T sendIndex,
        TlsHandshakeMessageView& message);

    void TestTls12ClientHelloAdvertisesStrictExtensions()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for strict ClientHello extensions");

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

        Expect(status == STATUS_SUCCESS, "TLS 1.2 strict ClientHello encodes");
        TlsHandshakeMessageView parsed = {};
        status = TlsHandshake12::ParseMessage(message, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 strict ClientHello parses");
        Expect(ClientHelloHasExtension(parsed.Body, parsed.BodyLength, 23), "TLS 1.2 ClientHello advertises extended_master_secret");
        Expect(ClientHelloHasExtension(parsed.Body, parsed.BodyLength, 0xff01), "TLS 1.2 ClientHello advertises secure renegotiation");
        const UCHAR emptyRenegotiationInfo[] = { 0 };
        Expect(
            ClientHelloExtensionPayloadEquals(
                parsed.Body,
                parsed.BodyLength,
                0xff01,
                emptyRenegotiationInfo,
                sizeof(emptyRenegotiationInfo)),
            "TLS 1.2 initial ClientHello sends empty renegotiation_info");
    }

    void TestTls12ClientHelloCarriesRenegotiationInfo()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for renegotiation ClientHello");

        UCHAR verifyData[TlsVerifyDataLength] = {};
        for (SIZE_T index = 0; index < sizeof(verifyData); ++index) {
            verifyData[index] = static_cast<UCHAR>(0x80 + index);
        }

        UCHAR message[512] = {};
        SIZE_T written = 0;
        TlsClientHelloOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.RenegotiationInfo = verifyData;
        options.RenegotiationInfoLength = sizeof(verifyData);

        status = TlsHandshake12::EncodeClientHello(
            context,
            options,
            message,
            sizeof(message),
            &written);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 renegotiation ClientHello encodes");

        TlsHandshakeMessageView parsed = {};
        status = TlsHandshake12::ParseMessage(message, written, parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 renegotiation ClientHello parses");

        UCHAR expectedPayload[1 + TlsVerifyDataLength] = {};
        expectedPayload[0] = static_cast<UCHAR>(sizeof(verifyData));
        memcpy(expectedPayload + 1, verifyData, sizeof(verifyData));
        Expect(
            ClientHelloExtensionPayloadEquals(
                parsed.Body,
                parsed.BodyLength,
                0xff01,
                expectedPayload,
                sizeof(expectedPayload)),
            "TLS 1.2 renegotiation ClientHello carries previous client verify_data");

        options.RenegotiationInfo = nullptr;
        options.RenegotiationInfoLength = 1;
        written = 0;
        status = TlsHandshake12::EncodeClientHello(
            context,
            options,
            message,
            sizeof(message),
            &written);
        ExpectStatus(status, STATUS_INVALID_PARAMETER, "TLS 1.2 ClientHello rejects malformed renegotiation_info input");
    }

    void TestParseTls12HelloRequest()
    {
        const UCHAR helloRequest[] = {
            static_cast<UCHAR>(TlsHandshakeType::HelloRequest), 0, 0, 0
        };

        TlsHandshakeMessageView parsed = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(helloRequest, sizeof(helloRequest), parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 HelloRequest parses generically");
        Expect(parsed.Type == TlsHandshakeType::HelloRequest, "TLS 1.2 HelloRequest type is exposed");
        Expect(parsed.BodyLength == 0, "TLS 1.2 HelloRequest body is empty");
        Expect(parsed.BytesConsumed == sizeof(helloRequest), "TLS 1.2 HelloRequest consumes its full header");

        const UCHAR nonEmptyHelloRequest[] = {
            static_cast<UCHAR>(TlsHandshakeType::HelloRequest), 0, 0, 1, 0
        };
        parsed = {};
        status = TlsHandshake12::ParseMessage(nonEmptyHelloRequest, sizeof(nonEmptyHelloRequest), parsed);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 non-empty HelloRequest parses as malformed generic view");
        Expect(parsed.Type == TlsHandshakeType::HelloRequest, "TLS 1.2 non-empty HelloRequest keeps type");
        Expect(parsed.BodyLength == 1, "TLS 1.2 non-empty HelloRequest body length is visible to connection policy");
    }

    void TestTls12ClientInitiatedRenegotiationRequiresEstablishedConnection()
    {
        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;

        const NTSTATUS status = connection.RenegotiateTls12(transport);

        ExpectStatus(
            status,
            STATUS_NOT_SUPPORTED,
            "TLS 1.2 client-initiated renegotiation requires an established compatible connection");
        Expect(transport.SendCalls() == 0, "TLS 1.2 rejected client-initiated renegotiation sends no record");
    }

    void TestTls12ConnectionClientHelloFollowsCompatibilityPolicy()
    {
        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls12;
        options.MaximumProtocol = TlsProtocol::Tls12;
        options.Policy.Profile = TlsSecurityProfile::CompatibilityExplicit;
        options.Policy.EnableTls12RsaKeyExchange = true;
        options.Policy.EnableTls12Cbc = true;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.2 compatibility ClientHello test stops after peer disconnect");
        Expect(transport.SendCalls() == 1, "TLS 1.2 compatibility ClientHello sends one record");

        TlsHandshakeMessageView clientHello = {};
        const bool parsed = ParseSentClientHello(transport, 0, clientHello);
        Expect(parsed, "TLS 1.2 compatibility ClientHello parses from sent record");
        if (!parsed) {
            return;
        }

        Expect(
            ClientHelloOffersCipherSuite(clientHello.Body, clientHello.BodyLength, TlsCipherSuite::TlsRsaWithAes128GcmSha256),
            "TLS 1.2 compatibility ClientHello offers RSA AES-GCM after opt-in");
        Expect(
            ClientHelloOffersCipherSuite(clientHello.Body, clientHello.BodyLength, TlsCipherSuite::TlsRsaWithAes128CbcSha256),
            "TLS 1.2 compatibility ClientHello offers RSA AES-CBC after opt-in");
        Expect(ClientHelloHasExtension(clientHello.Body, clientHello.BodyLength, 22), "TLS 1.2 compatibility ClientHello advertises encrypt_then_mac");
        Expect(ClientHelloHasExtension(clientHello.Body, clientHello.BodyLength, 5), "TLS 1.2 compatibility ClientHello advertises status_request");
    }

    void TestClientHelloRejectsInvalidSniNames()
    {
        const char nonAsciiName[] = {
            'e', 'x', static_cast<char>(0xc3), static_cast<char>(0xa1),
            'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '\0'
        };
        const char emptyLabelName[] = "example..com";
        const char ipLiteralName[] = "127.0.0.1";
        const char ipv6LiteralName[] = "::1";
        char longLabelName[72] = {};
        memset(longLabelName, 'a', 64);
        memcpy(longLabelName + 64, ".com", 5);

        const char* invalidNames[] = {
            nonAsciiName,
            emptyLabelName,
            ipLiteralName,
            ipv6LiteralName,
            longLabelName
        };
        const SIZE_T invalidNameLengths[] = {
            sizeof(nonAsciiName) - 1,
            sizeof(emptyLabelName) - 1,
            sizeof(ipLiteralName) - 1,
            sizeof(ipv6LiteralName) - 1,
            strlen(longLabelName)
        };

        for (SIZE_T index = 0; index < sizeof(invalidNames) / sizeof(invalidNames[0]); ++index) {
            TlsContext tls12Context;
            NTSTATUS status = tls12Context.InitializeClient({ 3, 3 });
            Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for invalid SNI test");

            UCHAR tls12Message[512] = {};
            SIZE_T tls12Written = 0;
            TlsClientHelloOptions tls12Options = {};
            tls12Options.ServerName = invalidNames[index];
            tls12Options.ServerNameLength = invalidNameLengths[index];
            status = TlsHandshake12::EncodeClientHello(
                tls12Context,
                tls12Options,
                tls12Message,
                sizeof(tls12Message),
                &tls12Written);
            ExpectStatus(status, STATUS_INVALID_PARAMETER, "TLS 1.2 ClientHello rejects invalid DNS SNI");

            TlsContext tls13Context;
            status = tls13Context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for invalid SNI test");

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

            UCHAR tls13Message[1024] = {};
            SIZE_T tls13Written = 0;
            Tls13ClientHelloOptions tls13Options = {};
            tls13Options.ServerName = invalidNames[index];
            tls13Options.ServerNameLength = invalidNameLengths[index];
            tls13Options.KeyShares = &keyShare;
            tls13Options.KeyShareCount = 1;
            status = TlsHandshake13::EncodeClientHello(
                tls13Context,
                tls13Options,
                tls13Message,
                sizeof(tls13Message),
                &tls13Written);
            ExpectStatus(status, STATUS_INVALID_PARAMETER, "TLS 1.3 ClientHello rejects invalid DNS SNI");
        }

        TlsContext tls12Context;
        NTSTATUS status = tls12Context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for valid SNI test");
        UCHAR tls12Message[512] = {};
        SIZE_T tls12Written = 0;
        TlsClientHelloOptions tls12Options = {};
        tls12Options.ServerName = "valid.example";
        tls12Options.ServerNameLength = strlen(tls12Options.ServerName);
        status = TlsHandshake12::EncodeClientHello(
            tls12Context,
            tls12Options,
            tls12Message,
            sizeof(tls12Message),
            &tls12Written);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 ClientHello accepts valid DNS SNI");
    }

    ULONGLONG TestCurrentMilliseconds()
    {
        return static_cast<ULONGLONG>(time(nullptr)) * 1000ULL;
    }

    void FillMatchingTls13Ticket(Tls13SessionTicket& ticket, ULONGLONG issueTimeMilliseconds)
    {
        ticket = {};
        const UCHAR identity[] = { 't', 'i', 'c', 'k', 'e', 't' };
        memcpy(ticket.Identity, identity, sizeof(identity));
        ticket.IdentityLength = sizeof(identity);
        ticket.LifetimeSeconds = 60;
        ticket.AgeAdd = 7;
        ticket.IssueTimeMilliseconds = issueTimeMilliseconds;
        ticket.Version = { 3, 4 };
        const char serverName[] = "example.com";
        memcpy(ticket.ServerName, serverName, sizeof(serverName) - 1);
        ticket.ServerNameLength = sizeof(serverName) - 1;
        const char alpn[] = "h2";
        memcpy(ticket.Alpn, alpn, sizeof(alpn) - 1);
        ticket.AlpnLength = sizeof(alpn) - 1;
        ticket.CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;
        for (SIZE_T index = 0; index < 32; ++index) {
            ticket.ResumptionSecret[index] = static_cast<UCHAR>(0x44 + index);
        }
        ticket.ResumptionSecretLength = 32;
        ticket.MaxEarlyDataSize = 0;
    }

    void FillMatchingTls12Session(Tls12Session& session, ULONGLONG issueTimeMilliseconds)
    {
        session = {};
        const UCHAR sessionId[] = {
            0x12, 0x10, 0x02, 0x04, 0x08, 0x16, 0x23, 0x42
        };
        memcpy(session.SessionId, sessionId, sizeof(sessionId));
        session.SessionIdLength = sizeof(sessionId);

        const UCHAR ticket[] = { 't', 'l', 's', '1', '2', '-', 't', 'k', 't' };
        memcpy(session.Ticket, ticket, sizeof(ticket));
        session.TicketLength = sizeof(ticket);
        session.TicketLifetimeHintSeconds = 60;
        session.IssueTimeMilliseconds = issueTimeMilliseconds;
        session.Version = { 3, 3 };

        const char serverName[] = "example.com";
        memcpy(session.ServerName, serverName, sizeof(serverName) - 1);
        session.ServerNameLength = sizeof(serverName) - 1;
        const char alpn[] = "h2";
        memcpy(session.Alpn, alpn, sizeof(alpn) - 1);
        session.AlpnLength = sizeof(alpn) - 1;
        session.CipherSuite = TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256;

        for (SIZE_T index = 0; index < TlsMasterSecretLength; ++index) {
            session.MasterSecret[index] = static_cast<UCHAR>(0x30 + index);
        }
        session.MasterSecretLength = TlsMasterSecretLength;
        session.PolicyIdentity = 0;
    }

    bool ParseSentClientHello(
        const ScriptedTlsTransport& transport,
        SIZE_T sendIndex,
        TlsHandshakeMessageView& message)
    {
        message = {};
        const UCHAR* recordBytes = transport.SentRecord(sendIndex);
        const SIZE_T recordLength = transport.SentRecordLength(sendIndex);
        if (recordBytes == nullptr || recordLength == 0) {
            return false;
        }

        TlsRecordView record = {};
        NTSTATUS status = TlsRecordLayer::Parse(recordBytes, recordLength, record);
        if (!NT_SUCCESS(status) ||
            record.ContentType != TlsContentType::Handshake ||
            record.BytesConsumed != recordLength) {
            return false;
        }

        status = TlsHandshake12::ParseMessage(record.Fragment, record.FragmentLength, message);
        return NT_SUCCESS(status) &&
            message.Type == TlsHandshakeType::ClientHello &&
            message.BytesConsumed == record.FragmentLength;
    }

    bool SentClientHelloHasExtension(
        const ScriptedTlsTransport& transport,
        SIZE_T sendIndex,
        USHORT extensionType)
    {
        TlsHandshakeMessageView message = {};
        return ParseSentClientHello(transport, sendIndex, message) &&
            ClientHelloHasExtension(message.Body, message.BodyLength, extensionType);
    }

    bool ReadFirstPskIdentityAge(const UCHAR* extension, SIZE_T extensionLength, ULONG* age)
    {
        if (age != nullptr) {
            *age = 0;
        }
        if (extension == nullptr || age == nullptr || extensionLength < 8) {
            return false;
        }

        SIZE_T offset = 0;
        const SIZE_T identitiesLength =
            (static_cast<SIZE_T>(extension[offset]) << 8) | extension[offset + 1];
        offset += 2;
        if (identitiesLength == 0 || identitiesLength > extensionLength - offset) {
            return false;
        }

        const SIZE_T identitiesEnd = offset + identitiesLength;
        if (identitiesEnd - offset < 6) {
            return false;
        }

        const SIZE_T identityLength =
            (static_cast<SIZE_T>(extension[offset]) << 8) | extension[offset + 1];
        offset += 2;
        if (identityLength > identitiesEnd - offset || identitiesEnd - offset - identityLength < 4) {
            return false;
        }

        offset += identityLength;
        *age = (static_cast<ULONG>(extension[offset]) << 24) |
            (static_cast<ULONG>(extension[offset + 1]) << 16) |
            (static_cast<ULONG>(extension[offset + 2]) << 8) |
            extension[offset + 3];
        return true;
    }

    bool ReadFirstPskBinder(
        const UCHAR* extension,
        SIZE_T extensionLength,
        const UCHAR** binder,
        SIZE_T* binderLength)
    {
        if (binder != nullptr) {
            *binder = nullptr;
        }
        if (binderLength != nullptr) {
            *binderLength = 0;
        }
        if (extension == nullptr || binder == nullptr || binderLength == nullptr || extensionLength < 6) {
            return false;
        }

        SIZE_T offset = 0;
        const SIZE_T identitiesLength =
            (static_cast<SIZE_T>(extension[offset]) << 8) | extension[offset + 1];
        offset += 2;
        if (identitiesLength == 0 || identitiesLength > extensionLength - offset) {
            return false;
        }
        offset += identitiesLength;
        if (extensionLength - offset < 3) {
            return false;
        }

        const SIZE_T bindersLength =
            (static_cast<SIZE_T>(extension[offset]) << 8) | extension[offset + 1];
        offset += 2;
        if (bindersLength == 0 || bindersLength != extensionLength - offset) {
            return false;
        }

        const SIZE_T firstBinderLength = extension[offset++];
        if (firstBinderLength == 0 || firstBinderLength > extensionLength - offset) {
            return false;
        }

        *binder = extension + offset;
        *binderLength = firstBinderLength;
        return true;
    }

    void WriteUint16ForTest(UCHAR* destination, SIZE_T* offset, USHORT value)
    {
        destination[(*offset)++] = static_cast<UCHAR>((value >> 8) & 0xff);
        destination[(*offset)++] = static_cast<UCHAR>(value & 0xff);
    }

    bool AppendServerHelloExtensionForTest(
        UCHAR* body,
        SIZE_T bodyCapacity,
        SIZE_T* bodyLength,
        const UCHAR* extension,
        SIZE_T extensionLength)
    {
        if (body == nullptr ||
            bodyLength == nullptr ||
            extension == nullptr ||
            extensionLength == 0 ||
            *bodyLength > bodyCapacity ||
            *bodyLength < 40) {
            return false;
        }

        SIZE_T offset = 2 + 32;
        if (offset >= *bodyLength) {
            return false;
        }

        const SIZE_T sessionIdLength = body[offset++];
        if (sessionIdLength > *bodyLength - offset) {
            return false;
        }
        offset += sessionIdLength;
        if (*bodyLength - offset < 5) {
            return false;
        }

        offset += 2;
        ++offset;
        const SIZE_T extensionsLengthOffset = offset;
        const SIZE_T extensionsStart = extensionsLengthOffset + 2;
        if (*bodyLength < extensionsStart) {
            return false;
        }

        const SIZE_T currentExtensionsLength = ReadBigEndian16(body, extensionsLengthOffset);
        if (currentExtensionsLength > *bodyLength - extensionsStart ||
            extensionsStart + currentExtensionsLength != *bodyLength ||
            extensionLength > bodyCapacity - *bodyLength ||
            currentExtensionsLength + extensionLength > 0xffff) {
            return false;
        }

        memcpy(body + *bodyLength, extension, extensionLength);
        *bodyLength += extensionLength;
        WriteBigEndian16(
            body,
            extensionsLengthOffset,
            static_cast<USHORT>(currentExtensionsLength + extensionLength));
        return true;
    }

    void BuildTls13ServerHelloBody(
        UCHAR* body,
        SIZE_T* offset,
        TlsCipherSuite cipherSuite,
        bool helloRetryRequest,
        TlsNamedGroup group)
    {
        const UCHAR hrrRandom[] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };

        WriteUint16ForTest(body, offset, 0x0303);
        if (helloRetryRequest) {
            memcpy(body + *offset, hrrRandom, sizeof(hrrRandom));
            *offset += sizeof(hrrRandom);
        }
        else {
            for (SIZE_T index = 0; index < 32; ++index) {
                body[(*offset)++] = static_cast<UCHAR>(0x60 + index);
            }
        }
        body[(*offset)++] = 0;
        WriteUint16ForTest(body, offset, static_cast<USHORT>(cipherSuite));
        body[(*offset)++] = 0;

        const SIZE_T extensionsLengthOffset = *offset;
        WriteUint16ForTest(body, offset, 0);
        const SIZE_T extensionsStart = *offset;
        WriteUint16ForTest(body, offset, 43);
        WriteUint16ForTest(body, offset, 2);
        WriteUint16ForTest(body, offset, 0x0304);
        WriteUint16ForTest(body, offset, 51);
        if (helloRetryRequest) {
            WriteUint16ForTest(body, offset, 2);
            WriteUint16ForTest(body, offset, static_cast<USHORT>(group));
        }
        else {
            WriteUint16ForTest(body, offset, 8);
            WriteUint16ForTest(body, offset, static_cast<USHORT>(group));
            WriteUint16ForTest(body, offset, 4);
            body[(*offset)++] = 4;
            body[(*offset)++] = 1;
            body[(*offset)++] = 2;
            body[(*offset)++] = 3;
        }

        const SIZE_T extensionsLength = *offset - extensionsStart;
        body[extensionsLengthOffset] = static_cast<UCHAR>((extensionsLength >> 8) & 0xff);
        body[extensionsLengthOffset + 1] = static_cast<UCHAR>(extensionsLength & 0xff);
    }

    bool BuildHelloRetryRequestRecord(UCHAR* record, SIZE_T recordCapacity, SIZE_T* recordLength)
    {
        if (recordLength != nullptr) {
            *recordLength = 0;
        }
        if (record == nullptr || recordLength == nullptr || recordCapacity == 0) {
            return false;
        }

        const UCHAR hrrRandom[] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };

        UCHAR body[128] = {};
        SIZE_T bodyOffset = 0;
        WriteUint16ForTest(body, &bodyOffset, 0x0303);
        memcpy(body + bodyOffset, hrrRandom, sizeof(hrrRandom));
        bodyOffset += sizeof(hrrRandom);
        body[bodyOffset++] = 0;
        WriteUint16ForTest(body, &bodyOffset, static_cast<USHORT>(TlsCipherSuite::TlsAes128GcmSha256));
        body[bodyOffset++] = 0;

        const SIZE_T extensionsLengthOffset = bodyOffset;
        WriteUint16ForTest(body, &bodyOffset, 0);
        WriteUint16ForTest(body, &bodyOffset, 43);
        WriteUint16ForTest(body, &bodyOffset, 2);
        WriteUint16ForTest(body, &bodyOffset, 0x0304);
        WriteUint16ForTest(body, &bodyOffset, 51);
        WriteUint16ForTest(body, &bodyOffset, 2);
        WriteUint16ForTest(body, &bodyOffset, static_cast<USHORT>(TlsNamedGroup::Secp384r1));
        const SIZE_T extensionsLength = bodyOffset - extensionsLengthOffset - 2;
        body[extensionsLengthOffset] = static_cast<UCHAR>((extensionsLength >> 8) & 0xff);
        body[extensionsLengthOffset + 1] = static_cast<UCHAR>(extensionsLength & 0xff);

        UCHAR message[sizeof(body) + 4] = {};
        SIZE_T messageOffset = 0;
        message[messageOffset++] = static_cast<UCHAR>(TlsHandshakeType::ServerHello);
        message[messageOffset++] = static_cast<UCHAR>((bodyOffset >> 16) & 0xff);
        message[messageOffset++] = static_cast<UCHAR>((bodyOffset >> 8) & 0xff);
        message[messageOffset++] = static_cast<UCHAR>(bodyOffset & 0xff);
        memcpy(message + messageOffset, body, bodyOffset);
        messageOffset += bodyOffset;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::Handshake;
        plain.Version = { 3, 3 };
        plain.Fragment = message;
        plain.FragmentLength = messageOffset;
        const NTSTATUS status = TlsRecordLayer::EncodePlaintext(
            plain,
            record,
            recordCapacity,
            recordLength);
        return NT_SUCCESS(status);
    }

    bool BuildTls12ServerHelloRecordWithExtensions(
        bool includeTls13DowngradeSentinel,
        const UCHAR* extensions,
        SIZE_T extensionsLength,
        UCHAR* record,
        SIZE_T recordCapacity,
        SIZE_T* recordLength)
    {
        if (recordLength != nullptr) {
            *recordLength = 0;
        }
        if (record == nullptr ||
            recordLength == nullptr ||
            recordCapacity == 0 ||
            (extensions == nullptr && extensionsLength != 0) ||
            extensionsLength > 0xffff) {
            return false;
        }

        const UCHAR tls12DowngradeSentinel[] = {
            'D', 'O', 'W', 'N', 'G', 'R', 'D', 0x01
        };

        UCHAR body[96] = {};
        SIZE_T bodyOffset = 0;
        WriteUint16ForTest(body, &bodyOffset, 0x0303);
        for (SIZE_T index = 0; index < 32; ++index) {
            body[bodyOffset++] = static_cast<UCHAR>(0x40 + index);
        }
        if (includeTls13DowngradeSentinel) {
            memcpy(body + bodyOffset - sizeof(tls12DowngradeSentinel), tls12DowngradeSentinel, sizeof(tls12DowngradeSentinel));
        }
        body[bodyOffset++] = 0;
        WriteUint16ForTest(body, &bodyOffset, static_cast<USHORT>(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256));
        body[bodyOffset++] = 0;
        WriteUint16ForTest(body, &bodyOffset, static_cast<USHORT>(extensionsLength));
        if (extensionsLength != 0) {
            memcpy(body + bodyOffset, extensions, extensionsLength);
            bodyOffset += extensionsLength;
        }

        UCHAR message[sizeof(body) + 4] = {};
        SIZE_T messageOffset = 0;
        message[messageOffset++] = static_cast<UCHAR>(TlsHandshakeType::ServerHello);
        message[messageOffset++] = static_cast<UCHAR>((bodyOffset >> 16) & 0xff);
        message[messageOffset++] = static_cast<UCHAR>((bodyOffset >> 8) & 0xff);
        message[messageOffset++] = static_cast<UCHAR>(bodyOffset & 0xff);
        memcpy(message + messageOffset, body, bodyOffset);
        messageOffset += bodyOffset;

        TlsPlaintextRecord plain = {};
        plain.ContentType = TlsContentType::Handshake;
        plain.Version = { 3, 3 };
        plain.Fragment = message;
        plain.FragmentLength = messageOffset;
        const NTSTATUS status = TlsRecordLayer::EncodePlaintext(
            plain,
            record,
            recordCapacity,
            recordLength);
        return NT_SUCCESS(status);
    }

    bool BuildTls12ServerHelloRecord(
        bool includeTls13DowngradeSentinel,
        UCHAR* record,
        SIZE_T recordCapacity,
        SIZE_T* recordLength)
    {
        return BuildTls12ServerHelloRecordWithExtensions(
            includeTls13DowngradeSentinel,
            nullptr,
            0,
            record,
            recordCapacity,
            recordLength);
    }

    NTSTATUS ConnectTls12WithServerHelloExtensionsForTest(
        const UCHAR* extensions,
        SIZE_T extensionsLength,
        const TlsAlpnProtocol* alpnProtocols,
        SIZE_T alpnProtocolCount,
        TlsHandshakeFailureCategory* failureCategory)
    {
        if (failureCategory != nullptr) {
            *failureCategory = TlsHandshakeFailureCategory::None;
        }

        UCHAR record[256] = {};
        SIZE_T recordLength = 0;
        const bool built = BuildTls12ServerHelloRecordWithExtensions(
            false,
            extensions,
            extensionsLength,
            record,
            sizeof(record),
            &recordLength);
        Expect(built, "TLS 1.2 ServerHello extension fixture builds");
        if (!built) {
            return STATUS_INVALID_PARAMETER;
        }

        ScriptedTlsTransport transport(record, recordLength);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls12;
        options.MaximumProtocol = TlsProtocol::Tls12;
        options.AlpnProtocols = alpnProtocols;
        options.AlpnProtocolCount = alpnProtocolCount;

        const NTSTATUS status = connection.Connect(transport, options);
        if (failureCategory != nullptr) {
            *failureCategory = connection.LastHandshakeFailure().Category;
        }
        return status;
    }

    void TestTls13AttemptClassifiesTls12ServerHello()
    {
        UCHAR record[256] = {};
        SIZE_T recordLength = 0;
        const bool built = BuildTls12ServerHelloRecord(false, record, sizeof(record), &recordLength);
        Expect(built, "TLS 1.2 ServerHello fixture builds");
        if (!built) {
            return;
        }

        ScriptedTlsTransport transport(record, recordLength);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_NOT_SUPPORTED,
            "TLS1.3 attempt returns parser status for TLS1.2 ServerHello cipher selection");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::VersionNegotiation,
            "TLS1.2 ServerHello during TLS1.3 attempt is classified as version negotiation");
    }

    void TestTls13AttemptRejectsTls12DowngradeSentinel()
    {
        UCHAR record[256] = {};
        SIZE_T recordLength = 0;
        const bool built = BuildTls12ServerHelloRecord(true, record, sizeof(record), &recordLength);
        Expect(built, "TLS 1.2 downgrade ServerHello fixture builds");
        if (!built) {
            return;
        }

        ScriptedTlsTransport transport(record, recordLength);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(
            status,
            STATUS_INVALID_NETWORK_RESPONSE,
            "TLS1.3 attempt rejects TLS1.2 ServerHello with TLS1.3 downgrade sentinel");
        const auto& failure = connection.LastHandshakeFailure();
        Expect(
            failure.Category == TlsHandshakeFailureCategory::DecodeError,
            "TLS1.2 ServerHello with TLS1.3 downgrade sentinel is not a confirmation candidate");
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

    void TestTls13ServerHelloRejectsStrictnessViolations()
    {
        {
            UCHAR body[160] = {};
            SIZE_T offset = 0;
            BuildTls13ServerHelloBody(
                body,
                &offset,
                TlsCipherSuite::TlsAes128GcmSha256,
                false,
                TlsNamedGroup::Secp256r1);
            body[1] = 2;

            TlsHandshakeMessageView message = {};
            message.Type = TlsHandshakeType::ServerHello;
            message.Body = body;
            message.BodyLength = offset;

            TlsContext context;
            NTSTATUS status = context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for bad legacy_version test");
            Tls13ServerHelloView serverHello = {};
            status = TlsHandshake13::ParseServerHello(context, message, serverHello);
            ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 ServerHello rejects legacy_version other than 0x0303");
        }

        {
            UCHAR body[192] = {};
            SIZE_T offset = 0;
            BuildTls13ServerHelloBody(
                body,
                &offset,
                TlsCipherSuite::TlsAes128GcmSha256,
                false,
                TlsNamedGroup::Secp256r1);
            const UCHAR duplicateSupportedVersions[] = { 0, 43, 0, 2, 3, 4 };
            const bool appended = AppendServerHelloExtensionForTest(
                body,
                sizeof(body),
                &offset,
                duplicateSupportedVersions,
                sizeof(duplicateSupportedVersions));
            Expect(appended, "duplicate TLS 1.3 ServerHello extension fixture appends");
            if (!appended) {
                return;
            }

            TlsHandshakeMessageView message = {};
            message.Type = TlsHandshakeType::ServerHello;
            message.Body = body;
            message.BodyLength = offset;

            TlsContext context;
            NTSTATUS status = context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for duplicate ServerHello extension test");
            Tls13ServerHelloView serverHello = {};
            status = TlsHandshake13::ParseServerHello(context, message, serverHello);
            ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 ServerHello rejects duplicate extensions");
        }

        {
            UCHAR body[192] = {};
            SIZE_T offset = 0;
            BuildTls13ServerHelloBody(
                body,
                &offset,
                TlsCipherSuite::TlsAes128GcmSha256,
                false,
                TlsNamedGroup::Secp256r1);
            const UCHAR sessionId[] = { 0xaa };
            const bool inserted = InsertBytes(
                body,
                sizeof(body),
                &offset,
                35,
                sessionId,
                sizeof(sessionId));
            Expect(inserted, "TLS 1.3 non-empty session id fixture inserts");
            if (!inserted) {
                return;
            }
        body[34] = static_cast<UCHAR>(sizeof(sessionId));

            TlsHandshakeMessageView message = {};
            message.Type = TlsHandshakeType::ServerHello;
            message.Body = body;
            message.BodyLength = offset;

            TlsContext context;
            NTSTATUS status = context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for session id test");
            Tls13ServerHelloView serverHello = {};
            status = TlsHandshake13::ParseServerHello(context, message, serverHello);
            Expect(status == STATUS_SUCCESS, "TLS 1.3 ServerHello with session id parses structurally");

            const UCHAR publicKey[] = { 4, 1, 2, 3 };
            Tls13KeyShareEntry keyShare = {};
            keyShare.Group = TlsNamedGroup::Secp256r1;
            keyShare.KeyExchange = publicKey;
            keyShare.KeyExchangeLength = sizeof(publicKey);
            Tls13ClientHelloOptions options = {};
            options.KeyShares = &keyShare;
            options.KeyShareCount = 1;
            status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
            ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 ServerHello rejects non-empty legacy session id");
        }
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

    void TestTls13ServerHelloOfferValidation()
    {
        const UCHAR publicKey[] = { 4, 1, 2, 3 };
        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::Secp256r1;
        keyShare.KeyExchange = publicKey;
        keyShare.KeyExchangeLength = sizeof(publicKey);

        const TlsCipherSuite cipherSuites[] = {
            TlsCipherSuite::TlsAes128GcmSha256
        };
        const TlsNamedGroup namedGroups[] = {
            TlsNamedGroup::Secp256r1,
            TlsNamedGroup::Secp384r1
        };

        Tls13ClientHelloOptions options = {};
        options.CipherSuites = cipherSuites;
        options.CipherSuiteCount = sizeof(cipherSuites) / sizeof(cipherSuites[0]);
        options.NamedGroups = namedGroups;
        options.NamedGroupCount = sizeof(namedGroups) / sizeof(namedGroups[0]);
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;

        {
            UCHAR body[160] = {};
            SIZE_T offset = 0;
            BuildTls13ServerHelloBody(
                body,
                &offset,
                TlsCipherSuite::TlsAes256GcmSha384,
                false,
                TlsNamedGroup::Secp256r1);
            TlsHandshakeMessageView message = {};
            message.Type = TlsHandshakeType::ServerHello;
            message.Body = body;
            message.BodyLength = offset;

            TlsContext context;
            NTSTATUS status = context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for unoffered cipher");
            Tls13ServerHelloView serverHello = {};
            status = TlsHandshake13::ParseServerHello(context, message, serverHello);
            Expect(status == STATUS_SUCCESS, "TLS 1.3 unoffered cipher ServerHello parses structurally");
            status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 rejects unoffered ServerHello cipher suite");
        }

        {
            UCHAR body[160] = {};
            SIZE_T offset = 0;
            BuildTls13ServerHelloBody(
                body,
                &offset,
                TlsCipherSuite::TlsAes128GcmSha256,
                false,
                TlsNamedGroup::Secp384r1);
            TlsHandshakeMessageView message = {};
            message.Type = TlsHandshakeType::ServerHello;
            message.Body = body;
            message.BodyLength = offset;

            TlsContext context;
            NTSTATUS status = context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for unoffered key share");
            Tls13ServerHelloView serverHello = {};
            status = TlsHandshake13::ParseServerHello(context, message, serverHello);
            Expect(status == STATUS_SUCCESS, "TLS 1.3 unoffered key share ServerHello parses structurally");
            status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 rejects unoffered ServerHello key share group");
        }
    }

    void TestTls13HelloRetryRequestOfferValidation()
    {
        const UCHAR publicKey[] = { 4, 1, 2, 3 };
        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::Secp256r1;
        keyShare.KeyExchange = publicKey;
        keyShare.KeyExchangeLength = sizeof(publicKey);

        const TlsNamedGroup namedGroups[] = {
            TlsNamedGroup::Secp256r1,
            TlsNamedGroup::Secp384r1
        };

        Tls13ClientHelloOptions options = {};
        options.NamedGroups = namedGroups;
        options.NamedGroupCount = sizeof(namedGroups) / sizeof(namedGroups[0]);
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;

        {
            UCHAR body[160] = {};
            SIZE_T offset = 0;
            BuildTls13ServerHelloBody(
                body,
                &offset,
                TlsCipherSuite::TlsAes128GcmSha256,
                true,
                TlsNamedGroup::Secp256r1);
            TlsHandshakeMessageView message = {};
            message.Type = TlsHandshakeType::ServerHello;
            message.Body = body;
            message.BodyLength = offset;

            TlsContext context;
            NTSTATUS status = context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for HRR repeated group");
            Tls13ServerHelloView serverHello = {};
            status = TlsHandshake13::ParseServerHello(context, message, serverHello);
            Expect(status == STATUS_SUCCESS, "TLS 1.3 HRR repeated key share parses structurally");
            status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 HRR rejects group already sent as key_share");
        }

        {
            UCHAR body[160] = {};
            SIZE_T offset = 0;
            BuildTls13ServerHelloBody(
                body,
                &offset,
                TlsCipherSuite::TlsAes128GcmSha256,
                true,
                TlsNamedGroup::Secp521r1);
            TlsHandshakeMessageView message = {};
            message.Type = TlsHandshakeType::ServerHello;
            message.Body = body;
            message.BodyLength = offset;

            TlsContext context;
            NTSTATUS status = context.InitializeClient13();
            Expect(status == STATUS_SUCCESS, "TLS 1.3 context initializes for HRR unadvertised group");
            Tls13ServerHelloView serverHello = {};
            status = TlsHandshake13::ParseServerHello(context, message, serverHello);
            Expect(status == STATUS_SUCCESS, "TLS 1.3 HRR unadvertised group parses structurally");
            status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 HRR rejects unadvertised retry group");
        }
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

    void TestParseTls13EncryptedExtensionsRejectsDuplicateExtensions()
    {
        const UCHAR body[] = {
            0, 8,
            0, 42, 0, 0,
            0, 42, 0, 0
        };

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::EncryptedExtensions;
        message.Body = body;
        message.BodyLength = sizeof(body);

        Tls13EncryptedExtensionsView parsed = {};
        const NTSTATUS status = TlsHandshake13::ParseEncryptedExtensions(message, parsed);

        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 EncryptedExtensions rejects duplicate extensions");
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

    void TestParseTls13NewSessionTicketRejectsDuplicateExtensions()
    {
        const UCHAR body[] = {
            0, 0, 0, 10,
            1, 2, 3, 4,
            0,
            0, 3, 'p', 's', 'k',
            0, 8,
            0, 42, 0, 0,
            0, 42, 0, 0
        };

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::NewSessionTicket;
        message.Body = body;
        message.BodyLength = sizeof(body);

        Tls13NewSessionTicketView ticket = {};
        const NTSTATUS status = TlsHandshake13::ParseNewSessionTicket(message, ticket);

        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 NewSessionTicket rejects duplicate extensions");
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

    void TestParseTls13PostHandshakeRejectsKeyUpdate()
    {
        const UCHAR keyUpdate[] = {
            static_cast<UCHAR>(TlsHandshakeType::KeyUpdate), 0, 0, 1, 0
        };

        SIZE_T offset = 0;
        Tls13NewSessionTicketView ticket = {};
        const NTSTATUS status = TlsHandshake13::ParseNextNewSessionTicket(
            keyUpdate,
            sizeof(keyUpdate),
            &offset,
            ticket);

        ExpectStatus(status, STATUS_NOT_SUPPORTED, "TLS 1.3 post-handshake parser rejects KeyUpdate explicitly");
        Expect(offset == 0, "TLS 1.3 KeyUpdate rejection does not advance offset");
    }

    void TestParseTls13KeyUpdate()
    {
        const UCHAR body[] = {
            static_cast<UCHAR>(Tls13KeyUpdateRequest::UpdateRequested)
        };

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::KeyUpdate;
        message.Body = body;
        message.BodyLength = sizeof(body);

        Tls13KeyUpdateView keyUpdate = {};
        NTSTATUS status = TlsHandshake13::ParseKeyUpdate(message, keyUpdate);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 KeyUpdate parses");
        Expect(
            keyUpdate.Request == Tls13KeyUpdateRequest::UpdateRequested,
            "TLS 1.3 KeyUpdate request_update is retained");

        const UCHAR invalidBody[] = { 2 };
        message.Body = invalidBody;
        message.BodyLength = sizeof(invalidBody);
        status = TlsHandshake13::ParseKeyUpdate(message, keyUpdate);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 KeyUpdate rejects invalid request_update");
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
        const SIZE_T expectedInputLength =
            64 + (sizeof("TLS 1.3, server CertificateVerify") - 1) + 1 + sizeof(transcriptHash);

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
        Expect(written == expectedInputLength, "TLS 1.3 CertificateVerify reports actual required input length");

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
        Expect(written == expectedInputLength, "TLS 1.3 CertificateVerify uses SHA-384 transcript length");
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

    void TestTls13SelectedPskIdentityValidation()
    {
        Tls13ServerHelloView serverHello = {};
        serverHello.SelectedPskIdentity = 0xffff;
        NTSTATUS status = TlsHandshake13::ValidateSelectedPskIdentity(serverHello, 0);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 accepts absent selected_psk_identity without offered PSK");

        serverHello.SelectedPskIdentity = 0;
        status = TlsHandshake13::ValidateSelectedPskIdentity(serverHello, 0);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 rejects selected_psk_identity when no PSK was offered");

        serverHello.SelectedPskIdentity = 1;
        status = TlsHandshake13::ValidateSelectedPskIdentity(serverHello, 1);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.3 rejects out-of-range selected_psk_identity");

        serverHello.SelectedPskIdentity = 0;
        status = TlsHandshake13::ValidateSelectedPskIdentity(serverHello, 1);
        Expect(status == STATUS_SUCCESS, "TLS 1.3 accepts in-range selected_psk_identity");
    }

    void TestTls13TicketSelectionBindsContextAndAge()
    {
        Tls13SessionCache cache = {};
        FillMatchingTls13Ticket(cache.Tickets[0], TestCurrentMilliseconds() - 2000ULL);
        cache.TicketCount = 1;

        const TlsAlpnProtocol alpn[] = {
            { "h2", 2 }
        };

        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls13;
        options.MaximumProtocol = TlsProtocol::Tls13;
        options.AlpnProtocols = alpn;
        options.AlpnProtocolCount = 1;
        options.SessionCache = &cache;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.3 ticket test stops after ClientHello when peer disconnects");
        Expect(transport.SendCalls() == 1, "TLS 1.3 ticket test sends one ClientHello");

        TlsHandshakeMessageView clientHello = {};
        const bool parsed = ParseSentClientHello(transport, 0, clientHello);
        Expect(parsed, "TLS 1.3 ticket ClientHello parses from sent record");
        if (!parsed) {
            return;
        }

        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        const bool found = FindClientHelloExtension(clientHello.Body, clientHello.BodyLength, 41, &extension, &extensionLength);
        Expect(found, "TLS 1.3 matching ticket offers PSK extension");
        if (!found) {
            return;
        }

        ULONG obfuscatedAge = 0;
        Expect(ReadFirstPskIdentityAge(extension, extensionLength, &obfuscatedAge), "TLS 1.3 PSK identity age parses");
        Expect(obfuscatedAge >= 2007 && obfuscatedAge <= 6007, "TLS 1.3 PSK obfuscated age includes issue time delta and age_add");
        Expect(!ClientHelloHasExtension(clientHello.Body, clientHello.BodyLength, 42), "TLS 1.3 early_data is not offered by default");
    }

    void TestTls13TicketSelectionSkipsMismatches()
    {
        const TlsAlpnProtocol h2[] = {
            { "h2", 2 }
        };
        const TlsAlpnProtocol http11[] = {
            { "http/1.1", 8 }
        };

        Tls13SessionTicket ticket = {};
        FillMatchingTls13Ticket(ticket, TestCurrentMilliseconds() - 10000ULL);
        ticket.LifetimeSeconds = 1;
        Tls13SessionCache cache = {};
        cache.Tickets[0] = ticket;
        cache.TicketCount = 1;
        ScriptedTlsTransport expiredTransport(nullptr, 0);
        TlsConnection expiredConnection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls13;
        options.MaximumProtocol = TlsProtocol::Tls13;
        options.AlpnProtocols = h2;
        options.AlpnProtocolCount = 1;
        options.SessionCache = &cache;
        NTSTATUS status = expiredConnection.Connect(expiredTransport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.3 expired ticket test stops after ClientHello");
        Expect(!SentClientHelloHasExtension(expiredTransport, 0, 41), "TLS 1.3 expired ticket is not offered");

        FillMatchingTls13Ticket(cache.Tickets[0], TestCurrentMilliseconds() - 1000ULL);
        memcpy(cache.Tickets[0].ServerName, "other.example", 13);
        cache.Tickets[0].ServerNameLength = 13;
        ScriptedTlsTransport sniTransport(nullptr, 0);
        TlsConnection sniConnection;
        status = sniConnection.Connect(sniTransport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.3 SNI mismatch ticket test stops after ClientHello");
        Expect(!SentClientHelloHasExtension(sniTransport, 0, 41), "TLS 1.3 SNI-mismatched ticket is not offered");

        FillMatchingTls13Ticket(cache.Tickets[0], TestCurrentMilliseconds() - 1000ULL);
        options.AlpnProtocols = http11;
        options.AlpnProtocolCount = 1;
        ScriptedTlsTransport alpnTransport(nullptr, 0);
        TlsConnection alpnConnection;
        status = alpnConnection.Connect(alpnTransport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.3 ALPN mismatch ticket test stops after ClientHello");
        Expect(!SentClientHelloHasExtension(alpnTransport, 0, 41), "TLS 1.3 ALPN-mismatched ticket is not offered");

        FillMatchingTls13Ticket(cache.Tickets[0], TestCurrentMilliseconds() - 1000ULL);
        cache.Tickets[0].CipherSuite = TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256;
        options.AlpnProtocols = h2;
        options.AlpnProtocolCount = 1;
        ScriptedTlsTransport cipherTransport(nullptr, 0);
        TlsConnection cipherConnection;
        status = cipherConnection.Connect(cipherTransport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.3 cipher mismatch ticket test stops after ClientHello");
        Expect(!SentClientHelloHasExtension(cipherTransport, 0, 41), "TLS 1.3 non-TLS1.3-cipher ticket is not offered");
    }

    void TestTls13HelloRetryRequestRecomputesPskBinder()
    {
        UCHAR hrrRecord[256] = {};
        SIZE_T hrrRecordLength = 0;
        Expect(BuildHelloRetryRequestRecord(hrrRecord, sizeof(hrrRecord), &hrrRecordLength), "TLS 1.3 HRR record fixture builds");
        if (hrrRecordLength == 0) {
            return;
        }

        Tls13SessionCache cache = {};
        FillMatchingTls13Ticket(cache.Tickets[0], TestCurrentMilliseconds() - 1000ULL);
        cache.TicketCount = 1;

        const TlsAlpnProtocol alpn[] = {
            { "h2", 2 }
        };

        ScriptedTlsTransport transport(hrrRecord, hrrRecordLength);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls13;
        options.MaximumProtocol = TlsProtocol::Tls13;
        options.AlpnProtocols = alpn;
        options.AlpnProtocolCount = 1;
        options.SessionCache = &cache;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.3 HRR test stops after second ClientHello when peer disconnects");
        Expect(transport.SendCalls() == 2, "TLS 1.3 HRR sends a second ClientHello");

        TlsHandshakeMessageView firstClientHello = {};
        TlsHandshakeMessageView secondClientHello = {};
        const bool firstParsed = ParseSentClientHello(transport, 0, firstClientHello);
        const bool secondParsed = ParseSentClientHello(transport, 1, secondClientHello);
        Expect(firstParsed && secondParsed, "TLS 1.3 HRR ClientHellos parse from sent records");
        if (!firstParsed || !secondParsed) {
            return;
        }

        const UCHAR* firstExtension = nullptr;
        const UCHAR* secondExtension = nullptr;
        SIZE_T firstExtensionLength = 0;
        SIZE_T secondExtensionLength = 0;
        Expect(
            FindClientHelloExtension(firstClientHello.Body, firstClientHello.BodyLength, 41, &firstExtension, &firstExtensionLength),
            "TLS 1.3 first HRR ClientHello has PSK extension");
        Expect(
            FindClientHelloExtension(secondClientHello.Body, secondClientHello.BodyLength, 41, &secondExtension, &secondExtensionLength),
            "TLS 1.3 second HRR ClientHello has PSK extension");
        if (firstExtension == nullptr || secondExtension == nullptr) {
            return;
        }

        const UCHAR* firstBinder = nullptr;
        const UCHAR* secondBinder = nullptr;
        SIZE_T firstBinderLength = 0;
        SIZE_T secondBinderLength = 0;
        Expect(ReadFirstPskBinder(firstExtension, firstExtensionLength, &firstBinder, &firstBinderLength), "TLS 1.3 first HRR binder parses");
        Expect(ReadFirstPskBinder(secondExtension, secondExtensionLength, &secondBinder, &secondBinderLength), "TLS 1.3 second HRR binder parses");
        if (firstBinder == nullptr || secondBinder == nullptr || firstBinderLength != secondBinderLength) {
            return;
        }

        Expect(
            memcmp(firstBinder, secondBinder, firstBinderLength) != 0,
            "TLS 1.3 HRR second ClientHello recomputes PSK binder");
    }

    void TestTls13EarlyDataRequiresReplaySafe()
    {
        Tls13SessionCache cache = {};
        FillMatchingTls13Ticket(cache.Tickets[0], TestCurrentMilliseconds() - 1000ULL);
        cache.Tickets[0].MaxEarlyDataSize = 32;
        cache.TicketCount = 1;

        const TlsAlpnProtocol alpn[] = {
            { "h2", 2 }
        };
        const UCHAR earlyData[] = { 'G', 'E', 'T' };
        SIZE_T earlyDataBytesSent = 99;
        bool earlyDataAccepted = true;

        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls13;
        options.MaximumProtocol = TlsProtocol::Tls13;
        options.AlpnProtocols = alpn;
        options.AlpnProtocolCount = 1;
        options.SessionCache = &cache;
        options.EnableEarlyData = true;
        options.EarlyData = earlyData;
        options.EarlyDataLength = sizeof(earlyData);
        options.EarlyDataBytesSent = &earlyDataBytesSent;
        options.EarlyDataAccepted = &earlyDataAccepted;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "TLS 1.3 rejects 0-RTT without replay-safe opt-in");
        Expect(transport.SendCalls() == 0, "TLS 1.3 non replay-safe 0-RTT sends no data");
        Expect(earlyDataBytesSent == 0, "TLS 1.3 non replay-safe 0-RTT reports zero bytes sent");
        Expect(!earlyDataAccepted, "TLS 1.3 non replay-safe 0-RTT reports not accepted");
    }

    void TestTls12SessionCachePopulatesClientHello()
    {
        Tls12SessionCache cache = {};
        FillMatchingTls12Session(cache.Sessions[0], TestCurrentMilliseconds() - 1000ULL);
        cache.SessionCount = 1;

        const TlsAlpnProtocol alpn[] = {
            { "h2", 2 }
        };

        ScriptedTlsTransport transport(nullptr, 0);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls12;
        options.MaximumProtocol = TlsProtocol::Tls12;
        options.AlpnProtocols = alpn;
        options.AlpnProtocolCount = 1;
        options.Tls12SessionCache = &cache;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(status, STATUS_CONNECTION_DISCONNECTED, "TLS 1.2 session cache test stops after ClientHello");
        Expect(transport.SendCalls() == 1, "TLS 1.2 session cache test sends one ClientHello");

        TlsHandshakeMessageView clientHello = {};
        const bool parsed = ParseSentClientHello(transport, 0, clientHello);
        Expect(parsed, "TLS 1.2 session cache ClientHello parses from sent record");
        if (!parsed) {
            return;
        }

        Expect(
            ClientHelloSessionIdEquals(
                clientHello.Body,
                clientHello.BodyLength,
                cache.Sessions[0].SessionId,
                cache.Sessions[0].SessionIdLength),
            "TLS 1.2 session cache ClientHello carries cached session_id");
        Expect(
            ClientHelloExtensionPayloadEquals(
                clientHello.Body,
                clientHello.BodyLength,
                35,
                cache.Sessions[0].Ticket,
                cache.Sessions[0].TicketLength),
            "TLS 1.2 session cache ClientHello carries cached session ticket");
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

    void TestParseCertificateStatusMessage()
    {
        const UCHAR message[] = {
            22, 0, 0, 8,
            1,
            0, 0, 4,
            0xde, 0xad, 0xbe, 0xef
        };

        TlsHandshakeMessageView parsed = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(message, sizeof(message), parsed);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 CertificateStatus handshake parses");

        Tls12CertificateStatusView certificateStatus = {};
        status = TlsHandshake12::ParseCertificateStatus(parsed, certificateStatus);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 CertificateStatus payload parses");
        Expect(certificateStatus.StatusType == 1, "TLS 1.2 CertificateStatus status_type is OCSP");
        Expect(certificateStatus.OcspResponseLength == 4, "TLS 1.2 CertificateStatus OCSP response length parses");
        Expect(
            certificateStatus.OcspResponse != nullptr &&
                memcmp(certificateStatus.OcspResponse, message + 8, 4) == 0,
            "TLS 1.2 CertificateStatus OCSP response bytes parse");
    }

    void TestParseCertificateStatusRejectsMalformed()
    {
        const UCHAR emptyOcsp[] = {
            22, 0, 0, 4,
            1,
            0, 0, 0
        };
        TlsHandshakeMessageView parsed = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(emptyOcsp, sizeof(emptyOcsp), parsed);
        ExpectStatus(status, STATUS_SUCCESS, "malformed TLS 1.2 CertificateStatus parses generically");

        Tls12CertificateStatusView certificateStatus = {};
        status = TlsHandshake12::ParseCertificateStatus(parsed, certificateStatus);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 CertificateStatus rejects empty OCSP response");

        const UCHAR unsupportedType[] = {
            22, 0, 0, 5,
            2,
            0, 0, 1,
            0
        };
        status = TlsHandshake12::ParseMessage(unsupportedType, sizeof(unsupportedType), parsed);
        ExpectStatus(status, STATUS_SUCCESS, "unsupported TLS 1.2 CertificateStatus parses generically");
        status = TlsHandshake12::ParseCertificateStatus(parsed, certificateStatus);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 CertificateStatus rejects unsupported status_type");
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

    void TestParseTls12ServerHelloStrictExtensions()
    {
        const UCHAR strictExtensions[] = {
            0, 23, 0, 0,
            0xff, 0x01, 0, 1, 0
        };

        UCHAR body[128] = {};
        SIZE_T offset = 0;
        body[offset++] = 3;
        body[offset++] = 3;
        for (SIZE_T index = 0; index < 32; ++index) {
            body[offset++] = static_cast<UCHAR>(0x40 + index);
        }
        body[offset++] = 0;
        WriteUint16ForTest(
            body,
            &offset,
            static_cast<USHORT>(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256));
        body[offset++] = 0;
        WriteUint16ForTest(body, &offset, static_cast<USHORT>(sizeof(strictExtensions)));
        memcpy(body + offset, strictExtensions, sizeof(strictExtensions));
        offset += sizeof(strictExtensions);

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = body;
        message.BodyLength = offset;

        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for strict ServerHello extension test");

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context, message, serverHello);

        Expect(status == STATUS_SUCCESS, "TLS 1.2 ServerHello strict extensions parse");
        Expect(serverHello.HasExtendedMasterSecret, "TLS 1.2 ServerHello reports extended_master_secret");
        Expect(serverHello.HasSecureRenegotiation, "TLS 1.2 ServerHello reports secure renegotiation");
        Expect(serverHello.SecureRenegotiationDataLength == 0, "TLS 1.2 initial ServerHello reports empty renegotiation_info");

        UCHAR renegotiationData[TlsVerifyDataLength * 2] = {};
        for (SIZE_T index = 0; index < sizeof(renegotiationData); ++index) {
            renegotiationData[index] = static_cast<UCHAR>(0xa0 + index);
        }

        UCHAR renegotiationExtensions[4 + 4 + 1 + sizeof(renegotiationData)] = {};
        SIZE_T renegotiationExtensionOffset = 0;
        WriteUint16ForTest(renegotiationExtensions, &renegotiationExtensionOffset, 23);
        WriteUint16ForTest(renegotiationExtensions, &renegotiationExtensionOffset, 0);
        WriteUint16ForTest(renegotiationExtensions, &renegotiationExtensionOffset, 0xff01);
        WriteUint16ForTest(
            renegotiationExtensions,
            &renegotiationExtensionOffset,
            static_cast<USHORT>(1 + sizeof(renegotiationData)));
        renegotiationExtensions[renegotiationExtensionOffset++] = static_cast<UCHAR>(sizeof(renegotiationData));
        memcpy(renegotiationExtensions + renegotiationExtensionOffset, renegotiationData, sizeof(renegotiationData));
        renegotiationExtensionOffset += sizeof(renegotiationData);

        UCHAR renegotiationBody[128] = {};
        SIZE_T renegotiationOffset = 0;
        renegotiationBody[renegotiationOffset++] = 3;
        renegotiationBody[renegotiationOffset++] = 3;
        for (SIZE_T index = 0; index < 32; ++index) {
            renegotiationBody[renegotiationOffset++] = static_cast<UCHAR>(0x60 + index);
        }
        renegotiationBody[renegotiationOffset++] = 0;
        WriteUint16ForTest(
            renegotiationBody,
            &renegotiationOffset,
            static_cast<USHORT>(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256));
        renegotiationBody[renegotiationOffset++] = 0;
        WriteUint16ForTest(
            renegotiationBody,
            &renegotiationOffset,
            static_cast<USHORT>(renegotiationExtensionOffset));
        memcpy(renegotiationBody + renegotiationOffset, renegotiationExtensions, renegotiationExtensionOffset);
        renegotiationOffset += renegotiationExtensionOffset;

        message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = renegotiationBody;
        message.BodyLength = renegotiationOffset;

        status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context reinitializes for renegotiation_info ServerHello test");
        serverHello = {};
        status = TlsHandshake12::ParseServerHello(context, message, serverHello);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 renegotiation ServerHello parses secure renegotiation payload");
        Expect(serverHello.HasSecureRenegotiation, "TLS 1.2 renegotiation ServerHello reports secure renegotiation");
        Expect(
            serverHello.SecureRenegotiationDataLength == sizeof(renegotiationData),
            "TLS 1.2 renegotiation ServerHello exposes verify_data pair length");
        Expect(
            serverHello.SecureRenegotiationData != nullptr &&
                memcmp(serverHello.SecureRenegotiationData, renegotiationData, sizeof(renegotiationData)) == 0,
            "TLS 1.2 renegotiation ServerHello exposes verify_data pair bytes");

        const UCHAR malformedRenegotiationExtensions[] = {
            0, 23, 0, 0,
            0xff, 0x01, 0, 2, 2
        };
        UCHAR malformedBody[128] = {};
        SIZE_T malformedOffset = 0;
        malformedBody[malformedOffset++] = 3;
        malformedBody[malformedOffset++] = 3;
        for (SIZE_T index = 0; index < 32; ++index) {
            malformedBody[malformedOffset++] = static_cast<UCHAR>(0x70 + index);
        }
        malformedBody[malformedOffset++] = 0;
        WriteUint16ForTest(
            malformedBody,
            &malformedOffset,
            static_cast<USHORT>(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256));
        malformedBody[malformedOffset++] = 0;
        WriteUint16ForTest(malformedBody, &malformedOffset, static_cast<USHORT>(sizeof(malformedRenegotiationExtensions)));
        memcpy(malformedBody + malformedOffset, malformedRenegotiationExtensions, sizeof(malformedRenegotiationExtensions));
        malformedOffset += sizeof(malformedRenegotiationExtensions);

        message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = malformedBody;
        message.BodyLength = malformedOffset;

        status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context reinitializes for malformed renegotiation_info test");
        serverHello = {};
        status = TlsHandshake12::ParseServerHello(context, message, serverHello);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 ServerHello rejects malformed renegotiation_info length");

        const UCHAR duplicateExtensions[] = {
            0, 23, 0, 0,
            0, 23, 0, 0
        };

        UCHAR duplicateBody[128] = {};
        SIZE_T duplicateOffset = 0;
        duplicateBody[duplicateOffset++] = 3;
        duplicateBody[duplicateOffset++] = 3;
        for (SIZE_T index = 0; index < 32; ++index) {
            duplicateBody[duplicateOffset++] = static_cast<UCHAR>(0x50 + index);
        }
        duplicateBody[duplicateOffset++] = 0;
        WriteUint16ForTest(
            duplicateBody,
            &duplicateOffset,
            static_cast<USHORT>(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256));
        duplicateBody[duplicateOffset++] = 0;
        WriteUint16ForTest(duplicateBody, &duplicateOffset, static_cast<USHORT>(sizeof(duplicateExtensions)));
        memcpy(duplicateBody + duplicateOffset, duplicateExtensions, sizeof(duplicateExtensions));
        duplicateOffset += sizeof(duplicateExtensions);

        message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = duplicateBody;
        message.BodyLength = duplicateOffset;

        status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context reinitializes for duplicate extension test");
        serverHello = {};
        status = TlsHandshake12::ParseServerHello(context, message, serverHello);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 ServerHello rejects duplicate extensions");
    }

    void TestTls12ConnectionRejectsServerHelloWithoutEms()
    {
        UCHAR record[256] = {};
        SIZE_T recordLength = 0;
        const bool built = BuildTls12ServerHelloRecord(false, record, sizeof(record), &recordLength);
        Expect(built, "TLS 1.2 ServerHello without EMS fixture builds");
        if (!built) {
            return;
        }

        ScriptedTlsTransport transport(record, recordLength);
        TlsConnection connection;
        TlsClientConnectionOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.VerifyCertificate = false;
        options.MinimumProtocol = TlsProtocol::Tls12;
        options.MaximumProtocol = TlsProtocol::Tls12;

        const NTSTATUS status = connection.Connect(transport, options);
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "TLS 1.2 connection rejects ServerHello without EMS");
        Expect(
            connection.LastHandshakeFailure().Category == TlsHandshakeFailureCategory::LocalPolicy,
            "TLS 1.2 missing EMS is recorded as local policy");
    }

    void TestTls12ServerHelloAlpnStrictness()
    {
        const TlsAlpnProtocol h2[] = {
            { "h2", 2 }
        };
        const TlsAlpnProtocol http11[] = {
            { "http/1.1", 8 }
        };

        const UCHAR malformedListLength[] = {
            0, 23, 0, 0,
            0xff, 0x01, 0, 1, 0,
            0, 16, 0, 5, 0, 4, 2, 'h', '2'
        };
        TlsHandshakeFailureCategory category = TlsHandshakeFailureCategory::None;
        NTSTATUS status = ConnectTls12WithServerHelloExtensionsForTest(
            malformedListLength,
            sizeof(malformedListLength),
            h2,
            sizeof(h2) / sizeof(h2[0]),
            &category);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 ServerHello ALPN rejects mismatched list length");
        Expect(category == TlsHandshakeFailureCategory::DecodeError, "TLS 1.2 malformed ALPN is recorded as decode error");

        const UCHAR trailingGarbage[] = {
            0, 23, 0, 0,
            0xff, 0x01, 0, 1, 0,
            0, 16, 0, 6, 0, 4, 2, 'h', '2', 0
        };
        category = TlsHandshakeFailureCategory::None;
        status = ConnectTls12WithServerHelloExtensionsForTest(
            trailingGarbage,
            sizeof(trailingGarbage),
            h2,
            sizeof(h2) / sizeof(h2[0]),
            &category);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 ServerHello ALPN rejects trailing bytes");
        Expect(category == TlsHandshakeFailureCategory::DecodeError, "TLS 1.2 trailing ALPN bytes are recorded as decode error");

        const UCHAR multipleProtocols[] = {
            0, 23, 0, 0,
            0xff, 0x01, 0, 1, 0,
            0, 16, 0, 8, 0, 6, 2, 'h', '2', 2, 'h', '3'
        };
        category = TlsHandshakeFailureCategory::None;
        status = ConnectTls12WithServerHelloExtensionsForTest(
            multipleProtocols,
            sizeof(multipleProtocols),
            h2,
            sizeof(h2) / sizeof(h2[0]),
            &category);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 ServerHello ALPN rejects multiple selected protocols");
        Expect(category == TlsHandshakeFailureCategory::DecodeError, "TLS 1.2 multiple ALPN protocols are recorded as decode error");

        const UCHAR selectedH2[] = {
            0, 23, 0, 0,
            0xff, 0x01, 0, 1, 0,
            0, 16, 0, 5, 0, 3, 2, 'h', '2'
        };
        category = TlsHandshakeFailureCategory::None;
        status = ConnectTls12WithServerHelloExtensionsForTest(
            selectedH2,
            sizeof(selectedH2),
            http11,
            sizeof(http11) / sizeof(http11[0]),
            &category);
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "TLS 1.2 ServerHello ALPN rejects unoffered protocol");
        Expect(category == TlsHandshakeFailureCategory::AlpnMismatch, "TLS 1.2 unoffered ALPN is recorded as ALPN mismatch");
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

    void TestParseWsPostmanEchoServerKeyExchange()
    {
        UCHAR body[329] = {};
        SIZE_T bodyLength = 0;
        const bool loaded = ReadFileBytes(
            WsPostmanEchoServerKeyExchangePath,
            body,
            sizeof(body),
            &bodyLength);
        Expect(loaded, "ws.postman-echo.com ServerKeyExchange fixture loads");
        Expect(bodyLength == 329, "ws.postman-echo.com ServerKeyExchange body length matches");

        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "context initializes for ws.postman-echo.com ServerKeyExchange");
        status = context.SetCipherSuite(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256);
        Expect(status == STATUS_SUCCESS, "context selects TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::ServerKeyExchange;
        message.Body = body;
        message.BodyLength = bodyLength;

        TlsServerKeyExchangeView keyExchange = {};
        status = TlsHandshake12::ParseServerKeyExchange(context, message, keyExchange);

        Expect(status == STATUS_SUCCESS, "ws.postman-echo.com ServerKeyExchange parses");
        Expect(keyExchange.NamedGroup == TlsNamedGroup::Secp256r1,
            "ws.postman-echo.com ServerKeyExchange named group parses");
        Expect(keyExchange.EcPointLength == 65,
            "ws.postman-echo.com ServerKeyExchange EC point length parses");
        Expect(keyExchange.SignatureScheme == TlsSignatureScheme::RsaPkcs1Sha256,
            "ws.postman-echo.com ServerKeyExchange signature scheme parses");
        Expect(keyExchange.SignatureLength == 256,
            "ws.postman-echo.com ServerKeyExchange signature length parses");
    }

    void TestTls12ServerHelloOfferValidation()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for offer validation");

        UCHAR body[96] = {};
        SIZE_T offset = 0;
        body[offset++] = 3;
        body[offset++] = 3;
        for (SIZE_T index = 0; index < 32; ++index) {
            body[offset++] = static_cast<UCHAR>(0x40 + index);
        }
        body[offset++] = 0;
        WriteUint16ForTest(
            body,
            &offset,
            static_cast<USHORT>(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256));
        body[offset++] = 0;
        body[offset++] = 0;
        body[offset++] = 0;

        TlsHandshakeMessageView message = {};
        message.Type = TlsHandshakeType::ServerHello;
        message.Body = body;
        message.BodyLength = offset;

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context, message, serverHello);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 ServerHello parses structurally for offer validation");

        const TlsCipherSuite cipherSuites[] = {
            TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256
        };
        TlsClientHelloOptions options = {};
        options.CipherSuites = cipherSuites;
        options.CipherSuiteCount = sizeof(cipherSuites) / sizeof(cipherSuites[0]);

        status = TlsHandshake12::ValidateServerHelloOffer(serverHello, options);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 rejects unoffered ServerHello cipher suite");
    }

    void TestTls12ServerKeyExchangeOfferValidation()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for ServerKeyExchange offer validation");

        UCHAR point[65] = {};
        point[0] = 4;
        for (SIZE_T index = 1; index < sizeof(point); ++index) {
            point[index] = static_cast<UCHAR>(index);
        }

        UCHAR body[160] = {};
        SIZE_T offset = 0;
        body[offset++] = 3;
        WriteUint16ForTest(body, &offset, static_cast<USHORT>(TlsNamedGroup::Secp256r1));
        body[offset++] = sizeof(point);
        memcpy(body + offset, point, sizeof(point));
        offset += sizeof(point);
        WriteUint16ForTest(body, &offset, static_cast<USHORT>(TlsSignatureScheme::RsaPkcs1Sha256));
        WriteUint16ForTest(body, &offset, 4);
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
        Expect(status == STATUS_SUCCESS, "TLS 1.2 ServerKeyExchange parses structurally for offer validation");

        const TlsNamedGroup namedGroups[] = {
            TlsNamedGroup::Secp384r1
        };
        TlsClientHelloOptions groupOptions = {};
        groupOptions.NamedGroups = namedGroups;
        groupOptions.NamedGroupCount = sizeof(namedGroups) / sizeof(namedGroups[0]);
        status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, groupOptions);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 rejects unoffered ServerKeyExchange group");

        const TlsSignatureScheme signatureSchemes[] = {
            TlsSignatureScheme::EcdsaSecp256r1Sha256
        };
        TlsClientHelloOptions signatureOptions = {};
        signatureOptions.SignatureSchemes = signatureSchemes;
        signatureOptions.SignatureSchemeCount = sizeof(signatureSchemes) / sizeof(signatureSchemes[0]);
        status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, signatureOptions);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "TLS 1.2 rejects unoffered ServerKeyExchange signature scheme");

        TlsContext sha1Context;
        status = sha1Context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS 1.2 context initializes for SHA1 ServerKeyExchange offer validation");

        offset = 0;
        body[offset++] = 3;
        WriteUint16ForTest(body, &offset, static_cast<USHORT>(TlsNamedGroup::Secp256r1));
        body[offset++] = sizeof(point);
        memcpy(body + offset, point, sizeof(point));
        offset += sizeof(point);
        WriteUint16ForTest(body, &offset, static_cast<USHORT>(TlsSignatureScheme::RsaPkcs1Sha1));
        WriteUint16ForTest(body, &offset, 4);
        body[offset++] = 1;
        body[offset++] = 2;
        body[offset++] = 3;
        body[offset++] = 4;

        message.BodyLength = offset;
        keyExchange = {};
        status = TlsHandshake12::ParseServerKeyExchange(sha1Context, message, keyExchange);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 rsa_pkcs1_sha1 ServerKeyExchange parses structurally");
        Expect(
            keyExchange.SignatureScheme == TlsSignatureScheme::RsaPkcs1Sha1,
            "TLS 1.2 rsa_pkcs1_sha1 ServerKeyExchange signature scheme parses");

        TlsClientHelloOptions modernOptions = {};
        status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, modernOptions);
        Expect(
            status == STATUS_INVALID_NETWORK_RESPONSE,
            "TLS 1.2 modern offer rejects unoffered rsa_pkcs1_sha1 ServerKeyExchange");

        const TlsSignatureScheme sha1SignatureSchemes[] = {
            TlsSignatureScheme::RsaPkcs1Sha1
        };
        TlsClientHelloOptions sha1Options = {};
        sha1Options.SignatureSchemes = sha1SignatureSchemes;
        sha1Options.SignatureSchemeCount = sizeof(sha1SignatureSchemes) / sizeof(sha1SignatureSchemes[0]);
        status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, sha1Options);
        Expect(status == STATUS_SUCCESS, "TLS 1.2 accepts offered rsa_pkcs1_sha1 ServerKeyExchange");
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

        const char notBefore[] = "260608144411Z";
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

    void TestCertificateParserRejectsNonMinimalDerLengths()
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
        Expect(loaded, "localhost certificate fixture loads for non-minimal length tests");
        if (!loaded) {
            return;
        }

        UCHAR leadingZeroLength[TestMaxDerCertificateLength + 16] = {};
        leadingZeroLength[0] = 0x30;
        leadingZeroLength[1] = 0x83;
        leadingZeroLength[2] = 0x00;
        leadingZeroLength[3] = der[2];
        leadingZeroLength[4] = der[3];
        memcpy(leadingZeroLength + 5, der + 4, derLength - 4);

        ParsedCertificate parsed = {};
        NTSTATUS status = CertificateValidator::ParseCertificate(leadingZeroLength, derLength + 1, parsed);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects DER length with leading zero length octet");

        const UCHAR versionHeader[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
        SIZE_T versionOffset = 0;
        const bool foundVersion = FindBytes(der, derLength, versionHeader, sizeof(versionHeader), 0, &versionOffset);
        Expect(foundVersion, "localhost certificate version header is found for non-minimal short length test");
        if (!foundVersion) {
            return;
        }

        UCHAR longFormShortLength[TestMaxDerCertificateLength + 16] = {};
        memcpy(longFormShortLength, der, derLength);
        SIZE_T longFormShortLengthLength = derLength;
        const UCHAR longFormMarker[] = { 0x81 };
        const bool inserted = InsertBytes(
            longFormShortLength,
            sizeof(longFormShortLength),
            &longFormShortLengthLength,
            versionOffset + 1,
            longFormMarker,
            sizeof(longFormMarker));
        Expect(inserted, "non-minimal short length mutation is inserted");
        if (!inserted) {
            return;
        }

        WriteBigEndian16(longFormShortLength, 2, static_cast<USHORT>(ReadBigEndian16(der, 2) + 1));
        WriteBigEndian16(longFormShortLength, 6, static_cast<USHORT>(ReadBigEndian16(der, 6) + 1));

        parsed = {};
        status = CertificateValidator::ParseCertificate(longFormShortLength, longFormShortLengthLength, parsed);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects long-form DER length for short value");
    }

    void TestCertificateParserRejectsRedundantUnsignedIntegerEncoding()
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
        Expect(loaded, "localhost certificate fixture loads for redundant integer test");
        if (!loaded) {
            return;
        }

        const UCHAR basicConstraintsValue[] = { 0x04, 0x02, 0x30, 0x00 };
        SIZE_T valueOffset = 0;
        const bool foundValue = FindBytes(
            der,
            derLength,
            basicConstraintsValue,
            sizeof(basicConstraintsValue),
            0,
            &valueOffset);
        Expect(foundValue, "localhost certificate Basic Constraints value is found");
        if (!foundValue) {
            return;
        }

        UCHAR mutated[TestMaxDerCertificateLength + 16] = {};
        memcpy(mutated, der, derLength);
        SIZE_T mutatedLength = derLength;
        const UCHAR insertedBytes[] = { 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x00 };
        const bool inserted = InsertBytes(
            mutated,
            sizeof(mutated),
            &mutatedLength,
            valueOffset + sizeof(basicConstraintsValue),
            insertedBytes,
            sizeof(insertedBytes));
        Expect(inserted, "redundant integer Basic Constraints mutation is inserted");
        if (!inserted) {
            return;
        }

        const UCHAR replacementValue[] = { 0x04, 0x09, 0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x00 };
        memcpy(mutated + valueOffset, replacementValue, sizeof(replacementValue));
        WriteBigEndian16(mutated, 2, static_cast<USHORT>(ReadBigEndian16(der, 2) + 7));
        WriteBigEndian16(mutated, 6, static_cast<USHORT>(ReadBigEndian16(der, 6) + 7));
        mutated[valueOffset - 14] = static_cast<UCHAR>(mutated[valueOffset - 14] + 7);
        mutated[valueOffset - 11] = static_cast<UCHAR>(mutated[valueOffset - 11] + 7);
        mutated[valueOffset - 9] = static_cast<UCHAR>(mutated[valueOffset - 9] + 7);

        ParsedCertificate parsed = {};
        const NTSTATUS status = CertificateValidator::ParseCertificate(mutated, mutatedLength, parsed);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects redundant DER unsigned integer zero");
    }

    void TestCertificateParserRejectsSubjectAltNameOverflow()
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
        Expect(loaded, "localhost certificate fixture loads for SAN overflow test");
        if (!loaded) {
            return;
        }

        const UCHAR originalSan[] = {
            0x30, 0x23,
            0x82, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
            0x87, 0x04, 0x7f, 0x00, 0x00, 0x01,
            0x87, 0x10,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01
        };
        SIZE_T sanOffset = 0;
        const bool foundSan = FindBytes(der, derLength, originalSan, sizeof(originalSan), 0, &sanOffset);
        Expect(foundSan, "localhost certificate SAN value is found");
        if (!foundSan) {
            return;
        }

        const UCHAR overflowSan[] = {
            0x30, 0x23,
            0x82, 0x01, 'a',
            0x82, 0x01, 'b',
            0x82, 0x01, 'c',
            0x82, 0x01, 'd',
            0x82, 0x01, 'e',
            0x82, 0x01, 'f',
            0x82, 0x01, 'g',
            0x82, 0x01, 'h',
            0x82, 0x09, 'o', 'v', 'e', 'r', 'f', 'l', 'o', 'w', 'x'
        };
        static_assert(sizeof(overflowSan) == sizeof(originalSan), "SAN overflow fixture must preserve certificate lengths");

        UCHAR mutated[TestMaxDerCertificateLength] = {};
        memcpy(mutated, der, derLength);
        memcpy(mutated + sanOffset, overflowSan, sizeof(overflowSan));

        ParsedCertificate parsed = {};
        const NTSTATUS status = CertificateValidator::ParseCertificate(mutated, derLength, parsed);
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "certificate parser rejects SAN lists beyond fixed parsed capacity");
    }

    void TestCertificateParserRejectsSignatureAlgorithmMismatch()
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
        Expect(loaded, "localhost certificate fixture loads for signature algorithm mismatch test");
        if (!loaded) {
            return;
        }

        const UCHAR sha256WithRsaOid[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
        SIZE_T innerOidOffset = 0;
        const bool foundInnerOid = FindBytes(
            der,
            derLength,
            sha256WithRsaOid,
            sizeof(sha256WithRsaOid),
            0,
            &innerOidOffset);
        Expect(foundInnerOid, "localhost certificate inner signature OID is found");
        if (!foundInnerOid) {
            return;
        }

        der[innerOidOffset + sizeof(sha256WithRsaOid) - 1] = 0x0c;

        ParsedCertificate parsed = {};
        const NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects TBSCertificate/outer signatureAlgorithm mismatch");
    }

    void TestCertificateParserRejectsDuplicateExtensionOid()
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
        Expect(loaded, "localhost certificate fixture loads for duplicate extension OID test");
        if (!loaded) {
            return;
        }

        const UCHAR subjectAltNameOid[] = { 0x55, 0x1d, 0x11 };
        const UCHAR extendedKeyUsageOid[] = { 0x55, 0x1d, 0x25 };
        SIZE_T sanOidOffset = 0;
        const bool foundSanOid = FindBytes(
            der,
            derLength,
            subjectAltNameOid,
            sizeof(subjectAltNameOid),
            0,
            &sanOidOffset);
        Expect(foundSanOid, "localhost certificate SAN OID is found for duplicate extension OID test");
        if (!foundSanOid) {
            return;
        }

        memcpy(der + sanOidOffset, extendedKeyUsageOid, sizeof(extendedKeyUsageOid));

        ParsedCertificate parsed = {};
        const NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects duplicate certificate extension OIDs");
    }

    void TestCertificateParserRejectsUnknownCriticalExtension()
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
        Expect(loaded, "localhost certificate fixture loads for unknown critical extension test");
        if (!loaded) {
            return;
        }

        const UCHAR keyUsageOid[] = { 0x55, 0x1d, 0x0f };
        SIZE_T keyUsageOidOffset = 0;
        const bool foundKeyUsageOid = FindBytes(
            der,
            derLength,
            keyUsageOid,
            sizeof(keyUsageOid),
            0,
            &keyUsageOidOffset);
        Expect(foundKeyUsageOid, "localhost certificate KeyUsage OID is found for unknown critical extension test");
        if (!foundKeyUsageOid) {
            return;
        }

        der[keyUsageOidOffset + 2] = 0x7f;

        ParsedCertificate parsed = {};
        const NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects unknown critical extensions");
    }

    void TestCertificateValidationAcceptsNonCriticalCertificatePolicies()
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
        Expect(loaded, "localhost certificate fixture loads for certificatePolicies test");
        if (!loaded) {
            return;
        }

        const bool patched = PatchSubjectAltNameAsCertificatePolicies(
            der,
            sizeof(der),
            &derLength,
            false,
            false);
        Expect(patched, "localhost certificate receives non-critical certificatePolicies fixture");
        if (!patched) {
            return;
        }

        ParsedCertificate parsed = {};
        NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        Expect(status == STATUS_SUCCESS, "certificate parser accepts valid non-critical certificatePolicies extension");
        Expect(parsed.HasCertificatePolicies, "certificate parser records certificatePolicies presence");
        Expect(!parsed.CertificatePoliciesCritical, "certificate parser records non-critical certificatePolicies criticality");
        if (!NT_SUCCESS(status)) {
            return;
        }

        const bool rebuilt = RebuildCertificateList(
            der,
            derLength,
            certificateList,
            sizeof(certificateList),
            &certificateListLength);
        Expect(rebuilt, "certificate list rebuilds for certificatePolicies validation test");
        if (!rebuilt) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions options = {};
        options.HostName = "localhost";
        options.HostNameLength = strlen(options.HostName);

        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "non-critical certificatePolicies reaches normal trust evaluation");
    }

    void TestCertificateValidationRejectsCriticalCertificatePoliciesExtension()
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
        Expect(loaded, "localhost certificate fixture loads for critical certificatePolicies test");
        if (!loaded) {
            return;
        }

        const bool patched = PatchSubjectAltNameAsCertificatePolicies(
            der,
            sizeof(der),
            &derLength,
            true,
            false);
        Expect(patched, "localhost certificate receives critical certificatePolicies fixture");
        if (!patched) {
            return;
        }

        ParsedCertificate parsed = {};
        NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        Expect(status == STATUS_SUCCESS, "certificate parser accepts syntactically valid critical certificatePolicies");
        Expect(parsed.HasCertificatePolicies, "certificate parser records critical certificatePolicies presence");
        Expect(parsed.CertificatePoliciesCritical, "certificate parser records critical certificatePolicies criticality");
        if (!NT_SUCCESS(status)) {
            return;
        }

        const bool rebuilt = RebuildCertificateList(
            der,
            derLength,
            certificateList,
            sizeof(certificateList),
            &certificateListLength);
        Expect(rebuilt, "certificate list rebuilds for critical certificatePolicies validation test");
        if (!rebuilt) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions options = {};
        options.HostName = "localhost";
        options.HostNameLength = strlen(options.HostName);

        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "critical certificatePolicies are processed before normal trust evaluation");
    }

    void TestCertificateValidationRejectsMalformedCertificatePoliciesExtension()
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
        Expect(loaded, "localhost certificate fixture loads for malformed certificatePolicies test");
        if (!loaded) {
            return;
        }

        const bool patched = PatchSubjectAltNameAsCertificatePolicies(
            der,
            sizeof(der),
            &derLength,
            false,
            true);
        Expect(patched, "localhost certificate receives malformed certificatePolicies fixture");
        if (!patched) {
            return;
        }

        ParsedCertificate parsed = {};
        const NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate parser rejects malformed certificatePolicies DER");
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

    void TestCertificateValidationPinDoesNotCreateTrust()
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
        Expect(loaded, "localhost certificate fixture loads for pin trust test");
        if (!loaded) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions skipOptions = {};
        skipOptions.VerifyCertificate = false;
        CertificateValidationResult result = {};
        NTSTATUS status = CertificateValidator::ValidateChain(chain, skipOptions, &result);
        Expect(status == STATUS_SUCCESS, "certificate validation skip computes leaf SPKI pin material");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificatePin pin = {};
        pin.HostName = "localhost";
        pin.HostNameLength = strlen(pin.HostName);
        memcpy(pin.LeafSubjectPublicKeySha256, result.LeafSubjectPublicKeySha256, sizeof(pin.LeafSubjectPublicKeySha256));

        CertificateStoreOptions storeOptions = {};
        storeOptions.Pins = &pin;
        storeOptions.PinCount = 1;

        CertificateStore store;
        status = store.Initialize(storeOptions);
        Expect(status == STATUS_SUCCESS, "certificate store accepts pin without trust anchor");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateValidationOptions options = {};
        options.HostName = "localhost";
        options.HostNameLength = strlen(options.HostName);
        options.Store = &store;

        status = CertificateValidator::ValidateChain(chain, options);
        Expect(status == STATUS_TRUST_FAILURE, "matching pin does not create certificate trust without an anchor");
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

    void TestCertificateValidationBuildsUnorderedExternalPath()
    {
        UCHAR rootPem[TestMaxPemCertificateLength] = {};
        UCHAR rootDer[TestMaxDerCertificateLength] = {};
        UCHAR intermediatePem[TestMaxPemCertificateLength] = {};
        UCHAR intermediateDer[TestMaxDerCertificateLength] = {};
        UCHAR leafPem[TestMaxPemCertificateLength] = {};
        UCHAR leafDer[TestMaxDerCertificateLength] = {};
        SIZE_T rootPemLength = 0;
        SIZE_T rootDerLength = 0;
        SIZE_T intermediatePemLength = 0;
        SIZE_T intermediateDerLength = 0;
        SIZE_T leafPemLength = 0;
        SIZE_T leafDerLength = 0;

        const bool loaded =
            LoadPemCertificate(PkiRootCertificatePath, rootPem, sizeof(rootPem), &rootPemLength, rootDer, sizeof(rootDer), &rootDerLength) &&
            LoadPemCertificate(PkiIntermediateCertificatePath, intermediatePem, sizeof(intermediatePem), &intermediatePemLength, intermediateDer, sizeof(intermediateDer), &intermediateDerLength) &&
            LoadPemCertificate(PkiLeafCertificatePath, leafPem, sizeof(leafPem), &leafPemLength, leafDer, sizeof(leafDer), &leafDerLength);
        Expect(loaded, "PKI chain fixtures load for unordered path test");
        if (!loaded) {
            return;
        }

        UCHAR certificateList[TestMaxCertificateListLength] = {};
        SIZE_T certificateListLength = 0;
        bool appended = AppendCertificateToList(intermediateDer, intermediateDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        appended = appended && AppendCertificateToList(leafDer, leafDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        Expect(appended, "unordered certificate list is built");
        if (!appended) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = rootPem;
        bundle.DataLength = rootPemLength;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;

        CertificateStore store;
        NTSTATUS status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts root authority bundle");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 2;

        CertificateValidationOptions options = {};
        options.HostName = "www.example.test";
        options.HostNameLength = strlen(options.HostName);
        options.Store = &store;

        CertificateValidationResult result = {};
        status = CertificateValidator::ValidateChain(chain, options, &result);
        ExpectStatus(status, STATUS_SUCCESS, "certificate validation builds leaf-to-root path from unordered input");
        Expect(result.Leaf.DerLength == leafDerLength, "unordered path validation selects the DNS leaf");
    }

    void TestCertificateValidationBacktracksCrossSignedIntermediate()
    {
        UCHAR rootPem[TestMaxPemCertificateLength] = {};
        UCHAR rootDer[TestMaxDerCertificateLength] = {};
        UCHAR trustedIntermediatePem[TestMaxPemCertificateLength] = {};
        UCHAR trustedIntermediateDer[TestMaxDerCertificateLength] = {};
        UCHAR untrustedIntermediatePem[TestMaxPemCertificateLength] = {};
        UCHAR untrustedIntermediateDer[TestMaxDerCertificateLength] = {};
        UCHAR leafPem[TestMaxPemCertificateLength] = {};
        UCHAR leafDer[TestMaxDerCertificateLength] = {};
        SIZE_T rootPemLength = 0;
        SIZE_T rootDerLength = 0;
        SIZE_T trustedIntermediatePemLength = 0;
        SIZE_T trustedIntermediateDerLength = 0;
        SIZE_T untrustedIntermediatePemLength = 0;
        SIZE_T untrustedIntermediateDerLength = 0;
        SIZE_T leafPemLength = 0;
        SIZE_T leafDerLength = 0;

        const bool loaded =
            LoadPemCertificate(PkiCrossTrustedRootCertificatePath, rootPem, sizeof(rootPem), &rootPemLength, rootDer, sizeof(rootDer), &rootDerLength) &&
            LoadPemCertificate(PkiCrossIntermediateByTrustedCertificatePath, trustedIntermediatePem, sizeof(trustedIntermediatePem), &trustedIntermediatePemLength, trustedIntermediateDer, sizeof(trustedIntermediateDer), &trustedIntermediateDerLength) &&
            LoadPemCertificate(PkiCrossIntermediateByUntrustedCertificatePath, untrustedIntermediatePem, sizeof(untrustedIntermediatePem), &untrustedIntermediatePemLength, untrustedIntermediateDer, sizeof(untrustedIntermediateDer), &untrustedIntermediateDerLength) &&
            LoadPemCertificate(PkiCrossLeafCertificatePath, leafPem, sizeof(leafPem), &leafPemLength, leafDer, sizeof(leafDer), &leafDerLength);
        Expect(loaded, "cross-signed PKI fixtures load");
        if (!loaded) {
            return;
        }

        ParsedCertificate leaf = {};
        ParsedCertificate trustedIntermediate = {};
        ParsedCertificate untrustedIntermediate = {};
        NTSTATUS status = CertificateValidator::ParseCertificate(leafDer, leafDerLength, leaf);
        ExpectStatus(status, STATUS_SUCCESS, "cross-signed leaf parses");
        status = CertificateValidator::ParseCertificate(
            trustedIntermediateDer,
            trustedIntermediateDerLength,
            trustedIntermediate);
        ExpectStatus(status, STATUS_SUCCESS, "trusted cross-signed intermediate parses");
        status = CertificateValidator::ParseCertificate(
            untrustedIntermediateDer,
            untrustedIntermediateDerLength,
            untrustedIntermediate);
        ExpectStatus(status, STATUS_SUCCESS, "untrusted cross-signed intermediate parses");
        if (!leaf.HasAuthorityKeyIdentifier ||
            !trustedIntermediate.HasSubjectKeyIdentifier ||
            !untrustedIntermediate.HasSubjectKeyIdentifier) {
            Expect(false, "AKI/SKI extensions are parsed from cross-signed fixtures");
            return;
        }
        Expect(
            leaf.AuthorityKeyIdentifierLength == trustedIntermediate.SubjectKeyIdentifierLength &&
                memcmp(
                    leaf.AuthorityKeyIdentifier,
                    trustedIntermediate.SubjectKeyIdentifier,
                    leaf.AuthorityKeyIdentifierLength) == 0,
            "leaf AKI matches trusted intermediate SKI");
        Expect(
            untrustedIntermediate.SubjectKeyIdentifierLength == trustedIntermediate.SubjectKeyIdentifierLength &&
                memcmp(
                    untrustedIntermediate.SubjectKeyIdentifier,
                    trustedIntermediate.SubjectKeyIdentifier,
                    trustedIntermediate.SubjectKeyIdentifierLength) == 0,
            "cross-signed intermediates retain the same SKI");

        UCHAR certificateList[TestMaxCertificateListLength] = {};
        SIZE_T certificateListLength = 0;
        bool appended = AppendCertificateToList(leafDer, leafDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        appended = appended && AppendCertificateToList(
            untrustedIntermediateDer,
            untrustedIntermediateDerLength,
            certificateList,
            sizeof(certificateList),
            &certificateListLength);
        appended = appended && AppendCertificateToList(
            trustedIntermediateDer,
            trustedIntermediateDerLength,
            certificateList,
            sizeof(certificateList),
            &certificateListLength);
        Expect(appended, "cross-signed certificate list is built with untrusted candidate first");
        if (!appended) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = rootPem;
        bundle.DataLength = rootPemLength;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;

        CertificateStore store;
        status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts cross-sign trusted root");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 3;

        CertificateValidationOptions options = {};
        options.HostName = "www.cross.example.test";
        options.HostNameLength = strlen(options.HostName);
        options.Store = &store;

        CertificateValidationResult result = {};
        status = CertificateValidator::ValidateChain(chain, options, &result);
        ExpectStatus(status, STATUS_SUCCESS, "certificate validation backtracks from untrusted cross-sign to trusted path");
        Expect(
            result.Leaf.DerLength == leafDerLength &&
                result.Leaf.HasAuthorityKeyIdentifier,
            "cross-signed path validation returns parsed leaf metadata");
    }

    void TestCertificateValidationAppliesNameConstraints()
    {
        UCHAR rootPem[TestMaxPemCertificateLength] = {};
        UCHAR rootDer[TestMaxDerCertificateLength] = {};
        UCHAR intermediatePem[TestMaxPemCertificateLength] = {};
        UCHAR intermediateDer[TestMaxDerCertificateLength] = {};
        UCHAR leafPem[TestMaxPemCertificateLength] = {};
        UCHAR leafDer[TestMaxDerCertificateLength] = {};
        UCHAR badLeafPem[TestMaxPemCertificateLength] = {};
        UCHAR badLeafDer[TestMaxDerCertificateLength] = {};
        SIZE_T rootPemLength = 0;
        SIZE_T rootDerLength = 0;
        SIZE_T intermediatePemLength = 0;
        SIZE_T intermediateDerLength = 0;
        SIZE_T leafPemLength = 0;
        SIZE_T leafDerLength = 0;
        SIZE_T badLeafPemLength = 0;
        SIZE_T badLeafDerLength = 0;

        const bool loaded =
            LoadPemCertificate(PkiRootCertificatePath, rootPem, sizeof(rootPem), &rootPemLength, rootDer, sizeof(rootDer), &rootDerLength) &&
            LoadPemCertificate(PkiIntermediateCertificatePath, intermediatePem, sizeof(intermediatePem), &intermediatePemLength, intermediateDer, sizeof(intermediateDer), &intermediateDerLength) &&
            LoadPemCertificate(PkiLeafCertificatePath, leafPem, sizeof(leafPem), &leafPemLength, leafDer, sizeof(leafDer), &leafDerLength) &&
            LoadPemCertificate(PkiBadLeafCertificatePath, badLeafPem, sizeof(badLeafPem), &badLeafPemLength, badLeafDer, sizeof(badLeafDer), &badLeafDerLength);
        Expect(loaded, "PKI chain fixtures load for Name Constraints test");
        if (!loaded) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = rootPem;
        bundle.DataLength = rootPemLength;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;

        CertificateStore store;
        NTSTATUS status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts root bundle for Name Constraints test");
        if (!NT_SUCCESS(status)) {
            return;
        }

        UCHAR certificateList[TestMaxCertificateListLength] = {};
        SIZE_T certificateListLength = 0;
        bool appended = AppendCertificateToList(leafDer, leafDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        appended = appended && AppendCertificateToList(intermediateDer, intermediateDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        Expect(appended, "permitted certificate list is built");
        if (!appended) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 2;

        CertificateValidationOptions options = {};
        options.HostName = "www.example.test";
        options.HostNameLength = strlen(options.HostName);
        options.Store = &store;

        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_SUCCESS, "Name Constraints permits DNS subtree");

        RtlZeroMemory(certificateList, sizeof(certificateList));
        certificateListLength = 0;
        appended = AppendCertificateToList(badLeafDer, badLeafDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        appended = appended && AppendCertificateToList(intermediateDer, intermediateDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        Expect(appended, "excluded certificate list is built");
        if (!appended) {
            return;
        }

        chain.CertificatesLength = certificateListLength;
        options.HostName = "www.bad.test";
        options.HostNameLength = strlen(options.HostName);
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "Name Constraints rejects DNS name outside permitted subtree");
    }

    void TestCertificateValidationMatchesIdnaName()
    {
        UCHAR rootPem[TestMaxPemCertificateLength] = {};
        UCHAR rootDer[TestMaxDerCertificateLength] = {};
        UCHAR intermediatePem[TestMaxPemCertificateLength] = {};
        UCHAR intermediateDer[TestMaxDerCertificateLength] = {};
        UCHAR leafPem[TestMaxPemCertificateLength] = {};
        UCHAR leafDer[TestMaxDerCertificateLength] = {};
        SIZE_T rootPemLength = 0;
        SIZE_T rootDerLength = 0;
        SIZE_T intermediatePemLength = 0;
        SIZE_T intermediateDerLength = 0;
        SIZE_T leafPemLength = 0;
        SIZE_T leafDerLength = 0;

        const bool loaded =
            LoadPemCertificate(PkiRootCertificatePath, rootPem, sizeof(rootPem), &rootPemLength, rootDer, sizeof(rootDer), &rootDerLength) &&
            LoadPemCertificate(PkiIntermediateCertificatePath, intermediatePem, sizeof(intermediatePem), &intermediatePemLength, intermediateDer, sizeof(intermediateDer), &intermediateDerLength) &&
            LoadPemCertificate(PkiIdnaLeafCertificatePath, leafPem, sizeof(leafPem), &leafPemLength, leafDer, sizeof(leafDer), &leafDerLength);
        Expect(loaded, "PKI chain fixtures load for IDNA test");
        if (!loaded) {
            return;
        }

        UCHAR certificateList[TestMaxCertificateListLength] = {};
        SIZE_T certificateListLength = 0;
        bool appended = AppendCertificateToList(leafDer, leafDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        appended = appended && AppendCertificateToList(intermediateDer, intermediateDerLength, certificateList, sizeof(certificateList), &certificateListLength);
        Expect(appended, "IDNA certificate list is built");
        if (!appended) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = rootPem;
        bundle.DataLength = rootPemLength;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;

        CertificateStore store;
        NTSTATUS status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts root bundle for IDNA test");
        if (!NT_SUCCESS(status)) {
            return;
        }

        const char idnaHost[] = {
            'b',
            static_cast<char>(0xc3),
            static_cast<char>(0xbc),
            'c', 'h', 'e', 'r',
            '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            '.', 't', 'e', 's', 't',
            '\0'
        };

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 2;

        CertificateValidationOptions options = {};
        options.HostName = idnaHost;
        options.HostNameLength = sizeof(idnaHost) - 1;
        options.Store = &store;

        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_SUCCESS, "certificate validation normalizes IDNA U-label host to dNSName A-label");

        options.EnableIdna = false;
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "certificate validation rejects non-ASCII host when IDNA policy is disabled");
    }

    void TestCertificateValidationMatchesIpAddressSan()
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
        Expect(loaded, "localhost certificate fixture loads for IP SAN test");
        if (!loaded) {
            return;
        }

        ParsedCertificate parsed = {};
        NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        Expect(status == STATUS_SUCCESS, "localhost certificate parses for IP SAN test");
        Expect(parsed.IpAddressCount >= 2, "localhost certificate exposes IPv4 and IPv6 SANs");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = pem;
        bundle.DataLength = pemLength;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;

        CertificateStore store;
        status = store.Initialize(storeOptions);
        Expect(status == STATUS_SUCCESS, "certificate store accepts PEM bundle for IP SAN test");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions options = {};
        options.HostName = "127.0.0.1";
        options.HostNameLength = strlen(options.HostName);
        options.Store = &store;
        status = CertificateValidator::ValidateChain(chain, options);
        Expect(status == STATUS_SUCCESS, "certificate validation matches IPv4 iPAddress SAN");

        options.HostName = "::1";
        options.HostNameLength = strlen(options.HostName);
        status = CertificateValidator::ValidateChain(chain, options);
        Expect(status == STATUS_SUCCESS, "certificate validation matches IPv6 iPAddress SAN");

        options.HostName = "127.0.0.2";
        options.HostNameLength = strlen(options.HostName);
        status = CertificateValidator::ValidateChain(chain, options);
        Expect(status == STATUS_TRUST_FAILURE, "certificate validation rejects mismatched IP literal without CN fallback");
    }

    void TestCertificateValidationUsesRevocationCache()
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
        Expect(loaded, "localhost certificate fixture loads for revocation-required test");
        if (!loaded) {
            return;
        }

        ParsedCertificate parsed = {};
        NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        ExpectStatus(status, STATUS_SUCCESS, "localhost certificate parses for revocation cache test");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = pem;
        bundle.DataLength = pemLength;

        CertificateRevocationEntry entry = {};
        entry.IssuerName = parsed.Issuer;
        entry.IssuerNameLength = parsed.IssuerLength;
        entry.SerialNumber = parsed.SerialNumber;
        entry.SerialNumberLength = parsed.SerialNumberLength;
        entry.Source = CertificateRevocationSource::Ocsp;
        entry.Status = CertificateRevocationStatus::Good;
        entry.ThisUpdate = 20200101000000LL;
        entry.NextUpdate = 20990101000000LL;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;
        storeOptions.RevocationEntries = &entry;
        storeOptions.RevocationEntryCount = 1;

        CertificateStore store;
        status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts OCSP revocation cache entry");
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
        options.RequireRevocationCheck = true;
        options.RevocationMode = CertificateRevocationMode::StapledOnly;

        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_SUCCESS, "certificate validation accepts fresh good OCSP cache entry");

        entry.Status = CertificateRevocationStatus::Revoked;
        status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts revoked OCSP cache entry");
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "certificate validation rejects revoked OCSP cache entry");

        entry.Status = CertificateRevocationStatus::Good;
        entry.NextUpdate = 20210101000000LL;
        status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts expired OCSP cache entry");
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "certificate validation rejects expired OCSP cache entry");

        entry.Source = CertificateRevocationSource::Crl;
        entry.Status = CertificateRevocationStatus::Good;
        entry.NextUpdate = 20990101000000LL;
        status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts CRL revocation cache entry");
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "stapled-only revocation does not accept CRL cache entries");

        options.RevocationMode = CertificateRevocationMode::OnlineRequired;
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_SUCCESS, "online-required revocation accepts fresh good CRL cache entry");
    }

    struct RevocationProviderCapture
    {
        CertificateRevocationEntry Entry = {};
        NTSTATUS Status = STATUS_SUCCESS;
        SIZE_T Calls = 0;
        CertificateRevocationSource LastSource = CertificateRevocationSource::Ocsp;
    };

    NTSTATUS TestRevocationProvider(
        void* context,
        const CertificateRevocationProviderQuery* query,
        CertificateRevocationEntry* entry)
    {
        auto* capture = static_cast<RevocationProviderCapture*>(context);
        if (capture == nullptr || query == nullptr || entry == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->Calls;
        capture->LastSource = query->PreferredSource;
        if (!NT_SUCCESS(capture->Status)) {
            return capture->Status;
        }

        *entry = capture->Entry;
        entry->Source = query->PreferredSource;
        entry->IssuerName = query->IssuerName;
        entry->IssuerNameLength = query->IssuerNameLength;
        entry->SerialNumber = query->SerialNumber;
        entry->SerialNumberLength = query->SerialNumberLength;
        return STATUS_SUCCESS;
    }

    void TestCertificateValidationUsesRevocationProvider()
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
        Expect(loaded, "localhost certificate fixture loads for revocation provider test");
        if (!loaded) {
            return;
        }

        ParsedCertificate parsed = {};
        NTSTATUS status = CertificateValidator::ParseCertificate(der, derLength, parsed);
        ExpectStatus(status, STATUS_SUCCESS, "localhost certificate parses for revocation provider test");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateAuthorityBundle bundle = {};
        bundle.Data = pem;
        bundle.DataLength = pemLength;

        RevocationProviderCapture provider = {};
        provider.Entry.Status = CertificateRevocationStatus::Good;
        provider.Entry.ThisUpdate = 20200101000000LL;
        provider.Entry.NextUpdate = 20990101000000LL;

        CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &bundle;
        storeOptions.AuthorityBundleCount = 1;
        storeOptions.RevocationProvider = TestRevocationProvider;
        storeOptions.RevocationProviderContext = &provider;

        CertificateStore store;
        status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate store accepts revocation provider");
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
        options.RequireRevocationCheck = true;
        options.RevocationMode = CertificateRevocationMode::StapledOnly;

        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_SUCCESS, "stapled-only revocation accepts provider OCSP good status");
        Expect(provider.Calls == 1, "revocation provider called once for OCSP");
        Expect(provider.LastSource == CertificateRevocationSource::Ocsp, "revocation provider receives OCSP source");

        provider.Entry.Status = CertificateRevocationStatus::Revoked;
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "revocation provider revoked status fails validation");

        provider.Entry.Status = CertificateRevocationStatus::Good;
        provider.Status = STATUS_NOT_FOUND;
        options.RevocationMode = CertificateRevocationMode::OnlineRequired;
        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "online-required revocation provider miss fails closed");
    }

    void TestCertificateValidationRejectsIdnaHost()
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
        Expect(loaded, "localhost certificate fixture loads for IDNA test");
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
        Expect(status == STATUS_SUCCESS, "certificate store accepts PEM bundle for IDNA test");
        if (!NT_SUCCESS(status)) {
            return;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        const char idnaHost[] = {
            'l', 'o', 'c', 'a', 'l',
            static_cast<char>(0xc3),
            static_cast<char>(0xb6),
            'h', 'o', 's', 't',
            '\0'
        };

        CertificateValidationOptions options = {};
        options.HostName = idnaHost;
        options.HostNameLength = sizeof(idnaHost) - 1;
        options.Store = &store;

        status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_TRUST_FAILURE, "certificate validation rejects normalized IDNA host when certificate name does not match");
    }

    void TestCertificateValidationRejectsNameConstraintsExtension()
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
        Expect(loaded, "localhost certificate fixture loads for Name Constraints test");
        if (!loaded) {
            return;
        }

        const UCHAR subjectAltNameOid[] = { 0x55, 0x1d, 0x11 };
        SIZE_T oidOffset = 0;
        const bool foundOid = FindBytes(der, derLength, subjectAltNameOid, sizeof(subjectAltNameOid), 0, &oidOffset);
        Expect(foundOid, "localhost certificate SAN OID is found for Name Constraints test");
        if (!foundOid) {
            return;
        }

        der[oidOffset + 2] = 0x1e;
        certificateList[0] = static_cast<UCHAR>((derLength >> 16) & 0xff);
        certificateList[1] = static_cast<UCHAR>((derLength >> 8) & 0xff);
        certificateList[2] = static_cast<UCHAR>(derLength & 0xff);
        memcpy(certificateList + 3, der, derLength);
        certificateListLength = derLength + 3;

        CertificateChainView chain = {};
        chain.Certificates = certificateList;
        chain.CertificatesLength = certificateListLength;
        chain.CertificateCount = 1;

        CertificateValidationOptions options = {};
        options.HostName = "localhost";
        options.HostNameLength = strlen(options.HostName);

        const NTSTATUS status = CertificateValidator::ValidateChain(chain, options);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "certificate validation rejects malformed Name Constraints instead of ignoring them");
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

    void TestTls12NewSessionTicketAffectsServerFinishedTranscript()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        Expect(status == STATUS_SUCCESS, "TLS context initializes for NewSessionTicket transcript");

        UCHAR serverRandom[32] = {};
        for (SIZE_T index = 0; index < sizeof(serverRandom); ++index) {
            serverRandom[index] = static_cast<UCHAR>(0x40 + index);
        }

        status = context.SetServerRandom(serverRandom);
        Expect(status == STATUS_SUCCESS, "server random sets for NewSessionTicket transcript");

        const UCHAR premaster[] = {
            0x03, 0x03, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d
        };
        status = context.DeriveMasterSecret(premaster, sizeof(premaster));
        Expect(status == STATUS_SUCCESS, "master secret derives for NewSessionTicket transcript");

        const UCHAR clientHello[] = { 1, 0, 0, 1, 0xa1 };
        const UCHAR serverHello[] = { 2, 0, 0, 1, 0xb2 };
        const UCHAR clientFinished[] = {
            20, 0, 0, 12,
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
            0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb
        };
        const UCHAR newSessionTicket[] = {
            4, 0, 0, 10,
            0, 0, 0, 60,
            0, 4,
            0xd0, 0xd1, 0xd2, 0xd3
        };

        TlsTranscriptHash fullTranscript;
        status = fullTranscript.Initialize(HashAlgorithm::Sha256);
        Expect(status == STATUS_SUCCESS, "full transcript initializes");
        status = fullTranscript.Update(clientHello, sizeof(clientHello));
        if (NT_SUCCESS(status)) {
            status = fullTranscript.Update(serverHello, sizeof(serverHello));
        }
        if (NT_SUCCESS(status)) {
            status = fullTranscript.Update(clientFinished, sizeof(clientFinished));
        }
        if (NT_SUCCESS(status)) {
            status = fullTranscript.Update(newSessionTicket, sizeof(newSessionTicket));
        }
        Expect(status == STATUS_SUCCESS, "full transcript includes NewSessionTicket");

        UCHAR fullHash[32] = {};
        SIZE_T fullHashLength = 0;
        status = fullTranscript.Finish(fullHash, sizeof(fullHash), &fullHashLength);
        Expect(status == STATUS_SUCCESS, "full transcript hash finishes");

        UCHAR serverFinished[32] = {};
        SIZE_T serverFinishedLength = 0;
        status = TlsHandshake12::EncodeFinished(
            context,
            false,
            fullHash,
            fullHashLength,
            serverFinished,
            sizeof(serverFinished),
            &serverFinishedLength);
        Expect(status == STATUS_SUCCESS, "server Finished encodes with NewSessionTicket transcript");
        Expect(serverFinishedLength == 4 + TlsVerifyDataLength, "server Finished length matches");

        TlsTranscriptHash missingTicketTranscript;
        status = missingTicketTranscript.Initialize(HashAlgorithm::Sha256);
        Expect(status == STATUS_SUCCESS, "missing-ticket transcript initializes");
        status = missingTicketTranscript.Update(clientHello, sizeof(clientHello));
        if (NT_SUCCESS(status)) {
            status = missingTicketTranscript.Update(serverHello, sizeof(serverHello));
        }
        if (NT_SUCCESS(status)) {
            status = missingTicketTranscript.Update(clientFinished, sizeof(clientFinished));
        }
        Expect(status == STATUS_SUCCESS, "missing-ticket transcript omits NewSessionTicket");

        UCHAR missingTicketHash[32] = {};
        SIZE_T missingTicketHashLength = 0;
        status = missingTicketTranscript.Finish(
            missingTicketHash,
            sizeof(missingTicketHash),
            &missingTicketHashLength);
        Expect(status == STATUS_SUCCESS, "missing-ticket transcript hash finishes");

        status = TlsHandshake12::VerifyFinished(
            context,
            false,
            missingTicketHash,
            missingTicketHashLength,
            serverFinished + 4,
            TlsVerifyDataLength);
        ExpectStatus(
            status,
            STATUS_INVALID_NETWORK_RESPONSE,
            "server Finished rejects transcript that omits NewSessionTicket");

        status = TlsHandshake12::VerifyFinished(
            context,
            false,
            fullHash,
            fullHashLength,
            serverFinished + 4,
            TlsVerifyDataLength);
        Expect(status == STATUS_SUCCESS, "server Finished accepts transcript that includes NewSessionTicket");
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

    void TestTlsCapabilityMatrix()
    {
        Expect(KernelHttp::tls::TlsIsKnownNamedGroup(TlsNamedGroup::X25519), "X25519 is a known named group");
        Expect(KernelHttp::tls::TlsIsKnownNamedGroup(TlsNamedGroup::X448), "X448 is a known named group");
        Expect(KernelHttp::tls::TlsIsKnownCipherSuite(TlsCipherSuite::TlsChaCha20Poly1305Sha256), "TLS 1.3 ChaCha20-Poly1305 is known");
        Expect(KernelHttp::tls::TlsIsKnownSignatureScheme(TlsSignatureScheme::Ed25519), "Ed25519 is a known signature scheme");
        Expect(KernelHttp::tls::TlsIsKnownSignatureScheme(TlsSignatureScheme::Ed448), "Ed448 is a known signature scheme");
        Expect(KernelHttp::tls::TlsIsKnownSignatureScheme(TlsSignatureScheme::RsaPkcs1Sha1), "TLS 1.2 rsa_pkcs1_sha1 is known");
        Expect(KernelHttp::tls::TlsIsKnownSignatureScheme(TlsSignatureScheme::EcdsaSha1), "TLS 1.2 ecdsa_sha1 is known");
        Expect(KernelHttp::tls::TlsIsDefaultEnabledNamedGroup(TlsNamedGroup::X25519), "X25519 is default-enabled");
        Expect(KernelHttp::tls::TlsIsDefaultEnabledSignatureScheme(TlsSignatureScheme::Ed448), "Ed448 is default-enabled");
        Expect(!KernelHttp::tls::TlsIsDefaultEnabledSignatureScheme(TlsSignatureScheme::RsaPkcs1Sha1), "rsa_pkcs1_sha1 is not modern-default");
        Expect(!KernelHttp::tls::TlsIsDefaultEnabledSignatureScheme(TlsSignatureScheme::EcdsaSha1), "ecdsa_sha1 is not modern-default");
        Expect(!KernelHttp::tls::TlsIsDefaultEnabledTls12KeyExchange(Tls12KeyExchangeKind::Rsa), "TLS 1.2 RSA key exchange is not default-enabled");
    }

    void TestTlsPolicyValidation()
    {
        TlsPolicy policy = {};
        ExpectStatus(KernelHttp::tls::TlsValidatePolicy(policy), STATUS_SUCCESS, "modern default policy validates");
        Expect(KernelHttp::tls::TlsPolicyAllowsNamedGroup(policy, TlsNamedGroup::X25519), "modern default policy allows X25519");
        Expect(KernelHttp::tls::TlsPolicyAllowsCipherSuite(policy, TlsCipherSuite::TlsChaCha20Poly1305Sha256), "modern default policy allows ChaCha20-Poly1305");
        Expect(!KernelHttp::tls::TlsPolicyAllowsCipherSuite(policy, TlsCipherSuite::TlsRsaWithAes128GcmSha256), "modern default policy rejects RSA key exchange");
        Expect(!KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::RsaPkcs1Sha1), "modern policy rejects rsa_pkcs1_sha1");
        Expect(!KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::EcdsaSha1), "modern policy rejects ecdsa_sha1");

        policy.EnableTls12RsaKeyExchange = true;
        ExpectStatus(KernelHttp::tls::TlsValidatePolicy(policy), STATUS_INVALID_PARAMETER, "modern default policy rejects legacy RSA opt-in");

        policy = {};
        policy.EnableTls12Sha1Signatures = true;
        ExpectStatus(KernelHttp::tls::TlsValidatePolicy(policy), STATUS_INVALID_PARAMETER, "modern default policy rejects SHA1 signature opt-in");

        policy = {};
        policy.Profile = TlsSecurityProfile::CompatibilityExplicit;
        Expect(!KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::RsaPkcs1Sha1), "compatibility policy keeps rsa_pkcs1_sha1 off by default");
        Expect(!KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::EcdsaSha1), "compatibility policy keeps ecdsa_sha1 off by default");
        policy.EnableTls12RsaKeyExchange = true;
        policy.EnableTls12Cbc = true;
        policy.EnableTls12Renegotiation = true;
        policy.EnableTls12Sha1Signatures = true;
        ExpectStatus(KernelHttp::tls::TlsValidatePolicy(policy), STATUS_SUCCESS, "compatibility policy validates");
        Expect(KernelHttp::tls::TlsPolicyAllowsTls12KeyExchange(policy, Tls12KeyExchangeKind::Rsa), "compatibility policy allows TLS 1.2 RSA");
        Expect(KernelHttp::tls::TlsPolicyAllowsCipherSuite(policy, TlsCipherSuite::TlsRsaWithAes128GcmSha256), "compatibility policy allows RSA GCM");
        Expect(KernelHttp::tls::TlsPolicyAllowsCipherSuite(policy, TlsCipherSuite::TlsRsaWithAes128CbcSha256), "compatibility policy allows RSA CBC");
        Expect(KernelHttp::tls::TlsPolicyAllowsTls12Renegotiation(policy), "compatibility policy allows renegotiation");
        Expect(KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::RsaPkcs1Sha1), "compatibility policy allows rsa_pkcs1_sha1 when explicitly enabled");
        Expect(KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::EcdsaSha1), "compatibility policy allows ecdsa_sha1 when explicitly enabled");
        Expect(KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::EcdsaSecp256r1Sha256), "compatibility policy still allows modern signatures");
        Expect(KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::Ed25519), "Ed25519 is offered after software verify implementation");
        Expect(KernelHttp::tls::TlsPolicyAllowsSignatureScheme(policy, TlsSignatureScheme::Ed448), "Ed448 is offered after software verify implementation");
    }
}

int main()
{
    TestPlainRecordRoundTrip();
    TestAlertParsing();
    TestTlsHandshakeFailureRecordsLocalPolicy();
    TestTlsHandshakeFailureRecordsProtocolVersionAlert();
    TestTlsHandshakeFailureRecordsTls13HandshakeFailureAsVersionCandidate();
    TestTlsHandshakeFailureDoesNotClassifyTls13OnlyHandshakeFailure();
    TestTlsHandshakeFailureRecordsTls13CloseNotifyAsVersionCandidate();
    TestTlsHandshakeFailureDoesNotClassifyTls13OnlyCloseNotify();
    TestTlsHandshakeFailureMarksTls13FirstServerHelloNetworkIo();
    TestTlsHandshakeFailureDoesNotMarkTls13OnlyFirstServerHelloNetworkIo();
    TestRecordNeedsMoreData();
    TestRecordRejectsInvalidHeader();
    TestPlainRecordSizeProbe();
    TestSequenceNumberEncoding();
    TestAesGcmRecordProtection();
    TestAesCbcEncryptThenMacRecordProtection();
    TestAesGcmRejectsSmallPlaintextBuffer();
    TestAesGcmRejectsTruncatedCiphertext();
    TestAesGcmRejectsSequenceNumberExhaustion();
    TestHkdfExtractExpand();
    TestTls13EarlySecretUsesZeroPsk();
    TestTls13ApplicationMasterSecretUsesZeroIkm();
    TestTls13ExporterAndTrafficUpdate();
    TestTls13AesGcmRecordProtection();
    TestTls13AesGcmAllowsEmptyApplicationData();
    TestTls13AesGcmProtectsMaxPlaintextRecord();
    TestTls13AesGcmProtectsWithHeapScratch();
    TestTls13AesGcmProtectsOverlappingDestination();
    TestTls13AesGcmProtectsWithExplicitPadding();
    TestTls13AesGcmRejectsOversizedPadding();
    TestTls13AesGcmRejectsSequenceNumberExhaustion();
    TestClientHello();
    TestTls12ClientHelloAdvertisesStrictExtensions();
    TestTls12ClientHelloCarriesRenegotiationInfo();
    TestParseTls12HelloRequest();
    TestTls12ClientInitiatedRenegotiationRequiresEstablishedConnection();
    TestTls12ConnectionClientHelloFollowsCompatibilityPolicy();
    TestClientHelloRejectsInvalidSniNames();
    TestClientHelloAdvertisesSessionTicket();
    TestTls13ClientHelloExtensions();
    TestParseTls13ServerHello();
    TestTls13ServerHelloRejectsStrictnessViolations();
    TestParseTls13HelloRetryRequest();
    TestTls13ServerHelloOfferValidation();
    TestTls13HelloRetryRequestOfferValidation();
    TestParseTls13EncryptedExtensions();
    TestParseTls13EncryptedExtensionsRejectsDuplicateExtensions();
    TestParseTls13NewSessionTicket();
    TestParseTls13NewSessionTicketRejectsDuplicateExtensions();
    TestParseTls13NewSessionTicketAllowsLargeIdentity();
    TestParseMultipleTls13NewSessionTicketsFromOneRecord();
    TestParseTls13PostHandshakeRejectsUnexpectedType();
    TestParseTls13PostHandshakeRejectsKeyUpdate();
    TestParseTls13KeyUpdate();
    TestTls13FinishedVerifyData();
    TestTls13CertificateVerifyInputCapacity();
    TestTls13PskBinderComputes();
    TestTls13ClientHelloPskBinderTranscriptLength();
    TestTls13PskBinderRejectsWrongHashLength();
    TestTls13SelectedPskIdentityValidation();
    TestTls13AttemptClassifiesTls12ServerHello();
    TestTls13AttemptRejectsTls12DowngradeSentinel();
    TestTls13TicketSelectionBindsContextAndAge();
    TestTls13TicketSelectionSkipsMismatches();
    TestTls13HelloRetryRequestRecomputesPskBinder();
    TestTls13EarlyDataRequiresReplaySafe();
    TestTls12SessionCachePopulatesClientHello();
    TestParseNewSessionTicketMessage();
    TestParseNewSessionTicketRejectsUnexpectedType();
    TestParseNewSessionTicketRejectsBadLength();
    TestParseCertificateStatusMessage();
    TestParseCertificateStatusRejectsMalformed();
    TestParseServerHello();
    TestParseTls12ServerHelloStrictExtensions();
    TestTls12ConnectionRejectsServerHelloWithoutEms();
    TestTls12ServerHelloAlpnStrictness();
    TestParseServerKeyExchange();
    TestParseWsPostmanEchoServerKeyExchange();
    TestTls12ServerHelloOfferValidation();
    TestTls12ServerKeyExchangeOfferValidation();
    TestParseCertificateListState();
    TestCertificateStoreTrustAndPin();
    TestCertificateStoreRejectsEmptyTrustAnchor();
    TestCertificateStoreRejectsDnOnlyTrustAnchor();
    TestCertificateParserRejectsInvalidCalendarDate();
    TestCertificateParserRejectsNonMinimalDerLengths();
    TestCertificateParserRejectsRedundantUnsignedIntegerEncoding();
    TestCertificateParserRejectsSubjectAltNameOverflow();
    TestCertificateParserRejectsSignatureAlgorithmMismatch();
    TestCertificateParserRejectsDuplicateExtensionOid();
    TestCertificateParserRejectsUnknownCriticalExtension();
    TestCertificateValidationAcceptsNonCriticalCertificatePolicies();
    TestCertificateValidationRejectsCriticalCertificatePoliciesExtension();
    TestCertificateValidationRejectsMalformedCertificatePoliciesExtension();
    TestCertificateValidationCanSkipVerification();
    TestCertificateValidationRequiresTrustMaterial();
    TestCertificateValidationPinDoesNotCreateTrust();
    TestCertificateValidationAcceptsExternalPemBundle();
    TestCertificateValidationBuildsUnorderedExternalPath();
    TestCertificateValidationBacktracksCrossSignedIntermediate();
    TestCertificateValidationAppliesNameConstraints();
    TestCertificateValidationMatchesIdnaName();
    TestCertificateValidationMatchesIpAddressSan();
    TestCertificateValidationUsesRevocationCache();
    TestCertificateValidationUsesRevocationProvider();
    TestCertificateValidationRejectsIdnaHost();
    TestCertificateValidationRejectsNameConstraintsExtension();
    TestEncodeClientKeyExchange();
    TestFinishedVerifyData();
    TestTls12NewSessionTicketAffectsServerFinishedTranscript();
    TestTranscriptHash();
    TestTlsCapabilityMatrix();
    TestTlsPolicyValidation();

    if (g_failed) {
        return 1;
    }

    printf("PASS: TLS record tests\n");
    return 0;
}
