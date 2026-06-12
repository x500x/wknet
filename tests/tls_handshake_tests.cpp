#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/tls/TlsCapabilities.h>
#include <KernelHttp/tls/TlsHandshake12.h>
#include <KernelHttp/tls/TlsHandshake13.h>
#include <KernelHttp/tls/TlsPolicy.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::tls::TlsCipherSuite;
using KernelHttp::tls::TlsCipherSuiteCapability;
using KernelHttp::tls::TlsClientHelloOptions;
using KernelHttp::tls::TlsContext;
using KernelHttp::tls::TlsHandshake12;
using KernelHttp::tls::TlsHandshake13;
using KernelHttp::tls::TlsHandshakeMessageView;
using KernelHttp::tls::TlsHandshakeType;
using KernelHttp::tls::TlsNamedGroup;
using KernelHttp::tls::TlsPolicy;
using KernelHttp::tls::TlsSignatureScheme;
using KernelHttp::tls::Tls13ClientHelloOptions;
using KernelHttp::tls::Tls13KeyShareEntry;
using KernelHttp::tls::Tls13ServerHelloView;

namespace
{
    constexpr USHORT ExtensionSignatureAlgorithms = 13;
    constexpr USHORT ExtensionSignatureAlgorithmsCert = 50;
    constexpr USHORT ExtensionSupportedGroups = 10;
    constexpr USHORT ExtensionSupportedVersions = 43;
    constexpr USHORT ExtensionKeyShare = 51;

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

    USHORT ReadUint16(const UCHAR* data)
    {
        return static_cast<USHORT>((static_cast<USHORT>(data[0]) << 8) | data[1]);
    }

    bool FindExtension(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength,
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
        if (clientHello == nullptr || extension == nullptr || extensionLength == nullptr || clientHelloLength < 4 + 34) {
            return false;
        }

        SIZE_T offset = 4 + 34;
        if (offset >= clientHelloLength) {
            return false;
        }

        const UCHAR sessionIdLength = clientHello[offset++];
        if (sessionIdLength > clientHelloLength - offset) {
            return false;
        }
        offset += sessionIdLength;

        if (clientHelloLength - offset < 2) {
            return false;
        }
        const SIZE_T cipherSuitesLength = ReadUint16(clientHello + offset);
        offset += 2;
        if (cipherSuitesLength > clientHelloLength - offset) {
            return false;
        }
        offset += cipherSuitesLength;

        if (clientHelloLength - offset < 1) {
            return false;
        }
        const UCHAR compressionMethodsLength = clientHello[offset++];
        if (compressionMethodsLength > clientHelloLength - offset) {
            return false;
        }
        offset += compressionMethodsLength;

        if (clientHelloLength - offset < 2) {
            return false;
        }
        const SIZE_T extensionsLength = ReadUint16(clientHello + offset);
        offset += 2;
        if (extensionsLength != clientHelloLength - offset) {
            return false;
        }

        const SIZE_T extensionsEnd = offset + extensionsLength;
        while (offset < extensionsEnd) {
            if (extensionsEnd - offset < 4) {
                return false;
            }

            const USHORT currentType = ReadUint16(clientHello + offset);
            const SIZE_T currentLength = ReadUint16(clientHello + offset + 2);
            offset += 4;
            if (currentLength > extensionsEnd - offset) {
                return false;
            }

            if (currentType == extensionType) {
                *extension = clientHello + offset;
                *extensionLength = currentLength;
                return true;
            }

            offset += currentLength;
        }

        return false;
    }

    bool FirstSupportedGroupIs(const UCHAR* clientHello, SIZE_T clientHelloLength, TlsNamedGroup expected)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindExtension(clientHello, clientHelloLength, ExtensionSupportedGroups, &extension, &extensionLength) ||
            extensionLength < 4) {
            return false;
        }

        const SIZE_T vectorLength = ReadUint16(extension);
        if (vectorLength + 2 != extensionLength || vectorLength < 2) {
            return false;
        }

        return ReadUint16(extension + 2) == static_cast<USHORT>(expected);
    }

    bool ClientHelloOffersNamedGroup(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength,
        TlsNamedGroup expected)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindExtension(clientHello, clientHelloLength, ExtensionSupportedGroups, &extension, &extensionLength) ||
            extensionLength < 4) {
            return false;
        }

        const SIZE_T vectorLength = ReadUint16(extension);
        if (vectorLength + 2 != extensionLength || (vectorLength % 2) != 0) {
            return false;
        }

        for (SIZE_T offset = 2; offset < extensionLength; offset += 2) {
            if (ReadUint16(extension + offset) == static_cast<USHORT>(expected)) {
                return true;
            }
        }

        return false;
    }

    bool ClientHelloOffersCipherSuite(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength,
        TlsCipherSuite expected)
    {
        if (clientHello == nullptr || clientHelloLength < 4 + 34) {
            return false;
        }

        SIZE_T offset = 4 + 34;
        if (offset >= clientHelloLength) {
            return false;
        }
        const UCHAR sessionIdLength = clientHello[offset++];
        if (sessionIdLength > clientHelloLength - offset) {
            return false;
        }
        offset += sessionIdLength;

        if (clientHelloLength - offset < 2) {
            return false;
        }
        const SIZE_T cipherSuitesLength = ReadUint16(clientHello + offset);
        offset += 2;
        if ((cipherSuitesLength % 2) != 0 || cipherSuitesLength > clientHelloLength - offset) {
            return false;
        }

        for (SIZE_T index = 0; index < cipherSuitesLength; index += 2) {
            if (ReadUint16(clientHello + offset + index) == static_cast<USHORT>(expected)) {
                return true;
            }
        }
        return false;
    }

    bool ExtensionPayloadEquals(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength,
        USHORT leftType,
        USHORT rightType)
    {
        const UCHAR* left = nullptr;
        const UCHAR* right = nullptr;
        SIZE_T leftLength = 0;
        SIZE_T rightLength = 0;

        return FindExtension(clientHello, clientHelloLength, leftType, &left, &leftLength) &&
            FindExtension(clientHello, clientHelloLength, rightType, &right, &rightLength) &&
            leftLength == rightLength &&
            memcmp(left, right, leftLength) == 0;
    }

    bool ClientHelloOffersSignatureScheme(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength,
        TlsSignatureScheme expected)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindExtension(clientHello, clientHelloLength, ExtensionSignatureAlgorithms, &extension, &extensionLength) ||
            extensionLength < 4) {
            return false;
        }

        const SIZE_T vectorLength = ReadUint16(extension);
        if (vectorLength + 2 != extensionLength || (vectorLength % 2) != 0) {
            return false;
        }

        for (SIZE_T offset = 2; offset < extensionLength; offset += 2) {
            if (ReadUint16(extension + offset) == static_cast<USHORT>(expected)) {
                return true;
            }
        }

        return false;
    }

    bool Tls13ClientHelloSupportedVersionsAreTls13Only(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindExtension(clientHello, clientHelloLength, ExtensionSupportedVersions, &extension, &extensionLength) ||
            extensionLength != 3) {
            return false;
        }

        return extension[0] == 2 && ReadUint16(extension + 1) == 0x0304;
    }

    bool HasRequiredExtension(const TlsCipherSuiteCapability& capability, ULONG extensionFlag)
    {
        return (capability.RequiredExtensions & extensionFlag) != 0;
    }

    bool KeyShareIsRawX25519(const UCHAR* clientHello, SIZE_T clientHelloLength)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindExtension(clientHello, clientHelloLength, ExtensionKeyShare, &extension, &extensionLength) ||
            extensionLength < 6) {
            return false;
        }

        const SIZE_T vectorLength = ReadUint16(extension);
        if (vectorLength + 2 != extensionLength || vectorLength < 4) {
            return false;
        }

        const USHORT group = ReadUint16(extension + 2);
        const SIZE_T keyLength = ReadUint16(extension + 4);
        return group == static_cast<USHORT>(TlsNamedGroup::X25519) &&
            keyLength == 32 &&
            vectorLength == 4 + keyLength &&
            extension[6] != 4;
    }

    void TestDefaultTls13ClientHelloOffersX25519First()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 context initializes");

        UCHAR message[2048] = {};
        SIZE_T written = 0;
        Tls13ClientHelloOptions options = {};
        status = TlsHandshake13::EncodeClientHello(context, options, message, sizeof(message), &written);

        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 ClientHello encodes with defaults");
        Expect(written > 0, "TLS 1.3 ClientHello has content");
        Expect(message[0] == static_cast<UCHAR>(TlsHandshakeType::ClientHello), "ClientHello type is written");
        Expect(FirstSupportedGroupIs(message, written, TlsNamedGroup::X25519), "default supported_groups starts with X25519");
        Expect(ClientHelloOffersNamedGroup(message, written, TlsNamedGroup::X448), "default supported_groups offers X448");
        Expect(ClientHelloOffersNamedGroup(message, written, TlsNamedGroup::Ffdhe2048), "default supported_groups offers FFDHE2048");
        Expect(ClientHelloOffersNamedGroup(message, written, TlsNamedGroup::Ffdhe8192), "default supported_groups offers FFDHE8192");
        Expect(
            ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsAes128GcmSha256),
            "TLS 1.3 ClientHello offers AES_128_GCM_SHA256");
        Expect(
            ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsAes256GcmSha384),
            "TLS 1.3 ClientHello offers AES_256_GCM_SHA384");
        Expect(
            ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsChaCha20Poly1305Sha256),
            "TLS 1.3 ClientHello offers CHACHA20_POLY1305_SHA256");
        Expect(
            ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsAes128CcmSha256),
            "TLS 1.3 ClientHello offers AES_128_CCM_SHA256");
        Expect(
            ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsAes128Ccm8Sha256),
            "TLS 1.3 ClientHello offers AES_128_CCM_8_SHA256");
        Expect(
            ExtensionPayloadEquals(message, written, ExtensionSignatureAlgorithms, ExtensionSignatureAlgorithmsCert),
            "TLS 1.3 ClientHello sends signature_algorithms_cert matching signature_algorithms");
        Expect(
            Tls13ClientHelloSupportedVersionsAreTls13Only(message, written),
            "TLS 1.3 ClientHello supported_versions only offers 0x0304");
        Expect(
            ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPssRsaeSha512),
            "TLS 1.3 ClientHello offers RSA-PSS-RSAE SHA512");
        Expect(
            ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPssPssSha512),
            "TLS 1.3 ClientHello offers RSA-PSS-PSS SHA512");
        Expect(
            ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::EcdsaSecp521r1Sha512),
            "TLS 1.3 ClientHello offers ECDSA P-521 SHA512");
        Expect(
            ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::Ed25519),
            "TLS 1.3 ClientHello offers Ed25519");
        Expect(
            ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::Ed448),
            "TLS 1.3 ClientHello offers Ed448");
    }

    void TestTls13ClientHelloEncodesRawX25519KeyShare()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 context initializes for X25519 key share");

        UCHAR rawShare[32] = {};
        for (SIZE_T index = 0; index < sizeof(rawShare); ++index) {
            rawShare[index] = static_cast<UCHAR>(index + 1);
        }

        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::X25519;
        keyShare.KeyExchange = rawShare;
        keyShare.KeyExchangeLength = sizeof(rawShare);

        Tls13ClientHelloOptions options = {};
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;

        UCHAR message[2048] = {};
        SIZE_T written = 0;
        status = TlsHandshake13::EncodeClientHello(context, options, message, sizeof(message), &written);

        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 ClientHello encodes X25519 key share");
        Expect(KeyShareIsRawX25519(message, written), "TLS 1.3 X25519 key_share is raw 32 bytes");
    }

    void TestTls13HelloRetryRequestCanSelectP256AfterX25519Offer()
    {
        UCHAR rawShare[32] = {};
        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::X25519;
        keyShare.KeyExchange = rawShare;
        keyShare.KeyExchangeLength = sizeof(rawShare);

        TlsNamedGroup groups[] = {
            TlsNamedGroup::X25519,
            TlsNamedGroup::Secp256r1,
            TlsNamedGroup::Secp384r1
        };

        TlsCipherSuite cipherSuites[] = {
            TlsCipherSuite::TlsAes128GcmSha256
        };

        Tls13ClientHelloOptions options = {};
        options.CipherSuites = cipherSuites;
        options.CipherSuiteCount = sizeof(cipherSuites) / sizeof(cipherSuites[0]);
        options.NamedGroups = groups;
        options.NamedGroupCount = sizeof(groups) / sizeof(groups[0]);
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;

        Tls13ServerHelloView serverHello = {};
        serverHello.CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;
        serverHello.IsHelloRetryRequest = true;
        serverHello.RetryGroup = TlsNamedGroup::Secp256r1;

        NTSTATUS status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
        ExpectStatus(status, STATUS_SUCCESS, "HRR can request offered P-256 after initial X25519 share");

        serverHello.RetryGroup = TlsNamedGroup::X25519;
        status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "HRR rejects group already carrying a key_share");
    }

    void TestTls13HelloRetryRequestCanSelectFfdheAfterX25519Offer()
    {
        UCHAR rawShare[32] = {};
        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::X25519;
        keyShare.KeyExchange = rawShare;
        keyShare.KeyExchangeLength = sizeof(rawShare);

        TlsNamedGroup groups[] = {
            TlsNamedGroup::X25519,
            TlsNamedGroup::Ffdhe2048,
            TlsNamedGroup::Ffdhe3072
        };

        TlsCipherSuite cipherSuites[] = {
            TlsCipherSuite::TlsAes128GcmSha256
        };

        Tls13ClientHelloOptions options = {};
        options.CipherSuites = cipherSuites;
        options.CipherSuiteCount = sizeof(cipherSuites) / sizeof(cipherSuites[0]);
        options.NamedGroups = groups;
        options.NamedGroupCount = sizeof(groups) / sizeof(groups[0]);
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;

        Tls13ServerHelloView serverHello = {};
        serverHello.CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;
        serverHello.IsHelloRetryRequest = true;
        serverHello.RetryGroup = TlsNamedGroup::Ffdhe2048;

        NTSTATUS status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
        ExpectStatus(status, STATUS_SUCCESS, "HRR can request offered FFDHE2048 after initial X25519 share");
    }

    void TestTls13EncodeEmptyClientCertificate()
    {
        UCHAR message[32] = {};
        SIZE_T written = 0;
        NTSTATUS status = TlsHandshake13::EncodeEmptyCertificate(nullptr, 0, message, sizeof(message), &written);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 empty client Certificate encodes");
        Expect(written == 8, "TLS 1.3 empty client Certificate length matches");
        Expect(message[0] == static_cast<UCHAR>(TlsHandshakeType::Certificate), "empty client Certificate type is written");
        Expect(message[1] == 0 && message[2] == 0 && message[3] == 4, "empty client Certificate body length is written");
        Expect(message[4] == 0, "empty client Certificate request context is empty");
        Expect(message[5] == 0 && message[6] == 0 && message[7] == 0, "empty client Certificate certificate_list is empty");
    }

    void TestTls13EncodeClientCertificateVerifyAndEndOfEarlyData()
    {
        const UCHAR requestContext[] = { 0x7a };
        const UCHAR certificateList[] = {
            0, 0, 1, 0xaa, 0, 0
        };
        UCHAR message[64] = {};
        SIZE_T written = 0;

        NTSTATUS status = TlsHandshake13::EncodeCertificate(
            requestContext,
            sizeof(requestContext),
            certificateList,
            sizeof(certificateList),
            message,
            sizeof(message),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 client Certificate with credentials encodes");
        Expect(written == 4 + 1 + sizeof(requestContext) + 3 + sizeof(certificateList), "TLS 1.3 client Certificate length matches");
        Expect(message[0] == static_cast<UCHAR>(TlsHandshakeType::Certificate), "TLS 1.3 credential Certificate type is written");
        Expect(message[4] == sizeof(requestContext), "TLS 1.3 credential Certificate request context length is written");
        Expect(message[5] == requestContext[0], "TLS 1.3 credential Certificate request context is copied");
        Expect(message[6] == 0 && message[7] == 0 && message[8] == sizeof(certificateList), "TLS 1.3 credential Certificate list length is written");

        const UCHAR signature[] = { 0x11, 0x22, 0x33 };
        status = TlsHandshake13::EncodeCertificateVerify(
            KernelHttp::tls::TlsSignatureScheme::RsaPssRsaeSha256,
            signature,
            sizeof(signature),
            message,
            sizeof(message),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 client CertificateVerify encodes");
        Expect(written == 4 + 2 + 2 + sizeof(signature), "TLS 1.3 CertificateVerify length matches");
        Expect(message[0] == static_cast<UCHAR>(TlsHandshakeType::CertificateVerify), "TLS 1.3 CertificateVerify type is written");
        Expect(message[4] == 0x08 && message[5] == 0x04, "TLS 1.3 CertificateVerify signature scheme is written");
        Expect(message[6] == 0 && message[7] == sizeof(signature), "TLS 1.3 CertificateVerify signature length is written");
        Expect(memcmp(message + 8, signature, sizeof(signature)) == 0, "TLS 1.3 CertificateVerify signature bytes are copied");

        status = TlsHandshake13::EncodeEndOfEarlyData(message, sizeof(message), &written);
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 EndOfEarlyData encodes");
        Expect(written == 4, "TLS 1.3 EndOfEarlyData has empty body");
        Expect(message[0] == static_cast<UCHAR>(TlsHandshakeType::EndOfEarlyData), "TLS 1.3 EndOfEarlyData type is written");
        Expect(message[1] == 0 && message[2] == 0 && message[3] == 0, "TLS 1.3 EndOfEarlyData body length is zero");
    }

    void TestTls12CipherSuiteMetadata()
    {
        const TlsCipherSuiteCapability* ecdheRsa =
            KernelHttp::tls::TlsFindCipherSuiteCapability(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256);
        Expect(ecdheRsa != nullptr, "TLS 1.2 ECDHE_RSA AES-GCM capability exists");
        if (ecdheRsa != nullptr) {
            Expect(ecdheRsa->Protocol == KernelHttp::tls::TlsProtocol::Tls12, "ECDHE_RSA AES-GCM is TLS 1.2");
            Expect(
                ecdheRsa->Tls12KeyExchange == KernelHttp::tls::Tls12KeyExchangeKind::EcdheRsa,
                "ECDHE_RSA AES-GCM declares ECDHE_RSA key exchange");
            Expect(
                ecdheRsa->Authentication == KernelHttp::tls::TlsAuthenticationKind::Rsa,
                "ECDHE_RSA AES-GCM declares RSA authentication");
            Expect(
                ecdheRsa->BulkCipher == KernelHttp::tls::TlsBulkCipherKind::AesGcm,
                "ECDHE_RSA AES-GCM declares AES-GCM bulk cipher");
            Expect(
                ecdheRsa->RecordMac == KernelHttp::tls::TlsRecordMacKind::Aead,
                "ECDHE_RSA AES-GCM declares AEAD record protection");
            Expect(
                ecdheRsa->PrfHash == KernelHttp::tls::TlsPrfHashKind::Sha256,
                "ECDHE_RSA AES-GCM declares SHA-256 PRF");
            Expect(
                HasRequiredExtension(*ecdheRsa, KernelHttp::tls::TlsCipherSuiteExtensionExtendedMasterSecret),
                "TLS 1.2 ECDHE_RSA AES-GCM requires extended_master_secret");
            Expect(
                HasRequiredExtension(*ecdheRsa, KernelHttp::tls::TlsCipherSuiteExtensionSecureRenegotiation),
                "TLS 1.2 ECDHE_RSA AES-GCM requires secure renegotiation");
            Expect(
                HasRequiredExtension(*ecdheRsa, KernelHttp::tls::TlsCipherSuiteExtensionSupportedGroups),
                "TLS 1.2 ECDHE_RSA AES-GCM requires supported_groups");
        }

        const TlsCipherSuiteCapability* ecdheEcdsa =
            KernelHttp::tls::TlsFindCipherSuiteCapability(TlsCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256);
        Expect(ecdheEcdsa != nullptr, "TLS 1.2 ECDHE_ECDSA ChaCha20-Poly1305 capability exists");
        if (ecdheEcdsa != nullptr) {
            Expect(
                ecdheEcdsa->Tls12KeyExchange == KernelHttp::tls::Tls12KeyExchangeKind::EcdheEcdsa,
                "ECDHE_ECDSA ChaCha20-Poly1305 declares ECDHE_ECDSA key exchange");
            Expect(
                ecdheEcdsa->Authentication == KernelHttp::tls::TlsAuthenticationKind::Ecdsa,
                "ECDHE_ECDSA ChaCha20-Poly1305 declares ECDSA authentication");
            Expect(
                ecdheEcdsa->BulkCipher == KernelHttp::tls::TlsBulkCipherKind::ChaCha20Poly1305,
                "ECDHE_ECDSA ChaCha20-Poly1305 declares ChaCha20-Poly1305 bulk cipher");
        }

        const TlsCipherSuiteCapability* dheRsa =
            KernelHttp::tls::TlsFindCipherSuiteCapability(TlsCipherSuite::TlsDheRsaWithAes256GcmSha384);
        Expect(dheRsa != nullptr, "TLS 1.2 DHE_RSA AES-256-GCM capability exists");
        if (dheRsa != nullptr) {
            Expect(
                dheRsa->Tls12KeyExchange == KernelHttp::tls::Tls12KeyExchangeKind::DheRsa,
                "DHE_RSA AES-256-GCM declares DHE_RSA key exchange");
            Expect(
                dheRsa->PrfHash == KernelHttp::tls::TlsPrfHashKind::Sha384,
                "DHE_RSA AES-256-GCM declares SHA-384 PRF");
            Expect(
                TlsHandshake12::PrfHashForCipherSuite(TlsCipherSuite::TlsDheRsaWithAes256GcmSha384) ==
                    KernelHttp::crypto::HashAlgorithm::Sha384,
                "TLS 1.2 PRF hash reads SHA-384 suite metadata");
        }

        const TlsCipherSuiteCapability* rsaCbc =
            KernelHttp::tls::TlsFindCipherSuiteCapability(TlsCipherSuite::TlsRsaWithAes128CbcSha256);
        Expect(rsaCbc != nullptr, "TLS 1.2 RSA AES-CBC capability exists");
        if (rsaCbc != nullptr) {
            Expect(
                rsaCbc->Tls12KeyExchange == KernelHttp::tls::Tls12KeyExchangeKind::Rsa,
                "RSA AES-CBC declares RSA key exchange");
            Expect(
                rsaCbc->Authentication == KernelHttp::tls::TlsAuthenticationKind::Rsa,
                "RSA AES-CBC declares RSA authentication");
            Expect(
                rsaCbc->BulkCipher == KernelHttp::tls::TlsBulkCipherKind::AesCbc,
                "RSA AES-CBC declares AES-CBC bulk cipher");
            Expect(
                rsaCbc->RecordMac == KernelHttp::tls::TlsRecordMacKind::HmacSha256,
                "RSA AES-CBC declares HMAC-SHA256 record MAC");
            Expect(
                HasRequiredExtension(*rsaCbc, KernelHttp::tls::TlsCipherSuiteExtensionEncryptThenMac),
                "TLS 1.2 RSA AES-CBC requires encrypt-then-MAC");
        }
    }

    void TestTls12PolicyMatrix()
    {
        TlsPolicy modern = {};
        Expect(
            KernelHttp::tls::TlsPolicyAllowsCipherSuite(modern, TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256),
            "modern policy allows TLS 1.2 ECDHE_RSA AES-GCM");
        Expect(
            KernelHttp::tls::TlsPolicyAllowsCipherSuite(modern, TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256),
            "modern policy allows TLS 1.2 ECDHE_ECDSA AES-GCM");
        Expect(
            KernelHttp::tls::TlsPolicyAllowsCipherSuite(modern, TlsCipherSuite::TlsDheRsaWithAes128GcmSha256),
            "modern policy allows TLS 1.2 DHE_RSA AES-GCM");
        Expect(
            KernelHttp::tls::TlsPolicyAllowsCipherSuite(modern, TlsCipherSuite::TlsDheRsaWithChaCha20Poly1305Sha256),
            "modern policy allows TLS 1.2 DHE_RSA ChaCha20-Poly1305");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsCipherSuite(modern, TlsCipherSuite::TlsRsaWithAes128GcmSha256),
            "modern policy rejects TLS 1.2 RSA key exchange");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsCipherSuite(modern, TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256),
            "modern policy rejects TLS 1.2 AES-CBC");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsSignatureScheme(modern, TlsSignatureScheme::RsaPkcs1Sha1),
            "modern policy rejects TLS 1.2 rsa_pkcs1_sha1");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsSignatureScheme(modern, TlsSignatureScheme::EcdsaSha1),
            "modern policy rejects TLS 1.2 ecdsa_sha1");

        modern.EnableTls12Sha1Signatures = true;
        ExpectStatus(
            KernelHttp::tls::TlsValidatePolicy(modern),
            STATUS_INVALID_PARAMETER,
            "modern policy rejects SHA1 signature opt-in");

        TlsPolicy compatibility = {};
        compatibility.Profile = KernelHttp::tls::TlsSecurityProfile::CompatibilityExplicit;
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsCipherSuite(compatibility, TlsCipherSuite::TlsRsaWithAes128GcmSha256),
            "compatibility policy still requires explicit RSA key exchange opt-in");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsCipherSuite(compatibility, TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256),
            "compatibility policy still requires explicit CBC opt-in");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsSignatureScheme(compatibility, TlsSignatureScheme::RsaPkcs1Sha1),
            "compatibility policy keeps rsa_pkcs1_sha1 disabled without SHA1 opt-in");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsSignatureScheme(compatibility, TlsSignatureScheme::EcdsaSha1),
            "compatibility policy keeps ecdsa_sha1 disabled without SHA1 opt-in");

        compatibility.EnableTls12RsaKeyExchange = true;
        Expect(
            KernelHttp::tls::TlsPolicyAllowsCipherSuite(compatibility, TlsCipherSuite::TlsRsaWithAes128GcmSha256),
            "compatibility policy allows RSA AES-GCM after RSA opt-in");
        Expect(
            !KernelHttp::tls::TlsPolicyAllowsCipherSuite(compatibility, TlsCipherSuite::TlsRsaWithAes128CbcSha256),
            "compatibility policy keeps RSA AES-CBC disabled without CBC opt-in");

        compatibility.EnableTls12Cbc = true;
        Expect(
            KernelHttp::tls::TlsPolicyAllowsCipherSuite(compatibility, TlsCipherSuite::TlsRsaWithAes128CbcSha256),
            "compatibility policy allows RSA AES-CBC after RSA and CBC opt-in");
        Expect(
            KernelHttp::tls::TlsPolicyAllowsCipherSuite(compatibility, TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256),
            "compatibility policy allows ECDHE AES-CBC after CBC opt-in");

        compatibility.EnableTls12Sha1Signatures = true;
        Expect(
            KernelHttp::tls::TlsPolicyAllowsSignatureScheme(compatibility, TlsSignatureScheme::RsaPkcs1Sha1),
            "compatibility policy allows rsa_pkcs1_sha1 after SHA1 opt-in");
        Expect(
            KernelHttp::tls::TlsPolicyAllowsSignatureScheme(compatibility, TlsSignatureScheme::EcdsaSha1),
            "compatibility policy allows ecdsa_sha1 after SHA1 opt-in");
    }

    void TestTls12ClientHelloEncodesExplicitFullMatrix()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 context initializes for explicit suite matrix");

        const TlsCipherSuite suites[] = {
            TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite::TlsDheRsaWithAes128GcmSha256,
            TlsCipherSuite::TlsRsaWithAes128GcmSha256,
            TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256,
            TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256
        };

        TlsClientHelloOptions options = {};
        options.ServerName = "example.com";
        options.ServerNameLength = strlen(options.ServerName);
        options.CipherSuites = suites;
        options.CipherSuiteCount = sizeof(suites) / sizeof(suites[0]);

        UCHAR message[2048] = {};
        SIZE_T written = 0;
        status = TlsHandshake12::EncodeClientHello(context, options, message, sizeof(message), &written);

        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 ClientHello encodes explicit full suite matrix");
        Expect(ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256), "TLS 1.2 ClientHello offers ECDHE_RSA AES-GCM");
        Expect(ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256), "TLS 1.2 ClientHello offers ECDHE_ECDSA AES-GCM");
        Expect(ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsDheRsaWithAes128GcmSha256), "TLS 1.2 ClientHello offers DHE_RSA AES-GCM");
        Expect(ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsRsaWithAes128GcmSha256), "TLS 1.2 ClientHello offers RSA AES-GCM");
        Expect(ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256), "TLS 1.2 ClientHello offers AES-CBC");
        Expect(ClientHelloOffersCipherSuite(message, written, TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256), "TLS 1.2 ClientHello offers ChaCha20-Poly1305");
        Expect(ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPssRsaeSha512), "TLS 1.2 ClientHello offers RSA-PSS-RSAE SHA512");
        Expect(ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPkcs1Sha512), "TLS 1.2 ClientHello offers RSA-PKCS1 SHA512");
        Expect(ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::EcdsaSecp521r1Sha512), "TLS 1.2 ClientHello offers ECDSA P-521 SHA512");
        Expect(ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::Ed25519), "TLS 1.2 ClientHello offers Ed25519");
        Expect(ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::Ed448), "TLS 1.2 ClientHello offers Ed448");
    }

    void TestTls12ClientHelloSignatureSha1Matrix()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient({ 3, 3 });
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 context initializes for default signature matrix");

        UCHAR message[2048] = {};
        SIZE_T written = 0;
        TlsClientHelloOptions options = {};
        status = TlsHandshake12::EncodeClientHello(context, options, message, sizeof(message), &written);

        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 ClientHello encodes default signature matrix");
        Expect(
            !ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPkcs1Sha1),
            "modern TLS 1.2 ClientHello does not offer rsa_pkcs1_sha1");
        Expect(
            !ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::EcdsaSha1),
            "modern TLS 1.2 ClientHello does not offer ecdsa_sha1");

        const TlsSignatureScheme compatibilitySchemes[] = {
            TlsSignatureScheme::RsaPssRsaeSha256,
            TlsSignatureScheme::EcdsaSecp256r1Sha256,
            TlsSignatureScheme::RsaPkcs1Sha1,
            TlsSignatureScheme::EcdsaSha1
        };

        TlsContext compatibilityContext;
        status = compatibilityContext.InitializeClient({ 3, 3 });
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 context initializes for compatibility signature matrix");

        options = {};
        options.SignatureSchemes = compatibilitySchemes;
        options.SignatureSchemeCount = sizeof(compatibilitySchemes) / sizeof(compatibilitySchemes[0]);
        written = 0;
        status = TlsHandshake12::EncodeClientHello(
            compatibilityContext,
            options,
            message,
            sizeof(message),
            &written);

        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.2 ClientHello encodes explicit compatibility signature matrix");
        Expect(
            ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::RsaPkcs1Sha1),
            "compatibility TLS 1.2 ClientHello can offer rsa_pkcs1_sha1 when enabled by policy");
        Expect(
            ClientHelloOffersSignatureScheme(message, written, TlsSignatureScheme::EcdsaSha1),
            "compatibility TLS 1.2 ClientHello can offer ecdsa_sha1 when enabled by policy");
    }
}

int main()
{
    TestDefaultTls13ClientHelloOffersX25519First();
    TestTls13ClientHelloEncodesRawX25519KeyShare();
    TestTls13HelloRetryRequestCanSelectP256AfterX25519Offer();
    TestTls13HelloRetryRequestCanSelectFfdheAfterX25519Offer();
    TestTls13EncodeEmptyClientCertificate();
    TestTls13EncodeClientCertificateVerifyAndEndOfEarlyData();
    TestTls12CipherSuiteMetadata();
    TestTls12PolicyMatrix();
    TestTls12ClientHelloEncodesExplicitFullMatrix();
    TestTls12ClientHelloSignatureSha1Matrix();

    if (g_failed) {
        return 1;
    }

    printf("PASS: TLS handshake tests\n");
    return 0;
}
