#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/tls/CertificateStore.h>
#include <wknet/tls/CertificateValidator.h>
#include <wknet/tls/TlsCapabilities.h>
#include <wknet/tls/TlsConnection.h>
#include <wknet/tls/TlsPolicy.h>

#include <stdio.h>
#include <string.h>

using wknet::tls::CertificateRevocationEntry;
using wknet::tls::CertificateRevocationMode;
using wknet::tls::CertificateRevocationSource;
using wknet::tls::CertificateRevocationStatus;
using wknet::tls::CertificateStore;
using wknet::tls::CertificateStoreOptions;
using wknet::tls::CertificateValidationOptions;
using wknet::tls::Tls12KeyExchangeKind;
using wknet::tls::Tls12SessionCache;
using wknet::tls::Tls13SessionCache;
using wknet::tls::TlsBulkCipherKind;
using wknet::tls::TlsCapabilityDisposition;
using wknet::tls::TlsCipherSuite;
using wknet::tls::TlsCipherSuiteCapability;
using wknet::tls::TlsClientConnectionOptions;
using wknet::tls::TlsClientCredential;
using wknet::tls::TlsClientCredentialKeyAlgorithm;
using wknet::tls::TlsNamedGroup;
using wknet::tls::TlsNamedGroupKind;
using wknet::tls::TlsPolicy;
using wknet::tls::TlsPrfHashKind;
using wknet::tls::TlsProtocol;
using wknet::tls::TlsRecordMacKind;
using wknet::tls::TlsSecurityProfile;
using wknet::tls::TlsSignatureScheme;

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* scenario, const char* message)
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s: %s\n", scenario, message);
        }
    }

    void ExpectStatus(NTSTATUS actual, NTSTATUS expected, const char* scenario, const char* message)
    {
        if (actual != expected) {
            g_failed = true;
            printf(
                "FAIL: %s: %s (actual=0x%08X expected=0x%08X)\n",
                scenario,
                message,
                static_cast<unsigned int>(actual),
                static_cast<unsigned int>(expected));
        }
    }

    const char* AlpnH2 = "h2";
    const char* AlpnHttp11 = "http/1.1";

    struct Tls13CipherExpectation final
    {
        const char* Name;
        TlsCipherSuite Suite;
        TlsBulkCipherKind BulkCipher;
        TlsPrfHashKind PrfHash;
        TlsCapabilityDisposition ExpectedDisposition;
    };

    struct NamedGroupExpectation final
    {
        const char* Name;
        TlsNamedGroup Group;
        TlsNamedGroupKind Kind;
    };

    struct Tls12CipherExpectation final
    {
        const char* Name;
        TlsCipherSuite Suite;
        Tls12KeyExchangeKind KeyExchange;
        TlsBulkCipherKind BulkCipher;
        TlsRecordMacKind RecordMac;
        TlsPrfHashKind PrfHash;
        bool ModernPolicyAllowed;
        bool CompatibilityPolicyAllowed;
        ULONG RequiredExtensions;
    };

    struct InteropScenario final
    {
        const char* Name;
        TlsProtocol Protocol;
        TlsCipherSuite Suite;
        bool HasGroup;
        TlsNamedGroup Group;
        Tls12KeyExchangeKind KeyExchange;
        bool RequiresCompatibilityPolicy;
        bool RequiresRenegotiationPolicy;
        bool UsesClientCertificate;
        bool UsesResumption;
        bool UsesEarlyData;
        bool UsesKeyUpdate;
        const char* Alpn;
        SIZE_T AlpnLength;
    };

    NTSTATUS TestCredentialSign(
        void* context,
        TlsSignatureScheme scheme,
        const UCHAR* input,
        SIZE_T inputLength,
        UCHAR* signature,
        SIZE_T signatureCapacity,
        SIZE_T* signatureLength)
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(scheme);
        UNREFERENCED_PARAMETER(input);
        UNREFERENCED_PARAMETER(inputLength);

        if (signatureLength != nullptr) {
            *signatureLength = 0;
        }
        if (signature == nullptr || signatureLength == nullptr || signatureCapacity < 4) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        signature[0] = 0x4b;
        signature[1] = 0x48;
        signature[2] = 0x54;
        signature[3] = 0x50;
        *signatureLength = 4;
        return STATUS_SUCCESS;
    }

    bool HasRequiredExtensions(const TlsCipherSuiteCapability& capability, ULONG extensions)
    {
        return (capability.RequiredExtensions & extensions) == extensions;
    }

    void TestTls13CapabilityMatrix()
    {
        static const Tls13CipherExpectation ciphers[] = {
            {
                "TLS 1.3 AES_128_GCM_SHA256",
                TlsCipherSuite::TlsAes128GcmSha256,
                TlsBulkCipherKind::AesGcm,
                TlsPrfHashKind::Sha256,
                TlsCapabilityDisposition::Default
            },
            {
                "TLS 1.3 AES_256_GCM_SHA384",
                TlsCipherSuite::TlsAes256GcmSha384,
                TlsBulkCipherKind::AesGcm,
                TlsPrfHashKind::Sha384,
                TlsCapabilityDisposition::Default
            },
            {
                "TLS 1.3 CHACHA20_POLY1305_SHA256",
                TlsCipherSuite::TlsChaCha20Poly1305Sha256,
                TlsBulkCipherKind::ChaCha20Poly1305,
                TlsPrfHashKind::Sha256,
                TlsCapabilityDisposition::Default
            },
            {
                "TLS 1.3 AES_128_CCM_SHA256",
                TlsCipherSuite::TlsAes128CcmSha256,
                TlsBulkCipherKind::AesCcm,
                TlsPrfHashKind::Sha256,
                TlsCapabilityDisposition::Optional
            },
            {
                "TLS 1.3 AES_128_CCM_8_SHA256",
                TlsCipherSuite::TlsAes128Ccm8Sha256,
                TlsBulkCipherKind::AesCcm,
                TlsPrfHashKind::Sha256,
                TlsCapabilityDisposition::Optional
            }
        };

        TlsPolicy policy = {};
        for (SIZE_T index = 0; index < sizeof(ciphers) / sizeof(ciphers[0]); ++index) {
            const Tls13CipherExpectation& expected = ciphers[index];
            const TlsCipherSuiteCapability* capability =
                wknet::tls::TlsFindCipherSuiteCapability(expected.Suite);

            Expect(capability != nullptr, expected.Name, "cipher suite is present in the matrix");
            if (capability == nullptr) {
                continue;
            }

            Expect(capability->Protocol == TlsProtocol::Tls13, expected.Name, "protocol is TLS 1.3");
            Expect(capability->BulkCipher == expected.BulkCipher, expected.Name, "bulk cipher metadata matches");
            Expect(capability->RecordMac == TlsRecordMacKind::Aead, expected.Name, "record MAC is AEAD");
            Expect(capability->PrfHash == expected.PrfHash, expected.Name, "HKDF hash metadata matches");
            Expect(
                capability->DefaultDisposition == expected.ExpectedDisposition,
                expected.Name,
                "default disposition matches the public policy table");
            Expect(
                wknet::tls::TlsPolicyAllowsCipherSuite(policy, expected.Suite),
                expected.Name,
                "modern policy can offer the implemented TLS 1.3 suite");
        }
    }

    void TestNamedGroupMatrix()
    {
        static const NamedGroupExpectation groups[] = {
            { "X25519", TlsNamedGroup::X25519, TlsNamedGroupKind::Xdh },
            { "X448", TlsNamedGroup::X448, TlsNamedGroupKind::Xdh },
            { "P-256", TlsNamedGroup::Secp256r1, TlsNamedGroupKind::NistCurve },
            { "P-384", TlsNamedGroup::Secp384r1, TlsNamedGroupKind::NistCurve },
            { "P-521", TlsNamedGroup::Secp521r1, TlsNamedGroupKind::NistCurve },
            { "FFDHE2048", TlsNamedGroup::Ffdhe2048, TlsNamedGroupKind::Ffdhe },
            { "FFDHE3072", TlsNamedGroup::Ffdhe3072, TlsNamedGroupKind::Ffdhe },
            { "FFDHE4096", TlsNamedGroup::Ffdhe4096, TlsNamedGroupKind::Ffdhe },
            { "FFDHE6144", TlsNamedGroup::Ffdhe6144, TlsNamedGroupKind::Ffdhe },
            { "FFDHE8192", TlsNamedGroup::Ffdhe8192, TlsNamedGroupKind::Ffdhe }
        };

        TlsPolicy policy = {};
        for (SIZE_T index = 0; index < sizeof(groups) / sizeof(groups[0]); ++index) {
            const NamedGroupExpectation& expected = groups[index];
            const auto* capability = wknet::tls::TlsFindNamedGroupCapability(expected.Group);
            Expect(capability != nullptr, expected.Name, "named group is present in the matrix");
            if (capability == nullptr) {
                continue;
            }

            Expect(capability->Kind == expected.Kind, expected.Name, "group family metadata matches");
            Expect(
                wknet::tls::TlsPolicyAllowsNamedGroup(policy, expected.Group),
                expected.Name,
                "modern policy can offer the implemented group");
        }
    }

    void TestTls12CapabilityMatrix()
    {
        constexpr ULONG BaseExtensions =
            wknet::tls::TlsCipherSuiteExtensionExtendedMasterSecret |
            wknet::tls::TlsCipherSuiteExtensionSecureRenegotiation;
        constexpr ULONG EphemeralExtensions =
            BaseExtensions |
            wknet::tls::TlsCipherSuiteExtensionSupportedGroups;
        constexpr ULONG CbcExtensions =
            EphemeralExtensions |
            wknet::tls::TlsCipherSuiteExtensionEncryptThenMac;

        static const Tls12CipherExpectation suites[] = {
            {
                "TLS 1.2 ECDHE_RSA AES_128_GCM_SHA256",
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                Tls12KeyExchangeKind::EcdheRsa,
                TlsBulkCipherKind::AesGcm,
                TlsRecordMacKind::Aead,
                TlsPrfHashKind::Sha256,
                true,
                true,
                EphemeralExtensions
            },
            {
                "TLS 1.2 ECDHE_ECDSA AES_128_GCM_SHA256",
                TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
                Tls12KeyExchangeKind::EcdheEcdsa,
                TlsBulkCipherKind::AesGcm,
                TlsRecordMacKind::Aead,
                TlsPrfHashKind::Sha256,
                true,
                true,
                EphemeralExtensions
            },
            {
                "TLS 1.2 DHE_RSA AES_128_GCM_SHA256",
                TlsCipherSuite::TlsDheRsaWithAes128GcmSha256,
                Tls12KeyExchangeKind::DheRsa,
                TlsBulkCipherKind::AesGcm,
                TlsRecordMacKind::Aead,
                TlsPrfHashKind::Sha256,
                true,
                true,
                EphemeralExtensions
            },
            {
                "TLS 1.2 RSA AES_128_GCM_SHA256",
                TlsCipherSuite::TlsRsaWithAes128GcmSha256,
                Tls12KeyExchangeKind::Rsa,
                TlsBulkCipherKind::AesGcm,
                TlsRecordMacKind::Aead,
                TlsPrfHashKind::Sha256,
                false,
                true,
                BaseExtensions
            },
            {
                "TLS 1.2 ECDHE_RSA AES_128_CBC_SHA256",
                TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256,
                Tls12KeyExchangeKind::EcdheRsa,
                TlsBulkCipherKind::AesCbc,
                TlsRecordMacKind::HmacSha256,
                TlsPrfHashKind::Sha256,
                false,
                true,
                CbcExtensions
            },
            {
                "TLS 1.2 RSA AES_128_CBC_SHA256",
                TlsCipherSuite::TlsRsaWithAes128CbcSha256,
                Tls12KeyExchangeKind::Rsa,
                TlsBulkCipherKind::AesCbc,
                TlsRecordMacKind::HmacSha256,
                TlsPrfHashKind::Sha256,
                false,
                true,
                BaseExtensions | wknet::tls::TlsCipherSuiteExtensionEncryptThenMac
            },
            {
                "TLS 1.2 ECDHE_RSA CHACHA20_POLY1305_SHA256",
                TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256,
                Tls12KeyExchangeKind::EcdheRsa,
                TlsBulkCipherKind::ChaCha20Poly1305,
                TlsRecordMacKind::Aead,
                TlsPrfHashKind::Sha256,
                true,
                true,
                EphemeralExtensions
            },
            {
                "TLS 1.2 DHE_RSA CHACHA20_POLY1305_SHA256",
                TlsCipherSuite::TlsDheRsaWithChaCha20Poly1305Sha256,
                Tls12KeyExchangeKind::DheRsa,
                TlsBulkCipherKind::ChaCha20Poly1305,
                TlsRecordMacKind::Aead,
                TlsPrfHashKind::Sha256,
                true,
                true,
                EphemeralExtensions
            }
        };

        TlsPolicy modern = {};
        TlsPolicy compatibility = {};
        compatibility.Profile = TlsSecurityProfile::CompatibilityExplicit;
        compatibility.EnableTls12RsaKeyExchange = true;
        compatibility.EnableTls12Cbc = true;
        compatibility.EnableTls12Renegotiation = true;

        for (SIZE_T index = 0; index < sizeof(suites) / sizeof(suites[0]); ++index) {
            const Tls12CipherExpectation& expected = suites[index];
            const TlsCipherSuiteCapability* capability =
                wknet::tls::TlsFindCipherSuiteCapability(expected.Suite);

            Expect(capability != nullptr, expected.Name, "cipher suite is present in the matrix");
            if (capability == nullptr) {
                continue;
            }

            Expect(capability->Protocol == TlsProtocol::Tls12, expected.Name, "protocol is TLS 1.2");
            Expect(capability->Tls12KeyExchange == expected.KeyExchange, expected.Name, "key exchange metadata matches");
            Expect(capability->BulkCipher == expected.BulkCipher, expected.Name, "bulk cipher metadata matches");
            Expect(capability->RecordMac == expected.RecordMac, expected.Name, "record MAC metadata matches");
            Expect(capability->PrfHash == expected.PrfHash, expected.Name, "PRF hash metadata matches");
            Expect(HasRequiredExtensions(*capability, expected.RequiredExtensions), expected.Name, "required extension metadata matches");
            Expect(
                wknet::tls::TlsPolicyAllowsCipherSuite(modern, expected.Suite) == expected.ModernPolicyAllowed,
                expected.Name,
                "modern policy decision matches matrix expectation");
            Expect(
                wknet::tls::TlsPolicyAllowsCipherSuite(compatibility, expected.Suite) ==
                    expected.CompatibilityPolicyAllowed,
                expected.Name,
                "compatibility policy decision matches matrix expectation");
        }

        Expect(
            !wknet::tls::TlsPolicyAllowsTls12Renegotiation(modern),
            "TLS 1.2 renegotiation",
            "modern policy disables renegotiation");
        Expect(
            wknet::tls::TlsPolicyAllowsTls12Renegotiation(compatibility),
            "TLS 1.2 renegotiation",
            "compatibility policy enables renegotiation only after explicit opt-in");
    }

    void TestLocalInteropScenarioManifest()
    {
        static const InteropScenario scenarios[] = {
            {
                "tls13-aes128-gcm-x25519-h2",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes128GcmSha256,
                true,
                TlsNamedGroup::X25519,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnH2,
                2
            },
            {
                "tls13-aes256-gcm-x448-http11",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes256GcmSha384,
                true,
                TlsNamedGroup::X448,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls13-chacha20-p256",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsChaCha20Poly1305Sha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnH2,
                2
            },
            {
                "tls13-aes128-ccm-p384",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes128CcmSha256,
                true,
                TlsNamedGroup::Secp384r1,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls13-aes128-ccm8-p521",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes128Ccm8Sha256,
                true,
                TlsNamedGroup::Secp521r1,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls13-aes128-gcm-ffdhe2048",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes128GcmSha256,
                true,
                TlsNamedGroup::Ffdhe2048,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnH2,
                2
            },
            {
                "tls13-client-cert",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes128GcmSha256,
                true,
                TlsNamedGroup::X25519,
                Tls12KeyExchangeKind::None,
                false,
                false,
                true,
                false,
                false,
                false,
                AlpnH2,
                2
            },
            {
                "tls13-resumption-0rtt",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes128GcmSha256,
                true,
                TlsNamedGroup::X25519,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                true,
                true,
                false,
                AlpnH2,
                2
            },
            {
                "tls13-keyupdate",
                TlsProtocol::Tls13,
                TlsCipherSuite::TlsAes256GcmSha384,
                true,
                TlsNamedGroup::X25519,
                Tls12KeyExchangeKind::None,
                false,
                false,
                false,
                false,
                false,
                true,
                AlpnHttp11,
                8
            },
            {
                "tls12-ecdhe-rsa-aesgcm",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::EcdheRsa,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnH2,
                2
            },
            {
                "tls12-ecdhe-ecdsa-aesgcm",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::EcdheEcdsa,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls12-dhe-rsa-ffdhe-aesgcm",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsDheRsaWithAes128GcmSha256,
                true,
                TlsNamedGroup::Ffdhe2048,
                Tls12KeyExchangeKind::DheRsa,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls12-rsa-aesgcm-compat",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsRsaWithAes128GcmSha256,
                false,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::Rsa,
                true,
                false,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls12-ecdhe-rsa-cbc-etm-compat",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::EcdheRsa,
                true,
                false,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls12-ecdhe-rsa-chacha20",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::EcdheRsa,
                false,
                false,
                false,
                false,
                false,
                false,
                AlpnH2,
                2
            },
            {
                "tls12-client-cert",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::EcdheRsa,
                false,
                false,
                true,
                false,
                false,
                false,
                AlpnHttp11,
                8
            },
            {
                "tls12-session-resumption",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::EcdheRsa,
                false,
                false,
                false,
                true,
                false,
                false,
                AlpnH2,
                2
            },
            {
                "tls12-renegotiation-policy",
                TlsProtocol::Tls12,
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                true,
                TlsNamedGroup::Secp256r1,
                Tls12KeyExchangeKind::EcdheRsa,
                true,
                true,
                false,
                false,
                false,
                false,
                AlpnHttp11,
                8
            }
        };

        TlsPolicy modern = {};
        TlsPolicy compatibility = {};
        compatibility.Profile = TlsSecurityProfile::CompatibilityExplicit;
        compatibility.EnableTls12RsaKeyExchange = true;
        compatibility.EnableTls12Cbc = true;
        compatibility.EnableTls12Renegotiation = true;
        compatibility.EnablePostHandshakeClientAuth = true;

        bool sawClientCert = false;
        bool sawResumption = false;
        bool sawEarlyData = false;
        bool sawKeyUpdate = false;
        bool sawRenegotiationPolicy = false;

        for (SIZE_T index = 0; index < sizeof(scenarios) / sizeof(scenarios[0]); ++index) {
            const InteropScenario& scenario = scenarios[index];
            const TlsPolicy& policy = scenario.RequiresCompatibilityPolicy ? compatibility : modern;
            const TlsCipherSuiteCapability* capability =
                wknet::tls::TlsFindCipherSuiteCapability(scenario.Suite);

            Expect(capability != nullptr, scenario.Name, "scenario cipher is implemented");
            if (capability == nullptr) {
                continue;
            }

            Expect(capability->Protocol == scenario.Protocol, scenario.Name, "scenario protocol matches cipher metadata");
            if (scenario.Protocol == TlsProtocol::Tls12) {
                Expect(
                    capability->Tls12KeyExchange == scenario.KeyExchange,
                    scenario.Name,
                    "scenario TLS 1.2 key exchange matches cipher metadata");
            }
            if (scenario.HasGroup) {
                Expect(wknet::tls::TlsIsKnownNamedGroup(scenario.Group), scenario.Name, "scenario group is implemented");
                Expect(
                    wknet::tls::TlsPolicyAllowsNamedGroup(policy, scenario.Group),
                    scenario.Name,
                    "scenario policy can offer the named group");
            }

            Expect(
                wknet::tls::TlsPolicyAllowsCipherSuite(policy, scenario.Suite),
                scenario.Name,
                "scenario policy can offer the cipher");
            if (scenario.RequiresRenegotiationPolicy) {
                Expect(
                    wknet::tls::TlsPolicyAllowsTls12Renegotiation(policy),
                    scenario.Name,
                    "scenario has explicit renegotiation policy");
                sawRenegotiationPolicy = true;
            }

            Expect(scenario.Alpn != nullptr && scenario.AlpnLength != 0, scenario.Name, "scenario declares ALPN");
            sawClientCert = sawClientCert || scenario.UsesClientCertificate;
            sawResumption = sawResumption || scenario.UsesResumption;
            sawEarlyData = sawEarlyData || scenario.UsesEarlyData;
            sawKeyUpdate = sawKeyUpdate || scenario.UsesKeyUpdate;
            if (scenario.UsesEarlyData) {
                Expect(scenario.Protocol == TlsProtocol::Tls13, scenario.Name, "0-RTT is TLS 1.3 only");
                Expect(scenario.UsesResumption, scenario.Name, "0-RTT scenario is tied to resumption");
            }
            if (scenario.UsesKeyUpdate) {
                Expect(scenario.Protocol == TlsProtocol::Tls13, scenario.Name, "KeyUpdate is TLS 1.3 only");
            }
        }

        Expect(sawClientCert, "interop manifest", "client certificate scenarios are present");
        Expect(sawResumption, "interop manifest", "resumption scenarios are present");
        Expect(sawEarlyData, "interop manifest", "0-RTT scenario is present");
        Expect(sawKeyUpdate, "interop manifest", "KeyUpdate scenario is present");
        Expect(sawRenegotiationPolicy, "interop manifest", "renegotiation policy scenario is present");
    }

    void TestClientCredentialAndResumptionSurface()
    {
        static const TlsSignatureScheme schemes[] = {
            TlsSignatureScheme::RsaPssRsaeSha256,
            TlsSignatureScheme::RsaPssRsaeSha384,
            TlsSignatureScheme::RsaPkcs1Sha256
        };
        static const UCHAR certificateList[] = { 0, 0, 3, 1, 2, 3 };
        static const UCHAR earlyData[] = { 'G', 'E', 'T' };

        TlsClientCredential credential = {};
        credential.CertificateList = certificateList;
        credential.CertificateListLength = sizeof(certificateList);
        credential.KeyAlgorithm = TlsClientCredentialKeyAlgorithm::Rsa;
        credential.SupportedSignatureSchemes = schemes;
        credential.SupportedSignatureSchemeCount = sizeof(schemes) / sizeof(schemes[0]);
        credential.Sign = TestCredentialSign;
        credential.AllowsDigitalSignature = true;

        UCHAR signature[8] = {};
        SIZE_T signatureLength = 0;
        NTSTATUS status = credential.Sign(
            credential.SignContext,
            schemes[0],
            earlyData,
            sizeof(earlyData),
            signature,
            sizeof(signature),
            &signatureLength);
        ExpectStatus(status, STATUS_SUCCESS, "client credential", "test signing callback succeeds");
        Expect(signatureLength == 4, "client credential", "test signing callback reports signature length");

        Tls13SessionCache tls13Cache = {};
        Tls12SessionCache tls12Cache = {};
        TlsClientConnectionOptions options = {};
        options.ServerName = "localhost";
        options.ServerNameLength = strlen(options.ServerName);
        options.SessionCache = &tls13Cache;
        options.Tls12SessionCache = &tls12Cache;
        options.ClientCredential = &credential;
        options.EnableSessionResumption = true;
        options.EnableEarlyData = true;
        options.EarlyDataReplaySafe = true;
        options.EarlyData = earlyData;
        options.EarlyDataLength = sizeof(earlyData);
        options.Policy.Profile = TlsSecurityProfile::CompatibilityExplicit;
        options.Policy.EnablePostHandshakeClientAuth = true;

        Expect(options.SessionCache != nullptr, "connection options", "TLS 1.3 session cache is plumbed");
        Expect(options.Tls12SessionCache != nullptr, "connection options", "TLS 1.2 session cache is plumbed");
        Expect(options.ClientCredential != nullptr, "connection options", "client credential is plumbed");
        Expect(options.EnableEarlyData && options.EarlyDataReplaySafe, "connection options", "0-RTT requires explicit replay-safe opt-in");
        Expect(
            options.Policy.EnablePostHandshakeClientAuth,
            "connection options",
            "post-handshake client auth is explicit policy");
    }

    void TestCertificatePolicySurface()
    {
        static const UCHAR issuerName[] = { 0x30, 0x03, 0x31, 0x01, 0x00 };
        static const UCHAR serialNumber[] = { 0x01, 0x23, 0x45 };
        static const UCHAR evidenceDer[] = { 0x30, 0x00 };

        CertificateRevocationEntry entry = {};
        entry.IssuerName = issuerName;
        entry.IssuerNameLength = sizeof(issuerName);
        entry.SerialNumber = serialNumber;
        entry.SerialNumberLength = sizeof(serialNumber);
        entry.Source = CertificateRevocationSource::Ocsp;
        entry.EvidenceDer = evidenceDer;
        entry.EvidenceDerLength = sizeof(evidenceDer);

        CertificateStoreOptions storeOptions = {};
        storeOptions.RevocationEntries = &entry;
        storeOptions.RevocationEntryCount = 1;

        CertificateStore store;
        NTSTATUS status = store.Initialize(storeOptions);
        ExpectStatus(status, STATUS_SUCCESS, "certificate policy", "revocation cache entry is accepted");
        Expect(store.RevocationEntryCount() == 1, "certificate policy", "revocation cache count is visible");
        Expect(
            store.FindRevocationEntry(
                issuerName,
                sizeof(issuerName),
                serialNumber,
                sizeof(serialNumber),
                CertificateRevocationSource::Ocsp) == &entry,
            "certificate policy",
            "OCSP revocation entry lookup is available");

        CertificateValidationOptions validation = {};
        validation.Store = &store;
        validation.RevocationMode = CertificateRevocationMode::StapledOnly;
        validation.EnableIdna = true;
        Expect(validation.RevocationMode == CertificateRevocationMode::StapledOnly, "certificate policy", "stapled revocation mode is selectable");
        validation.RevocationMode = CertificateRevocationMode::OnlineRequired;
        Expect(validation.RevocationMode == CertificateRevocationMode::OnlineRequired, "certificate policy", "online-required revocation mode is selectable");
        validation.EnableIdna = false;
        Expect(!validation.EnableIdna, "certificate policy", "IDNA policy can be disabled explicitly");
    }
}

int main()
{
    TestTls13CapabilityMatrix();
    TestNamedGroupMatrix();
    TestTls12CapabilityMatrix();
    TestLocalInteropScenarioManifest();
    TestClientCredentialAndResumptionSurface();
    TestCertificatePolicySurface();

    if (g_failed) {
        printf("TLS INTEROP MATRIX TESTS FAILED\n");
        return 1;
    }

    printf("PASS: TLS interop matrix tests\n");
    return 0;
}
