#include <KernelHttp/tls/TlsCapabilities.h>

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        const TlsCipherSuiteCapability CipherSuiteCapabilities[] = {
            {
                TlsCipherSuite::TlsAes128GcmSha256,
                TlsProtocol::Tls13,
                Tls12KeyExchangeKind::None,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsAes256GcmSha384,
                TlsProtocol::Tls13,
                Tls12KeyExchangeKind::None,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsChaCha20Poly1305Sha256,
                TlsProtocol::Tls13,
                Tls12KeyExchangeKind::None,
                TlsBulkCipherKind::ChaCha20Poly1305,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsAes128CcmSha256,
                TlsProtocol::Tls13,
                Tls12KeyExchangeKind::None,
                TlsBulkCipherKind::AesCcm,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsCipherSuite::TlsAes128Ccm8Sha256,
                TlsProtocol::Tls13,
                Tls12KeyExchangeKind::None,
                TlsBulkCipherKind::AesCcm,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheRsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheEcdsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheRsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheEcdsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheRsa,
                TlsBulkCipherKind::ChaCha20Poly1305,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheEcdsa,
                TlsBulkCipherKind::ChaCha20Poly1305,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsCipherSuite::TlsDheRsaWithAes128GcmSha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::DheRsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsCipherSuite::TlsDheRsaWithAes256GcmSha384,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::DheRsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsCipherSuite::TlsDheRsaWithChaCha20Poly1305Sha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::DheRsa,
                TlsBulkCipherKind::ChaCha20Poly1305,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsCipherSuite::TlsEcdheRsaWithAes128CbcSha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheRsa,
                TlsBulkCipherKind::AesCbc,
                TlsCapabilityDisposition::Legacy,
                TlsCapabilityDisposition::Legacy
            },
            {
                TlsCipherSuite::TlsEcdheEcdsaWithAes128CbcSha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::EcdheEcdsa,
                TlsBulkCipherKind::AesCbc,
                TlsCapabilityDisposition::Legacy,
                TlsCapabilityDisposition::Legacy
            },
            {
                TlsCipherSuite::TlsRsaWithAes128GcmSha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::Rsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Legacy,
                TlsCapabilityDisposition::Legacy
            },
            {
                TlsCipherSuite::TlsRsaWithAes256GcmSha384,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::Rsa,
                TlsBulkCipherKind::AesGcm,
                TlsCapabilityDisposition::Legacy,
                TlsCapabilityDisposition::Legacy
            },
            {
                TlsCipherSuite::TlsRsaWithAes128CbcSha256,
                TlsProtocol::Tls12,
                Tls12KeyExchangeKind::Rsa,
                TlsBulkCipherKind::AesCbc,
                TlsCapabilityDisposition::Legacy,
                TlsCapabilityDisposition::Legacy
            }
        };

        const TlsNamedGroupCapability NamedGroupCapabilities[] = {
            {
                TlsNamedGroup::X25519,
                TlsNamedGroupKind::Xdh,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsNamedGroup::Secp256r1,
                TlsNamedGroupKind::NistCurve,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsNamedGroup::Secp384r1,
                TlsNamedGroupKind::NistCurve,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsNamedGroup::Secp521r1,
                TlsNamedGroupKind::NistCurve,
                TlsCapabilityDisposition::Default,
                TlsCapabilityDisposition::Default
            },
            {
                TlsNamedGroup::X448,
                TlsNamedGroupKind::Xdh,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsNamedGroup::Ffdhe2048,
                TlsNamedGroupKind::Ffdhe,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsNamedGroup::Ffdhe3072,
                TlsNamedGroupKind::Ffdhe,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsNamedGroup::Ffdhe4096,
                TlsNamedGroupKind::Ffdhe,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsNamedGroup::Ffdhe6144,
                TlsNamedGroupKind::Ffdhe,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            },
            {
                TlsNamedGroup::Ffdhe8192,
                TlsNamedGroupKind::Ffdhe,
                TlsCapabilityDisposition::Optional,
                TlsCapabilityDisposition::Optional
            }
        };

        const TlsSignatureSchemeCapability SignatureSchemeCapabilities[] = {
            { TlsSignatureScheme::RsaPssRsaeSha256, TlsCapabilityDisposition::Default, TlsCapabilityDisposition::Default },
            { TlsSignatureScheme::RsaPssRsaeSha384, TlsCapabilityDisposition::Default, TlsCapabilityDisposition::Default },
            { TlsSignatureScheme::RsaPssRsaeSha512, TlsCapabilityDisposition::Default, TlsCapabilityDisposition::Default },
            { TlsSignatureScheme::EcdsaSecp256r1Sha256, TlsCapabilityDisposition::Default, TlsCapabilityDisposition::Default },
            { TlsSignatureScheme::EcdsaSecp384r1Sha384, TlsCapabilityDisposition::Default, TlsCapabilityDisposition::Default },
            { TlsSignatureScheme::EcdsaSecp521r1Sha512, TlsCapabilityDisposition::Default, TlsCapabilityDisposition::Default },
            { TlsSignatureScheme::Ed25519, TlsCapabilityDisposition::Default, TlsCapabilityDisposition::Default },
            { TlsSignatureScheme::Ed448, TlsCapabilityDisposition::Optional, TlsCapabilityDisposition::Optional },
            { TlsSignatureScheme::RsaPssPssSha256, TlsCapabilityDisposition::Optional, TlsCapabilityDisposition::Optional },
            { TlsSignatureScheme::RsaPssPssSha384, TlsCapabilityDisposition::Optional, TlsCapabilityDisposition::Optional },
            { TlsSignatureScheme::RsaPssPssSha512, TlsCapabilityDisposition::Optional, TlsCapabilityDisposition::Optional },
            { TlsSignatureScheme::RsaPkcs1Sha256, TlsCapabilityDisposition::Legacy, TlsCapabilityDisposition::Legacy },
            { TlsSignatureScheme::RsaPkcs1Sha384, TlsCapabilityDisposition::Legacy, TlsCapabilityDisposition::Legacy },
            { TlsSignatureScheme::RsaPkcs1Sha512, TlsCapabilityDisposition::Legacy, TlsCapabilityDisposition::Legacy }
        };

        _Must_inspect_result_
        bool IsDefaultDisposition(TlsCapabilityDisposition disposition) noexcept
        {
            return disposition == TlsCapabilityDisposition::Default ||
                disposition == TlsCapabilityDisposition::Optional;
        }
    }

    const TlsCipherSuiteCapability* TlsFindCipherSuiteCapability(TlsCipherSuite cipherSuite) noexcept
    {
        for (SIZE_T index = 0; index < sizeof(CipherSuiteCapabilities) / sizeof(CipherSuiteCapabilities[0]); ++index) {
            if (CipherSuiteCapabilities[index].CipherSuite == cipherSuite) {
                return &CipherSuiteCapabilities[index];
            }
        }
        return nullptr;
    }

    const TlsNamedGroupCapability* TlsFindNamedGroupCapability(TlsNamedGroup group) noexcept
    {
        for (SIZE_T index = 0; index < sizeof(NamedGroupCapabilities) / sizeof(NamedGroupCapabilities[0]); ++index) {
            if (NamedGroupCapabilities[index].Group == group) {
                return &NamedGroupCapabilities[index];
            }
        }
        return nullptr;
    }

    const TlsSignatureSchemeCapability* TlsFindSignatureSchemeCapability(TlsSignatureScheme scheme) noexcept
    {
        for (SIZE_T index = 0; index < sizeof(SignatureSchemeCapabilities) / sizeof(SignatureSchemeCapabilities[0]); ++index) {
            if (SignatureSchemeCapabilities[index].Scheme == scheme) {
                return &SignatureSchemeCapabilities[index];
            }
        }
        return nullptr;
    }

    bool TlsIsKnownCipherSuite(TlsCipherSuite cipherSuite) noexcept
    {
        return TlsFindCipherSuiteCapability(cipherSuite) != nullptr;
    }

    bool TlsIsKnownNamedGroup(TlsNamedGroup group) noexcept
    {
        return TlsFindNamedGroupCapability(group) != nullptr;
    }

    bool TlsIsKnownSignatureScheme(TlsSignatureScheme scheme) noexcept
    {
        return TlsFindSignatureSchemeCapability(scheme) != nullptr;
    }

    bool TlsIsDefaultEnabledCipherSuite(TlsCipherSuite cipherSuite) noexcept
    {
        const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
        return capability != nullptr && IsDefaultDisposition(capability->DefaultDisposition);
    }

    bool TlsIsDefaultEnabledNamedGroup(TlsNamedGroup group) noexcept
    {
        const TlsNamedGroupCapability* capability = TlsFindNamedGroupCapability(group);
        return capability != nullptr && IsDefaultDisposition(capability->DefaultDisposition);
    }

    bool TlsIsDefaultEnabledSignatureScheme(TlsSignatureScheme scheme) noexcept
    {
        const TlsSignatureSchemeCapability* capability = TlsFindSignatureSchemeCapability(scheme);
        return capability != nullptr && IsDefaultDisposition(capability->DefaultDisposition);
    }

    bool TlsIsDefaultEnabledTls12KeyExchange(Tls12KeyExchangeKind keyExchange) noexcept
    {
        switch (keyExchange) {
        case Tls12KeyExchangeKind::EcdheRsa:
        case Tls12KeyExchangeKind::EcdheEcdsa:
        case Tls12KeyExchangeKind::DheRsa:
            return true;
        case Tls12KeyExchangeKind::Rsa:
        case Tls12KeyExchangeKind::None:
        default:
            return false;
        }
    }
}
}
