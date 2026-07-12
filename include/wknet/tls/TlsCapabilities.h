#pragma once

#include <wknet/tls/TlsHandshake13.h>

namespace wknet
{
namespace tls
{
    enum class TlsCapabilityDisposition : UCHAR
    {
        Unsupported,
        Default,
        Optional,
        Legacy
    };

    enum class Tls12KeyExchangeKind : UCHAR
    {
        None,
        Rsa,
        DheRsa,
        EcdheRsa,
        EcdheEcdsa
    };

    enum class TlsBulkCipherKind : UCHAR
    {
        None,
        AesGcm,
        AesCcm,
        ChaCha20Poly1305,
        AesCbc
    };

    enum class TlsAuthenticationKind : UCHAR
    {
        None,
        Rsa,
        Ecdsa
    };

    enum class TlsRecordMacKind : UCHAR
    {
        None,
        Aead,
        HmacSha256,
        HmacSha384
    };

    enum class TlsPrfHashKind : UCHAR
    {
        None,
        Sha256,
        Sha384
    };

    enum class TlsNamedGroupKind : UCHAR
    {
        NistCurve,
        Xdh,
        Ffdhe
    };

    constexpr ULONG TlsCipherSuiteExtensionNone = 0x00000000;
    constexpr ULONG TlsCipherSuiteExtensionSupportedGroups = 0x00000001;
    constexpr ULONG TlsCipherSuiteExtensionExtendedMasterSecret = 0x00000002;
    constexpr ULONG TlsCipherSuiteExtensionSecureRenegotiation = 0x00000004;
    constexpr ULONG TlsCipherSuiteExtensionEncryptThenMac = 0x00000008;

    struct TlsCipherSuiteCapability final
    {
        TlsCipherSuite CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;
        TlsProtocol Protocol = TlsProtocol::Tls13;
        Tls12KeyExchangeKind Tls12KeyExchange = Tls12KeyExchangeKind::None;
        TlsBulkCipherKind BulkCipher = TlsBulkCipherKind::None;
        TlsAuthenticationKind Authentication = TlsAuthenticationKind::None;
        TlsRecordMacKind RecordMac = TlsRecordMacKind::None;
        TlsPrfHashKind PrfHash = TlsPrfHashKind::None;
        ULONG RequiredExtensions = TlsCipherSuiteExtensionNone;
        TlsCapabilityDisposition DefaultDisposition = TlsCapabilityDisposition::Unsupported;
        TlsCapabilityDisposition CompatibilityDisposition = TlsCapabilityDisposition::Unsupported;
    };

    struct TlsNamedGroupCapability final
    {
        TlsNamedGroup Group = TlsNamedGroup::Secp256r1;
        TlsNamedGroupKind Kind = TlsNamedGroupKind::NistCurve;
        TlsCapabilityDisposition DefaultDisposition = TlsCapabilityDisposition::Unsupported;
        TlsCapabilityDisposition CompatibilityDisposition = TlsCapabilityDisposition::Unsupported;
    };

    struct TlsSignatureSchemeCapability final
    {
        TlsSignatureScheme Scheme = TlsSignatureScheme::RsaPkcs1Sha256;
        TlsCapabilityDisposition DefaultDisposition = TlsCapabilityDisposition::Unsupported;
        TlsCapabilityDisposition CompatibilityDisposition = TlsCapabilityDisposition::Unsupported;
    };

    _Must_inspect_result_
    bool TlsIsKnownCipherSuite(TlsCipherSuite cipherSuite) noexcept;

    _Must_inspect_result_
    bool TlsIsKnownNamedGroup(TlsNamedGroup group) noexcept;

    _Must_inspect_result_
    bool TlsIsKnownSignatureScheme(TlsSignatureScheme scheme) noexcept;

    _Must_inspect_result_
    bool TlsIsDefaultEnabledCipherSuite(TlsCipherSuite cipherSuite) noexcept;

    _Must_inspect_result_
    bool TlsIsDefaultEnabledNamedGroup(TlsNamedGroup group) noexcept;

    _Must_inspect_result_
    bool TlsIsDefaultEnabledSignatureScheme(TlsSignatureScheme scheme) noexcept;

    _Must_inspect_result_
    bool TlsIsDefaultEnabledTls12KeyExchange(Tls12KeyExchangeKind keyExchange) noexcept;

    _Must_inspect_result_
    SIZE_T TlsCipherSuiteCapabilityCount() noexcept;

    _Must_inspect_result_
    const TlsCipherSuiteCapability* TlsCipherSuiteCapabilityAt(SIZE_T index) noexcept;

    _Must_inspect_result_
    const TlsCipherSuiteCapability* TlsFindCipherSuiteCapability(TlsCipherSuite cipherSuite) noexcept;

    _Must_inspect_result_
    const TlsNamedGroupCapability* TlsFindNamedGroupCapability(TlsNamedGroup group) noexcept;

    _Must_inspect_result_
    const TlsSignatureSchemeCapability* TlsFindSignatureSchemeCapability(TlsSignatureScheme scheme) noexcept;
}
}
