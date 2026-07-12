#pragma once

#include <wknet/core/IScratchAllocator.h>
#include <wknet/tls/CertificateStore.h>
#include <wknet/tls/TlsHandshake12.h>

namespace wknet
{
namespace crypto
{
    class CngProviderCache;
}

namespace tls
{
    constexpr SIZE_T CertificateMaxChainLength = 8;
    constexpr SIZE_T CertificateMaxNameConstraints = 8;
    constexpr SIZE_T CertificateMaxCertificatePolicies = 8;
    constexpr SIZE_T CertificateMaxRevocationUriLength = 255;

    enum class CertificatePublicKeyAlgorithm : UCHAR
    {
        Unknown,
        Rsa,
        EcdsaP256,
        EcdsaP384,
        EcdsaP521,
        Ed25519,
        Ed448
    };

    enum class CertificateSignatureAlgorithm : UCHAR
    {
        Unknown,
        RsaPkcs1Sha256,
        RsaPkcs1Sha384,
        EcdsaSha256,
        EcdsaSha384,
        Ed25519,
        Ed448
    };

    struct ParsedCertificate final
    {
        const UCHAR* Der = nullptr;
        SIZE_T DerLength = 0;
        const UCHAR* TbsCertificate = nullptr;
        SIZE_T TbsCertificateLength = 0;
        const UCHAR* SerialNumber = nullptr;
        SIZE_T SerialNumberLength = 0;
        const UCHAR* Subject = nullptr;
        SIZE_T SubjectLength = 0;
        const UCHAR* Issuer = nullptr;
        SIZE_T IssuerLength = 0;
        const UCHAR* SubjectPublicKeyInfo = nullptr;
        SIZE_T SubjectPublicKeyInfoLength = 0;
        const UCHAR* SubjectKeyIdentifier = nullptr;
        SIZE_T SubjectKeyIdentifierLength = 0;
        bool HasSubjectKeyIdentifier = false;
        const UCHAR* AuthorityKeyIdentifier = nullptr;
        SIZE_T AuthorityKeyIdentifierLength = 0;
        bool HasAuthorityKeyIdentifier = false;
        const UCHAR* PublicKey = nullptr;
        SIZE_T PublicKeyLength = 0;
        const UCHAR* RsaModulus = nullptr;
        SIZE_T RsaModulusLength = 0;
        const UCHAR* RsaExponent = nullptr;
        SIZE_T RsaExponentLength = 0;
        const UCHAR* Signature = nullptr;
        SIZE_T SignatureLength = 0;
        const char* CommonName = nullptr;
        SIZE_T CommonNameLength = 0;
        const char* DnsNames[8] = {};
        SIZE_T DnsNameLengths[8] = {};
        SIZE_T DnsNameCount = 0;
        UCHAR IpAddresses[8][16] = {};
        SIZE_T IpAddressLengths[8] = {};
        SIZE_T IpAddressCount = 0;
        CertificatePublicKeyAlgorithm PublicKeyAlgorithm = CertificatePublicKeyAlgorithm::Unknown;
        CertificateSignatureAlgorithm SignatureAlgorithm = CertificateSignatureAlgorithm::Unknown;
        long long NotBefore = 0;
        long long NotAfter = 0;
        bool IsCa = false;
        bool HasBasicConstraints = false;
        bool HasPathLenConstraint = false;
        ULONG PathLenConstraint = 0;
        bool HasKeyUsage = false;
        bool AllowsDigitalSignature = false;
        bool AllowsKeyEncipherment = false;
        bool AllowsKeyCertSign = false;
        bool AllowsCrlSign = false;
        bool HasExtendedKeyUsage = false;
        bool AllowsServerAuth = false;
        bool AllowsOcspSigning = false;
        bool HasNameConstraints = false;
        const char* PermittedDnsSubtrees[CertificateMaxNameConstraints] = {};
        SIZE_T PermittedDnsSubtreeLengths[CertificateMaxNameConstraints] = {};
        SIZE_T PermittedDnsSubtreeCount = 0;
        const char* ExcludedDnsSubtrees[CertificateMaxNameConstraints] = {};
        SIZE_T ExcludedDnsSubtreeLengths[CertificateMaxNameConstraints] = {};
        SIZE_T ExcludedDnsSubtreeCount = 0;
        UCHAR PermittedIpSubtrees[CertificateMaxNameConstraints][32] = {};
        SIZE_T PermittedIpSubtreeLengths[CertificateMaxNameConstraints] = {};
        SIZE_T PermittedIpSubtreeCount = 0;
        UCHAR ExcludedIpSubtrees[CertificateMaxNameConstraints][32] = {};
        SIZE_T ExcludedIpSubtreeLengths[CertificateMaxNameConstraints] = {};
        SIZE_T ExcludedIpSubtreeCount = 0;
        const UCHAR* PermittedDirectoryNames[CertificateMaxNameConstraints] = {};
        SIZE_T PermittedDirectoryNameLengths[CertificateMaxNameConstraints] = {};
        SIZE_T PermittedDirectoryNameCount = 0;
        const UCHAR* ExcludedDirectoryNames[CertificateMaxNameConstraints] = {};
        SIZE_T ExcludedDirectoryNameLengths[CertificateMaxNameConstraints] = {};
        SIZE_T ExcludedDirectoryNameCount = 0;
        bool HasCertificatePolicies = false;
        bool CertificatePoliciesCritical = false;
        const UCHAR* CertificatePolicyOids[CertificateMaxCertificatePolicies] = {};
        SIZE_T CertificatePolicyOidLengths[CertificateMaxCertificatePolicies] = {};
        SIZE_T CertificatePolicyOidCount = 0;
        bool HasAnyPolicy = false;
        bool HasPolicyConstraints = false;
        bool RequireExplicitPolicy = false;
        ULONG RequireExplicitPolicySkipCerts = 0;
        bool InhibitPolicyMapping = false;
        ULONG InhibitPolicyMappingSkipCerts = 0;
        bool HasInhibitAnyPolicy = false;
        ULONG InhibitAnyPolicySkipCerts = 0;
        const char* OcspUris[CertificateMaxRevocationUris] = {};
        SIZE_T OcspUriLengths[CertificateMaxRevocationUris] = {};
        SIZE_T OcspUriCount = 0;
        const char* CrlDistributionPointUris[CertificateMaxRevocationUris] = {};
        SIZE_T CrlDistributionPointUriLengths[CertificateMaxRevocationUris] = {};
        SIZE_T CrlDistributionPointUriCount = 0;
    };

    struct CertificateChainView final
    {
        const UCHAR* Certificates = nullptr;
        SIZE_T CertificatesLength = 0;
        SIZE_T CertificateCount = 0;
    };

    struct CertificateValidationOptions final
    {
        const char* HostName = nullptr;
        SIZE_T HostNameLength = 0;
        const CertificateStore* Store = nullptr;
        core::IScratchAllocator* ScratchAllocator = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        bool VerifyCertificate = true;
        bool RequireServerAuthEku = true;
        bool RequireRevocationCheck = false;
        CertificateRevocationMode RevocationMode = CertificateRevocationMode::Off;
        bool EnableIdna = true;
        const UCHAR* StapledOcspResponse = nullptr;
        SIZE_T StapledOcspResponseLength = 0;
    };

    struct CertificateValidationResult final
    {
        ParsedCertificate Leaf = {};
        UCHAR LeafSubjectPublicKeySha256[CertificateSha256ThumbprintLength] = {};
    };

    class CertificateValidator final
    {
    public:
        CertificateValidator() = delete;

        _Must_inspect_result_
        static NTSTATUS ParseCertificate(
            _In_reads_bytes_(derLength) const UCHAR* der,
            SIZE_T derLength,
            _Out_ ParsedCertificate& certificate) noexcept;

        _Must_inspect_result_
        static NTSTATUS ValidateChain(
            _In_ const CertificateChainView& chain,
            _In_ const CertificateValidationOptions& options,
            _Out_opt_ CertificateValidationResult* result = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportSubjectPublicKey(
            _In_ const ParsedCertificate& certificate,
            _Out_ crypto::CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportSubjectPublicKey(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _Out_ crypto::CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ToSignatureAlgorithm(
            CertificateSignatureAlgorithm algorithm,
            _Out_ crypto::SignatureAlgorithm* signatureAlgorithm) noexcept;
    };
}
}
