#pragma once

#include <KernelHttp/tls/CertificateStore.h>
#include <KernelHttp/tls/TlsHandshake12.h>

namespace KernelHttp
{
namespace engine
{
    struct KhWorkspace;
}

namespace crypto
{
    class CngProviderCache;
}

namespace tls
{
    constexpr SIZE_T CertificateMaxChainLength = 8;

    enum class CertificatePublicKeyAlgorithm : UCHAR
    {
        Unknown,
        Rsa,
        EcdsaP256,
        EcdsaP384,
        EcdsaP521
    };

    enum class CertificateSignatureAlgorithm : UCHAR
    {
        Unknown,
        RsaPkcs1Sha256,
        RsaPkcs1Sha384,
        EcdsaSha256,
        EcdsaSha384
    };

    struct ParsedCertificate final
    {
        const UCHAR* Der = nullptr;
        SIZE_T DerLength = 0;
        const UCHAR* TbsCertificate = nullptr;
        SIZE_T TbsCertificateLength = 0;
        const UCHAR* Subject = nullptr;
        SIZE_T SubjectLength = 0;
        const UCHAR* Issuer = nullptr;
        SIZE_T IssuerLength = 0;
        const UCHAR* SubjectPublicKeyInfo = nullptr;
        SIZE_T SubjectPublicKeyInfoLength = 0;
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
        CertificatePublicKeyAlgorithm PublicKeyAlgorithm = CertificatePublicKeyAlgorithm::Unknown;
        CertificateSignatureAlgorithm SignatureAlgorithm = CertificateSignatureAlgorithm::Unknown;
        long long NotBefore = 0;
        long long NotAfter = 0;
        bool IsCa = false;
        bool HasBasicConstraints = false;
        bool HasExtendedKeyUsage = false;
        bool AllowsServerAuth = false;
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
        engine::KhWorkspace* Workspace = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        bool VerifyCertificate = true;
        bool RequireServerAuthEku = true;
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
        static crypto::SignatureAlgorithm ToSignatureAlgorithm(
            CertificateSignatureAlgorithm algorithm) noexcept;
    };
}
}
