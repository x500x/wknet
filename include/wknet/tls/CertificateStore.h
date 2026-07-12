#pragma once

#include <wknet/crypto/CngProvider.h>
#include <wknet/tls/TlsHandshake12.h>

namespace wknet
{
namespace tls
{
    constexpr SIZE_T CertificateSha256ThumbprintLength = 32;
    constexpr SIZE_T CertificateSha1ThumbprintLength = 20;
    constexpr SIZE_T CertificateMaxTrustAnchors = 16;
    constexpr SIZE_T CertificateMaxAuthorityBundles = 8;
    constexpr SIZE_T CertificateMaxRevocationEntries = 32;
    constexpr SIZE_T CertificateMaxRevocationUris = 4;

    struct CertificateTrustAnchor final
    {
        const UCHAR* SubjectName = nullptr;
        SIZE_T SubjectNameLength = 0;
        UCHAR SubjectPublicKeySha256[CertificateSha256ThumbprintLength] = {};
        bool MatchSubjectPublicKey = false;
    };

    struct CertificatePin final
    {
        const char* HostName = nullptr;
        SIZE_T HostNameLength = 0;
        UCHAR LeafSubjectPublicKeySha256[CertificateSha256ThumbprintLength] = {};
    };

    struct CertificateAuthorityBundle final
    {
        // Caller-owned PEM bundle or single DER certificate loaded from external trust data.
        const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
    };

    enum class CertificateRevocationMode : UCHAR
    {
        Off,
        StapledOnly,
        OnlineRequired
    };

    enum class CertificateRevocationSource : UCHAR
    {
        Ocsp,
        Crl
    };

    enum class CertificateRevocationStatus : UCHAR
    {
        Good,
        Revoked,
        Unknown
    };

    struct CertificateRevocationEntry final
    {
        const UCHAR* IssuerName = nullptr;
        SIZE_T IssuerNameLength = 0;
        const UCHAR* SerialNumber = nullptr;
        SIZE_T SerialNumberLength = 0;
        CertificateRevocationSource Source = CertificateRevocationSource::Ocsp;
        CertificateRevocationStatus Status = CertificateRevocationStatus::Unknown;
        long long ThisUpdate = 0;
        long long NextUpdate = 0;
        const UCHAR* EvidenceDer = nullptr;
        SIZE_T EvidenceDerLength = 0;
    };

    struct CertificateRevocationProviderQuery final
    {
        const UCHAR* CertificateDer = nullptr;
        SIZE_T CertificateDerLength = 0;
        const UCHAR* IssuerCertificateDer = nullptr;
        SIZE_T IssuerCertificateDerLength = 0;
        const UCHAR* IssuerName = nullptr;
        SIZE_T IssuerNameLength = 0;
        const UCHAR* SerialNumber = nullptr;
        SIZE_T SerialNumberLength = 0;
        const UCHAR* IssuerSubjectPublicKeyInfo = nullptr;
        SIZE_T IssuerSubjectPublicKeyInfoLength = 0;
        UCHAR OcspIssuerNameSha1[CertificateSha1ThumbprintLength] = {};
        UCHAR OcspIssuerKeySha1[CertificateSha1ThumbprintLength] = {};
        const UCHAR* OcspRequestDer = nullptr;
        SIZE_T OcspRequestDerLength = 0;
        const char* OcspUris[CertificateMaxRevocationUris] = {};
        SIZE_T OcspUriLengths[CertificateMaxRevocationUris] = {};
        SIZE_T OcspUriCount = 0;
        const char* CrlDistributionPointUris[CertificateMaxRevocationUris] = {};
        SIZE_T CrlDistributionPointUriLengths[CertificateMaxRevocationUris] = {};
        SIZE_T CrlDistributionPointUriCount = 0;
        CertificateRevocationSource PreferredSource = CertificateRevocationSource::Ocsp;
    };

    typedef NTSTATUS (*CertificateRevocationProviderCallback)(
        _In_opt_ void* context,
        _In_ const CertificateRevocationProviderQuery* query,
        _Out_ CertificateRevocationEntry* entry);

    struct CertificateStoreOptions final
    {
        const CertificateTrustAnchor* TrustAnchors = nullptr;
        SIZE_T TrustAnchorCount = 0;
        const CertificateAuthorityBundle* AuthorityBundles = nullptr;
        SIZE_T AuthorityBundleCount = 0;
        const CertificatePin* Pins = nullptr;
        SIZE_T PinCount = 0;
        const CertificateRevocationEntry* RevocationEntries = nullptr;
        SIZE_T RevocationEntryCount = 0;
        CertificateRevocationProviderCallback RevocationProvider = nullptr;
        void* RevocationProviderContext = nullptr;
    };

    enum class TlsClientCredentialKeyAlgorithm : UCHAR
    {
        Unknown,
        Rsa,
        RsaPss,
        EcdsaP256,
        EcdsaP384,
        EcdsaP521,
        Ed25519,
        Ed448
    };

    typedef NTSTATUS (*TlsClientCredentialSignCallback)(
        _In_opt_ void* context,
        TlsSignatureScheme scheme,
        _In_reads_bytes_(inputLength) const UCHAR* input,
        SIZE_T inputLength,
        _Out_writes_bytes_(signatureCapacity) UCHAR* signature,
        SIZE_T signatureCapacity,
        _Out_ SIZE_T* signatureLength);

    struct TlsClientCredential final
    {
        const UCHAR* CertificateList = nullptr;
        SIZE_T CertificateListLength = 0;
        TlsClientCredentialKeyAlgorithm KeyAlgorithm = TlsClientCredentialKeyAlgorithm::Unknown;
        const TlsSignatureScheme* SupportedSignatureSchemes = nullptr;
        SIZE_T SupportedSignatureSchemeCount = 0;
        TlsClientCredentialSignCallback Sign = nullptr;
        void* SignContext = nullptr;
        bool AllowsDigitalSignature = true;
    };

    class CertificateStore final
    {
    public:
        CertificateStore() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(_In_ const CertificateStoreOptions& options) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        bool IsTrustedAnchor(
            _In_reads_bytes_(subjectNameLength) const UCHAR* subjectName,
            SIZE_T subjectNameLength,
            _In_reads_bytes_(spkiSha256Length) const UCHAR* spkiSha256,
            SIZE_T spkiSha256Length) const noexcept;

        _Must_inspect_result_
        bool MatchesPin(
            _In_reads_(hostNameLength) const char* hostName,
            SIZE_T hostNameLength,
            _In_reads_bytes_(spkiSha256Length) const UCHAR* spkiSha256,
            SIZE_T spkiSha256Length) const noexcept;

        SIZE_T TrustAnchorCount() const noexcept;
        SIZE_T AuthorityBundleCount() const noexcept;
        SIZE_T PinCount() const noexcept;
        SIZE_T RevocationEntryCount() const noexcept;
        _Must_inspect_result_
        const CertificateAuthorityBundle* AuthorityBundleAt(SIZE_T index) const noexcept;
        _Must_inspect_result_
        const CertificateRevocationEntry* FindRevocationEntry(
            _In_reads_bytes_(issuerNameLength) const UCHAR* issuerName,
            SIZE_T issuerNameLength,
            _In_reads_bytes_(serialNumberLength) const UCHAR* serialNumber,
            SIZE_T serialNumberLength,
            CertificateRevocationSource source) const noexcept;

        _Must_inspect_result_
        NTSTATUS QueryRevocationProvider(
            _In_ const CertificateRevocationProviderQuery& query,
            _Out_ CertificateRevocationEntry* entry) const noexcept;

    private:
        const CertificateTrustAnchor* trustAnchors_ = nullptr;
        SIZE_T trustAnchorCount_ = 0;
        const CertificateAuthorityBundle* authorityBundles_ = nullptr;
        SIZE_T authorityBundleCount_ = 0;
        const CertificatePin* pins_ = nullptr;
        SIZE_T pinCount_ = 0;
        const CertificateRevocationEntry* revocationEntries_ = nullptr;
        SIZE_T revocationEntryCount_ = 0;
        CertificateRevocationProviderCallback revocationProvider_ = nullptr;
        void* revocationProviderContext_ = nullptr;
    };
}
}
