#pragma once

#include <wknet/WknetConfig.h>
#include <wknet/crypto/TlsCredential.h>

namespace wknet::http {
    constexpr SIZE_T CertificateSha256ThumbprintLength = 32;
    constexpr SIZE_T CertificateSha1ThumbprintLength = 20;
    // Soft documentation defaults / hard growth ceilings for store lists.
    // Actual storage is heap-grown; these are not fixed embedded array sizes.
    constexpr SIZE_T CertificateMaxTrustAnchors = 1024;
    constexpr SIZE_T CertificateMaxAuthorityBundles = 256;
    constexpr SIZE_T CertificateMaxPins = 1024;
    constexpr SIZE_T CertificateMaxRevocationEntries = 4096;
    // Public query ABI still exposes a fixed URI slot array of this size.
    constexpr SIZE_T CertificateMaxRevocationUris = 4;

    struct CertificateStore;

    using TlsSignatureScheme = crypto::TlsSignatureScheme;

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

    using CertificateRevocationProviderCallback = NTSTATUS(*)(
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

    using TlsClientCredentialKeyAlgorithm = crypto::TlsClientCredentialKeyAlgorithm;
    using TlsClientCredentialSignCallback = crypto::TlsClientCredentialSignCallback;
    using TlsClientCredential = crypto::TlsClientCredential;

    _Must_inspect_result_
    NTSTATUS CertificateStoreCreate(
        _In_opt_ const CertificateStoreOptions* options,
        _Out_ CertificateStore** store) noexcept;

    _Must_inspect_result_
    NTSTATUS CertificateStoreLoadPemBundle(
        _In_ CertificateStore* store,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept;

    _Must_inspect_result_
    NTSTATUS CertificateStoreLoadDer(
        _In_ CertificateStore* store,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept;

    void CertificateStoreClose(_In_opt_ CertificateStore* store) noexcept;
}
