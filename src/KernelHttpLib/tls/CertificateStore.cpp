#include <KernelHttp/tls/CertificateStore.h>

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        _Must_inspect_result_
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        bool MemoryEquals(const UCHAR* left, const UCHAR* right, SIZE_T length) noexcept
        {
            UCHAR diff = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                diff = static_cast<UCHAR>(diff | (left[index] ^ right[index]));
            }

            return diff == 0;
        }

        _Must_inspect_result_
        bool TextEqualsIgnoreCase(
            _In_reads_(leftLength) const char* left,
            SIZE_T leftLength,
            _In_reads_(rightLength) const char* right,
            SIZE_T rightLength) noexcept
        {
            if (left == nullptr || right == nullptr || leftLength != rightLength) {
                return false;
            }

            for (SIZE_T index = 0; index < leftLength; ++index) {
                char l = left[index];
                char r = right[index];
                if (l >= 'A' && l <= 'Z') {
                    l = static_cast<char>(l - 'A' + 'a');
                }

                if (r >= 'A' && r <= 'Z') {
                    r = static_cast<char>(r - 'A' + 'a');
                }

                if (l != r) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool IsValidRevocationSource(CertificateRevocationSource source) noexcept
        {
            return source == CertificateRevocationSource::Ocsp ||
                source == CertificateRevocationSource::Crl;
        }

        _Must_inspect_result_
        bool IsValidRevocationStatus(CertificateRevocationStatus status) noexcept
        {
            return status == CertificateRevocationStatus::Good ||
                status == CertificateRevocationStatus::Revoked ||
                status == CertificateRevocationStatus::Unknown;
        }
    }

    NTSTATUS CertificateStore::Initialize(const CertificateStoreOptions& options) noexcept
    {
        if (options.TrustAnchorCount > CertificateMaxTrustAnchors ||
            options.AuthorityBundleCount > CertificateMaxAuthorityBundles ||
            options.RevocationEntryCount > CertificateMaxRevocationEntries ||
            (options.TrustAnchorCount != 0 && options.TrustAnchors == nullptr) ||
            (options.AuthorityBundleCount != 0 && options.AuthorityBundles == nullptr) ||
            (options.PinCount != 0 && options.Pins == nullptr) ||
            (options.RevocationEntryCount != 0 && options.RevocationEntries == nullptr) ||
            (options.RevocationProvider == nullptr && options.RevocationProviderContext != nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < options.TrustAnchorCount; ++index) {
            const CertificateTrustAnchor& anchor = options.TrustAnchors[index];
            if (!IsValidBuffer(anchor.SubjectName, anchor.SubjectNameLength) ||
                !anchor.MatchSubjectPublicKey) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        for (SIZE_T index = 0; index < options.AuthorityBundleCount; ++index) {
            const CertificateAuthorityBundle& bundle = options.AuthorityBundles[index];
            if (!IsValidBuffer(bundle.Data, bundle.DataLength) || bundle.DataLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        for (SIZE_T index = 0; index < options.PinCount; ++index) {
            const CertificatePin& pin = options.Pins[index];
            if (pin.HostName == nullptr || pin.HostNameLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        for (SIZE_T index = 0; index < options.RevocationEntryCount; ++index) {
            const CertificateRevocationEntry& entry = options.RevocationEntries[index];
            if (!IsValidBuffer(entry.IssuerName, entry.IssuerNameLength) ||
                entry.IssuerNameLength == 0 ||
                !IsValidBuffer(entry.SerialNumber, entry.SerialNumberLength) ||
                entry.SerialNumberLength == 0 ||
                !IsValidBuffer(entry.EvidenceDer, entry.EvidenceDerLength) ||
                entry.EvidenceDerLength == 0 ||
                !IsValidRevocationSource(entry.Source) ||
                !IsValidRevocationStatus(entry.Status) ||
                (entry.NextUpdate != 0 && entry.ThisUpdate > entry.NextUpdate)) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        trustAnchors_ = options.TrustAnchors;
        trustAnchorCount_ = options.TrustAnchorCount;
        authorityBundles_ = options.AuthorityBundles;
        authorityBundleCount_ = options.AuthorityBundleCount;
        pins_ = options.Pins;
        pinCount_ = options.PinCount;
        revocationEntries_ = options.RevocationEntries;
        revocationEntryCount_ = options.RevocationEntryCount;
        revocationProvider_ = options.RevocationProvider;
        revocationProviderContext_ = options.RevocationProviderContext;
        return STATUS_SUCCESS;
    }

    void CertificateStore::Reset() noexcept
    {
        trustAnchors_ = nullptr;
        trustAnchorCount_ = 0;
        authorityBundles_ = nullptr;
        authorityBundleCount_ = 0;
        pins_ = nullptr;
        pinCount_ = 0;
        revocationEntries_ = nullptr;
        revocationEntryCount_ = 0;
        revocationProvider_ = nullptr;
        revocationProviderContext_ = nullptr;
    }

    bool CertificateStore::IsTrustedAnchor(
        const UCHAR* subjectName,
        SIZE_T subjectNameLength,
        const UCHAR* spkiSha256,
        SIZE_T spkiSha256Length) const noexcept
    {
        if (!IsValidBuffer(subjectName, subjectNameLength) ||
            !IsValidBuffer(spkiSha256, spkiSha256Length) ||
            spkiSha256Length != CertificateSha256ThumbprintLength) {
            return false;
        }

        for (SIZE_T index = 0; index < trustAnchorCount_; ++index) {
            const CertificateTrustAnchor& anchor = trustAnchors_[index];

            if (anchor.SubjectNameLength != 0 &&
                (anchor.SubjectNameLength != subjectNameLength ||
                    !MemoryEquals(anchor.SubjectName, subjectName, subjectNameLength))) {
                continue;
            }

            if (anchor.MatchSubjectPublicKey &&
                !MemoryEquals(anchor.SubjectPublicKeySha256, spkiSha256, CertificateSha256ThumbprintLength)) {
                continue;
            }

            return true;
        }

        return false;
    }

    bool CertificateStore::MatchesPin(
        const char* hostName,
        SIZE_T hostNameLength,
        const UCHAR* spkiSha256,
        SIZE_T spkiSha256Length) const noexcept
    {
        if (hostName == nullptr ||
            hostNameLength == 0 ||
            spkiSha256 == nullptr ||
            spkiSha256Length != CertificateSha256ThumbprintLength) {
            return false;
        }

        bool hostHasPin = false;
        for (SIZE_T index = 0; index < pinCount_; ++index) {
            const CertificatePin& pin = pins_[index];
            if (!TextEqualsIgnoreCase(pin.HostName, pin.HostNameLength, hostName, hostNameLength)) {
                continue;
            }

            hostHasPin = true;
            if (MemoryEquals(pin.LeafSubjectPublicKeySha256, spkiSha256, CertificateSha256ThumbprintLength)) {
                return true;
            }
        }

        return !hostHasPin;
    }

    SIZE_T CertificateStore::TrustAnchorCount() const noexcept
    {
        return trustAnchorCount_;
    }

    SIZE_T CertificateStore::AuthorityBundleCount() const noexcept
    {
        return authorityBundleCount_;
    }

    SIZE_T CertificateStore::PinCount() const noexcept
    {
        return pinCount_;
    }

    SIZE_T CertificateStore::RevocationEntryCount() const noexcept
    {
        return revocationEntryCount_;
    }

    const CertificateAuthorityBundle* CertificateStore::AuthorityBundleAt(SIZE_T index) const noexcept
    {
        return index < authorityBundleCount_ ? authorityBundles_ + index : nullptr;
    }

    const CertificateRevocationEntry* CertificateStore::FindRevocationEntry(
        const UCHAR* issuerName,
        SIZE_T issuerNameLength,
        const UCHAR* serialNumber,
        SIZE_T serialNumberLength,
        CertificateRevocationSource source) const noexcept
    {
        if (!IsValidBuffer(issuerName, issuerNameLength) ||
            issuerNameLength == 0 ||
            !IsValidBuffer(serialNumber, serialNumberLength) ||
            serialNumberLength == 0 ||
            !IsValidRevocationSource(source)) {
            return nullptr;
        }

        for (SIZE_T index = 0; index < revocationEntryCount_; ++index) {
            const CertificateRevocationEntry& entry = revocationEntries_[index];
            if (entry.Source == source &&
                entry.IssuerNameLength == issuerNameLength &&
                entry.SerialNumberLength == serialNumberLength &&
                MemoryEquals(entry.IssuerName, issuerName, issuerNameLength) &&
                MemoryEquals(entry.SerialNumber, serialNumber, serialNumberLength)) {
                return &entry;
            }
        }

        return nullptr;
    }

    NTSTATUS CertificateStore::QueryRevocationProvider(
        const CertificateRevocationProviderQuery& query,
        CertificateRevocationEntry* entry) const noexcept
    {
        if (entry != nullptr) {
            *entry = {};
        }
        if (!IsValidBuffer(query.CertificateDer, query.CertificateDerLength) ||
            query.CertificateDerLength == 0 ||
            !IsValidBuffer(query.IssuerCertificateDer, query.IssuerCertificateDerLength) ||
            query.IssuerCertificateDerLength == 0 ||
            !IsValidBuffer(query.IssuerName, query.IssuerNameLength) ||
            query.IssuerNameLength == 0 ||
            !IsValidBuffer(query.SerialNumber, query.SerialNumberLength) ||
            query.SerialNumberLength == 0 ||
            !IsValidBuffer(query.IssuerSubjectPublicKeyInfo, query.IssuerSubjectPublicKeyInfoLength) ||
            query.IssuerSubjectPublicKeyInfoLength == 0 ||
            !IsValidBuffer(query.OcspRequestDer, query.OcspRequestDerLength) ||
            (query.PreferredSource == CertificateRevocationSource::Ocsp && query.OcspRequestDerLength == 0) ||
            !IsValidRevocationSource(query.PreferredSource) ||
            entry == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (query.OcspUriCount > CertificateMaxRevocationUris ||
            query.CrlDistributionPointUriCount > CertificateMaxRevocationUris) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T index = 0; index < query.OcspUriCount; ++index) {
            if (query.OcspUris[index] == nullptr || query.OcspUriLengths[index] == 0) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        for (SIZE_T index = 0; index < query.CrlDistributionPointUriCount; ++index) {
            if (query.CrlDistributionPointUris[index] == nullptr ||
                query.CrlDistributionPointUriLengths[index] == 0) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        if (revocationProvider_ == nullptr) {
            return STATUS_NOT_FOUND;
        }

        NTSTATUS status = revocationProvider_(revocationProviderContext_, &query, entry);
        if (!NT_SUCCESS(status)) {
            *entry = {};
            return status;
        }
        if (entry->IssuerNameLength != query.IssuerNameLength ||
            entry->SerialNumberLength != query.SerialNumberLength ||
            !IsValidBuffer(entry->IssuerName, entry->IssuerNameLength) ||
            !IsValidBuffer(entry->SerialNumber, entry->SerialNumberLength) ||
            !IsValidBuffer(entry->EvidenceDer, entry->EvidenceDerLength) ||
            entry->EvidenceDerLength == 0 ||
            !IsValidRevocationSource(entry->Source) ||
            !IsValidRevocationStatus(entry->Status) ||
            entry->Source != query.PreferredSource ||
            !MemoryEquals(entry->IssuerName, query.IssuerName, query.IssuerNameLength) ||
            !MemoryEquals(entry->SerialNumber, query.SerialNumber, query.SerialNumberLength) ||
            (entry->NextUpdate != 0 && entry->ThisUpdate > entry->NextUpdate)) {
            *entry = {};
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return STATUS_SUCCESS;
    }
}
}
