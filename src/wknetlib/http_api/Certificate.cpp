#include <wknet/http/Certificate.h>

#include "session/detail/HttpHandles.h"
#include "tls/CertificateValidator.h"

namespace wknet::http {
namespace
{
    enum class AuthorityBundleFormat : UCHAR
    {
        Auto,
        Pem,
        Der
    };

    tls::CertificateRevocationSource ToInternalSource(CertificateRevocationSource source) noexcept
    {
        return source == CertificateRevocationSource::Crl
            ? tls::CertificateRevocationSource::Crl
            : tls::CertificateRevocationSource::Ocsp;
    }

    CertificateRevocationSource FromInternalSource(tls::CertificateRevocationSource source) noexcept
    {
        return source == tls::CertificateRevocationSource::Crl
            ? CertificateRevocationSource::Crl
            : CertificateRevocationSource::Ocsp;
    }

    tls::CertificateRevocationStatus ToInternalStatus(CertificateRevocationStatus status) noexcept
    {
        switch (status) {
        case CertificateRevocationStatus::Good:
            return tls::CertificateRevocationStatus::Good;
        case CertificateRevocationStatus::Revoked:
            return tls::CertificateRevocationStatus::Revoked;
        case CertificateRevocationStatus::Unknown:
        default:
            return tls::CertificateRevocationStatus::Unknown;
        }
    }

    void FreeOwnedBundles(CertificateStore* store) noexcept
    {
        if (store == nullptr) {
            return;
        }
        for (SIZE_T index = 0; index < CertificateMaxAuthorityBundles; ++index) {
            FreeNonPagedPoolBytes(store->OwnedAuthorityBundleData[index]);
            store->OwnedAuthorityBundleData[index] = nullptr;
            store->AuthorityBundles[index] = {};
        }
        store->AuthorityBundleCount = 0;
    }

    NTSTATUS PublicRevocationProvider(
        void* context,
        const tls::CertificateRevocationProviderQuery* query,
        tls::CertificateRevocationEntry* entry) noexcept
    {
        auto* store = static_cast<CertificateStore*>(context);
        if (store == nullptr ||
            store->Magic != detail::HighCertificateStoreMagic ||
            store->RevocationProvider == nullptr ||
            query == nullptr ||
            entry == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        CertificateRevocationProviderQuery publicQuery = {};
        publicQuery.CertificateDer = query->CertificateDer;
        publicQuery.CertificateDerLength = query->CertificateDerLength;
        publicQuery.IssuerCertificateDer = query->IssuerCertificateDer;
        publicQuery.IssuerCertificateDerLength = query->IssuerCertificateDerLength;
        publicQuery.IssuerName = query->IssuerName;
        publicQuery.IssuerNameLength = query->IssuerNameLength;
        publicQuery.SerialNumber = query->SerialNumber;
        publicQuery.SerialNumberLength = query->SerialNumberLength;
        publicQuery.IssuerSubjectPublicKeyInfo = query->IssuerSubjectPublicKeyInfo;
        publicQuery.IssuerSubjectPublicKeyInfoLength = query->IssuerSubjectPublicKeyInfoLength;
        RtlCopyMemory(publicQuery.OcspIssuerNameSha1, query->OcspIssuerNameSha1, sizeof(publicQuery.OcspIssuerNameSha1));
        RtlCopyMemory(publicQuery.OcspIssuerKeySha1, query->OcspIssuerKeySha1, sizeof(publicQuery.OcspIssuerKeySha1));
        publicQuery.OcspRequestDer = query->OcspRequestDer;
        publicQuery.OcspRequestDerLength = query->OcspRequestDerLength;
        publicQuery.OcspUriCount = query->OcspUriCount;
        publicQuery.CrlDistributionPointUriCount = query->CrlDistributionPointUriCount;
        for (SIZE_T index = 0; index < CertificateMaxRevocationUris; ++index) {
            publicQuery.OcspUris[index] = query->OcspUris[index];
            publicQuery.OcspUriLengths[index] = query->OcspUriLengths[index];
            publicQuery.CrlDistributionPointUris[index] = query->CrlDistributionPointUris[index];
            publicQuery.CrlDistributionPointUriLengths[index] = query->CrlDistributionPointUriLengths[index];
        }
        publicQuery.PreferredSource = FromInternalSource(query->PreferredSource);

        CertificateRevocationEntry publicEntry = {};
        NTSTATUS status = store->RevocationProvider(
            store->RevocationProviderContext,
            &publicQuery,
            &publicEntry);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        entry->IssuerName = publicEntry.IssuerName;
        entry->IssuerNameLength = publicEntry.IssuerNameLength;
        entry->SerialNumber = publicEntry.SerialNumber;
        entry->SerialNumberLength = publicEntry.SerialNumberLength;
        entry->Source = ToInternalSource(publicEntry.Source);
        entry->Status = ToInternalStatus(publicEntry.Status);
        entry->ThisUpdate = publicEntry.ThisUpdate;
        entry->NextUpdate = publicEntry.NextUpdate;
        entry->EvidenceDer = publicEntry.EvidenceDer;
        entry->EvidenceDerLength = publicEntry.EvidenceDerLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS Reinitialize(CertificateStore* store) noexcept
    {
        store->EngineOptions = {};
        store->EngineOptions.TrustAnchors = store->TrustAnchors;
        store->EngineOptions.TrustAnchorCount = store->TrustAnchorCount;
        store->EngineOptions.AuthorityBundles = store->AuthorityBundles;
        store->EngineOptions.AuthorityBundleCount = store->AuthorityBundleCount;
        store->EngineOptions.Pins = store->Pins;
        store->EngineOptions.PinCount = store->PinCount;
        store->EngineOptions.RevocationEntries = store->RevocationEntries;
        store->EngineOptions.RevocationEntryCount = store->RevocationEntryCount;
        if (store->RevocationProvider != nullptr) {
            store->EngineOptions.RevocationProvider = PublicRevocationProvider;
            store->EngineOptions.RevocationProviderContext = store;
        }
        return store->Engine->Initialize(store->EngineOptions);
    }

    NTSTATUS AppendOwnedBundle(
        CertificateStore* store,
        const UCHAR* data,
        SIZE_T dataLength,
        AuthorityBundleFormat format) noexcept
    {
        if (store == nullptr ||
            store->Magic != detail::HighCertificateStoreMagic ||
            store->Engine == nullptr ||
            data == nullptr ||
            dataLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (store->AuthorityBundleCount >= CertificateMaxAuthorityBundles) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = STATUS_INVALID_PARAMETER;
        switch (format) {
        case AuthorityBundleFormat::Auto:
            status = tls::CertificateValidator::ValidateAuthorityBundle(data, dataLength);
            break;
        case AuthorityBundleFormat::Pem:
            status = tls::CertificateValidator::ValidateAuthorityPemBundle(data, dataLength);
            break;
        case AuthorityBundleFormat::Der:
            status = tls::CertificateValidator::ValidateAuthorityDer(data, dataLength);
            break;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* copy = static_cast<UCHAR*>(AllocateNonPagedPoolBytes(dataLength));
        if (copy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(copy, data, dataLength);

        const SIZE_T index = store->AuthorityBundleCount;
        store->OwnedAuthorityBundleData[index] = copy;
        store->AuthorityBundles[index].Data = copy;
        store->AuthorityBundles[index].DataLength = dataLength;
        ++store->AuthorityBundleCount;

        status = Reinitialize(store);
        if (!NT_SUCCESS(status)) {
            --store->AuthorityBundleCount;
            store->AuthorityBundles[index] = {};
            store->OwnedAuthorityBundleData[index] = nullptr;
            FreeNonPagedPoolBytes(copy);
        }
        return status;
    }
}

NTSTATUS CertificateStoreCreate(
    const CertificateStoreOptions* options,
    CertificateStore** store) noexcept
{
    if (store != nullptr) {
        *store = nullptr;
    }
    if (store == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    if (options != nullptr &&
        (options->TrustAnchorCount > CertificateMaxTrustAnchors ||
         options->AuthorityBundleCount > CertificateMaxAuthorityBundles ||
         options->PinCount > CertificateMaxPins ||
         options->RevocationEntryCount > CertificateMaxRevocationEntries ||
         (options->TrustAnchorCount != 0 && options->TrustAnchors == nullptr) ||
         (options->AuthorityBundleCount != 0 && options->AuthorityBundles == nullptr) ||
         (options->PinCount != 0 && options->Pins == nullptr) ||
         (options->RevocationEntryCount != 0 && options->RevocationEntries == nullptr))) {
        return STATUS_INVALID_PARAMETER;
    }

    auto* created = AllocateNonPagedObject<CertificateStore>();
    if (created == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    created->Engine = AllocateNonPagedObject<tls::CertificateStore>();
    if (created->Engine == nullptr) {
        CertificateStoreClose(created);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (options == nullptr) {
        const NTSTATUS status = Reinitialize(created);
        if (!NT_SUCCESS(status)) {
            CertificateStoreClose(created);
            return status;
        }
        *store = created;
        return STATUS_SUCCESS;
    }

    const CertificateStoreOptions& source = *options;
    created->RevocationProvider = source.RevocationProvider;
    created->RevocationProviderContext = source.RevocationProviderContext;

    for (SIZE_T index = 0; index < source.TrustAnchorCount; ++index) {
        const CertificateTrustAnchor& input = source.TrustAnchors[index];
        tls::CertificateTrustAnchor& output = created->TrustAnchors[index];
        output.SubjectName = input.SubjectName;
        output.SubjectNameLength = input.SubjectNameLength;
        RtlCopyMemory(output.SubjectPublicKeySha256, input.SubjectPublicKeySha256, sizeof(output.SubjectPublicKeySha256));
        output.MatchSubjectPublicKey = input.MatchSubjectPublicKey;
    }
    created->TrustAnchorCount = source.TrustAnchorCount;

    for (SIZE_T index = 0; index < source.PinCount; ++index) {
        const CertificatePin& input = source.Pins[index];
        tls::CertificatePin& output = created->Pins[index];
        output.HostName = input.HostName;
        output.HostNameLength = input.HostNameLength;
        RtlCopyMemory(output.LeafSubjectPublicKeySha256, input.LeafSubjectPublicKeySha256, sizeof(output.LeafSubjectPublicKeySha256));
    }
    created->PinCount = source.PinCount;

    for (SIZE_T index = 0; index < source.RevocationEntryCount; ++index) {
        const CertificateRevocationEntry& input = source.RevocationEntries[index];
        tls::CertificateRevocationEntry& output = created->RevocationEntries[index];
        output.IssuerName = input.IssuerName;
        output.IssuerNameLength = input.IssuerNameLength;
        output.SerialNumber = input.SerialNumber;
        output.SerialNumberLength = input.SerialNumberLength;
        output.Source = ToInternalSource(input.Source);
        output.Status = ToInternalStatus(input.Status);
        output.ThisUpdate = input.ThisUpdate;
        output.NextUpdate = input.NextUpdate;
        output.EvidenceDer = input.EvidenceDer;
        output.EvidenceDerLength = input.EvidenceDerLength;
    }
    created->RevocationEntryCount = source.RevocationEntryCount;

    for (SIZE_T index = 0; index < source.AuthorityBundleCount; ++index) {
        NTSTATUS status = AppendOwnedBundle(
            created,
            source.AuthorityBundles[index].Data,
            source.AuthorityBundles[index].DataLength,
            AuthorityBundleFormat::Auto);
        if (!NT_SUCCESS(status)) {
            CertificateStoreClose(created);
            return status;
        }
    }

    NTSTATUS status = Reinitialize(created);
    if (!NT_SUCCESS(status)) {
        CertificateStoreClose(created);
        return status;
    }

    *store = created;
    return STATUS_SUCCESS;
}

NTSTATUS CertificateStoreLoadPemBundle(
    CertificateStore* store,
    const UCHAR* data,
    SIZE_T dataLength) noexcept
{
    return AppendOwnedBundle(store, data, dataLength, AuthorityBundleFormat::Pem);
}

NTSTATUS CertificateStoreLoadDer(
    CertificateStore* store,
    const UCHAR* data,
    SIZE_T dataLength) noexcept
{
    return AppendOwnedBundle(store, data, dataLength, AuthorityBundleFormat::Der);
}

void CertificateStoreClose(CertificateStore* store) noexcept
{
    if (store == nullptr || store->Magic != detail::HighCertificateStoreMagic) {
        return;
    }
    store->Magic = 0;
    FreeOwnedBundles(store);
    if (store->Engine != nullptr) {
        store->Engine->Reset();
        FreeNonPagedObject(store->Engine);
        store->Engine = nullptr;
    }
    FreeNonPagedObject(store);
}
}
