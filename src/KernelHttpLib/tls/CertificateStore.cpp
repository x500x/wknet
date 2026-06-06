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
    }

    NTSTATUS CertificateStore::Initialize(const CertificateStoreOptions& options) noexcept
    {
        if (options.TrustAnchorCount > CertificateMaxTrustAnchors ||
            options.AuthorityBundleCount > CertificateMaxAuthorityBundles ||
            (options.TrustAnchorCount != 0 && options.TrustAnchors == nullptr) ||
            (options.AuthorityBundleCount != 0 && options.AuthorityBundles == nullptr) ||
            (options.PinCount != 0 && options.Pins == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < options.TrustAnchorCount; ++index) {
            const CertificateTrustAnchor& anchor = options.TrustAnchors[index];
            if (!IsValidBuffer(anchor.SubjectName, anchor.SubjectNameLength) ||
                (anchor.SubjectNameLength == 0 && !anchor.MatchSubjectPublicKey)) {
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

        trustAnchors_ = options.TrustAnchors;
        trustAnchorCount_ = options.TrustAnchorCount;
        authorityBundles_ = options.AuthorityBundles;
        authorityBundleCount_ = options.AuthorityBundleCount;
        pins_ = options.Pins;
        pinCount_ = options.PinCount;
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

    const CertificateAuthorityBundle* CertificateStore::AuthorityBundleAt(SIZE_T index) const noexcept
    {
        return index < authorityBundleCount_ ? authorityBundles_ + index : nullptr;
    }
}
}
