#pragma once

#include <KernelHttp/crypto/CngProvider.h>

namespace KernelHttp
{
namespace tls
{
    constexpr SIZE_T CertificateSha256ThumbprintLength = 32;
    constexpr SIZE_T CertificateMaxTrustAnchors = 16;
    constexpr SIZE_T CertificateMaxAuthorityBundles = 8;

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

    struct CertificateStoreOptions final
    {
        const CertificateTrustAnchor* TrustAnchors = nullptr;
        SIZE_T TrustAnchorCount = 0;
        const CertificateAuthorityBundle* AuthorityBundles = nullptr;
        SIZE_T AuthorityBundleCount = 0;
        const CertificatePin* Pins = nullptr;
        SIZE_T PinCount = 0;
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
        _Must_inspect_result_
        const CertificateAuthorityBundle* AuthorityBundleAt(SIZE_T index) const noexcept;

    private:
        const CertificateTrustAnchor* trustAnchors_ = nullptr;
        SIZE_T trustAnchorCount_ = 0;
        const CertificateAuthorityBundle* authorityBundles_ = nullptr;
        SIZE_T authorityBundleCount_ = 0;
        const CertificatePin* pins_ = nullptr;
        SIZE_T pinCount_ = 0;
    };
}
}
