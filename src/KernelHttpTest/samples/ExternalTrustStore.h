#pragma once

#include <KernelHttp/tls/CertificateStore.h>

namespace KernelHttp
{
namespace samples
{
    constexpr SIZE_T ExternalTrustStoreDefaultMaxBundleBytes = 2 * 1024 * 1024;

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    constexpr const char* ExternalTrustStoreDefaultBundlePath = "certs\\cacert.pem";
#else
    constexpr const char* ExternalTrustStoreDefaultBundlePath = nullptr;
#endif

    struct ExternalTrustStore final
    {
        tls::CertificateAuthorityBundle AuthorityBundle = {};
        tls::CertificateStore Store = {};
        UCHAR* BundleData = nullptr;
        SIZE_T BundleDataLength = 0;
    };

    _Must_inspect_result_
    NTSTATUS InitializeExternalTrustStore(
        _Inout_ ExternalTrustStore& trustStore,
        _In_z_ const char* bundlePath = ExternalTrustStoreDefaultBundlePath,
        SIZE_T maxBundleBytes = ExternalTrustStoreDefaultMaxBundleBytes) noexcept;

    void ResetExternalTrustStore(_Inout_ ExternalTrustStore& trustStore) noexcept;
}
}
