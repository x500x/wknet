#pragma once

#include <KernelHttp/crypto/CngProvider.h>

namespace KernelHttp
{
namespace crypto
{
    class CngProviderCache final
    {
    public:
        CngProviderCache() noexcept = default;
        CngProviderCache(const CngProviderCache&) = delete;
        CngProviderCache& operator=(const CngProviderCache&) = delete;
        ~CngProviderCache() noexcept;

        _Must_inspect_result_
        NTSTATUS Initialize() noexcept;

        void Shutdown() noexcept;

        _Must_inspect_result_
        bool IsInitialized() const noexcept;

        _Ret_maybenull_
        const CngAlgorithmProvider* Aes() const noexcept;

        _Ret_maybenull_
        const CngAlgorithmProvider* Hash(HashAlgorithm algorithm) const noexcept;

        _Ret_maybenull_
        const CngAlgorithmProvider* Hmac(HashAlgorithm algorithm) const noexcept;

        _Ret_maybenull_
        const CngAlgorithmProvider* Rsa() const noexcept;

        _Ret_maybenull_
        const CngAlgorithmProvider* Ecdsa(EcCurve curve) const noexcept;

        _Ret_maybenull_
        const CngAlgorithmProvider* Ecdh(EcCurve curve) const noexcept;

        void MarkProviderUsed() const noexcept;

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        ULONG CachedProviderUseCountForTest() const noexcept;
#endif

    private:
        CngAlgorithmProvider aes_ = {};
        CngAlgorithmProvider sha1_ = {};
        CngAlgorithmProvider sha256_ = {};
        CngAlgorithmProvider sha384_ = {};
        CngAlgorithmProvider hmacSha1_ = {};
        CngAlgorithmProvider hmacSha256_ = {};
        CngAlgorithmProvider hmacSha384_ = {};
        CngAlgorithmProvider rsa_ = {};
        CngAlgorithmProvider ecdsaP256_ = {};
        CngAlgorithmProvider ecdsaP384_ = {};
        CngAlgorithmProvider ecdsaP521_ = {};
        CngAlgorithmProvider ecdhP256_ = {};
        CngAlgorithmProvider ecdhP384_ = {};
        CngAlgorithmProvider ecdhP521_ = {};
        bool initialized_ = false;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        mutable ULONG cachedProviderUseCount_ = 0;
#endif
    };
}
}
