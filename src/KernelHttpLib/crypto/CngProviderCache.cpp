#include <KernelHttp/crypto/CngProviderCache.h>

namespace KernelHttp
{
namespace crypto
{
namespace
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    constexpr LPCWSTR KhBcryptAesAlgorithm = L"AES";
    constexpr LPCWSTR KhBcryptSha1Algorithm = L"SHA1";
    constexpr LPCWSTR KhBcryptSha256Algorithm = L"SHA256";
    constexpr LPCWSTR KhBcryptSha384Algorithm = L"SHA384";
    constexpr LPCWSTR KhBcryptRsaAlgorithm = L"RSA";
    constexpr LPCWSTR KhBcryptEcdsaP256Algorithm = L"ECDSA_P256";
    constexpr LPCWSTR KhBcryptEcdsaP384Algorithm = L"ECDSA_P384";
    constexpr LPCWSTR KhBcryptEcdsaP521Algorithm = L"ECDSA_P521";
    constexpr LPCWSTR KhBcryptEcdhP256Algorithm = L"ECDH_P256";
    constexpr LPCWSTR KhBcryptEcdhP384Algorithm = L"ECDH_P384";
    constexpr LPCWSTR KhBcryptEcdhP521Algorithm = L"ECDH_P521";
    constexpr ULONG KhBcryptAlgHandleHmacFlag = 0x00000008;
#else
    constexpr LPCWSTR KhBcryptAesAlgorithm = BCRYPT_AES_ALGORITHM;
    constexpr LPCWSTR KhBcryptSha1Algorithm = BCRYPT_SHA1_ALGORITHM;
    constexpr LPCWSTR KhBcryptSha256Algorithm = BCRYPT_SHA256_ALGORITHM;
    constexpr LPCWSTR KhBcryptSha384Algorithm = BCRYPT_SHA384_ALGORITHM;
    constexpr LPCWSTR KhBcryptRsaAlgorithm = BCRYPT_RSA_ALGORITHM;
    constexpr LPCWSTR KhBcryptEcdsaP256Algorithm = BCRYPT_ECDSA_P256_ALGORITHM;
    constexpr LPCWSTR KhBcryptEcdsaP384Algorithm = BCRYPT_ECDSA_P384_ALGORITHM;
    constexpr LPCWSTR KhBcryptEcdsaP521Algorithm = BCRYPT_ECDSA_P521_ALGORITHM;
    constexpr LPCWSTR KhBcryptEcdhP256Algorithm = BCRYPT_ECDH_P256_ALGORITHM;
    constexpr LPCWSTR KhBcryptEcdhP384Algorithm = BCRYPT_ECDH_P384_ALGORITHM;
    constexpr LPCWSTR KhBcryptEcdhP521Algorithm = BCRYPT_ECDH_P521_ALGORITHM;
    constexpr ULONG KhBcryptAlgHandleHmacFlag = BCRYPT_ALG_HANDLE_HMAC_FLAG;
#endif

    _Must_inspect_result_
    NTSTATUS OpenProvider(CngAlgorithmProvider& provider, LPCWSTR algorithm, ULONG flags = 0) noexcept
    {
        return provider.Open(algorithm, flags);
    }

    _Ret_maybenull_
    const CngAlgorithmProvider* ProviderIfOpen(const CngAlgorithmProvider& provider) noexcept
    {
        return provider.IsOpen() ? &provider : nullptr;
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS SetCachedAesGcmMode(CngAlgorithmProvider& provider) noexcept
    {
        return BCryptSetProperty(
            provider.Handle(),
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM),
            0);
    }
#else
    _Must_inspect_result_
    NTSTATUS SetCachedAesGcmMode(CngAlgorithmProvider& provider) noexcept
    {
        UNREFERENCED_PARAMETER(provider);
        return STATUS_SUCCESS;
    }
#endif
}

    CngProviderCache::~CngProviderCache() noexcept
    {
        Shutdown();
    }

    NTSTATUS CngProviderCache::Initialize() noexcept
    {
        Shutdown();

        NTSTATUS status = OpenProvider(aes_, KhBcryptAesAlgorithm);
        if (NT_SUCCESS(status)) {
            status = SetCachedAesGcmMode(aes_);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(sha1_, KhBcryptSha1Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(sha256_, KhBcryptSha256Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(sha384_, KhBcryptSha384Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(hmacSha1_, KhBcryptSha1Algorithm, KhBcryptAlgHandleHmacFlag);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(hmacSha256_, KhBcryptSha256Algorithm, KhBcryptAlgHandleHmacFlag);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(hmacSha384_, KhBcryptSha384Algorithm, KhBcryptAlgHandleHmacFlag);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(rsa_, KhBcryptRsaAlgorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdsaP256_, KhBcryptEcdsaP256Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdsaP384_, KhBcryptEcdsaP384Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdsaP521_, KhBcryptEcdsaP521Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdhP256_, KhBcryptEcdhP256Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdhP384_, KhBcryptEcdhP384Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdhP521_, KhBcryptEcdhP521Algorithm);
        }

        if (!NT_SUCCESS(status)) {
            Shutdown();
            return status;
        }

        initialized_ = true;
        return STATUS_SUCCESS;
    }

    void CngProviderCache::Shutdown() noexcept
    {
        ecdhP521_.Close();
        ecdhP384_.Close();
        ecdhP256_.Close();
        ecdsaP521_.Close();
        ecdsaP384_.Close();
        ecdsaP256_.Close();
        rsa_.Close();
        hmacSha384_.Close();
        hmacSha256_.Close();
        hmacSha1_.Close();
        sha384_.Close();
        sha256_.Close();
        sha1_.Close();
        aes_.Close();
        initialized_ = false;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        cachedProviderUseCount_ = 0;
#endif
    }

    bool CngProviderCache::IsInitialized() const noexcept
    {
        return initialized_;
    }

    const CngAlgorithmProvider* CngProviderCache::Aes() const noexcept
    {
        return initialized_ ? ProviderIfOpen(aes_) : nullptr;
    }

    const CngAlgorithmProvider* CngProviderCache::Hash(HashAlgorithm algorithm) const noexcept
    {
        if (!initialized_) {
            return nullptr;
        }

        switch (algorithm) {
        case HashAlgorithm::Sha1:
            return ProviderIfOpen(sha1_);
        case HashAlgorithm::Sha256:
            return ProviderIfOpen(sha256_);
        case HashAlgorithm::Sha384:
            return ProviderIfOpen(sha384_);
        default:
            return nullptr;
        }
    }

    const CngAlgorithmProvider* CngProviderCache::Hmac(HashAlgorithm algorithm) const noexcept
    {
        if (!initialized_) {
            return nullptr;
        }

        switch (algorithm) {
        case HashAlgorithm::Sha1:
            return ProviderIfOpen(hmacSha1_);
        case HashAlgorithm::Sha256:
            return ProviderIfOpen(hmacSha256_);
        case HashAlgorithm::Sha384:
            return ProviderIfOpen(hmacSha384_);
        default:
            return nullptr;
        }
    }

    const CngAlgorithmProvider* CngProviderCache::Rsa() const noexcept
    {
        return initialized_ ? ProviderIfOpen(rsa_) : nullptr;
    }

    const CngAlgorithmProvider* CngProviderCache::Ecdsa(EcCurve curve) const noexcept
    {
        if (!initialized_) {
            return nullptr;
        }

        switch (curve) {
        case EcCurve::P256:
            return ProviderIfOpen(ecdsaP256_);
        case EcCurve::P384:
            return ProviderIfOpen(ecdsaP384_);
        case EcCurve::P521:
            return ProviderIfOpen(ecdsaP521_);
        default:
            return nullptr;
        }
    }

    const CngAlgorithmProvider* CngProviderCache::Ecdh(EcCurve curve) const noexcept
    {
        if (!initialized_) {
            return nullptr;
        }

        switch (curve) {
        case EcCurve::P256:
            return ProviderIfOpen(ecdhP256_);
        case EcCurve::P384:
            return ProviderIfOpen(ecdhP384_);
        case EcCurve::P521:
            return ProviderIfOpen(ecdhP521_);
        default:
            return nullptr;
        }
    }

    void CngProviderCache::MarkProviderUsed() const noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        ++cachedProviderUseCount_;
#endif
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    ULONG CngProviderCache::CachedProviderUseCountForTest() const noexcept
    {
        return cachedProviderUseCount_;
    }
#endif
}
}
