#include <wknet/crypto/CngProviderCache.h>

namespace wknet
{
namespace crypto
{
namespace
{
#if defined(WKNET_USER_MODE_TEST)
    constexpr LPCWSTR BcryptAesAlgorithm = L"AES";
    constexpr LPCWSTR BcryptSha1Algorithm = L"SHA1";
    constexpr LPCWSTR BcryptSha256Algorithm = L"SHA256";
    constexpr LPCWSTR BcryptSha384Algorithm = L"SHA384";
    constexpr LPCWSTR BcryptSha512Algorithm = L"SHA512";
    constexpr LPCWSTR BcryptRsaAlgorithm = L"RSA";
    constexpr LPCWSTR BcryptEcdsaP256Algorithm = L"ECDSA_P256";
    constexpr LPCWSTR BcryptEcdsaP384Algorithm = L"ECDSA_P384";
    constexpr LPCWSTR BcryptEcdsaP521Algorithm = L"ECDSA_P521";
    constexpr LPCWSTR BcryptEcdhP256Algorithm = L"ECDH_P256";
    constexpr LPCWSTR BcryptEcdhP384Algorithm = L"ECDH_P384";
    constexpr LPCWSTR BcryptEcdhP521Algorithm = L"ECDH_P521";
    constexpr ULONG BcryptAlgHandleHmacFlag = 0x00000008;
#else
    constexpr LPCWSTR BcryptAesAlgorithm = BCRYPT_AES_ALGORITHM;
    constexpr LPCWSTR BcryptSha1Algorithm = BCRYPT_SHA1_ALGORITHM;
    constexpr LPCWSTR BcryptSha256Algorithm = BCRYPT_SHA256_ALGORITHM;
    constexpr LPCWSTR BcryptSha384Algorithm = BCRYPT_SHA384_ALGORITHM;
    constexpr LPCWSTR BcryptSha512Algorithm = BCRYPT_SHA512_ALGORITHM;
    constexpr LPCWSTR BcryptRsaAlgorithm = BCRYPT_RSA_ALGORITHM;
    constexpr LPCWSTR BcryptEcdsaP256Algorithm = BCRYPT_ECDSA_P256_ALGORITHM;
    constexpr LPCWSTR BcryptEcdsaP384Algorithm = BCRYPT_ECDSA_P384_ALGORITHM;
    constexpr LPCWSTR BcryptEcdsaP521Algorithm = BCRYPT_ECDSA_P521_ALGORITHM;
    constexpr LPCWSTR BcryptEcdhP256Algorithm = BCRYPT_ECDH_P256_ALGORITHM;
    constexpr LPCWSTR BcryptEcdhP384Algorithm = BCRYPT_ECDH_P384_ALGORITHM;
    constexpr LPCWSTR BcryptEcdhP521Algorithm = BCRYPT_ECDH_P521_ALGORITHM;
    constexpr ULONG BcryptAlgHandleHmacFlag = BCRYPT_ALG_HANDLE_HMAC_FLAG;
#endif

    _Must_inspect_result_
    NTSTATUS OpenProvider(CngAlgorithmProvider& provider, LPCWSTR algorithm, ULONG flags = 0) noexcept
    {
        return provider.Open(algorithm, flags);
    }

#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS RequirePassiveLevel() noexcept
    {
        return KeGetCurrentIrql() == PASSIVE_LEVEL ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
    }
#endif

    _Ret_maybenull_
    const CngAlgorithmProvider* ProviderIfOpen(const CngAlgorithmProvider& provider) noexcept
    {
        return provider.IsOpen() ? &provider : nullptr;
    }

#if !defined(WKNET_USER_MODE_TEST)
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
#if !defined(WKNET_USER_MODE_TEST)
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }
#else
        NTSTATUS status = STATUS_SUCCESS;
#endif

        Shutdown();

        status = OpenProvider(aes_, BcryptAesAlgorithm);
        if (NT_SUCCESS(status)) {
            status = SetCachedAesGcmMode(aes_);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(sha1_, BcryptSha1Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(sha256_, BcryptSha256Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(sha384_, BcryptSha384Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(sha512_, BcryptSha512Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(hmacSha1_, BcryptSha1Algorithm, BcryptAlgHandleHmacFlag);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(hmacSha256_, BcryptSha256Algorithm, BcryptAlgHandleHmacFlag);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(hmacSha384_, BcryptSha384Algorithm, BcryptAlgHandleHmacFlag);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(hmacSha512_, BcryptSha512Algorithm, BcryptAlgHandleHmacFlag);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(rsa_, BcryptRsaAlgorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdsaP256_, BcryptEcdsaP256Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdsaP384_, BcryptEcdsaP384Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdsaP521_, BcryptEcdsaP521Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdhP256_, BcryptEcdhP256Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdhP384_, BcryptEcdhP384Algorithm);
        }
        if (NT_SUCCESS(status)) {
            status = OpenProvider(ecdhP521_, BcryptEcdhP521Algorithm);
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
        hmacSha512_.Close();
        hmacSha256_.Close();
        hmacSha1_.Close();
        sha512_.Close();
        sha384_.Close();
        sha256_.Close();
        sha1_.Close();
        aes_.Close();
        initialized_ = false;
#if defined(WKNET_USER_MODE_TEST)
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
        case HashAlgorithm::Sha512:
            return ProviderIfOpen(sha512_);
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
        case HashAlgorithm::Sha512:
            return ProviderIfOpen(hmacSha512_);
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
#if defined(WKNET_USER_MODE_TEST)
        ++cachedProviderUseCount_;
#endif
    }

#if defined(WKNET_USER_MODE_TEST)
    ULONG CngProviderCache::CachedProviderUseCountForTest() const noexcept
    {
        return cachedProviderUseCount_;
    }
#endif
}
}
