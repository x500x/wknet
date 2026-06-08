#pragma once

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <KernelHttp/http/HttpTypes.h>

using LPCWSTR = const wchar_t*;

#ifndef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(x)
#endif
#else
#include <KernelHttp/KernelHttpConfig.h>
#include <bcrypt.h>
#endif

namespace KernelHttp
{
namespace crypto
{
    enum class HashAlgorithm : UCHAR
    {
        Sha1,
        Sha256,
        Sha384
    };

    enum class EcCurve : UCHAR
    {
        P256,
        P384,
        P521
    };

    enum class SignatureAlgorithm : UCHAR
    {
        RsaPkcs1Sha256,
        RsaPkcs1Sha384,
        RsaPssSha256,
        RsaPssSha384,
        EcdsaSha256,
        EcdsaSha384
    };

    struct BufferView final
    {
        const UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    class CngProviderCache;

    struct MutableBuffer final
    {
        UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct AesGcmKey final
    {
        const UCHAR* Key = nullptr;
        SIZE_T KeyLength = 0;
    };

    struct AesGcmParameters final
    {
        BufferView Nonce = {};
        BufferView Aad = {};
        BufferView Tag = {};
    };

    class CngAlgorithmProvider final
    {
    public:
        CngAlgorithmProvider() noexcept = default;

        CngAlgorithmProvider(const CngAlgorithmProvider&) = delete;
        CngAlgorithmProvider& operator=(const CngAlgorithmProvider&) = delete;

        ~CngAlgorithmProvider() noexcept;

        _Must_inspect_result_
        NTSTATUS Open(_In_ LPCWSTR algorithm, ULONG flags = 0) noexcept;

        void Close() noexcept;

        _Must_inspect_result_
        bool IsOpen() const noexcept;

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        _Ret_maybenull_
        BCRYPT_ALG_HANDLE Handle() const noexcept;
#endif

    private:
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        BCRYPT_ALG_HANDLE handle_ = nullptr;
#else
        void* handle_ = nullptr;
#endif
    };

    class CngKey final
    {
        friend class CngProvider;

    public:
        CngKey() noexcept = default;

        CngKey(const CngKey&) = delete;
        CngKey& operator=(const CngKey&) = delete;

        ~CngKey() noexcept;

        _Must_inspect_result_
        NTSTATUS ImportPublicKey(
            _In_ const CngAlgorithmProvider& provider,
            _In_ LPCWSTR blobType,
            _In_reads_bytes_(blobLength) const UCHAR* blob,
            SIZE_T blobLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ExportPublicKey(
            _In_ LPCWSTR blobType,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) const noexcept;

        void Close() noexcept;

        _Must_inspect_result_
        bool IsOpen() const noexcept;

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        _Ret_maybenull_
        BCRYPT_KEY_HANDLE Handle() const noexcept;
#endif

    private:
        void Adopt(
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
            BCRYPT_KEY_HANDLE handle
#else
            void* handle
#endif
        ) noexcept;

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        BCRYPT_KEY_HANDLE handle_ = nullptr;
#else
        void* handle_ = nullptr;
#endif
    };

    class CngHashContext final
    {
    public:
        CngHashContext() noexcept = default;

        CngHashContext(const CngHashContext&) = delete;
        CngHashContext& operator=(const CngHashContext&) = delete;

        ~CngHashContext() noexcept;

        _Must_inspect_result_
        NTSTATUS Initialize(HashAlgorithm algorithm) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Update(
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength) noexcept;

        _Must_inspect_result_
        NTSTATUS Finish(
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) const noexcept;

        _Must_inspect_result_
        bool IsInitialized() const noexcept;

    private:
        HashAlgorithm algorithm_ = HashAlgorithm::Sha256;
        bool initialized_ = false;

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        CngAlgorithmProvider provider_ = {};
        BCRYPT_HASH_HANDLE hash_ = nullptr;
        UCHAR* hashObject_ = nullptr;
        ULONG hashObjectLength_ = 0;
#else
        UCHAR state_[32768] = {};
        SIZE_T stateLength_ = 0;
#endif
    };

    class CngProvider final
    {
    public:
        CngProvider() = delete;

        _Must_inspect_result_
        static NTSTATUS GenerateRandom(
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS Hash(
            _In_opt_ const CngProviderCache* cache,
            HashAlgorithm algorithm,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS Hash(
            HashAlgorithm algorithm,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS Hmac(
            _In_opt_ const CngProviderCache* cache,
            HashAlgorithm algorithm,
            _In_reads_bytes_(keyLength) const UCHAR* key,
            SIZE_T keyLength,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS Hmac(
            HashAlgorithm algorithm,
            _In_reads_bytes_(keyLength) const UCHAR* key,
            SIZE_T keyLength,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS HkdfExtract(
            _In_opt_ const CngProviderCache* cache,
            HashAlgorithm algorithm,
            _In_reads_bytes_opt_(saltLength) const UCHAR* salt,
            SIZE_T saltLength,
            _In_reads_bytes_opt_(ikmLength) const UCHAR* ikm,
            SIZE_T ikmLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS HkdfExtract(
            HashAlgorithm algorithm,
            _In_reads_bytes_opt_(saltLength) const UCHAR* salt,
            SIZE_T saltLength,
            _In_reads_bytes_opt_(ikmLength) const UCHAR* ikm,
            SIZE_T ikmLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS HkdfExpand(
            _In_opt_ const CngProviderCache* cache,
            HashAlgorithm algorithm,
            _In_reads_bytes_(prkLength) const UCHAR* prk,
            SIZE_T prkLength,
            _In_reads_bytes_opt_(infoLength) const UCHAR* info,
            SIZE_T infoLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS HkdfExpand(
            HashAlgorithm algorithm,
            _In_reads_bytes_(prkLength) const UCHAR* prk,
            SIZE_T prkLength,
            _In_reads_bytes_opt_(infoLength) const UCHAR* info,
            SIZE_T infoLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS AesGcmEncrypt(
            _In_opt_ const CngProviderCache* cache,
            _In_ const AesGcmKey& key,
            _In_ const AesGcmParameters& parameters,
            _In_reads_bytes_(plaintextLength) const UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_writes_bytes_(ciphertextLength) UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(tagLength) UCHAR* tag,
            SIZE_T tagLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS AesGcmEncrypt(
            _In_ const AesGcmKey& key,
            _In_ const AesGcmParameters& parameters,
            _In_reads_bytes_(plaintextLength) const UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_writes_bytes_(ciphertextLength) UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(tagLength) UCHAR* tag,
            SIZE_T tagLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS AesGcmDecrypt(
            _In_opt_ const CngProviderCache* cache,
            _In_ const AesGcmKey& key,
            _In_ const AesGcmParameters& parameters,
            _In_reads_bytes_(ciphertextLength) const UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(plaintextLength) UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS AesGcmDecrypt(
            _In_ const AesGcmKey& key,
            _In_ const AesGcmParameters& parameters,
            _In_reads_bytes_(ciphertextLength) const UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(plaintextLength) UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS VerifySignature(
            _In_opt_ const CngProviderCache* cache,
            SignatureAlgorithm algorithm,
            _In_ const CngKey& publicKey,
            _In_reads_bytes_(hashLength) const UCHAR* hash,
            SIZE_T hashLength,
            _In_reads_bytes_(signatureLength) const UCHAR* signature,
            SIZE_T signatureLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS VerifySignature(
            SignatureAlgorithm algorithm,
            _In_ const CngKey& publicKey,
            _In_reads_bytes_(hashLength) const UCHAR* hash,
            SIZE_T hashLength,
            _In_reads_bytes_(signatureLength) const UCHAR* signature,
            SIZE_T signatureLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS GenerateEcdhKeyPair(
            _In_opt_ const CngProviderCache* cache,
            EcCurve curve,
            _Out_ CngKey& privateKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS GenerateEcdhKeyPair(
            EcCurve curve,
            _Out_ CngKey& privateKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportEcdhPublicKey(
            _In_opt_ const CngProviderCache* cache,
            EcCurve curve,
            _In_reads_bytes_(pointLength) const UCHAR* uncompressedPoint,
            SIZE_T pointLength,
            _Out_ CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportEcdhPublicKey(
            EcCurve curve,
            _In_reads_bytes_(pointLength) const UCHAR* uncompressedPoint,
            SIZE_T pointLength,
            _Out_ CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportEcdsaPublicKey(
            _In_opt_ const CngProviderCache* cache,
            EcCurve curve,
            _In_reads_bytes_(pointLength) const UCHAR* uncompressedPoint,
            SIZE_T pointLength,
            _Out_ CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportEcdsaPublicKey(
            EcCurve curve,
            _In_reads_bytes_(pointLength) const UCHAR* uncompressedPoint,
            SIZE_T pointLength,
            _Out_ CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportRsaPublicKey(
            _In_opt_ const CngProviderCache* cache,
            _In_reads_bytes_(exponentLength) const UCHAR* exponent,
            SIZE_T exponentLength,
            _In_reads_bytes_(modulusLength) const UCHAR* modulus,
            SIZE_T modulusLength,
            _Out_ CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS ImportRsaPublicKey(
            _In_reads_bytes_(exponentLength) const UCHAR* exponent,
            SIZE_T exponentLength,
            _In_reads_bytes_(modulusLength) const UCHAR* modulus,
            SIZE_T modulusLength,
            _Out_ CngKey& publicKey) noexcept;

        _Must_inspect_result_
        static NTSTATUS DeriveEcdhSecret(
            _In_opt_ const CngProviderCache* cache,
            _In_ const CngKey& privateKey,
            _In_ const CngKey& peerPublicKey,
            _Out_writes_bytes_(secretLength) UCHAR* secret,
            SIZE_T secretLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS DeriveEcdhSecret(
            _In_ const CngKey& privateKey,
            _In_ const CngKey& peerPublicKey,
            _Out_writes_bytes_(secretLength) UCHAR* secret,
            SIZE_T secretLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;
    };
}
}
