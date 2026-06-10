#pragma once

#include <KernelHttp/crypto/CngProvider.h>

namespace KernelHttp
{
namespace crypto
{
    class CngProviderCache;

    enum class AeadAlgorithm : UCHAR
    {
        Aes128Gcm,
        Aes256Gcm,
        ChaCha20Poly1305,
        Aes128Ccm,
        Aes128Ccm8
    };

    constexpr SIZE_T AeadMaxKeyLength = 32;
    constexpr SIZE_T AeadMaxNonceLength = 12;
    constexpr SIZE_T AeadMaxTagLength = 16;
    constexpr SIZE_T AeadChaCha20Poly1305KeyLength = 32;
    constexpr SIZE_T AeadChaCha20Poly1305NonceLength = 12;
    constexpr SIZE_T AeadChaCha20Poly1305TagLength = 16;

    struct AeadKey final
    {
        AeadAlgorithm Algorithm = AeadAlgorithm::Aes128Gcm;
        const UCHAR* Key = nullptr;
        SIZE_T KeyLength = 0;
    };

    struct AeadParameters final
    {
        BufferView Nonce = {};
        BufferView Aad = {};
        BufferView Tag = {};
    };

    class Aead final
    {
    public:
        Aead() = delete;

        _Must_inspect_result_
        static SIZE_T TagLength(AeadAlgorithm algorithm) noexcept;

        _Must_inspect_result_
        static NTSTATUS Encrypt(
            _In_opt_ const CngProviderCache* cache,
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(plaintextLength) const UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_writes_bytes_(ciphertextLength) UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(tagLength) UCHAR* tag,
            SIZE_T tagLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS Decrypt(
            _In_opt_ const CngProviderCache* cache,
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(ciphertextLength) const UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(plaintextLength) UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;
    };
}
}
