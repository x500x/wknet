#pragma once

#include <KernelHttp/crypto/CngProvider.h>

namespace KernelHttp
{
namespace crypto
{
    class CngProviderCache;

    enum class KeyExchangeGroup : USHORT
    {
        Secp256r1 = 23,
        Secp384r1 = 24,
        Secp521r1 = 25,
        X25519 = 29,
        X448 = 30,
        Ffdhe2048 = 256,
        Ffdhe3072 = 257,
        Ffdhe4096 = 258,
        Ffdhe6144 = 259,
        Ffdhe8192 = 260
    };

    constexpr SIZE_T KeyExchangeX25519KeyLength = 32;
    constexpr SIZE_T KeyExchangeX448KeyLength = 56;
    constexpr SIZE_T KeyExchangeMaxPublicKeyLength = 1024;
    constexpr SIZE_T KeyExchangeMaxPrivateKeyLength = 1024;
    constexpr SIZE_T KeyExchangeMaxSharedSecretLength = 1024;

    struct KeyExchangeKeyPair final
    {
        KeyExchangeGroup Group = KeyExchangeGroup::Secp256r1;
        UCHAR PrivateKey[KeyExchangeMaxPrivateKeyLength] = {};
        SIZE_T PrivateKeyLength = 0;
        UCHAR PublicKey[KeyExchangeMaxPublicKeyLength] = {};
        SIZE_T PublicKeyLength = 0;
        CngKey CngPrivateKey = {};

        void Reset() noexcept;
    };

    class KeyExchange final
    {
    public:
        KeyExchange() = delete;

        _Must_inspect_result_
        static bool IsSupportedGroup(KeyExchangeGroup group) noexcept;

        _Must_inspect_result_
        static bool IsRawKeyShareGroup(KeyExchangeGroup group) noexcept;

        _Must_inspect_result_
        static SIZE_T PublicKeyLength(KeyExchangeGroup group) noexcept;

        _Must_inspect_result_
        static SIZE_T SharedSecretLength(KeyExchangeGroup group) noexcept;

        _Must_inspect_result_
        static NTSTATUS GenerateKeyPair(
            _In_opt_ const CngProviderCache* cache,
            KeyExchangeGroup group,
            _Out_ KeyExchangeKeyPair& keyPair) noexcept;

        _Must_inspect_result_
        static NTSTATUS DerivePublicKey(
            KeyExchangeGroup group,
            _In_reads_bytes_(privateKeyLength) const UCHAR* privateKey,
            SIZE_T privateKeyLength,
            _Out_writes_bytes_(publicKeyCapacity) UCHAR* publicKey,
            SIZE_T publicKeyCapacity,
            _Out_ SIZE_T* publicKeyLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS DeriveSharedSecret(
            KeyExchangeGroup group,
            _In_reads_bytes_(privateKeyLength) const UCHAR* privateKey,
            SIZE_T privateKeyLength,
            _In_reads_bytes_(peerPublicKeyLength) const UCHAR* peerPublicKey,
            SIZE_T peerPublicKeyLength,
            _Out_writes_bytes_(sharedSecretCapacity) UCHAR* sharedSecret,
            SIZE_T sharedSecretCapacity,
            _Out_ SIZE_T* sharedSecretLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS DeriveSharedSecret(
            _In_opt_ const CngProviderCache* cache,
            _In_ const KeyExchangeKeyPair& keyPair,
            _In_reads_bytes_(peerPublicKeyLength) const UCHAR* peerPublicKey,
            SIZE_T peerPublicKeyLength,
            _Out_writes_bytes_(sharedSecretCapacity) UCHAR* sharedSecret,
            SIZE_T sharedSecretCapacity,
            _Out_ SIZE_T* sharedSecretLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS ValidateFiniteFieldPublicKey(
            KeyExchangeGroup group,
            _In_reads_bytes_(publicKeyLength) const UCHAR* publicKey,
            SIZE_T publicKeyLength) noexcept;
    };
}
}
