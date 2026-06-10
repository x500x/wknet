#include <KernelHttp/crypto/KeyExchange.h>
#include <KernelHttp/crypto/CngProviderCache.h>

namespace KernelHttp
{
namespace crypto
{
    namespace
    {
        constexpr SIZE_T FieldElementLength = 16;
        using FieldElement = long long[FieldElementLength];

        const UCHAR X25519BasePoint[KeyExchangeX25519KeyLength] = {
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        const FieldElement Field121665 = {
            0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        _Must_inspect_result_
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        bool IsAllZero(_In_reads_bytes_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            UCHAR diff = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                diff = static_cast<UCHAR>(diff | data[index]);
            }
            return diff == 0;
        }

        void AddFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement left,
            _In_reads_(FieldElementLength) const FieldElement right) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = left[index] + right[index];
            }
        }

        void SubtractFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement left,
            _In_reads_(FieldElementLength) const FieldElement right) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = left[index] - right[index];
            }
        }

        void CarryFieldElement(_Inout_updates_(FieldElementLength) FieldElement value) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                value[index] += 1LL << 16;
                const long long carry = value[index] >> 16;
                if (index < FieldElementLength - 1) {
                    value[index + 1] += carry - 1;
                }
                else {
                    value[0] += 38 * (carry - 1);
                }
                value[index] -= carry << 16;
            }
        }

        void SelectFieldElement(
            _Inout_updates_(FieldElementLength) FieldElement left,
            _Inout_updates_(FieldElementLength) FieldElement right,
            long long swap) noexcept
        {
            const long long mask = ~(swap - 1);
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                const long long value = mask & (left[index] ^ right[index]);
                left[index] ^= value;
                right[index] ^= value;
            }
        }

        void CopyFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = input[index];
            }
        }

        void MultiplyFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement left,
            _In_reads_(FieldElementLength) const FieldElement right) noexcept
        {
            long long product[31] = {};
            for (SIZE_T leftIndex = 0; leftIndex < FieldElementLength; ++leftIndex) {
                for (SIZE_T rightIndex = 0; rightIndex < FieldElementLength; ++rightIndex) {
                    product[leftIndex + rightIndex] += left[leftIndex] * right[rightIndex];
                }
            }

            for (SIZE_T index = 0; index < FieldElementLength - 1; ++index) {
                product[index] += 38 * product[index + FieldElementLength];
            }
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] = product[index];
            }

            CarryFieldElement(output);
            CarryFieldElement(output);
            RtlSecureZeroMemory(product, sizeof(product));
        }

        void SquareFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            MultiplyFieldElement(output, input, input);
        }

        void UnpackFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_bytes_(KeyExchangeX25519KeyLength) const UCHAR* input) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[index] =
                    static_cast<long long>(input[2 * index]) |
                    (static_cast<long long>(input[(2 * index) + 1]) << 8);
            }
            output[15] &= 0x7fff;
        }

        void PackFieldElement(
            _Out_writes_bytes_(KeyExchangeX25519KeyLength) UCHAR* output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            FieldElement value = {};
            FieldElement reduced = {};
            CopyFieldElement(value, input);
            CarryFieldElement(value);
            CarryFieldElement(value);
            CarryFieldElement(value);

            for (SIZE_T round = 0; round < 2; ++round) {
                CopyFieldElement(reduced, value);
                reduced[0] -= 0xffed;
                for (SIZE_T index = 1; index < FieldElementLength - 1; ++index) {
                    reduced[index] -= 0xffff + ((reduced[index - 1] >> 16) & 1);
                    reduced[index - 1] &= 0xffff;
                }
                reduced[15] -= 0x7fff + ((reduced[14] >> 16) & 1);
                reduced[14] &= 0xffff;
                SelectFieldElement(value, reduced, 1 - ((reduced[15] >> 16) & 1));
            }

            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[2 * index] = static_cast<UCHAR>(value[index] & 0xff);
                output[(2 * index) + 1] = static_cast<UCHAR>((value[index] >> 8) & 0xff);
            }

            RtlSecureZeroMemory(value, sizeof(value));
            RtlSecureZeroMemory(reduced, sizeof(reduced));
        }

        void InvertFieldElement(
            _Out_writes_(FieldElementLength) FieldElement output,
            _In_reads_(FieldElementLength) const FieldElement input) noexcept
        {
            FieldElement value = {};
            CopyFieldElement(value, input);
            for (int index = 253; index >= 0; --index) {
                SquareFieldElement(value, value);
                if (index != 2 && index != 4) {
                    MultiplyFieldElement(value, value, input);
                }
            }
            CopyFieldElement(output, value);
            RtlSecureZeroMemory(value, sizeof(value));
        }

        void ClampX25519Scalar(_Inout_updates_(KeyExchangeX25519KeyLength) UCHAR* scalar) noexcept
        {
            scalar[0] &= 248;
            scalar[31] &= 127;
            scalar[31] |= 64;
        }

        _Must_inspect_result_
        NTSTATUS X25519(
            _In_reads_bytes_(KeyExchangeX25519KeyLength) const UCHAR* privateKey,
            _In_reads_bytes_(KeyExchangeX25519KeyLength) const UCHAR* peerPublicKey,
            _Out_writes_bytes_(KeyExchangeX25519KeyLength) UCHAR* output) noexcept
        {
            if (privateKey == nullptr || peerPublicKey == nullptr || output == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR scalar[KeyExchangeX25519KeyLength] = {};
            RtlCopyMemory(scalar, privateKey, sizeof(scalar));
            ClampX25519Scalar(scalar);

            FieldElement x = {};
            FieldElement a = {};
            FieldElement b = {};
            FieldElement c = {};
            FieldElement d = {};
            FieldElement e = {};
            FieldElement f = {};

            UnpackFieldElement(x, peerPublicKey);
            a[0] = 1;
            d[0] = 1;
            CopyFieldElement(b, x);

            for (int bit = 254; bit >= 0; --bit) {
                const long long swap = (scalar[bit >> 3] >> (bit & 7)) & 1;
                SelectFieldElement(a, b, swap);
                SelectFieldElement(c, d, swap);
                AddFieldElement(e, a, c);
                SubtractFieldElement(a, a, c);
                AddFieldElement(c, b, d);
                SubtractFieldElement(b, b, d);
                SquareFieldElement(d, e);
                SquareFieldElement(f, a);
                MultiplyFieldElement(a, c, a);
                MultiplyFieldElement(c, b, e);
                AddFieldElement(e, a, c);
                SubtractFieldElement(a, a, c);
                SquareFieldElement(b, a);
                SubtractFieldElement(c, d, f);
                MultiplyFieldElement(a, c, Field121665);
                AddFieldElement(a, a, d);
                MultiplyFieldElement(c, c, a);
                MultiplyFieldElement(a, d, f);
                MultiplyFieldElement(d, b, x);
                SquareFieldElement(b, e);
                SelectFieldElement(a, b, swap);
                SelectFieldElement(c, d, swap);
            }

            InvertFieldElement(c, c);
            MultiplyFieldElement(a, a, c);
            PackFieldElement(output, a);

            RtlSecureZeroMemory(scalar, sizeof(scalar));
            RtlSecureZeroMemory(x, sizeof(x));
            RtlSecureZeroMemory(a, sizeof(a));
            RtlSecureZeroMemory(b, sizeof(b));
            RtlSecureZeroMemory(c, sizeof(c));
            RtlSecureZeroMemory(d, sizeof(d));
            RtlSecureZeroMemory(e, sizeof(e));
            RtlSecureZeroMemory(f, sizeof(f));
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        EcCurve ToEcCurve(KeyExchangeGroup group, _Out_ NTSTATUS* status) noexcept
        {
            if (status == nullptr) {
                return EcCurve::P256;
            }

            switch (group) {
            case KeyExchangeGroup::Secp256r1:
                *status = STATUS_SUCCESS;
                return EcCurve::P256;
            case KeyExchangeGroup::Secp384r1:
                *status = STATUS_SUCCESS;
                return EcCurve::P384;
            case KeyExchangeGroup::Secp521r1:
                *status = STATUS_SUCCESS;
                return EcCurve::P521;
            default:
                *status = STATUS_NOT_SUPPORTED;
                return EcCurve::P256;
            }
        }

        _Must_inspect_result_
        NTSTATUS ExportNistPublicKey(
            _In_ const CngKey& privateKey,
            _Out_writes_bytes_(publicKeyCapacity) UCHAR* publicKey,
            SIZE_T publicKeyCapacity,
            _Out_ SIZE_T* publicKeyLength) noexcept
        {
            if (publicKeyLength != nullptr) {
                *publicKeyLength = 0;
            }
            if (publicKey == nullptr || publicKeyLength == nullptr || publicKeyCapacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
            HeapArray<UCHAR> publicBlob(sizeof(BCRYPT_ECCKEY_BLOB) + (66 * 2));
            if (!publicBlob.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T publicBlobLength = 0;
            NTSTATUS status = privateKey.ExportPublicKey(
                BCRYPT_ECCPUBLIC_BLOB,
                publicBlob.Get(),
                publicBlob.Count(),
                &publicBlobLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(publicBlob.Get());
            const SIZE_T pointLength = (static_cast<SIZE_T>(header->cbKey) * 2) + 1;
            if (pointLength > publicKeyCapacity ||
                publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB) + (static_cast<SIZE_T>(header->cbKey) * 2)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            publicKey[0] = 4;
            RtlCopyMemory(publicKey + 1, publicBlob.Get() + sizeof(BCRYPT_ECCKEY_BLOB), header->cbKey * 2);
            *publicKeyLength = pointLength;
            RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
            return STATUS_SUCCESS;
#else
            return privateKey.ExportPublicKey(L"ECCPUBLICBLOB", publicKey, publicKeyCapacity, publicKeyLength);
#endif
        }

        _Must_inspect_result_
        NTSTATUS ValidateX25519Lengths(
            const UCHAR* privateKey,
            SIZE_T privateKeyLength,
            const UCHAR* peerPublicKey,
            SIZE_T peerPublicKeyLength,
            UCHAR* sharedSecret,
            SIZE_T sharedSecretCapacity,
            SIZE_T* sharedSecretLength) noexcept
        {
            if (sharedSecretLength != nullptr) {
                *sharedSecretLength = 0;
            }
            if (privateKey == nullptr ||
                privateKeyLength != KeyExchangeX25519KeyLength ||
                peerPublicKey == nullptr ||
                peerPublicKeyLength != KeyExchangeX25519KeyLength ||
                sharedSecret == nullptr ||
                sharedSecretCapacity < KeyExchangeX25519KeyLength ||
                sharedSecretLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }
    }

    void KeyExchangeKeyPair::Reset() noexcept
    {
        RtlSecureZeroMemory(PrivateKey, sizeof(PrivateKey));
        PrivateKeyLength = 0;
        RtlSecureZeroMemory(PublicKey, sizeof(PublicKey));
        PublicKeyLength = 0;
        CngPrivateKey.Close();
        Group = KeyExchangeGroup::Secp256r1;
    }

    bool KeyExchange::IsSupportedGroup(KeyExchangeGroup group) noexcept
    {
        switch (group) {
        case KeyExchangeGroup::Secp256r1:
        case KeyExchangeGroup::Secp384r1:
        case KeyExchangeGroup::Secp521r1:
        case KeyExchangeGroup::X25519:
            return true;
        default:
            return false;
        }
    }

    bool KeyExchange::IsRawKeyShareGroup(KeyExchangeGroup group) noexcept
    {
        return group == KeyExchangeGroup::X25519 || group == KeyExchangeGroup::X448;
    }

    SIZE_T KeyExchange::PublicKeyLength(KeyExchangeGroup group) noexcept
    {
        switch (group) {
        case KeyExchangeGroup::X25519:
            return KeyExchangeX25519KeyLength;
        case KeyExchangeGroup::X448:
            return KeyExchangeX448KeyLength;
        case KeyExchangeGroup::Secp256r1:
            return 65;
        case KeyExchangeGroup::Secp384r1:
            return 97;
        case KeyExchangeGroup::Secp521r1:
            return 133;
        default:
            return 0;
        }
    }

    SIZE_T KeyExchange::SharedSecretLength(KeyExchangeGroup group) noexcept
    {
        switch (group) {
        case KeyExchangeGroup::X25519:
            return KeyExchangeX25519KeyLength;
        case KeyExchangeGroup::X448:
            return KeyExchangeX448KeyLength;
        case KeyExchangeGroup::Secp256r1:
            return 32;
        case KeyExchangeGroup::Secp384r1:
            return 48;
        case KeyExchangeGroup::Secp521r1:
            return 66;
        default:
            return 0;
        }
    }

    NTSTATUS KeyExchange::GenerateKeyPair(
        const CngProviderCache* cache,
        KeyExchangeGroup group,
        KeyExchangeKeyPair& keyPair) noexcept
    {
        keyPair.Reset();
        keyPair.Group = group;

        if (group == KeyExchangeGroup::X25519) {
            NTSTATUS status = CngProvider::GenerateRandom(keyPair.PrivateKey, KeyExchangeX25519KeyLength);
            if (!NT_SUCCESS(status)) {
                keyPair.Reset();
                return status;
            }

            ClampX25519Scalar(keyPair.PrivateKey);
            keyPair.PrivateKeyLength = KeyExchangeX25519KeyLength;
            status = DerivePublicKey(
                group,
                keyPair.PrivateKey,
                keyPair.PrivateKeyLength,
                keyPair.PublicKey,
                sizeof(keyPair.PublicKey),
                &keyPair.PublicKeyLength);
            if (!NT_SUCCESS(status)) {
                keyPair.Reset();
            }
            return status;
        }

        NTSTATUS status = STATUS_SUCCESS;
        const EcCurve curve = ToEcCurve(group, &status);
        if (!NT_SUCCESS(status)) {
            keyPair.Reset();
            return status;
        }

        status = CngProvider::GenerateEcdhKeyPair(cache, curve, keyPair.CngPrivateKey);
        if (NT_SUCCESS(status)) {
            status = ExportNistPublicKey(
                keyPair.CngPrivateKey,
                keyPair.PublicKey,
                sizeof(keyPair.PublicKey),
                &keyPair.PublicKeyLength);
        }
        if (!NT_SUCCESS(status)) {
            keyPair.Reset();
        }
        return status;
    }

    NTSTATUS KeyExchange::DerivePublicKey(
        KeyExchangeGroup group,
        const UCHAR* privateKey,
        SIZE_T privateKeyLength,
        UCHAR* publicKey,
        SIZE_T publicKeyCapacity,
        SIZE_T* publicKeyLength) noexcept
    {
        if (publicKeyLength != nullptr) {
            *publicKeyLength = 0;
        }

        if (group != KeyExchangeGroup::X25519) {
            return STATUS_NOT_SUPPORTED;
        }

        if (privateKey == nullptr ||
            privateKeyLength != KeyExchangeX25519KeyLength ||
            publicKey == nullptr ||
            publicKeyCapacity < KeyExchangeX25519KeyLength ||
            publicKeyLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = X25519(privateKey, X25519BasePoint, publicKey);
        if (NT_SUCCESS(status)) {
            *publicKeyLength = KeyExchangeX25519KeyLength;
        }
        return status;
    }

    NTSTATUS KeyExchange::DeriveSharedSecret(
        KeyExchangeGroup group,
        const UCHAR* privateKey,
        SIZE_T privateKeyLength,
        const UCHAR* peerPublicKey,
        SIZE_T peerPublicKeyLength,
        UCHAR* sharedSecret,
        SIZE_T sharedSecretCapacity,
        SIZE_T* sharedSecretLength) noexcept
    {
        if (group != KeyExchangeGroup::X25519) {
            if (sharedSecretLength != nullptr) {
                *sharedSecretLength = 0;
            }
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS status = ValidateX25519Lengths(
            privateKey,
            privateKeyLength,
            peerPublicKey,
            peerPublicKeyLength,
            sharedSecret,
            sharedSecretCapacity,
            sharedSecretLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = X25519(privateKey, peerPublicKey, sharedSecret);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (IsAllZero(sharedSecret, KeyExchangeX25519KeyLength)) {
            RtlSecureZeroMemory(sharedSecret, sharedSecretCapacity);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        *sharedSecretLength = KeyExchangeX25519KeyLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS KeyExchange::DeriveSharedSecret(
        const CngProviderCache* cache,
        const KeyExchangeKeyPair& keyPair,
        const UCHAR* peerPublicKey,
        SIZE_T peerPublicKeyLength,
        UCHAR* sharedSecret,
        SIZE_T sharedSecretCapacity,
        SIZE_T* sharedSecretLength) noexcept
    {
        if (sharedSecretLength != nullptr) {
            *sharedSecretLength = 0;
        }

        if (!IsValidBuffer(peerPublicKey, peerPublicKeyLength) ||
            sharedSecret == nullptr ||
            sharedSecretLength == nullptr ||
            sharedSecretCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (keyPair.Group == KeyExchangeGroup::X25519) {
            return DeriveSharedSecret(
                keyPair.Group,
                keyPair.PrivateKey,
                keyPair.PrivateKeyLength,
                peerPublicKey,
                peerPublicKeyLength,
                sharedSecret,
                sharedSecretCapacity,
                sharedSecretLength);
        }

        NTSTATUS status = STATUS_SUCCESS;
        const EcCurve curve = ToEcCurve(keyPair.Group, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapObject<CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = CngProvider::ImportEcdhPublicKey(
            cache,
            curve,
            peerPublicKey,
            peerPublicKeyLength,
            *peerKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return CngProvider::DeriveEcdhSecret(
            cache,
            keyPair.CngPrivateKey,
            *peerKey.Get(),
            sharedSecret,
            sharedSecretCapacity,
            sharedSecretLength);
    }

    NTSTATUS KeyExchange::ValidateFiniteFieldPublicKey(
        KeyExchangeGroup group,
        const UCHAR* publicKey,
        SIZE_T publicKeyLength) noexcept
    {
        if (group != KeyExchangeGroup::Ffdhe2048 &&
            group != KeyExchangeGroup::Ffdhe3072 &&
            group != KeyExchangeGroup::Ffdhe4096 &&
            group != KeyExchangeGroup::Ffdhe6144 &&
            group != KeyExchangeGroup::Ffdhe8192) {
            return STATUS_NOT_SUPPORTED;
        }

        if (publicKey == nullptr || publicKeyLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsAllZero(publicKey, publicKeyLength)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        bool greaterThanOne = false;
        for (SIZE_T index = 0; index < publicKeyLength; ++index) {
            if (publicKey[index] > 1 || (publicKey[index] == 1 && index + 1 != publicKeyLength)) {
                greaterThanOne = true;
                break;
            }
        }

        return greaterThanOne ? STATUS_NOT_SUPPORTED : STATUS_INVALID_NETWORK_RESPONSE;
    }
}
}
