#include "crypto/CngProvider.h"

#if !defined(KERNEL_HTTP_USER_MODE_TEST)

namespace KernelHttp
{
namespace crypto
{
    namespace
    {
        constexpr ULONG AesGcmTagLength = 16;

        _Must_inspect_result_
        NTSTATUS ReadDerLength(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Inout_ SIZE_T* offset,
            _Out_ SIZE_T* length) noexcept
        {
            if (data == nullptr || offset == nullptr || length == nullptr || *offset >= dataLength) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR lengthByte = data[*offset];
            ++(*offset);

            if ((lengthByte & 0x80) == 0) {
                *length = lengthByte;
                return STATUS_SUCCESS;
            }

            UCHAR lengthBytes = static_cast<UCHAR>(lengthByte & 0x7f);
            if (lengthBytes == 0 || lengthBytes > sizeof(SIZE_T) || lengthBytes > dataLength - *offset) {
                return STATUS_INVALID_SIGNATURE;
            }

            SIZE_T value = 0;
            for (UCHAR index = 0; index < lengthBytes; ++index) {
                value = (value << 8) | data[*offset + index];
            }

            *offset += lengthBytes;
            *length = value;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS CopyDerIntegerToFixed(
            _In_reads_bytes_(integerLength) const UCHAR* integer,
            SIZE_T integerLength,
            _Out_writes_bytes_(componentLength) UCHAR* component,
            SIZE_T componentLength) noexcept
        {
            if (integer == nullptr || integerLength == 0 || component == nullptr || componentLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            while (integerLength > componentLength && integer[0] == 0) {
                ++integer;
                --integerLength;
            }

            if (integerLength > componentLength) {
                return STATUS_INVALID_SIGNATURE;
            }

            RtlZeroMemory(component, componentLength);
            RtlCopyMemory(component + (componentLength - integerLength), integer, integerLength);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ConvertDerEcdsaSignature(
            _In_reads_bytes_(derLength) const UCHAR* der,
            SIZE_T derLength,
            _Out_writes_bytes_(rawCapacity) UCHAR* raw,
            SIZE_T rawCapacity,
            SIZE_T rawLength) noexcept
        {
            if (der == nullptr || derLength == 0 || raw == nullptr || rawLength == 0 || rawLength > rawCapacity || (rawLength % 2) != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T offset = 0;
            if (der[offset] != 0x30) {
                return STATUS_INVALID_SIGNATURE;
            }
            ++offset;

            SIZE_T sequenceLength = 0;
            NTSTATUS status = ReadDerLength(der, derLength, &offset, &sequenceLength);
            if (!NT_SUCCESS(status) || sequenceLength != derLength - offset) {
                return NT_SUCCESS(status) ? STATUS_INVALID_SIGNATURE : status;
            }

            if (offset >= derLength || der[offset] != 0x02) {
                return STATUS_INVALID_SIGNATURE;
            }
            ++offset;

            SIZE_T rLength = 0;
            status = ReadDerLength(der, derLength, &offset, &rLength);
            if (!NT_SUCCESS(status) || rLength == 0 || rLength > derLength - offset) {
                return NT_SUCCESS(status) ? STATUS_INVALID_SIGNATURE : status;
            }
            const UCHAR* r = der + offset;
            offset += rLength;

            if (offset >= derLength || der[offset] != 0x02) {
                return STATUS_INVALID_SIGNATURE;
            }
            ++offset;

            SIZE_T sLength = 0;
            status = ReadDerLength(der, derLength, &offset, &sLength);
            if (!NT_SUCCESS(status) || sLength == 0 || sLength > derLength - offset) {
                return NT_SUCCESS(status) ? STATUS_INVALID_SIGNATURE : status;
            }
            const UCHAR* s = der + offset;
            offset += sLength;

            if (offset != derLength) {
                return STATUS_INVALID_SIGNATURE;
            }

            const SIZE_T componentLength = rawLength / 2;
            status = CopyDerIntegerToFixed(r, rLength, raw, componentLength);
            if (NT_SUCCESS(status)) {
                status = CopyDerIntegerToFixed(s, sLength, raw + componentLength, componentLength);
            }

            return status;
        }

        _Must_inspect_result_
        SIZE_T EcdsaSignatureLength(SignatureAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case SignatureAlgorithm::EcdsaSha256:
                return 64;
            case SignatureAlgorithm::EcdsaSha384:
                return 96;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        NTSTATUS VerifyEcdsaSignature(
            SignatureAlgorithm algorithm,
            _In_ const CngKey& publicKey,
            _In_reads_bytes_(hashSize) PUCHAR hash,
            ULONG hashSize,
            _In_reads_bytes_(signatureLength) const UCHAR* signature,
            SIZE_T signatureLength) noexcept
        {
            const SIZE_T rawLength = EcdsaSignatureLength(algorithm);
            if (rawLength == 0) {
                return STATUS_NOT_SUPPORTED;
            }

            UCHAR rawSignature[96] = {};
            const UCHAR* signatureToVerify = signature;
            SIZE_T signatureToVerifyLength = signatureLength;

            if (signatureLength != rawLength) {
                NTSTATUS status = ConvertDerEcdsaSignature(signature, signatureLength, rawSignature, sizeof(rawSignature), rawLength);
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(rawSignature, sizeof(rawSignature));
                    return status;
                }

                signatureToVerify = rawSignature;
                signatureToVerifyLength = rawLength;
            }

            NTSTATUS status = STATUS_SUCCESS;
            if (signatureToVerifyLength > MAXULONG) {
                status = STATUS_INTEGER_OVERFLOW;
            }
            ULONG signatureSize = static_cast<ULONG>(signatureToVerifyLength);
            if (NT_SUCCESS(status)) {
                status = BCryptVerifySignature(
                    publicKey.Handle(),
                    nullptr,
                    hash,
                    hashSize,
                    const_cast<PUCHAR>(signatureToVerify),
                    signatureSize,
                    0);
            }

            RtlSecureZeroMemory(rawSignature, sizeof(rawSignature));
            return status;
        }

        _Must_inspect_result_
        ULONG ToUlong(SIZE_T value, _Out_ NTSTATUS* status) noexcept
        {
            if (status == nullptr) {
                return 0;
            }

            if (value > MAXULONG) {
                *status = STATUS_INTEGER_OVERFLOW;
                return 0;
            }

            *status = STATUS_SUCCESS;
            return static_cast<ULONG>(value);
        }

        _Must_inspect_result_
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        bool IsValidMutableBuffer(_Out_writes_bytes_(length) UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Ret_z_
        LPCWSTR HashAlgorithmName(HashAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case HashAlgorithm::Sha256:
                return BCRYPT_SHA256_ALGORITHM;
            case HashAlgorithm::Sha384:
                return BCRYPT_SHA384_ALGORITHM;
            default:
                return nullptr;
            }
        }

        _Ret_z_
        LPCWSTR EcdhAlgorithmName(EcCurve curve) noexcept
        {
            switch (curve) {
            case EcCurve::P256:
                return BCRYPT_ECDH_P256_ALGORITHM;
            case EcCurve::P384:
                return BCRYPT_ECDH_P384_ALGORITHM;
            case EcCurve::P521:
                return BCRYPT_ECDH_P521_ALGORITHM;
            default:
                return nullptr;
            }
        }

        _Must_inspect_result_
        ULONG EcdhKeyLengthBits(EcCurve curve) noexcept
        {
            switch (curve) {
            case EcCurve::P256:
                return 256;
            case EcCurve::P384:
                return 384;
            case EcCurve::P521:
                return 521;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        ULONG EcKeyByteLength(EcCurve curve) noexcept
        {
            switch (curve) {
            case EcCurve::P256:
                return 32;
            case EcCurve::P384:
                return 48;
            case EcCurve::P521:
                return 66;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        ULONG EcdhPublicMagic(EcCurve curve) noexcept
        {
            switch (curve) {
            case EcCurve::P256:
                return BCRYPT_ECDH_PUBLIC_P256_MAGIC;
            case EcCurve::P384:
                return BCRYPT_ECDH_PUBLIC_P384_MAGIC;
            case EcCurve::P521:
                return BCRYPT_ECDH_PUBLIC_P521_MAGIC;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        ULONG EcdsaPublicMagic(EcCurve curve) noexcept
        {
            switch (curve) {
            case EcCurve::P256:
                return BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            case EcCurve::P384:
                return BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
            case EcCurve::P521:
                return BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
            default:
                return 0;
            }
        }

        _Ret_z_
        LPCWSTR EcdsaAlgorithmName(EcCurve curve) noexcept
        {
            switch (curve) {
            case EcCurve::P256:
                return BCRYPT_ECDSA_P256_ALGORITHM;
            case EcCurve::P384:
                return BCRYPT_ECDSA_P384_ALGORITHM;
            case EcCurve::P521:
                return BCRYPT_ECDSA_P521_ALGORITHM;
            default:
                return nullptr;
            }
        }

        _Must_inspect_result_
        NTSTATUS GetDwordProperty(
            _In_ BCRYPT_HANDLE handle,
            _In_ LPCWSTR property,
            _Out_ ULONG* value) noexcept
        {
            if (value == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            ULONG resultLength = 0;
            return BCryptGetProperty(
                handle,
                property,
                reinterpret_cast<PUCHAR>(value),
                sizeof(*value),
                &resultLength,
                0);
        }

        _Must_inspect_result_
        NTSTATUS CreateHash(
            _In_ BCRYPT_ALG_HANDLE algorithm,
            _In_reads_bytes_opt_(secretLength) UCHAR* secret,
            ULONG secretLength,
            _Out_ BCRYPT_HASH_HANDLE* hash,
            _Outptr_result_bytebuffer_(*objectLength) UCHAR** object,
            _Out_ ULONG* objectLength) noexcept
        {
            if (hash == nullptr || object == nullptr || objectLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *hash = nullptr;
            *object = nullptr;
            *objectLength = 0;

            NTSTATUS status = GetDwordProperty(algorithm, BCRYPT_OBJECT_LENGTH, objectLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *object = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, *objectLength, PoolTag));
            if (*object == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = BCryptCreateHash(
                algorithm,
                hash,
                *object,
                *objectLength,
                secret,
                secretLength,
                0);

            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(*object, PoolTag);
                *object = nullptr;
                *objectLength = 0;
            }

            return status;
        }

        _Must_inspect_result_
        NTSTATUS SetAesGcmMode(_In_ BCRYPT_ALG_HANDLE algorithm) noexcept
        {
            return BCryptSetProperty(
                algorithm,
                BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                sizeof(BCRYPT_CHAIN_MODE_GCM),
                0);
        }

        _Must_inspect_result_
        NTSTATUS ImportSymmetricKey(
            _In_ BCRYPT_ALG_HANDLE algorithm,
            _In_ const AesGcmKey& key,
            _Out_ BCRYPT_KEY_HANDLE* keyHandle,
            _Outptr_result_bytebuffer_(*keyObjectLength) UCHAR** keyObject,
            _Out_ ULONG* keyObjectLength) noexcept
        {
            if (keyHandle == nullptr || keyObject == nullptr || keyObjectLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *keyHandle = nullptr;
            *keyObject = nullptr;
            *keyObjectLength = 0;

            if (!IsValidBuffer(key.Key, key.KeyLength) || key.KeyLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = GetDwordProperty(algorithm, BCRYPT_OBJECT_LENGTH, keyObjectLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *keyObject = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, *keyObjectLength, PoolTag));
            if (*keyObject == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ULONG keyLength = ToUlong(key.KeyLength, &status);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(*keyObject, PoolTag);
                *keyObject = nullptr;
                *keyObjectLength = 0;
                return status;
            }

            status = BCryptGenerateSymmetricKey(
                algorithm,
                keyHandle,
                *keyObject,
                *keyObjectLength,
                const_cast<PUCHAR>(key.Key),
                keyLength,
                0);

            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(*keyObject, PoolTag);
                *keyObject = nullptr;
                *keyObjectLength = 0;
            }

            return status;
        }

        _Must_inspect_result_
        NTSTATUS ImportEcPublicKey(
            EcCurve curve,
            ULONG magic,
            LPCWSTR algorithmName,
            const UCHAR* uncompressedPoint,
            SIZE_T pointLength,
            CngKey& publicKey) noexcept
        {
            const ULONG keyBytes = EcKeyByteLength(curve);
            if (keyBytes == 0 || magic == 0 || algorithmName == nullptr) {
                return STATUS_NOT_SUPPORTED;
            }

            if (uncompressedPoint == nullptr ||
                pointLength != (static_cast<SIZE_T>(keyBytes) * 2) + 1 ||
                uncompressedPoint[0] != 4) {
                return STATUS_INVALID_PARAMETER;
            }

            CngAlgorithmProvider provider;
            NTSTATUS status = provider.Open(algorithmName);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            UCHAR blob[sizeof(BCRYPT_ECCKEY_BLOB) + (66 * 2)] = {};
            auto* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob);
            header->dwMagic = magic;
            header->cbKey = keyBytes;
            RtlCopyMemory(blob + sizeof(BCRYPT_ECCKEY_BLOB), uncompressedPoint + 1, keyBytes * 2);

            status = publicKey.ImportPublicKey(
                provider,
                BCRYPT_ECCPUBLIC_BLOB,
                blob,
                sizeof(BCRYPT_ECCKEY_BLOB) + (keyBytes * 2));

            RtlSecureZeroMemory(blob, sizeof(blob));
            return status;
        }
    }

    CngAlgorithmProvider::~CngAlgorithmProvider() noexcept
    {
        Close();
    }

    NTSTATUS CngAlgorithmProvider::Open(LPCWSTR algorithm, ULONG flags) noexcept
    {
        if (algorithm == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        Close();
        return BCryptOpenAlgorithmProvider(
            &handle_,
            algorithm,
            nullptr,
            flags);
    }

    void CngAlgorithmProvider::Close() noexcept
    {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
            handle_ = nullptr;
        }
    }

    bool CngAlgorithmProvider::IsOpen() const noexcept
    {
        return handle_ != nullptr;
    }

    BCRYPT_ALG_HANDLE CngAlgorithmProvider::Handle() const noexcept
    {
        return handle_;
    }

    CngKey::~CngKey() noexcept
    {
        Close();
    }

    NTSTATUS CngKey::ImportPublicKey(
        CngAlgorithmProvider& provider,
        LPCWSTR blobType,
        const UCHAR* blob,
        SIZE_T blobLength) noexcept
    {
        if (!provider.IsOpen() ||
            blobType == nullptr ||
            blob == nullptr ||
            blobLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        ULONG blobSize = ToUlong(blobLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        Close();
        return BCryptImportKeyPair(
            provider.Handle(),
            nullptr,
            blobType,
            &handle_,
            const_cast<PUCHAR>(blob),
            blobSize,
            0);
    }

    NTSTATUS CngKey::ExportPublicKey(
        LPCWSTR blobType,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) const noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (handle_ == nullptr || blobType == nullptr ||
            (destination == nullptr && destinationCapacity != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        ULONG destinationSize = ToUlong(destinationCapacity, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG written = 0;
        status = BCryptExportKey(
            handle_,
            nullptr,
            blobType,
            destination,
            destinationSize,
            &written,
            0);

        if (bytesWritten != nullptr) {
            *bytesWritten = written;
        }

        return status;
    }

    void CngKey::Close() noexcept
    {
        if (handle_ != nullptr) {
            BCryptDestroyKey(handle_);
            handle_ = nullptr;
        }
    }

    bool CngKey::IsOpen() const noexcept
    {
        return handle_ != nullptr;
    }

    BCRYPT_KEY_HANDLE CngKey::Handle() const noexcept
    {
        return handle_;
    }

    void CngKey::Adopt(BCRYPT_KEY_HANDLE handle) noexcept
    {
        Close();
        handle_ = handle;
    }

    CngHashContext::~CngHashContext() noexcept
    {
        Reset();
    }

    NTSTATUS CngHashContext::Initialize(HashAlgorithm algorithm) noexcept
    {
        Reset();

        LPCWSTR algorithmName = HashAlgorithmName(algorithm);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS status = provider_.Open(algorithmName);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = CreateHash(provider_.Handle(), nullptr, 0, &hash_, &hashObject_, &hashObjectLength_);
        if (!NT_SUCCESS(status)) {
            Reset();
            return status;
        }

        algorithm_ = algorithm;
        initialized_ = true;
        return STATUS_SUCCESS;
    }

    void CngHashContext::Reset() noexcept
    {
        if (hash_ != nullptr) {
            BCryptDestroyHash(hash_);
            hash_ = nullptr;
        }

        if (hashObject_ != nullptr) {
            RtlSecureZeroMemory(hashObject_, hashObjectLength_);
            ExFreePoolWithTag(hashObject_, PoolTag);
            hashObject_ = nullptr;
            hashObjectLength_ = 0;
        }

        provider_.Close();
        initialized_ = false;
    }

    NTSTATUS CngHashContext::Update(const UCHAR* data, SIZE_T dataLength) noexcept
    {
        if (!initialized_ || hash_ == nullptr || !IsValidBuffer(data, dataLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        ULONG dataSize = ToUlong(dataLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return BCryptHashData(hash_, const_cast<PUCHAR>(data), dataSize, 0);
    }

    NTSTATUS CngHashContext::Finish(UCHAR* output, SIZE_T outputLength, SIZE_T* bytesWritten) const noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!initialized_ || hash_ == nullptr || output == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG hashLength = 0;
        NTSTATUS status = GetDwordProperty(provider_.Handle(), BCRYPT_HASH_LENGTH, &hashLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (outputLength < hashLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG duplicateObjectLength = hashObjectLength_;
        UCHAR* duplicateObject = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, duplicateObjectLength, PoolTag));
        if (duplicateObject == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BCRYPT_HASH_HANDLE duplicateHash = nullptr;
        status = BCryptDuplicateHash(
            hash_,
            &duplicateHash,
            duplicateObject,
            duplicateObjectLength,
            0);
        if (NT_SUCCESS(status)) {
            status = BCryptFinishHash(duplicateHash, output, hashLength, 0);
            BCryptDestroyHash(duplicateHash);
        }

        RtlSecureZeroMemory(duplicateObject, duplicateObjectLength);
        ExFreePoolWithTag(duplicateObject, PoolTag);

        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = hashLength;
        }

        return status;
    }

    bool CngHashContext::IsInitialized() const noexcept
    {
        return initialized_;
    }

    NTSTATUS CngProvider::GenerateRandom(UCHAR* output, SIZE_T outputLength) noexcept
    {
        if (!IsValidMutableBuffer(output, outputLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        ULONG outputSize = ToUlong(outputLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return BCryptGenRandom(nullptr, output, outputSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }

    NTSTATUS CngProvider::Hash(
        HashAlgorithm algorithm,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!IsValidBuffer(data, dataLength) ||
            !IsValidMutableBuffer(output, outputLength) ||
            outputLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        LPCWSTR algorithmName = HashAlgorithmName(algorithm);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        CngAlgorithmProvider provider;
        NTSTATUS status = provider.Open(algorithmName);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG hashLength = 0;
        status = GetDwordProperty(provider.Handle(), BCRYPT_HASH_LENGTH, &hashLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (outputLength < hashLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        BCRYPT_HASH_HANDLE hash = nullptr;
        UCHAR* hashObject = nullptr;
        ULONG hashObjectLength = 0;

        status = CreateHash(provider.Handle(), nullptr, 0, &hash, &hashObject, &hashObjectLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG dataSize = ToUlong(dataLength, &status);
        if (NT_SUCCESS(status)) {
            status = BCryptHashData(hash, const_cast<PUCHAR>(data), dataSize, 0);
        }

        if (NT_SUCCESS(status)) {
            status = BCryptFinishHash(hash, output, hashLength, 0);
        }

        BCryptDestroyHash(hash);
        ExFreePoolWithTag(hashObject, PoolTag);

        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = hashLength;
        }

        return status;
    }

    NTSTATUS CngProvider::Hmac(
        HashAlgorithm algorithm,
        const UCHAR* key,
        SIZE_T keyLength,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!IsValidBuffer(key, keyLength) ||
            !IsValidBuffer(data, dataLength) ||
            !IsValidMutableBuffer(output, outputLength) ||
            keyLength == 0 ||
            outputLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        LPCWSTR algorithmName = HashAlgorithmName(algorithm);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        CngAlgorithmProvider provider;
        NTSTATUS status = provider.Open(algorithmName, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG hashLength = 0;
        status = GetDwordProperty(provider.Handle(), BCRYPT_HASH_LENGTH, &hashLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (outputLength < hashLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG keySize = ToUlong(keyLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_HASH_HANDLE hash = nullptr;
        UCHAR* hashObject = nullptr;
        ULONG hashObjectLength = 0;

        status = CreateHash(provider.Handle(), const_cast<PUCHAR>(key), keySize, &hash, &hashObject, &hashObjectLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG dataSize = ToUlong(dataLength, &status);
        if (NT_SUCCESS(status)) {
            status = BCryptHashData(hash, const_cast<PUCHAR>(data), dataSize, 0);
        }

        if (NT_SUCCESS(status)) {
            status = BCryptFinishHash(hash, output, hashLength, 0);
        }

        BCryptDestroyHash(hash);
        ExFreePoolWithTag(hashObject, PoolTag);

        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = hashLength;
        }

        return status;
    }

    NTSTATUS CngProvider::AesGcmEncrypt(
        const AesGcmKey& key,
        const AesGcmParameters& parameters,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* tag,
        SIZE_T tagLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!IsValidBuffer(plaintext, plaintextLength) ||
            !IsValidMutableBuffer(ciphertext, ciphertextLength) ||
            !IsValidMutableBuffer(tag, tagLength) ||
            !IsValidBuffer(parameters.Nonce.Data, parameters.Nonce.Length) ||
            !IsValidBuffer(parameters.Aad.Data, parameters.Aad.Length) ||
            ciphertextLength < plaintextLength ||
            tagLength != AesGcmTagLength ||
            parameters.Nonce.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        CngAlgorithmProvider provider;
        NTSTATUS status = provider.Open(BCRYPT_AES_ALGORITHM);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SetAesGcmMode(provider.Handle());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        UCHAR* keyObject = nullptr;
        ULONG keyObjectLength = 0;

        status = ImportSymmetricKey(provider.Handle(), key, &keyHandle, &keyObject, &keyObjectLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(parameters.Nonce.Data);
        authInfo.cbNonce = static_cast<ULONG>(parameters.Nonce.Length);
        authInfo.pbAuthData = const_cast<PUCHAR>(parameters.Aad.Data);
        authInfo.cbAuthData = static_cast<ULONG>(parameters.Aad.Length);
        authInfo.pbTag = tag;
        authInfo.cbTag = static_cast<ULONG>(tagLength);

        ULONG written = 0;
        status = BCryptEncrypt(
            keyHandle,
            const_cast<PUCHAR>(plaintext),
            static_cast<ULONG>(plaintextLength),
            &authInfo,
            nullptr,
            0,
            ciphertext,
            static_cast<ULONG>(ciphertextLength),
            &written,
            0);

        BCryptDestroyKey(keyHandle);
        ExFreePoolWithTag(keyObject, PoolTag);

        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = written;
        }

        return status;
    }

    NTSTATUS CngProvider::AesGcmDecrypt(
        const AesGcmKey& key,
        const AesGcmParameters& parameters,
        const UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* plaintext,
        SIZE_T plaintextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!IsValidBuffer(ciphertext, ciphertextLength) ||
            !IsValidMutableBuffer(plaintext, plaintextLength) ||
            !IsValidBuffer(parameters.Nonce.Data, parameters.Nonce.Length) ||
            !IsValidBuffer(parameters.Aad.Data, parameters.Aad.Length) ||
            !IsValidBuffer(parameters.Tag.Data, parameters.Tag.Length) ||
            plaintextLength < ciphertextLength ||
            parameters.Tag.Length != AesGcmTagLength ||
            parameters.Nonce.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        CngAlgorithmProvider provider;
        NTSTATUS status = provider.Open(BCRYPT_AES_ALGORITHM);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SetAesGcmMode(provider.Handle());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        UCHAR* keyObject = nullptr;
        ULONG keyObjectLength = 0;

        status = ImportSymmetricKey(provider.Handle(), key, &keyHandle, &keyObject, &keyObjectLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(parameters.Nonce.Data);
        authInfo.cbNonce = static_cast<ULONG>(parameters.Nonce.Length);
        authInfo.pbAuthData = const_cast<PUCHAR>(parameters.Aad.Data);
        authInfo.cbAuthData = static_cast<ULONG>(parameters.Aad.Length);
        authInfo.pbTag = const_cast<PUCHAR>(parameters.Tag.Data);
        authInfo.cbTag = static_cast<ULONG>(parameters.Tag.Length);

        ULONG written = 0;
        status = BCryptDecrypt(
            keyHandle,
            const_cast<PUCHAR>(ciphertext),
            static_cast<ULONG>(ciphertextLength),
            &authInfo,
            nullptr,
            0,
            plaintext,
            static_cast<ULONG>(plaintextLength),
            &written,
            0);

        BCryptDestroyKey(keyHandle);
        ExFreePoolWithTag(keyObject, PoolTag);

        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = written;
        }

        return status;
    }

    NTSTATUS CngProvider::VerifySignature(
        SignatureAlgorithm algorithm,
        const CngKey& publicKey,
        const UCHAR* hash,
        SIZE_T hashLength,
        const UCHAR* signature,
        SIZE_T signatureLength) noexcept
    {
        if (!publicKey.IsOpen() ||
            !IsValidBuffer(hash, hashLength) ||
            !IsValidBuffer(signature, signatureLength) ||
            hashLength == 0 ||
            signatureLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        ULONG hashSize = ToUlong(hashLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG signatureSize = ToUlong(signatureLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_PKCS1_PADDING_INFO pkcs1 = {};
        VOID* paddingInfo = nullptr;
        ULONG flags = 0;

        switch (algorithm) {
        case SignatureAlgorithm::RsaPkcs1Sha256:
            pkcs1.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            paddingInfo = &pkcs1;
            flags = BCRYPT_PAD_PKCS1;
            break;
        case SignatureAlgorithm::RsaPkcs1Sha384:
            pkcs1.pszAlgId = BCRYPT_SHA384_ALGORITHM;
            paddingInfo = &pkcs1;
            flags = BCRYPT_PAD_PKCS1;
            break;
        case SignatureAlgorithm::EcdsaSha256:
        case SignatureAlgorithm::EcdsaSha384:
            return VerifyEcdsaSignature(
                algorithm,
                publicKey,
                const_cast<PUCHAR>(hash),
                hashSize,
                signature,
                signatureLength);
        default:
            return STATUS_NOT_SUPPORTED;
        }

        return BCryptVerifySignature(
            publicKey.Handle(),
            paddingInfo,
            const_cast<PUCHAR>(hash),
            hashSize,
            const_cast<PUCHAR>(signature),
            signatureSize,
            flags);
    }

    NTSTATUS CngProvider::GenerateEcdhKeyPair(EcCurve curve, CngKey& privateKey) noexcept
    {
        LPCWSTR algorithmName = EcdhAlgorithmName(curve);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        CngAlgorithmProvider provider;
        NTSTATUS status = provider.Open(algorithmName);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        const ULONG keyLengthBits = EcdhKeyLengthBits(curve);
        if (keyLengthBits == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        status = BCryptGenerateKeyPair(provider.Handle(), &keyHandle, keyLengthBits, 0);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BCryptFinalizeKeyPair(keyHandle, 0);
        if (!NT_SUCCESS(status)) {
            BCryptDestroyKey(keyHandle);
            return status;
        }

        privateKey.Adopt(keyHandle);
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::ImportEcdhPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        return ImportEcPublicKey(
            curve,
            EcdhPublicMagic(curve),
            EcdhAlgorithmName(curve),
            uncompressedPoint,
            pointLength,
            publicKey);
    }

    NTSTATUS CngProvider::ImportEcdsaPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        return ImportEcPublicKey(
            curve,
            EcdsaPublicMagic(curve),
            EcdsaAlgorithmName(curve),
            uncompressedPoint,
            pointLength,
            publicKey);
    }

    NTSTATUS CngProvider::ImportRsaPublicKey(
        const UCHAR* exponent,
        SIZE_T exponentLength,
        const UCHAR* modulus,
        SIZE_T modulusLength,
        CngKey& publicKey) noexcept
    {
        if (exponent == nullptr ||
            exponentLength == 0 ||
            modulus == nullptr ||
            modulusLength == 0 ||
            exponentLength > MAXULONG ||
            modulusLength > MAXULONG) {
            return STATUS_INVALID_PARAMETER;
        }

        CngAlgorithmProvider provider;
        NTSTATUS status = provider.Open(BCRYPT_RSA_ALGORITHM);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T blobLength = sizeof(BCRYPT_RSAKEY_BLOB) + exponentLength + modulusLength;
        if (blobLength > MAXULONG) {
            return STATUS_INTEGER_OVERFLOW;
        }

        UCHAR* blob = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, blobLength, PoolTag));
        if (blob == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        auto* header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob);
        header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        header->BitLength = static_cast<ULONG>(modulusLength * 8);
        header->cbPublicExp = static_cast<ULONG>(exponentLength);
        header->cbModulus = static_cast<ULONG>(modulusLength);
        header->cbPrime1 = 0;
        header->cbPrime2 = 0;

        RtlCopyMemory(blob + sizeof(BCRYPT_RSAKEY_BLOB), exponent, exponentLength);
        RtlCopyMemory(blob + sizeof(BCRYPT_RSAKEY_BLOB) + exponentLength, modulus, modulusLength);

        status = publicKey.ImportPublicKey(provider, BCRYPT_RSAPUBLIC_BLOB, blob, blobLength);
        RtlSecureZeroMemory(blob, blobLength);
        ExFreePoolWithTag(blob, PoolTag);
        return status;
    }

    NTSTATUS CngProvider::DeriveEcdhSecret(
        const CngKey& privateKey,
        const CngKey& peerPublicKey,
        UCHAR* secret,
        SIZE_T secretLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!privateKey.IsOpen() ||
            !peerPublicKey.IsOpen() ||
            !IsValidMutableBuffer(secret, secretLength) ||
            secretLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        BCRYPT_SECRET_HANDLE agreement = nullptr;
        NTSTATUS status = BCryptSecretAgreement(privateKey.Handle(), peerPublicKey.Handle(), &agreement, 0);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG resultLength = 0;
        status = BCryptDeriveKey(
            agreement,
            BCRYPT_KDF_RAW_SECRET,
            nullptr,
            secret,
            static_cast<ULONG>(secretLength),
            &resultLength,
            0);

        BCryptDestroySecret(agreement);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        // BCRYPT_KDF_RAW_SECRET returns the shared secret in little-endian byte order.
        // TLS requires big-endian (network byte order), so reverse the bytes in-place.
        for (ULONG i = 0; i < resultLength / 2; ++i) {
            const UCHAR temp = secret[i];
            secret[i] = secret[resultLength - 1 - i];
            secret[resultLength - 1 - i] = temp;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = resultLength;
        }

        return status;
    }
}
}

#else

namespace KernelHttp
{
namespace crypto
{
    CngAlgorithmProvider::~CngAlgorithmProvider() noexcept
    {
        Close();
    }

    NTSTATUS CngAlgorithmProvider::Open(LPCWSTR algorithm, ULONG flags) noexcept
    {
        (void)algorithm;
        (void)flags;
        handle_ = this;
        return STATUS_SUCCESS;
    }

    void CngAlgorithmProvider::Close() noexcept
    {
        handle_ = nullptr;
    }

    bool CngAlgorithmProvider::IsOpen() const noexcept
    {
        return handle_ != nullptr;
    }

    CngKey::~CngKey() noexcept
    {
        Close();
    }

    NTSTATUS CngKey::ImportPublicKey(
        CngAlgorithmProvider& provider,
        LPCWSTR blobType,
        const UCHAR* blob,
        SIZE_T blobLength) noexcept
    {
        (void)blobType;

        if (!provider.IsOpen() || blob == nullptr || blobLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        handle_ = this;
        return STATUS_SUCCESS;
    }

    NTSTATUS CngKey::ExportPublicKey(
        LPCWSTR blobType,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) const noexcept
    {
        (void)blobType;

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (handle_ == nullptr || (destination == nullptr && destinationCapacity != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (destinationCapacity < 65) {
            if (bytesWritten != nullptr) {
                *bytesWritten = 65;
            }

            return STATUS_BUFFER_TOO_SMALL;
        }

        destination[0] = 4;
        for (SIZE_T index = 1; index < 65; ++index) {
            destination[index] = static_cast<UCHAR>(index);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = 65;
        }

        return STATUS_SUCCESS;
    }

    void CngKey::Close() noexcept
    {
        handle_ = nullptr;
    }

    bool CngKey::IsOpen() const noexcept
    {
        return handle_ != nullptr;
    }

    void CngKey::Adopt(void* handle) noexcept
    {
        Close();
        handle_ = handle;
    }

    CngHashContext::~CngHashContext() noexcept
    {
        Reset();
    }

    NTSTATUS CngHashContext::Initialize(HashAlgorithm algorithm) noexcept
    {
        Reset();
        algorithm_ = algorithm;
        initialized_ = true;
        return STATUS_SUCCESS;
    }

    void CngHashContext::Reset() noexcept
    {
        RtlSecureZeroMemory(state_, sizeof(state_));
        stateLength_ = 0;
        initialized_ = false;
    }

    NTSTATUS CngHashContext::Update(const UCHAR* data, SIZE_T dataLength) noexcept
    {
        if (!initialized_ || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < dataLength; ++index) {
            state_[index % sizeof(state_)] = static_cast<UCHAR>(
                state_[index % sizeof(state_)] ^ data[index] ^ static_cast<UCHAR>(index));
        }

        stateLength_ = algorithm_ == HashAlgorithm::Sha384 ? 48 : 32;
        return STATUS_SUCCESS;
    }

    NTSTATUS CngHashContext::Finish(UCHAR* output, SIZE_T outputLength, SIZE_T* bytesWritten) const noexcept
    {
        const SIZE_T required = algorithm_ == HashAlgorithm::Sha384 ? 48 : 32;

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!initialized_ || output == nullptr || outputLength < required) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        for (SIZE_T index = 0; index < required; ++index) {
            output[index] = static_cast<UCHAR>(state_[index] ^ static_cast<UCHAR>(index));
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = required;
        }

        return STATUS_SUCCESS;
    }

    bool CngHashContext::IsInitialized() const noexcept
    {
        return initialized_;
    }

    NTSTATUS CngProvider::GenerateRandom(UCHAR* output, SIZE_T outputLength) noexcept
    {
        if (output == nullptr && outputLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < outputLength; ++index) {
            output[index] = static_cast<UCHAR>((index * 29U) + 17U);
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::Hash(
        HashAlgorithm algorithm,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        (void)algorithm;
        (void)data;
        (void)dataLength;

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (output == nullptr || outputLength < 32) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        for (SIZE_T index = 0; index < 32; ++index) {
            output[index] = static_cast<UCHAR>(index);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = 32;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::Hmac(
        HashAlgorithm algorithm,
        const UCHAR* key,
        SIZE_T keyLength,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        return Hash(algorithm, key != nullptr ? key : data, keyLength + dataLength, output, outputLength, bytesWritten);
    }

    NTSTATUS CngProvider::AesGcmEncrypt(
        const AesGcmKey& key,
        const AesGcmParameters& parameters,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* tag,
        SIZE_T tagLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (key.Key == nullptr ||
            key.KeyLength == 0 ||
            parameters.Nonce.Data == nullptr ||
            parameters.Nonce.Length == 0 ||
            plaintext == nullptr ||
            ciphertext == nullptr ||
            tag == nullptr ||
            ciphertextLength < plaintextLength ||
            tagLength != 16) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < plaintextLength; ++index) {
            ciphertext[index] = static_cast<UCHAR>(plaintext[index] ^ key.Key[index % key.KeyLength]);
        }

        for (SIZE_T index = 0; index < tagLength; ++index) {
            tag[index] = static_cast<UCHAR>(0xA0U + index);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = plaintextLength;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::AesGcmDecrypt(
        const AesGcmKey& key,
        const AesGcmParameters& parameters,
        const UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* plaintext,
        SIZE_T plaintextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (key.Key == nullptr ||
            key.KeyLength == 0 ||
            parameters.Nonce.Data == nullptr ||
            parameters.Nonce.Length == 0 ||
            parameters.Tag.Data == nullptr ||
            parameters.Tag.Length != 16 ||
            ciphertext == nullptr ||
            plaintext == nullptr ||
            plaintextLength < ciphertextLength) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < ciphertextLength; ++index) {
            plaintext[index] = static_cast<UCHAR>(ciphertext[index] ^ key.Key[index % key.KeyLength]);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = ciphertextLength;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::VerifySignature(
        SignatureAlgorithm algorithm,
        const CngKey& publicKey,
        const UCHAR* hash,
        SIZE_T hashLength,
        const UCHAR* signature,
        SIZE_T signatureLength) noexcept
    {
        (void)algorithm;
        (void)publicKey;

        if (hash == nullptr || hashLength == 0 || signature == nullptr || signatureLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::GenerateEcdhKeyPair(EcCurve curve, CngKey& privateKey) noexcept
    {
        (void)curve;
        privateKey.Adopt(&privateKey);
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::ImportEcdhPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        (void)curve;

        if (uncompressedPoint == nullptr || pointLength == 0 || uncompressedPoint[0] != 4) {
            return STATUS_INVALID_PARAMETER;
        }

        publicKey.Adopt(&publicKey);
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::ImportEcdsaPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        return ImportEcdhPublicKey(curve, uncompressedPoint, pointLength, publicKey);
    }

    NTSTATUS CngProvider::ImportRsaPublicKey(
        const UCHAR* exponent,
        SIZE_T exponentLength,
        const UCHAR* modulus,
        SIZE_T modulusLength,
        CngKey& publicKey) noexcept
    {
        if (exponent == nullptr || exponentLength == 0 || modulus == nullptr || modulusLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        publicKey.Adopt(&publicKey);
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::DeriveEcdhSecret(
        const CngKey& privateKey,
        const CngKey& peerPublicKey,
        UCHAR* secret,
        SIZE_T secretLength,
        SIZE_T* bytesWritten) noexcept
    {
        (void)privateKey;
        (void)peerPublicKey;

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (secret == nullptr || secretLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < secretLength; ++index) {
            secret[index] = static_cast<UCHAR>(0xC0U + index);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = secretLength;
        }

        return STATUS_SUCCESS;
    }
}
}

#endif
