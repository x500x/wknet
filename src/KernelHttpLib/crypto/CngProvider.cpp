#include <KernelHttp/crypto/CngProvider.h>
#include <KernelHttp/crypto/CngProviderCache.h>

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
            case SignatureAlgorithm::EcdsaSha512:
                return 132;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        NTSTATUS GetDwordProperty(
            _In_ BCRYPT_HANDLE handle,
            _In_ LPCWSTR property,
            _Out_ ULONG* value) noexcept;

        _Must_inspect_result_
        NTSTATUS EcdsaSignatureLengthForSha1(
            _In_ const CngKey& publicKey,
            _Out_ SIZE_T* signatureLength) noexcept
        {
            if (signatureLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *signatureLength = 0;
            ULONG keyBits = 0;
            NTSTATUS status = GetDwordProperty(publicKey.Handle(), BCRYPT_KEY_LENGTH, &keyBits);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            switch (keyBits) {
            case 256:
                *signatureLength = 64;
                return STATUS_SUCCESS;
            case 384:
                *signatureLength = 96;
                return STATUS_SUCCESS;
            case 521:
                *signatureLength = 132;
                return STATUS_SUCCESS;
            default:
                return STATUS_NOT_SUPPORTED;
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
            SIZE_T rawLength = EcdsaSignatureLength(algorithm);
            if (algorithm == SignatureAlgorithm::EcdsaSha1) {
                NTSTATUS status = EcdsaSignatureLengthForSha1(publicKey, &rawLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            if (rawLength == 0) {
                return STATUS_NOT_SUPPORTED;
            }

            HeapArray<UCHAR> rawSignature(132);
            if (!rawSignature.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            const UCHAR* signatureToVerify = signature;
            SIZE_T signatureToVerifyLength = signatureLength;

            if (signatureLength != rawLength) {
                NTSTATUS status = ConvertDerEcdsaSignature(
                    signature,
                    signatureLength,
                    rawSignature.Get(),
                    rawSignature.Count(),
                    rawLength);
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(rawSignature.Get(), rawSignature.Count());
                    return status;
                }

                signatureToVerify = rawSignature.Get();
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

            RtlSecureZeroMemory(rawSignature.Get(), rawSignature.Count());
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

        _Must_inspect_result_
        NTSTATUS RequirePassiveLevel() noexcept
        {
            return KeGetCurrentIrql() == PASSIVE_LEVEL ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
        }

        _Ret_z_
        LPCWSTR HashAlgorithmName(HashAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case HashAlgorithm::Sha1:
                return BCRYPT_SHA1_ALGORITHM;
            case HashAlgorithm::Sha256:
                return BCRYPT_SHA256_ALGORITHM;
            case HashAlgorithm::Sha384:
                return BCRYPT_SHA384_ALGORITHM;
            case HashAlgorithm::Sha512:
                return BCRYPT_SHA512_ALGORITHM;
            default:
                return nullptr;
            }
        }

        _Must_inspect_result_
        SIZE_T HashDigestLength(HashAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case HashAlgorithm::Sha1:
                return 20;
            case HashAlgorithm::Sha256:
                return 32;
            case HashAlgorithm::Sha384:
                return 48;
            case HashAlgorithm::Sha512:
                return 64;
            default:
                return 0;
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
            _In_opt_ const CngProviderCache* cache,
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

            HeapObject<CngAlgorithmProvider> provider;
            if (!provider.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            const CngAlgorithmProvider* providerToUse = nullptr;
            if (cache != nullptr) {
                providerToUse = magic == EcdhPublicMagic(curve) ? cache->Ecdh(curve) : cache->Ecdsa(curve);
                if (providerToUse != nullptr) {
                    cache->MarkProviderUsed();
                }
            }

            NTSTATUS status = STATUS_SUCCESS;
            if (providerToUse == nullptr) {
                status = provider->Open(algorithmName);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                providerToUse = provider.Get();
            }

            HeapArray<UCHAR> blob(sizeof(BCRYPT_ECCKEY_BLOB) + (66 * 2));
            if (!blob.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            auto* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.Get());
            header->dwMagic = magic;
            header->cbKey = keyBytes;
            RtlCopyMemory(blob.Get() + sizeof(BCRYPT_ECCKEY_BLOB), uncompressedPoint + 1, keyBytes * 2);

            status = publicKey.ImportPublicKey(
                *providerToUse,
                BCRYPT_ECCPUBLIC_BLOB,
                blob.Get(),
                sizeof(BCRYPT_ECCKEY_BLOB) + (keyBytes * 2));

            RtlSecureZeroMemory(blob.Get(), blob.Count());
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
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
        const CngAlgorithmProvider& provider,
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

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
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        Reset();

        LPCWSTR algorithmName = HashAlgorithmName(algorithm);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = provider_.Open(algorithmName);
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG hashLength = 0;
        status = GetDwordProperty(provider_.Handle(), BCRYPT_HASH_LENGTH, &hashLength);
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG outputSize = ToUlong(outputLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return BCryptGenRandom(nullptr, output, outputSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }

    NTSTATUS CngProvider::Hash(
        const CngProviderCache* cache,
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        LPCWSTR algorithmName = HashAlgorithmName(algorithm);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        HeapObject<CngAlgorithmProvider> provider;
        if (!provider.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const CngAlgorithmProvider* providerToUse = cache != nullptr ? cache->Hash(algorithm) : nullptr;
        if (providerToUse != nullptr) {
            cache->MarkProviderUsed();
        }

        status = STATUS_SUCCESS;
        if (providerToUse == nullptr) {
            status = provider->Open(algorithmName);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            providerToUse = provider.Get();
        }

        ULONG hashLength = 0;
        status = GetDwordProperty(providerToUse->Handle(), BCRYPT_HASH_LENGTH, &hashLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (outputLength < hashLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        BCRYPT_HASH_HANDLE hash = nullptr;
        UCHAR* hashObject = nullptr;
        ULONG hashObjectLength = 0;

        status = CreateHash(providerToUse->Handle(), nullptr, 0, &hash, &hashObject, &hashObjectLength);
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
        const CngProviderCache* cache,
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        LPCWSTR algorithmName = HashAlgorithmName(algorithm);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        HeapObject<CngAlgorithmProvider> provider;
        if (!provider.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const CngAlgorithmProvider* providerToUse = cache != nullptr ? cache->Hmac(algorithm) : nullptr;
        if (providerToUse != nullptr) {
            cache->MarkProviderUsed();
        }

        status = STATUS_SUCCESS;
        if (providerToUse == nullptr) {
            status = provider->Open(algorithmName, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            providerToUse = provider.Get();
        }

        ULONG hashLength = 0;
        status = GetDwordProperty(providerToUse->Handle(), BCRYPT_HASH_LENGTH, &hashLength);
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

        status = CreateHash(providerToUse->Handle(), const_cast<PUCHAR>(key), keySize, &hash, &hashObject, &hashObjectLength);
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

    NTSTATUS CngProvider::HkdfExtract(
        const CngProviderCache* cache,
        HashAlgorithm algorithm,
        const UCHAR* salt,
        SIZE_T saltLength,
        const UCHAR* ikm,
        SIZE_T ikmLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T digestLength = HashDigestLength(algorithm);
        if (digestLength == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        if (!IsValidBuffer(salt, saltLength) ||
            !IsValidBuffer(ikm, ikmLength) ||
            !IsValidMutableBuffer(output, outputLength) ||
            outputLength < digestLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        HeapArray<UCHAR> zeroSalt(digestLength);
        if (!zeroSalt.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const UCHAR* actualSalt = salt;
        SIZE_T actualSaltLength = saltLength;
        if (actualSalt == nullptr || actualSaltLength == 0) {
            actualSalt = zeroSalt.Get();
            actualSaltLength = digestLength;
        }

        status = Hmac(
            cache,
            algorithm,
            actualSalt,
            actualSaltLength,
            ikm,
            ikmLength,
            output,
            outputLength,
            bytesWritten);

        RtlSecureZeroMemory(zeroSalt.Get(), zeroSalt.Count());
        return status;
    }

    NTSTATUS CngProvider::HkdfExpand(
        const CngProviderCache* cache,
        HashAlgorithm algorithm,
        const UCHAR* prk,
        SIZE_T prkLength,
        const UCHAR* info,
        SIZE_T infoLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T digestLength = HashDigestLength(algorithm);
        if (digestLength == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        if (!IsValidBuffer(prk, prkLength) ||
            !IsValidBuffer(info, infoLength) ||
            !IsValidMutableBuffer(output, outputLength) ||
            prkLength < digestLength ||
            outputLength == 0 ||
            outputLength > digestLength * 255 ||
            infoLength > 256) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> previous(digestLength);
        HeapArray<UCHAR> hmacInput(digestLength + 256 + 1);
        HeapArray<UCHAR> block(digestLength);
        if (!previous.IsValid() || !hmacInput.IsValid() || !block.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T previousLength = 0;
        SIZE_T produced = 0;
        UCHAR counter = 1;

        while (produced < outputLength) {
            SIZE_T inputLength = 0;
            RtlZeroMemory(hmacInput.Get(), hmacInput.Count());
            if (previousLength != 0) {
                RtlCopyMemory(hmacInput.Get(), previous.Get(), previousLength);
                inputLength += previousLength;
            }

            if (infoLength != 0) {
                RtlCopyMemory(hmacInput.Get() + inputLength, info, infoLength);
                inputLength += infoLength;
            }

            hmacInput[inputLength] = counter;
            ++inputLength;

            SIZE_T blockLength = 0;
            status = Hmac(
                cache,
                algorithm,
                prk,
                prkLength,
                hmacInput.Get(),
                inputLength,
                block.Get(),
                block.Count(),
                &blockLength);
            RtlSecureZeroMemory(hmacInput.Get(), hmacInput.Count());
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(previous.Get(), previous.Count());
                RtlSecureZeroMemory(block.Get(), block.Count());
                return status;
            }

            const SIZE_T copyLength = blockLength < outputLength - produced ? blockLength : outputLength - produced;
            RtlCopyMemory(output + produced, block.Get(), copyLength);
            produced += copyLength;

            RtlCopyMemory(previous.Get(), block.Get(), blockLength);
            previousLength = blockLength;
            ++counter;
        }

        RtlSecureZeroMemory(previous.Get(), previous.Count());
        RtlSecureZeroMemory(block.Get(), block.Count());
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::AesGcmEncrypt(
        const CngProviderCache* cache,
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsValidBuffer(plaintext, plaintextLength) ||
            !IsValidMutableBuffer(ciphertext, ciphertextLength) ||
            !IsValidMutableBuffer(tag, tagLength) ||
            !IsValidBuffer(parameters.Nonce.Data, parameters.Nonce.Length) ||
            !IsValidBuffer(parameters.Aad.Data, parameters.Aad.Length) ||
            plaintext == ciphertext ||
            ciphertextLength < plaintextLength ||
            tagLength != AesGcmTagLength ||
            parameters.Nonce.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapObject<CngAlgorithmProvider> provider;
        if (!provider.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const CngAlgorithmProvider* providerToUse = cache != nullptr ? cache->Aes() : nullptr;
        if (providerToUse != nullptr) {
            cache->MarkProviderUsed();
        }

        status = STATUS_SUCCESS;
        if (providerToUse == nullptr) {
            status = provider->Open(BCRYPT_AES_ALGORITHM);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = SetAesGcmMode(provider->Handle());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            providerToUse = provider.Get();
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        UCHAR* keyObject = nullptr;
        ULONG keyObjectLength = 0;

        status = ImportSymmetricKey(providerToUse->Handle(), key, &keyHandle, &keyObject, &keyObjectLength);
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
        const CngProviderCache* cache,
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

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
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

        HeapObject<CngAlgorithmProvider> provider;
        if (!provider.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const CngAlgorithmProvider* providerToUse = cache != nullptr ? cache->Aes() : nullptr;
        if (providerToUse != nullptr) {
            cache->MarkProviderUsed();
        }

        status = STATUS_SUCCESS;
        if (providerToUse == nullptr) {
            status = provider->Open(BCRYPT_AES_ALGORITHM);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = SetAesGcmMode(provider->Handle());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            providerToUse = provider.Get();
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        UCHAR* keyObject = nullptr;
        ULONG keyObjectLength = 0;

        status = ImportSymmetricKey(providerToUse->Handle(), key, &keyHandle, &keyObject, &keyObjectLength);
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
        const CngProviderCache* cache,
        SignatureAlgorithm algorithm,
        const CngKey& publicKey,
        const UCHAR* hash,
        SIZE_T hashLength,
        const UCHAR* signature,
        SIZE_T signatureLength) noexcept
    {
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!publicKey.IsOpen() ||
            !IsValidBuffer(hash, hashLength) ||
            !IsValidBuffer(signature, signatureLength) ||
            hashLength == 0 ||
            signatureLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (cache != nullptr && cache->IsInitialized()) {
            cache->MarkProviderUsed();
        }

        status = STATUS_SUCCESS;
        ULONG hashSize = ToUlong(hashLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG signatureSize = ToUlong(signatureLength, &status);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        BCRYPT_PKCS1_PADDING_INFO pkcs1 = {};
        BCRYPT_PSS_PADDING_INFO pss = {};
        VOID* paddingInfo = nullptr;
        ULONG flags = 0;

        switch (algorithm) {
        case SignatureAlgorithm::RsaPkcs1Sha1:
            pkcs1.pszAlgId = BCRYPT_SHA1_ALGORITHM;
            paddingInfo = &pkcs1;
            flags = BCRYPT_PAD_PKCS1;
            break;
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
        case SignatureAlgorithm::RsaPkcs1Sha512:
            pkcs1.pszAlgId = BCRYPT_SHA512_ALGORITHM;
            paddingInfo = &pkcs1;
            flags = BCRYPT_PAD_PKCS1;
            break;
        case SignatureAlgorithm::RsaPssSha256:
            pss.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            pss.cbSalt = 32;
            paddingInfo = &pss;
            flags = BCRYPT_PAD_PSS;
            break;
        case SignatureAlgorithm::RsaPssSha384:
            pss.pszAlgId = BCRYPT_SHA384_ALGORITHM;
            pss.cbSalt = 48;
            paddingInfo = &pss;
            flags = BCRYPT_PAD_PSS;
            break;
        case SignatureAlgorithm::RsaPssSha512:
            pss.pszAlgId = BCRYPT_SHA512_ALGORITHM;
            pss.cbSalt = 64;
            paddingInfo = &pss;
            flags = BCRYPT_PAD_PSS;
            break;
        case SignatureAlgorithm::EcdsaSha1:
        case SignatureAlgorithm::EcdsaSha256:
        case SignatureAlgorithm::EcdsaSha384:
        case SignatureAlgorithm::EcdsaSha512:
            return VerifyEcdsaSignature(
                algorithm,
                publicKey,
                const_cast<PUCHAR>(hash),
                hashSize,
                signature,
                signatureLength);
        case SignatureAlgorithm::Ed25519:
        case SignatureAlgorithm::Ed448:
            return STATUS_NOT_SUPPORTED;
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

    NTSTATUS CngProvider::GenerateEcdhKeyPair(
        const CngProviderCache* cache,
        EcCurve curve,
        CngKey& privateKey) noexcept
    {
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        LPCWSTR algorithmName = EcdhAlgorithmName(curve);
        if (algorithmName == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        HeapObject<CngAlgorithmProvider> provider;
        if (!provider.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const CngAlgorithmProvider* providerToUse = cache != nullptr ? cache->Ecdh(curve) : nullptr;
        if (providerToUse != nullptr) {
            cache->MarkProviderUsed();
        }

        status = STATUS_SUCCESS;
        if (providerToUse == nullptr) {
            status = provider->Open(algorithmName);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            providerToUse = provider.Get();
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        const ULONG keyLengthBits = EcdhKeyLengthBits(curve);
        if (keyLengthBits == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        status = BCryptGenerateKeyPair(providerToUse->Handle(), &keyHandle, keyLengthBits, 0);
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
        const CngProviderCache* cache,
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return ImportEcPublicKey(
            cache,
            curve,
            EcdhPublicMagic(curve),
            EcdhAlgorithmName(curve),
            uncompressedPoint,
            pointLength,
            publicKey);
    }

    NTSTATUS CngProvider::ImportEcdsaPublicKey(
        const CngProviderCache* cache,
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return ImportEcPublicKey(
            cache,
            curve,
            EcdsaPublicMagic(curve),
            EcdsaAlgorithmName(curve),
            uncompressedPoint,
            pointLength,
            publicKey);
    }

    NTSTATUS CngProvider::ImportRsaPublicKey(
        const CngProviderCache* cache,
        const UCHAR* exponent,
        SIZE_T exponentLength,
        const UCHAR* modulus,
        SIZE_T modulusLength,
        CngKey& publicKey) noexcept
    {
        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (exponent == nullptr ||
            exponentLength == 0 ||
            modulus == nullptr ||
            modulusLength == 0 ||
            exponentLength > MAXULONG ||
            modulusLength > MAXULONG) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T modulusOffset = 0;
        while (modulusOffset < modulusLength && modulus[modulusOffset] == 0) {
            ++modulusOffset;
        }
        if (modulusOffset == modulusLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const UCHAR* normalizedModulus = modulus + modulusOffset;
        const SIZE_T normalizedModulusLength = modulusLength - modulusOffset;
        const SIZE_T modulusBits = normalizedModulusLength * 8;
        if (modulusBits < KhMinRsaModulusBits || normalizedModulusLength > MAXULONG) {
            return STATUS_NOT_SUPPORTED;
        }

        ULONG exponentValue = 0;
        for (SIZE_T index = 0; index < exponentLength; ++index) {
            if (exponentValue > ((MAXULONG - exponent[index]) / 256)) {
                return STATUS_NOT_SUPPORTED;
            }
            exponentValue = (exponentValue * 256) + exponent[index];
        }
        if (exponentValue < 3 || (exponentValue & 1UL) == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        HeapObject<CngAlgorithmProvider> provider;
        if (!provider.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const CngAlgorithmProvider* providerToUse = cache != nullptr ? cache->Rsa() : nullptr;
        if (providerToUse != nullptr) {
            cache->MarkProviderUsed();
        }

        status = STATUS_SUCCESS;
        if (providerToUse == nullptr) {
            status = provider->Open(BCRYPT_RSA_ALGORITHM);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            providerToUse = provider.Get();
        }

        const SIZE_T blobLength = sizeof(BCRYPT_RSAKEY_BLOB) + exponentLength + normalizedModulusLength;
        if (blobLength > MAXULONG) {
            return STATUS_INTEGER_OVERFLOW;
        }

        UCHAR* blob = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, blobLength, PoolTag));
        if (blob == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        auto* header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob);
        header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        header->BitLength = static_cast<ULONG>(modulusBits);
        header->cbPublicExp = static_cast<ULONG>(exponentLength);
        header->cbModulus = static_cast<ULONG>(normalizedModulusLength);
        header->cbPrime1 = 0;
        header->cbPrime2 = 0;

        RtlCopyMemory(blob + sizeof(BCRYPT_RSAKEY_BLOB), exponent, exponentLength);
        RtlCopyMemory(
            blob + sizeof(BCRYPT_RSAKEY_BLOB) + exponentLength,
            normalizedModulus,
            normalizedModulusLength);

        status = publicKey.ImportPublicKey(*providerToUse, BCRYPT_RSAPUBLIC_BLOB, blob, blobLength);
        RtlSecureZeroMemory(blob, blobLength);
        ExFreePoolWithTag(blob, PoolTag);
        return status;
    }

    NTSTATUS CngProvider::DeriveEcdhSecret(
        const CngProviderCache* cache,
        const CngKey& privateKey,
        const CngKey& peerPublicKey,
        UCHAR* secret,
        SIZE_T secretLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!privateKey.IsOpen() ||
            !peerPublicKey.IsOpen() ||
            !IsValidMutableBuffer(secret, secretLength) ||
            secretLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (cache != nullptr && cache->IsInitialized()) {
            cache->MarkProviderUsed();
        }

        ULONG keyBits = 0;
        ULONG propertyLength = 0;
        status = BCryptGetProperty(
            privateKey.Handle(),
            BCRYPT_KEY_LENGTH,
            reinterpret_cast<PUCHAR>(&keyBits),
            sizeof(keyBits),
            &propertyLength,
            0);
        if (!NT_SUCCESS(status) || keyBits == 0) {
            return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
        }

        const SIZE_T expectedLength = (static_cast<SIZE_T>(keyBits) + 7) / 8;
        if (expectedLength == 0 || expectedLength > secretLength || expectedLength > MAXULONG) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        HeapArray<UCHAR> rawSecret(expectedLength);
        if (!rawSecret.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BCRYPT_SECRET_HANDLE agreement = nullptr;
        status = BCryptSecretAgreement(privateKey.Handle(), peerPublicKey.Handle(), &agreement, 0);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG resultLength = 0;
        status = BCryptDeriveKey(
            agreement,
            BCRYPT_KDF_RAW_SECRET,
            nullptr,
            rawSecret.Get(),
            static_cast<ULONG>(rawSecret.Count()),
            &resultLength,
            0);

        BCryptDestroySecret(agreement);

        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (resultLength > expectedLength) {
            RtlSecureZeroMemory(rawSecret.Get(), rawSecret.Count());
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T leadingZeroes = expectedLength - resultLength;
        if (leadingZeroes != 0) {
            RtlZeroMemory(secret, leadingZeroes);
        }
        for (SIZE_T index = 0; index < resultLength; ++index) {
            secret[leadingZeroes + index] = rawSecret[resultLength - 1 - index];
        }
        RtlSecureZeroMemory(rawSecret.Get(), rawSecret.Count());

        if (bytesWritten != nullptr) {
            *bytesWritten = expectedLength;
        }

        return status;
    }

    NTSTATUS CngProvider::Hash(
        HashAlgorithm algorithm,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        return Hash(nullptr, algorithm, data, dataLength, output, outputLength, bytesWritten);
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
        return Hmac(nullptr, algorithm, key, keyLength, data, dataLength, output, outputLength, bytesWritten);
    }

    NTSTATUS CngProvider::HkdfExtract(
        HashAlgorithm algorithm,
        const UCHAR* salt,
        SIZE_T saltLength,
        const UCHAR* ikm,
        SIZE_T ikmLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        return HkdfExtract(nullptr, algorithm, salt, saltLength, ikm, ikmLength, output, outputLength, bytesWritten);
    }

    NTSTATUS CngProvider::HkdfExpand(
        HashAlgorithm algorithm,
        const UCHAR* prk,
        SIZE_T prkLength,
        const UCHAR* info,
        SIZE_T infoLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        return HkdfExpand(nullptr, algorithm, prk, prkLength, info, infoLength, output, outputLength);
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
        return AesGcmEncrypt(
            nullptr,
            key,
            parameters,
            plaintext,
            plaintextLength,
            ciphertext,
            ciphertextLength,
            tag,
            tagLength,
            bytesWritten);
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
        return AesGcmDecrypt(nullptr, key, parameters, ciphertext, ciphertextLength, plaintext, plaintextLength, bytesWritten);
    }

    NTSTATUS CngProvider::AesCbcEncrypt(
        const UCHAR* key,
        SIZE_T keyLength,
        const UCHAR* iv,
        SIZE_T ivLength,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (key == nullptr ||
            (keyLength != 16 && keyLength != 32) ||
            iv == nullptr ||
            ivLength != 16 ||
            plaintext == nullptr ||
            ciphertext == nullptr ||
            plaintextLength == 0 ||
            (plaintextLength % 16) != 0 ||
            ciphertextLength < plaintextLength) {
            return STATUS_INVALID_PARAMETER;
        }

        CngAlgorithmProvider provider;
        status = provider.Open(BCRYPT_AES_ALGORITHM);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BCryptSetProperty(
            provider.Handle(),
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG objectLength = 0;
        status = GetDwordProperty(provider.Handle(), BCRYPT_OBJECT_LENGTH, &objectLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UCHAR* keyObject = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, objectLength, PoolTag));
        if (keyObject == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        status = BCryptGenerateSymmetricKey(
            provider.Handle(),
            &keyHandle,
            keyObject,
            objectLength,
            const_cast<PUCHAR>(key),
            static_cast<ULONG>(keyLength),
            0);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(keyObject, PoolTag);
            return status;
        }

        HeapArray<UCHAR> ivCopy(16);
        if (!ivCopy.IsValid()) {
            BCryptDestroyKey(keyHandle);
            RtlSecureZeroMemory(keyObject, objectLength);
            ExFreePoolWithTag(keyObject, PoolTag);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(ivCopy.Get(), iv, ivCopy.Count());
        ULONG written = 0;
        status = BCryptEncrypt(
            keyHandle,
            const_cast<PUCHAR>(plaintext),
            static_cast<ULONG>(plaintextLength),
            nullptr,
            ivCopy.Get(),
            static_cast<ULONG>(ivCopy.Count()),
            ciphertext,
            static_cast<ULONG>(ciphertextLength),
            &written,
            0);

        RtlSecureZeroMemory(ivCopy.Get(), ivCopy.Count());
        BCryptDestroyKey(keyHandle);
        RtlSecureZeroMemory(keyObject, objectLength);
        ExFreePoolWithTag(keyObject, PoolTag);

        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = written;
        }

        return status;
    }

    NTSTATUS CngProvider::AesCbcDecrypt(
        const UCHAR* key,
        SIZE_T keyLength,
        const UCHAR* iv,
        SIZE_T ivLength,
        const UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* plaintext,
        SIZE_T plaintextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (key == nullptr ||
            (keyLength != 16 && keyLength != 32) ||
            iv == nullptr ||
            ivLength != 16 ||
            ciphertext == nullptr ||
            plaintext == nullptr ||
            ciphertextLength == 0 ||
            (ciphertextLength % 16) != 0 ||
            plaintextLength < ciphertextLength) {
            return STATUS_INVALID_PARAMETER;
        }

        CngAlgorithmProvider provider;
        status = provider.Open(BCRYPT_AES_ALGORITHM);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BCryptSetProperty(
            provider.Handle(),
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG objectLength = 0;
        status = GetDwordProperty(provider.Handle(), BCRYPT_OBJECT_LENGTH, &objectLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UCHAR* keyObject = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, objectLength, PoolTag));
        if (keyObject == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        status = BCryptGenerateSymmetricKey(
            provider.Handle(),
            &keyHandle,
            keyObject,
            objectLength,
            const_cast<PUCHAR>(key),
            static_cast<ULONG>(keyLength),
            0);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(keyObject, PoolTag);
            return status;
        }

        HeapArray<UCHAR> ivCopy(16);
        if (!ivCopy.IsValid()) {
            BCryptDestroyKey(keyHandle);
            RtlSecureZeroMemory(keyObject, objectLength);
            ExFreePoolWithTag(keyObject, PoolTag);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(ivCopy.Get(), iv, ivCopy.Count());
        ULONG written = 0;
        status = BCryptDecrypt(
            keyHandle,
            const_cast<PUCHAR>(ciphertext),
            static_cast<ULONG>(ciphertextLength),
            nullptr,
            ivCopy.Get(),
            static_cast<ULONG>(ivCopy.Count()),
            plaintext,
            static_cast<ULONG>(plaintextLength),
            &written,
            0);

        RtlSecureZeroMemory(ivCopy.Get(), ivCopy.Count());
        BCryptDestroyKey(keyHandle);
        RtlSecureZeroMemory(keyObject, objectLength);
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
        return VerifySignature(nullptr, algorithm, publicKey, hash, hashLength, signature, signatureLength);
    }

    NTSTATUS CngProvider::EncryptRsaPkcs1(
        const CngProviderCache* cache,
        const CngKey& publicKey,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = RequirePassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!publicKey.IsOpen() ||
            !IsValidBuffer(plaintext, plaintextLength) ||
            plaintextLength == 0 ||
            ciphertext == nullptr ||
            ciphertextLength == 0 ||
            plaintextLength > MAXULONG ||
            ciphertextLength > MAXULONG) {
            return STATUS_INVALID_PARAMETER;
        }

        if (cache != nullptr && cache->IsInitialized()) {
            cache->MarkProviderUsed();
        }

        ULONG written = 0;
        status = BCryptEncrypt(
            publicKey.Handle(),
            const_cast<PUCHAR>(plaintext),
            static_cast<ULONG>(plaintextLength),
            nullptr,
            nullptr,
            0,
            ciphertext,
            static_cast<ULONG>(ciphertextLength),
            &written,
            BCRYPT_PAD_PKCS1);
        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = written;
        }

        return status;
    }

    NTSTATUS CngProvider::EncryptRsaPkcs1(
        const CngKey& publicKey,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        SIZE_T* bytesWritten) noexcept
    {
        return EncryptRsaPkcs1(nullptr, publicKey, plaintext, plaintextLength, ciphertext, ciphertextLength, bytesWritten);
    }

    NTSTATUS CngProvider::GenerateEcdhKeyPair(EcCurve curve, CngKey& privateKey) noexcept
    {
        return GenerateEcdhKeyPair(nullptr, curve, privateKey);
    }

    NTSTATUS CngProvider::ImportEcdhPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        return ImportEcdhPublicKey(nullptr, curve, uncompressedPoint, pointLength, publicKey);
    }

    NTSTATUS CngProvider::ImportEcdsaPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        return ImportEcdsaPublicKey(nullptr, curve, uncompressedPoint, pointLength, publicKey);
    }

    NTSTATUS CngProvider::ImportRsaPublicKey(
        const UCHAR* exponent,
        SIZE_T exponentLength,
        const UCHAR* modulus,
        SIZE_T modulusLength,
        CngKey& publicKey) noexcept
    {
        return ImportRsaPublicKey(nullptr, exponent, exponentLength, modulus, modulusLength, publicKey);
    }

    NTSTATUS CngProvider::DeriveEcdhSecret(
        const CngKey& privateKey,
        const CngKey& peerPublicKey,
        UCHAR* secret,
        SIZE_T secretLength,
        SIZE_T* bytesWritten) noexcept
    {
        return DeriveEcdhSecret(nullptr, privateKey, peerPublicKey, secret, secretLength, bytesWritten);
    }
}
}

#else

namespace KernelHttp
{
namespace crypto
{
    namespace
    {
        constexpr SIZE_T Sha1DigestLength = 20;
        constexpr SIZE_T Sha1BlockLength = 64;
        constexpr SIZE_T Sha256DigestLength = 32;
        constexpr SIZE_T Sha256BlockLength = 64;

        _Must_inspect_result_
        SIZE_T HashDigestLength(HashAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case HashAlgorithm::Sha1:
                return 20;
            case HashAlgorithm::Sha256:
                return 32;
            case HashAlgorithm::Sha384:
                return 48;
            case HashAlgorithm::Sha512:
                return 64;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        ULONG RotateLeft(ULONG value, UCHAR bits) noexcept
        {
            return (value << bits) | (value >> (32 - bits));
        }

        _Must_inspect_result_
        ULONG RotateRight(ULONG value, UCHAR bits) noexcept
        {
            return (value >> bits) | (value << (32 - bits));
        }

        _Must_inspect_result_
        ULONG Sha256Choose(ULONG x, ULONG y, ULONG z) noexcept
        {
            return (x & y) ^ ((~x) & z);
        }

        _Must_inspect_result_
        ULONG Sha256Majority(ULONG x, ULONG y, ULONG z) noexcept
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        _Must_inspect_result_
        ULONG Sha256BigSigma0(ULONG x) noexcept
        {
            return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);
        }

        _Must_inspect_result_
        ULONG Sha256BigSigma1(ULONG x) noexcept
        {
            return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);
        }

        _Must_inspect_result_
        ULONG Sha256SmallSigma0(ULONG x) noexcept
        {
            return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
        }

        _Must_inspect_result_
        ULONG Sha256SmallSigma1(ULONG x) noexcept
        {
            return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
        }

        void WriteBigEndian32(ULONG value, _Out_writes_bytes_(4) UCHAR* destination) noexcept
        {
            destination[0] = static_cast<UCHAR>((value >> 24) & 0xff);
            destination[1] = static_cast<UCHAR>((value >> 16) & 0xff);
            destination[2] = static_cast<UCHAR>((value >> 8) & 0xff);
            destination[3] = static_cast<UCHAR>(value & 0xff);
        }

        _Must_inspect_result_
        NTSTATUS ProcessSha1Block(_In_reads_bytes_(Sha1BlockLength) const UCHAR* block, _Inout_updates_(5) ULONG* state) noexcept
        {
            HeapArray<ULONG> w(80);
            if (!w.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            for (SIZE_T index = 0; index < 16; ++index) {
                w[index] =
                    (static_cast<ULONG>(block[index * 4]) << 24) |
                    (static_cast<ULONG>(block[(index * 4) + 1]) << 16) |
                    (static_cast<ULONG>(block[(index * 4) + 2]) << 8) |
                    static_cast<ULONG>(block[(index * 4) + 3]);
            }

            for (SIZE_T index = 16; index < 80; ++index) {
                w[index] = RotateLeft(w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16], 1);
            }

            ULONG a = state[0];
            ULONG b = state[1];
            ULONG c = state[2];
            ULONG d = state[3];
            ULONG e = state[4];

            for (SIZE_T index = 0; index < 80; ++index) {
                ULONG f = 0;
                ULONG k = 0;
                if (index < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                }
                else if (index < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (index < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                const ULONG temp = RotateLeft(a, 5) + f + e + k + w[index];
                e = d;
                d = c;
                c = RotateLeft(b, 30);
                b = a;
                a = temp;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ProcessSha256Block(_In_reads_bytes_(Sha256BlockLength) const UCHAR* block, _Inout_updates_(8) ULONG* state) noexcept
        {
            static const ULONG K[64] = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };

            HeapArray<ULONG> w(64);
            if (!w.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            for (SIZE_T index = 0; index < 16; ++index) {
                w[index] =
                    (static_cast<ULONG>(block[index * 4]) << 24) |
                    (static_cast<ULONG>(block[(index * 4) + 1]) << 16) |
                    (static_cast<ULONG>(block[(index * 4) + 2]) << 8) |
                    static_cast<ULONG>(block[(index * 4) + 3]);
            }

            for (SIZE_T index = 16; index < 64; ++index) {
                w[index] = Sha256SmallSigma1(w[index - 2]) + w[index - 7] + Sha256SmallSigma0(w[index - 15]) + w[index - 16];
            }

            ULONG a = state[0];
            ULONG b = state[1];
            ULONG c = state[2];
            ULONG d = state[3];
            ULONG e = state[4];
            ULONG f = state[5];
            ULONG g = state[6];
            ULONG h = state[7];

            for (SIZE_T index = 0; index < 64; ++index) {
                const ULONG t1 = h + Sha256BigSigma1(e) + Sha256Choose(e, f, g) + K[index] + w[index];
                const ULONG t2 = Sha256BigSigma0(a) + Sha256Majority(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS Sha1Hash(
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(Sha1DigestLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }

            if ((data == nullptr && dataLength != 0) || output == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (outputLength < Sha1DigestLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            HeapArray<ULONG> state(5);
            HeapArray<UCHAR> block(Sha1BlockLength * 2);
            if (!state.IsValid() || !block.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            state[0] = 0x67452301;
            state[1] = 0xEFCDAB89;
            state[2] = 0x98BADCFE;
            state[3] = 0x10325476;
            state[4] = 0xC3D2E1F0;

            SIZE_T cursor = 0;
            while (dataLength - cursor >= Sha1BlockLength) {
                NTSTATUS status = ProcessSha1Block(data + cursor, state.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                cursor += Sha1BlockLength;
            }

            const SIZE_T remaining = dataLength - cursor;
            if (remaining > 0) {
                RtlCopyMemory(block.Get(), data + cursor, remaining);
            }
            block[remaining] = 0x80;

            const ULONGLONG bitLength = static_cast<ULONGLONG>(dataLength) * 8ULL;
            SIZE_T paddedLength = remaining + 1;
            while ((paddedLength % Sha1BlockLength) != 56) {
                ++paddedLength;
            }

            for (SIZE_T index = 0; index < 8; ++index) {
                block[paddedLength + index] = static_cast<UCHAR>((bitLength >> (56 - (index * 8))) & 0xff);
            }
            paddedLength += 8;

            for (SIZE_T offset = 0; offset < paddedLength; offset += Sha1BlockLength) {
                NTSTATUS status = ProcessSha1Block(block.Get() + offset, state.Get());
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(block.Get(), block.Count());
                    return status;
                }
            }

            for (SIZE_T index = 0; index < 5; ++index) {
                output[index * 4] = static_cast<UCHAR>((state[index] >> 24) & 0xff);
                output[(index * 4) + 1] = static_cast<UCHAR>((state[index] >> 16) & 0xff);
                output[(index * 4) + 2] = static_cast<UCHAR>((state[index] >> 8) & 0xff);
                output[(index * 4) + 3] = static_cast<UCHAR>(state[index] & 0xff);
            }

            if (bytesWritten != nullptr) {
                *bytesWritten = Sha1DigestLength;
            }
            RtlSecureZeroMemory(block.Get(), block.Count());
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS Sha256Hash(
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(Sha256DigestLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }

            if ((data == nullptr && dataLength != 0) || output == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (outputLength < Sha256DigestLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            HeapArray<ULONG> state(8);
            HeapArray<UCHAR> block(Sha256BlockLength * 2);
            if (!state.IsValid() || !block.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            state[0] = 0x6a09e667;
            state[1] = 0xbb67ae85;
            state[2] = 0x3c6ef372;
            state[3] = 0xa54ff53a;
            state[4] = 0x510e527f;
            state[5] = 0x9b05688c;
            state[6] = 0x1f83d9ab;
            state[7] = 0x5be0cd19;

            SIZE_T cursor = 0;
            while (dataLength - cursor >= Sha256BlockLength) {
                NTSTATUS status = ProcessSha256Block(data + cursor, state.Get());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                cursor += Sha256BlockLength;
            }

            const SIZE_T remaining = dataLength - cursor;
            if (remaining > 0) {
                RtlCopyMemory(block.Get(), data + cursor, remaining);
            }
            block[remaining] = 0x80;

            const ULONGLONG bitLength = static_cast<ULONGLONG>(dataLength) * 8ULL;
            SIZE_T paddedLength = remaining + 1;
            while ((paddedLength % Sha256BlockLength) != 56) {
                ++paddedLength;
            }

            for (SIZE_T index = 0; index < 8; ++index) {
                block[paddedLength + index] = static_cast<UCHAR>((bitLength >> (56 - (index * 8))) & 0xff);
            }
            paddedLength += 8;

            for (SIZE_T offset = 0; offset < paddedLength; offset += Sha256BlockLength) {
                NTSTATUS status = ProcessSha256Block(block.Get() + offset, state.Get());
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(block.Get(), block.Count());
                    return status;
                }
            }

            for (SIZE_T index = 0; index < 8; ++index) {
                WriteBigEndian32(state[index], output + (index * 4));
            }

            if (bytesWritten != nullptr) {
                *bytesWritten = Sha256DigestLength;
            }
            RtlSecureZeroMemory(block.Get(), block.Count());
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS HmacSha256(
            _In_reads_bytes_(keyLength) const UCHAR* key,
            SIZE_T keyLength,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(Sha256DigestLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            if ((key == nullptr && keyLength != 0) ||
                (data == nullptr && dataLength != 0) ||
                output == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (outputLength < Sha256DigestLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            HeapArray<UCHAR> normalizedKey(Sha256BlockLength);
            HeapArray<UCHAR> inner(Sha256BlockLength);
            HeapArray<UCHAR> outer(Sha256BlockLength);
            HeapArray<UCHAR> innerInput(Sha256BlockLength + 512);
            HeapArray<UCHAR> innerHash(Sha256DigestLength);
            HeapArray<UCHAR> outerInput(Sha256BlockLength + Sha256DigestLength);
            if (!normalizedKey.IsValid() ||
                !inner.IsValid() ||
                !outer.IsValid() ||
                !innerInput.IsValid() ||
                !innerHash.IsValid() ||
                !outerInput.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (keyLength > Sha256BlockLength) {
                SIZE_T keyHashLength = 0;
                NTSTATUS status = Sha256Hash(
                    key,
                    keyLength,
                    normalizedKey.Get(),
                    normalizedKey.Count(),
                    &keyHashLength);
                if (!NT_SUCCESS(status) || keyHashLength != Sha256DigestLength) {
                    RtlSecureZeroMemory(normalizedKey.Get(), normalizedKey.Count());
                    return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
                }
            }
            else if (keyLength != 0) {
                RtlCopyMemory(normalizedKey.Get(), key, keyLength);
            }

            for (SIZE_T index = 0; index < Sha256BlockLength; ++index) {
                inner[index] = static_cast<UCHAR>(normalizedKey[index] ^ 0x36);
                outer[index] = static_cast<UCHAR>(normalizedKey[index] ^ 0x5c);
            }

            if (dataLength > innerInput.Count() - Sha256BlockLength) {
                RtlSecureZeroMemory(normalizedKey.Get(), normalizedKey.Count());
                return STATUS_BUFFER_TOO_SMALL;
            }
            RtlCopyMemory(innerInput.Get(), inner.Get(), inner.Count());
            if (dataLength != 0) {
                RtlCopyMemory(innerInput.Get() + Sha256BlockLength, data, dataLength);
            }

            SIZE_T innerHashLength = 0;
            NTSTATUS status = Sha256Hash(
                innerInput.Get(),
                Sha256BlockLength + dataLength,
                innerHash.Get(),
                innerHash.Count(),
                &innerHashLength);
            RtlSecureZeroMemory(innerInput.Get(), innerInput.Count());
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(normalizedKey.Get(), normalizedKey.Count());
                return status;
            }

            RtlCopyMemory(outerInput.Get(), outer.Get(), outer.Count());
            RtlCopyMemory(outerInput.Get() + Sha256BlockLength, innerHash.Get(), innerHash.Count());
            status = Sha256Hash(
                outerInput.Get(),
                outerInput.Count(),
                output,
                outputLength,
                bytesWritten);

            RtlSecureZeroMemory(normalizedKey.Get(), normalizedKey.Count());
            RtlSecureZeroMemory(inner.Get(), inner.Count());
            RtlSecureZeroMemory(outer.Get(), outer.Count());
            RtlSecureZeroMemory(innerHash.Get(), innerHash.Count());
            RtlSecureZeroMemory(outerInput.Get(), outerInput.Count());
            return status;
        }
    }

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
        const CngAlgorithmProvider& provider,
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

        if (dataLength > sizeof(state_) - stateLength_) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (dataLength > 0) {
            RtlCopyMemory(state_ + stateLength_, data, dataLength);
            stateLength_ += dataLength;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS CngHashContext::Finish(UCHAR* output, SIZE_T outputLength, SIZE_T* bytesWritten) const noexcept
    {
        const SIZE_T required = HashDigestLength(algorithm_);

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (required == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        if (!initialized_ || output == nullptr || outputLength < required) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (algorithm_ == HashAlgorithm::Sha1) {
            return Sha1Hash(state_, stateLength_, output, outputLength, bytesWritten);
        }
        if (algorithm_ == HashAlgorithm::Sha256) {
            return Sha256Hash(state_, stateLength_, output, outputLength, bytesWritten);
        }

        for (SIZE_T index = 0; index < required; ++index) {
            output[index] = static_cast<UCHAR>(index);
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
        const CngProviderCache* cache,
        HashAlgorithm algorithm,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (cache != nullptr && cache->Hash(algorithm) != nullptr) {
            cache->MarkProviderUsed();
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        const SIZE_T required = HashDigestLength(algorithm);
        if (required == 0) {
            return STATUS_NOT_SUPPORTED;
        }
        if (output == nullptr || outputLength < required) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (algorithm == HashAlgorithm::Sha1) {
            return Sha1Hash(data, dataLength, output, outputLength, bytesWritten);
        }
        if (algorithm == HashAlgorithm::Sha256) {
            return Sha256Hash(data, dataLength, output, outputLength, bytesWritten);
        }

        for (SIZE_T index = 0; index < required; ++index) {
            output[index] = static_cast<UCHAR>(index);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = required;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::Hmac(
        const CngProviderCache* cache,
        HashAlgorithm algorithm,
        const UCHAR* key,
        SIZE_T keyLength,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (cache != nullptr && cache->Hmac(algorithm) != nullptr) {
            cache->MarkProviderUsed();
        }

        if (algorithm == HashAlgorithm::Sha256) {
            return HmacSha256(key, keyLength, data, dataLength, output, outputLength, bytesWritten);
        }

        return Hash(algorithm, key != nullptr ? key : data, keyLength + dataLength, output, outputLength, bytesWritten);
    }

    NTSTATUS CngProvider::HkdfExtract(
        const CngProviderCache* cache,
        HashAlgorithm algorithm,
        const UCHAR* salt,
        SIZE_T saltLength,
        const UCHAR* ikm,
        SIZE_T ikmLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        const SIZE_T digestLength = HashDigestLength(algorithm);
        if (digestLength == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        if (output == nullptr || outputLength < digestLength || (salt == nullptr && saltLength != 0) || (ikm == nullptr && ikmLength != 0)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        HeapArray<UCHAR> zeroSalt(digestLength);
        if (!zeroSalt.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const UCHAR* actualSalt = salt;
        SIZE_T actualSaltLength = saltLength;
        if (actualSalt == nullptr || actualSaltLength == 0) {
            actualSalt = zeroSalt.Get();
            actualSaltLength = digestLength;
        }

        NTSTATUS status = Hmac(
            cache,
            algorithm,
            actualSalt,
            actualSaltLength,
            ikm,
            ikmLength,
            output,
            outputLength,
            bytesWritten);

        RtlSecureZeroMemory(zeroSalt.Get(), zeroSalt.Count());
        return status;
    }

    NTSTATUS CngProvider::HkdfExpand(
        const CngProviderCache* cache,
        HashAlgorithm algorithm,
        const UCHAR* prk,
        SIZE_T prkLength,
        const UCHAR* info,
        SIZE_T infoLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        const SIZE_T digestLength = HashDigestLength(algorithm);
        if (digestLength == 0) {
            return STATUS_NOT_SUPPORTED;
        }

        if (prk == nullptr ||
            prkLength < digestLength ||
            (info == nullptr && infoLength != 0) ||
            output == nullptr ||
            outputLength == 0 ||
            outputLength > digestLength * 255 ||
            infoLength > 256) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> previous(digestLength);
        HeapArray<UCHAR> hmacInput(digestLength + 256 + 1);
        HeapArray<UCHAR> block(digestLength);
        if (!previous.IsValid() || !hmacInput.IsValid() || !block.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T previousLength = 0;
        SIZE_T produced = 0;
        UCHAR counter = 1;

        while (produced < outputLength) {
            SIZE_T inputLength = 0;
            RtlZeroMemory(hmacInput.Get(), hmacInput.Count());
            if (previousLength != 0) {
                RtlCopyMemory(hmacInput.Get(), previous.Get(), previousLength);
                inputLength += previousLength;
            }

            if (infoLength != 0) {
                RtlCopyMemory(hmacInput.Get() + inputLength, info, infoLength);
                inputLength += infoLength;
            }

            hmacInput[inputLength] = counter;
            ++inputLength;

            SIZE_T blockLength = 0;
            NTSTATUS status = Hmac(
                cache,
                algorithm,
                prk,
                prkLength,
                hmacInput.Get(),
                inputLength,
                block.Get(),
                block.Count(),
                &blockLength);
            RtlSecureZeroMemory(hmacInput.Get(), hmacInput.Count());
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(previous.Get(), previous.Count());
                RtlSecureZeroMemory(block.Get(), block.Count());
                return status;
            }

            const SIZE_T copyLength = blockLength < outputLength - produced ? blockLength : outputLength - produced;
            RtlCopyMemory(output + produced, block.Get(), copyLength);
            produced += copyLength;
            RtlCopyMemory(previous.Get(), block.Get(), blockLength);
            previousLength = blockLength;
            ++counter;
        }

        RtlSecureZeroMemory(previous.Get(), previous.Count());
        RtlSecureZeroMemory(block.Get(), block.Count());
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::AesGcmEncrypt(
        const CngProviderCache* cache,
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
        if (cache != nullptr && cache->Aes() != nullptr) {
            cache->MarkProviderUsed();
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (key.Key == nullptr ||
            key.KeyLength == 0 ||
            parameters.Nonce.Data == nullptr ||
            parameters.Nonce.Length == 0 ||
            plaintext == nullptr ||
            ciphertext == nullptr ||
            plaintext == ciphertext ||
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
        const CngProviderCache* cache,
        const AesGcmKey& key,
        const AesGcmParameters& parameters,
        const UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* plaintext,
        SIZE_T plaintextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (cache != nullptr && cache->Aes() != nullptr) {
            cache->MarkProviderUsed();
        }

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

    NTSTATUS CngProvider::AesCbcEncrypt(
        const UCHAR* key,
        SIZE_T keyLength,
        const UCHAR* iv,
        SIZE_T ivLength,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (key == nullptr ||
            keyLength == 0 ||
            iv == nullptr ||
            ivLength == 0 ||
            plaintext == nullptr ||
            ciphertext == nullptr ||
            ciphertextLength < plaintextLength ||
            (plaintextLength % 16) != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < plaintextLength; ++index) {
            ciphertext[index] = static_cast<UCHAR>(plaintext[index] ^ key[index % keyLength] ^ iv[index % ivLength]);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = plaintextLength;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::AesCbcDecrypt(
        const UCHAR* key,
        SIZE_T keyLength,
        const UCHAR* iv,
        SIZE_T ivLength,
        const UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* plaintext,
        SIZE_T plaintextLength,
        SIZE_T* bytesWritten) noexcept
    {
        return AesCbcEncrypt(
            key,
            keyLength,
            iv,
            ivLength,
            ciphertext,
            ciphertextLength,
            plaintext,
            plaintextLength,
            bytesWritten);
    }

    NTSTATUS CngProvider::VerifySignature(
        const CngProviderCache* cache,
        SignatureAlgorithm algorithm,
        const CngKey& publicKey,
        const UCHAR* hash,
        SIZE_T hashLength,
        const UCHAR* signature,
        SIZE_T signatureLength) noexcept
    {
        (void)algorithm;
        (void)publicKey;

        if (cache != nullptr && cache->IsInitialized()) {
            cache->MarkProviderUsed();
        }

        if (hash == nullptr || hashLength == 0 || signature == nullptr || signatureLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::EncryptRsaPkcs1(
        const CngProviderCache* cache,
        const CngKey& publicKey,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        SIZE_T* bytesWritten) noexcept
    {
        (void)publicKey;

        if (cache != nullptr && cache->IsInitialized()) {
            cache->MarkProviderUsed();
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (plaintext == nullptr ||
            plaintextLength == 0 ||
            ciphertext == nullptr ||
            ciphertextLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < ciphertextLength; ++index) {
            ciphertext[index] = static_cast<UCHAR>(plaintext[index % plaintextLength] ^ 0x5aU);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = ciphertextLength;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::GenerateEcdhKeyPair(
        const CngProviderCache* cache,
        EcCurve curve,
        CngKey& privateKey) noexcept
    {
        if (cache != nullptr && cache->Ecdh(curve) != nullptr) {
            cache->MarkProviderUsed();
        }

        privateKey.Adopt(&privateKey);
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::ImportEcdhPublicKey(
        const CngProviderCache* cache,
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        if (cache != nullptr && cache->Ecdh(curve) != nullptr) {
            cache->MarkProviderUsed();
        }

        if (uncompressedPoint == nullptr || pointLength == 0 || uncompressedPoint[0] != 4) {
            return STATUS_INVALID_PARAMETER;
        }

        publicKey.Adopt(&publicKey);
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::ImportEcdsaPublicKey(
        const CngProviderCache* cache,
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        if (cache != nullptr && cache->Ecdsa(curve) != nullptr) {
            cache->MarkProviderUsed();
        }

        return ImportEcdhPublicKey(nullptr, curve, uncompressedPoint, pointLength, publicKey);
    }

    NTSTATUS CngProvider::ImportRsaPublicKey(
        const CngProviderCache* cache,
        const UCHAR* exponent,
        SIZE_T exponentLength,
        const UCHAR* modulus,
        SIZE_T modulusLength,
        CngKey& publicKey) noexcept
    {
        if (cache != nullptr && cache->Rsa() != nullptr) {
            cache->MarkProviderUsed();
        }

        if (exponent == nullptr || exponentLength == 0 || modulus == nullptr || modulusLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        publicKey.Adopt(&publicKey);
        return STATUS_SUCCESS;
    }

    NTSTATUS CngProvider::DeriveEcdhSecret(
        const CngProviderCache* cache,
        const CngKey& privateKey,
        const CngKey& peerPublicKey,
        UCHAR* secret,
        SIZE_T secretLength,
        SIZE_T* bytesWritten) noexcept
    {
        (void)privateKey;
        (void)peerPublicKey;

        if (cache != nullptr && cache->IsInitialized()) {
            cache->MarkProviderUsed();
        }

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

    NTSTATUS CngProvider::Hash(
        HashAlgorithm algorithm,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        return Hash(nullptr, algorithm, data, dataLength, output, outputLength, bytesWritten);
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
        return Hmac(nullptr, algorithm, key, keyLength, data, dataLength, output, outputLength, bytesWritten);
    }

    NTSTATUS CngProvider::HkdfExtract(
        HashAlgorithm algorithm,
        const UCHAR* salt,
        SIZE_T saltLength,
        const UCHAR* ikm,
        SIZE_T ikmLength,
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) noexcept
    {
        return HkdfExtract(nullptr, algorithm, salt, saltLength, ikm, ikmLength, output, outputLength, bytesWritten);
    }

    NTSTATUS CngProvider::HkdfExpand(
        HashAlgorithm algorithm,
        const UCHAR* prk,
        SIZE_T prkLength,
        const UCHAR* info,
        SIZE_T infoLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        return HkdfExpand(nullptr, algorithm, prk, prkLength, info, infoLength, output, outputLength);
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
        return AesGcmEncrypt(
            nullptr,
            key,
            parameters,
            plaintext,
            plaintextLength,
            ciphertext,
            ciphertextLength,
            tag,
            tagLength,
            bytesWritten);
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
        return AesGcmDecrypt(nullptr, key, parameters, ciphertext, ciphertextLength, plaintext, plaintextLength, bytesWritten);
    }

    NTSTATUS CngProvider::VerifySignature(
        SignatureAlgorithm algorithm,
        const CngKey& publicKey,
        const UCHAR* hash,
        SIZE_T hashLength,
        const UCHAR* signature,
        SIZE_T signatureLength) noexcept
    {
        return VerifySignature(nullptr, algorithm, publicKey, hash, hashLength, signature, signatureLength);
    }

    NTSTATUS CngProvider::EncryptRsaPkcs1(
        const CngKey& publicKey,
        const UCHAR* plaintext,
        SIZE_T plaintextLength,
        UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        SIZE_T* bytesWritten) noexcept
    {
        return EncryptRsaPkcs1(nullptr, publicKey, plaintext, plaintextLength, ciphertext, ciphertextLength, bytesWritten);
    }

    NTSTATUS CngProvider::GenerateEcdhKeyPair(EcCurve curve, CngKey& privateKey) noexcept
    {
        return GenerateEcdhKeyPair(nullptr, curve, privateKey);
    }

    NTSTATUS CngProvider::ImportEcdhPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        return ImportEcdhPublicKey(nullptr, curve, uncompressedPoint, pointLength, publicKey);
    }

    NTSTATUS CngProvider::ImportEcdsaPublicKey(
        EcCurve curve,
        const UCHAR* uncompressedPoint,
        SIZE_T pointLength,
        CngKey& publicKey) noexcept
    {
        return ImportEcdsaPublicKey(nullptr, curve, uncompressedPoint, pointLength, publicKey);
    }

    NTSTATUS CngProvider::ImportRsaPublicKey(
        const UCHAR* exponent,
        SIZE_T exponentLength,
        const UCHAR* modulus,
        SIZE_T modulusLength,
        CngKey& publicKey) noexcept
    {
        return ImportRsaPublicKey(nullptr, exponent, exponentLength, modulus, modulusLength, publicKey);
    }

    NTSTATUS CngProvider::DeriveEcdhSecret(
        const CngKey& privateKey,
        const CngKey& peerPublicKey,
        UCHAR* secret,
        SIZE_T secretLength,
        SIZE_T* bytesWritten) noexcept
    {
        return DeriveEcdhSecret(nullptr, privateKey, peerPublicKey, secret, secretLength, bytesWritten);
    }
}
}

#endif
