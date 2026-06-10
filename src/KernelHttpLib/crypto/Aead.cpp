#include <KernelHttp/crypto/Aead.h>
#include <KernelHttp/crypto/CngProviderCache.h>

namespace KernelHttp
{
namespace crypto
{
    namespace
    {
        constexpr SIZE_T ChaChaBlockLength = 64;
        _Must_inspect_result_
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        bool MemoryEquals(_In_reads_bytes_(length) const UCHAR* left, _In_reads_bytes_(length) const UCHAR* right, SIZE_T length) noexcept
        {
            UCHAR diff = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                diff = static_cast<UCHAR>(diff | (left[index] ^ right[index]));
            }
            return diff == 0;
        }

        _Must_inspect_result_
        ULONG ReadLittleEndian32(_In_reads_bytes_(4) const UCHAR* data) noexcept
        {
            return static_cast<ULONG>(data[0]) |
                (static_cast<ULONG>(data[1]) << 8) |
                (static_cast<ULONG>(data[2]) << 16) |
                (static_cast<ULONG>(data[3]) << 24);
        }

        void WriteLittleEndian32(ULONG value, _Out_writes_bytes_(4) UCHAR* data) noexcept
        {
            data[0] = static_cast<UCHAR>(value & 0xff);
            data[1] = static_cast<UCHAR>((value >> 8) & 0xff);
            data[2] = static_cast<UCHAR>((value >> 16) & 0xff);
            data[3] = static_cast<UCHAR>((value >> 24) & 0xff);
        }

        void WriteLittleEndian64(ULONGLONG value, _Out_writes_bytes_(8) UCHAR* data) noexcept
        {
            for (SIZE_T index = 0; index < 8; ++index) {
                data[index] = static_cast<UCHAR>((value >> (index * 8)) & 0xff);
            }
        }

        _Must_inspect_result_
        ULONG RotateLeft32(ULONG value, ULONG bits) noexcept
        {
            return (value << bits) | (value >> (32 - bits));
        }

        void QuarterRound(
            _Inout_ ULONG& a,
            _Inout_ ULONG& b,
            _Inout_ ULONG& c,
            _Inout_ ULONG& d) noexcept
        {
            a += b;
            d ^= a;
            d = RotateLeft32(d, 16);
            c += d;
            b ^= c;
            b = RotateLeft32(b, 12);
            a += b;
            d ^= a;
            d = RotateLeft32(d, 8);
            c += d;
            b ^= c;
            b = RotateLeft32(b, 7);
        }

        void ChaCha20Block(
            _In_reads_bytes_(AeadChaCha20Poly1305KeyLength) const UCHAR* key,
            ULONG counter,
            _In_reads_bytes_(AeadChaCha20Poly1305NonceLength) const UCHAR* nonce,
            _Out_writes_bytes_(ChaChaBlockLength) UCHAR* output) noexcept
        {
            ULONG state[16] = {
                0x61707865UL,
                0x3320646eUL,
                0x79622d32UL,
                0x6b206574UL,
                ReadLittleEndian32(key),
                ReadLittleEndian32(key + 4),
                ReadLittleEndian32(key + 8),
                ReadLittleEndian32(key + 12),
                ReadLittleEndian32(key + 16),
                ReadLittleEndian32(key + 20),
                ReadLittleEndian32(key + 24),
                ReadLittleEndian32(key + 28),
                counter,
                ReadLittleEndian32(nonce),
                ReadLittleEndian32(nonce + 4),
                ReadLittleEndian32(nonce + 8)
            };

            ULONG working[16] = {};
            for (SIZE_T index = 0; index < 16; ++index) {
                working[index] = state[index];
            }

            for (SIZE_T round = 0; round < 10; ++round) {
                QuarterRound(working[0], working[4], working[8], working[12]);
                QuarterRound(working[1], working[5], working[9], working[13]);
                QuarterRound(working[2], working[6], working[10], working[14]);
                QuarterRound(working[3], working[7], working[11], working[15]);
                QuarterRound(working[0], working[5], working[10], working[15]);
                QuarterRound(working[1], working[6], working[11], working[12]);
                QuarterRound(working[2], working[7], working[8], working[13]);
                QuarterRound(working[3], working[4], working[9], working[14]);
            }

            for (SIZE_T index = 0; index < 16; ++index) {
                WriteLittleEndian32(working[index] + state[index], output + (index * 4));
            }

            RtlSecureZeroMemory(state, sizeof(state));
            RtlSecureZeroMemory(working, sizeof(working));
        }

        _Must_inspect_result_
        NTSTATUS ChaCha20Xor(
            _In_reads_bytes_(AeadChaCha20Poly1305KeyLength) const UCHAR* key,
            ULONG counter,
            _In_reads_bytes_(AeadChaCha20Poly1305NonceLength) const UCHAR* nonce,
            _In_reads_bytes_opt_(inputLength) const UCHAR* input,
            SIZE_T inputLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept
        {
            if (!IsValidBuffer(input, inputLength) || output == nullptr || outputLength < inputLength) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR block[ChaChaBlockLength] = {};
            SIZE_T offset = 0;
            while (offset < inputLength) {
                ChaCha20Block(key, counter, nonce, block);
                ++counter;

                const SIZE_T remaining = inputLength - offset;
                const SIZE_T chunk = remaining < ChaChaBlockLength ? remaining : ChaChaBlockLength;
                for (SIZE_T index = 0; index < chunk; ++index) {
                    output[offset + index] = static_cast<UCHAR>(input[offset + index] ^ block[index]);
                }
                offset += chunk;
            }

            RtlSecureZeroMemory(block, sizeof(block));
            return STATUS_SUCCESS;
        }

        void Poly1305ProcessBlock(
            _Inout_updates_(5) ULONG h[5],
            _In_reads_(5) const ULONG r[5],
            _In_reads_bytes_(blockLength) const UCHAR* block,
            SIZE_T blockLength) noexcept
        {
            ULONG values[5] = {};
            UCHAR padded[17] = {};
            if (blockLength != 0) {
                RtlCopyMemory(padded, block, blockLength);
            }
            padded[blockLength] = 1;

            values[0] = ReadLittleEndian32(padded) & 0x3ffffffUL;
            values[1] = (ReadLittleEndian32(padded + 3) >> 2) & 0x3ffffffUL;
            values[2] = (ReadLittleEndian32(padded + 6) >> 4) & 0x3ffffffUL;
            values[3] = (ReadLittleEndian32(padded + 9) >> 6) & 0x3ffffffUL;
            values[4] = ReadLittleEndian32(padded + 13) & 0x3ffffffUL;

            h[0] += values[0];
            h[1] += values[1];
            h[2] += values[2];
            h[3] += values[3];
            h[4] += values[4];

            const ULONG s1 = r[1] * 5;
            const ULONG s2 = r[2] * 5;
            const ULONG s3 = r[3] * 5;
            const ULONG s4 = r[4] * 5;

            unsigned long long d0 =
                static_cast<unsigned long long>(h[0]) * r[0] +
                static_cast<unsigned long long>(h[1]) * s4 +
                static_cast<unsigned long long>(h[2]) * s3 +
                static_cast<unsigned long long>(h[3]) * s2 +
                static_cast<unsigned long long>(h[4]) * s1;
            unsigned long long d1 =
                static_cast<unsigned long long>(h[0]) * r[1] +
                static_cast<unsigned long long>(h[1]) * r[0] +
                static_cast<unsigned long long>(h[2]) * s4 +
                static_cast<unsigned long long>(h[3]) * s3 +
                static_cast<unsigned long long>(h[4]) * s2;
            unsigned long long d2 =
                static_cast<unsigned long long>(h[0]) * r[2] +
                static_cast<unsigned long long>(h[1]) * r[1] +
                static_cast<unsigned long long>(h[2]) * r[0] +
                static_cast<unsigned long long>(h[3]) * s4 +
                static_cast<unsigned long long>(h[4]) * s3;
            unsigned long long d3 =
                static_cast<unsigned long long>(h[0]) * r[3] +
                static_cast<unsigned long long>(h[1]) * r[2] +
                static_cast<unsigned long long>(h[2]) * r[1] +
                static_cast<unsigned long long>(h[3]) * r[0] +
                static_cast<unsigned long long>(h[4]) * s4;
            unsigned long long d4 =
                static_cast<unsigned long long>(h[0]) * r[4] +
                static_cast<unsigned long long>(h[1]) * r[3] +
                static_cast<unsigned long long>(h[2]) * r[2] +
                static_cast<unsigned long long>(h[3]) * r[1] +
                static_cast<unsigned long long>(h[4]) * r[0];

            ULONG carry = static_cast<ULONG>(d0 >> 26);
            h[0] = static_cast<ULONG>(d0) & 0x3ffffffUL;
            d1 += carry;
            carry = static_cast<ULONG>(d1 >> 26);
            h[1] = static_cast<ULONG>(d1) & 0x3ffffffUL;
            d2 += carry;
            carry = static_cast<ULONG>(d2 >> 26);
            h[2] = static_cast<ULONG>(d2) & 0x3ffffffUL;
            d3 += carry;
            carry = static_cast<ULONG>(d3 >> 26);
            h[3] = static_cast<ULONG>(d3) & 0x3ffffffUL;
            d4 += carry;
            carry = static_cast<ULONG>(d4 >> 26);
            h[4] = static_cast<ULONG>(d4) & 0x3ffffffUL;
            h[0] += carry * 5;
            carry = h[0] >> 26;
            h[0] &= 0x3ffffffUL;
            h[1] += carry;

            RtlSecureZeroMemory(values, sizeof(values));
            RtlSecureZeroMemory(padded, sizeof(padded));
        }

        void Poly1305(
            _In_reads_bytes_(32) const UCHAR* key,
            _In_reads_bytes_opt_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _Out_writes_bytes_(16) UCHAR* tag) noexcept
        {
            ULONG r[5] = {};
            ULONG h[5] = {};

            const ULONG t0 = ReadLittleEndian32(key);
            const ULONG t1 = ReadLittleEndian32(key + 4);
            const ULONG t2 = ReadLittleEndian32(key + 8);
            const ULONG t3 = ReadLittleEndian32(key + 12);

            r[0] = t0 & 0x3ffffffUL;
            r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03UL;
            r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffUL;
            r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffUL;
            r[4] = (t3 >> 8) & 0x00fffffUL;

            SIZE_T offset = 0;
            while (offset < messageLength) {
                const SIZE_T remaining = messageLength - offset;
                const SIZE_T chunk = remaining < 16 ? remaining : 16;
                Poly1305ProcessBlock(h, r, message + offset, chunk);
                offset += chunk;
            }

            ULONG carry = h[1] >> 26;
            h[1] &= 0x3ffffffUL;
            h[2] += carry;
            carry = h[2] >> 26;
            h[2] &= 0x3ffffffUL;
            h[3] += carry;
            carry = h[3] >> 26;
            h[3] &= 0x3ffffffUL;
            h[4] += carry;
            carry = h[4] >> 26;
            h[4] &= 0x3ffffffUL;
            h[0] += carry * 5;
            carry = h[0] >> 26;
            h[0] &= 0x3ffffffUL;
            h[1] += carry;

            ULONG g[5] = {};
            g[0] = h[0] + 5;
            carry = g[0] >> 26;
            g[0] &= 0x3ffffffUL;
            for (SIZE_T index = 1; index < 4; ++index) {
                g[index] = h[index] + carry;
                carry = g[index] >> 26;
                g[index] &= 0x3ffffffUL;
            }
            g[4] = h[4] + carry - (1UL << 26);

            const ULONG mask = (g[4] >> 31) - 1;
            const ULONG notMask = ~mask;
            for (SIZE_T index = 0; index < 5; ++index) {
                h[index] = (h[index] & notMask) | (g[index] & mask);
            }

            unsigned long long f0 =
                ((static_cast<unsigned long long>(h[0]) |
                    (static_cast<unsigned long long>(h[1]) << 26)) & 0xffffffffULL) +
                ReadLittleEndian32(key + 16);
            unsigned long long f1 =
                (((static_cast<unsigned long long>(h[1]) >> 6) |
                    (static_cast<unsigned long long>(h[2]) << 20)) & 0xffffffffULL) +
                ReadLittleEndian32(key + 20) +
                (f0 >> 32);
            unsigned long long f2 =
                (((static_cast<unsigned long long>(h[2]) >> 12) |
                    (static_cast<unsigned long long>(h[3]) << 14)) & 0xffffffffULL) +
                ReadLittleEndian32(key + 24) +
                (f1 >> 32);
            unsigned long long f3 =
                (((static_cast<unsigned long long>(h[3]) >> 18) |
                    (static_cast<unsigned long long>(h[4]) << 8)) & 0xffffffffULL) +
                ReadLittleEndian32(key + 28) +
                (f2 >> 32);

            WriteLittleEndian32(static_cast<ULONG>(f0), tag);
            WriteLittleEndian32(static_cast<ULONG>(f1), tag + 4);
            WriteLittleEndian32(static_cast<ULONG>(f2), tag + 8);
            WriteLittleEndian32(static_cast<ULONG>(f3), tag + 12);

            RtlSecureZeroMemory(r, sizeof(r));
            RtlSecureZeroMemory(h, sizeof(h));
            RtlSecureZeroMemory(g, sizeof(g));
        }

        _Must_inspect_result_
        NTSTATUS BuildChaCha20Poly1305MacInput(
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(ciphertextLength) const UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_ HeapArray<UCHAR>& macInput,
            _Out_ SIZE_T* macInputLength) noexcept
        {
            if (macInputLength != nullptr) {
                *macInputLength = 0;
            }

            if (!IsValidBuffer(parameters.Aad.Data, parameters.Aad.Length) ||
                !IsValidBuffer(ciphertext, ciphertextLength) ||
                macInputLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            const SIZE_T aadPadding = (16 - (parameters.Aad.Length % 16)) % 16;
            const SIZE_T ciphertextPadding = (16 - (ciphertextLength % 16)) % 16;
            const SIZE_T required =
                parameters.Aad.Length +
                aadPadding +
                ciphertextLength +
                ciphertextPadding +
                16;

            NTSTATUS status = macInput.Allocate(required);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T offset = 0;
            if (parameters.Aad.Length != 0) {
                RtlCopyMemory(macInput.Get() + offset, parameters.Aad.Data, parameters.Aad.Length);
                offset += parameters.Aad.Length;
            }
            offset += aadPadding;
            if (ciphertextLength != 0) {
                RtlCopyMemory(macInput.Get() + offset, ciphertext, ciphertextLength);
                offset += ciphertextLength;
            }
            offset += ciphertextPadding;
            WriteLittleEndian64(static_cast<ULONGLONG>(parameters.Aad.Length), macInput.Get() + offset);
            offset += 8;
            WriteLittleEndian64(static_cast<ULONGLONG>(ciphertextLength), macInput.Get() + offset);
            offset += 8;

            *macInputLength = offset;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateChaCha20Poly1305(
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters) noexcept
        {
            if (key.Key == nullptr ||
                key.KeyLength != AeadChaCha20Poly1305KeyLength ||
                parameters.Nonce.Data == nullptr ||
                parameters.Nonce.Length != AeadChaCha20Poly1305NonceLength ||
                !IsValidBuffer(parameters.Aad.Data, parameters.Aad.Length)) {
                return STATUS_INVALID_PARAMETER;
            }
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ChaCha20Poly1305Encrypt(
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(plaintextLength) const UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_writes_bytes_(ciphertextLength) UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(tagLength) UCHAR* tag,
            SIZE_T tagLength,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }

            NTSTATUS status = ValidateChaCha20Poly1305(key, parameters);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!IsValidBuffer(plaintext, plaintextLength) ||
                ciphertext == nullptr ||
                ciphertextLength < plaintextLength ||
                tag == nullptr ||
                tagLength != AeadChaCha20Poly1305TagLength) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR polyKey[32] = {};
            UCHAR block[ChaChaBlockLength] = {};
            ChaCha20Block(key.Key, 0, parameters.Nonce.Data, block);
            RtlCopyMemory(polyKey, block, sizeof(polyKey));
            RtlSecureZeroMemory(block, sizeof(block));

            status = ChaCha20Xor(
                key.Key,
                1,
                parameters.Nonce.Data,
                plaintext,
                plaintextLength,
                ciphertext,
                ciphertextLength);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(polyKey, sizeof(polyKey));
                return status;
            }

            HeapArray<UCHAR> macInput;
            SIZE_T macInputLength = 0;
            status = BuildChaCha20Poly1305MacInput(
                parameters,
                ciphertext,
                plaintextLength,
                macInput,
                &macInputLength);
            if (NT_SUCCESS(status)) {
                Poly1305(polyKey, macInput.Get(), macInputLength, tag);
                if (bytesWritten != nullptr) {
                    *bytesWritten = plaintextLength;
                }
            }

            RtlSecureZeroMemory(polyKey, sizeof(polyKey));
            if (macInput.IsValid()) {
                RtlSecureZeroMemory(macInput.Get(), macInput.Count());
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS ChaCha20Poly1305Decrypt(
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(ciphertextLength) const UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(plaintextLength) UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }

            NTSTATUS status = ValidateChaCha20Poly1305(key, parameters);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!IsValidBuffer(ciphertext, ciphertextLength) ||
                plaintext == nullptr ||
                plaintextLength < ciphertextLength ||
                parameters.Tag.Data == nullptr ||
                parameters.Tag.Length != AeadChaCha20Poly1305TagLength) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR polyKey[32] = {};
            UCHAR block[ChaChaBlockLength] = {};
            UCHAR expectedTag[AeadChaCha20Poly1305TagLength] = {};
            ChaCha20Block(key.Key, 0, parameters.Nonce.Data, block);
            RtlCopyMemory(polyKey, block, sizeof(polyKey));
            RtlSecureZeroMemory(block, sizeof(block));

            HeapArray<UCHAR> macInput;
            SIZE_T macInputLength = 0;
            status = BuildChaCha20Poly1305MacInput(
                parameters,
                ciphertext,
                ciphertextLength,
                macInput,
                &macInputLength);
            if (NT_SUCCESS(status)) {
                Poly1305(polyKey, macInput.Get(), macInputLength, expectedTag);
                if (!MemoryEquals(expectedTag, parameters.Tag.Data, sizeof(expectedTag))) {
                    status = STATUS_INVALID_SIGNATURE;
                }
            }

            if (NT_SUCCESS(status)) {
                status = ChaCha20Xor(
                    key.Key,
                    1,
                    parameters.Nonce.Data,
                    ciphertext,
                    ciphertextLength,
                    plaintext,
                    plaintextLength);
                if (NT_SUCCESS(status) && bytesWritten != nullptr) {
                    *bytesWritten = ciphertextLength;
                }
            }

            RtlSecureZeroMemory(polyKey, sizeof(polyKey));
            RtlSecureZeroMemory(expectedTag, sizeof(expectedTag));
            if (macInput.IsValid()) {
                RtlSecureZeroMemory(macInput.Get(), macInput.Count());
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS EncryptAesGcm(
            _In_opt_ const CngProviderCache* cache,
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(plaintextLength) const UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_writes_bytes_(ciphertextLength) UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(tagLength) UCHAR* tag,
            SIZE_T tagLength,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            AesGcmKey aesKey = {};
            aesKey.Key = key.Key;
            aesKey.KeyLength = key.KeyLength;

            AesGcmParameters aesParameters = {};
            aesParameters.Nonce = parameters.Nonce;
            aesParameters.Aad = parameters.Aad;
            aesParameters.Tag = parameters.Tag;

            return CngProvider::AesGcmEncrypt(
                cache,
                aesKey,
                aesParameters,
                plaintext,
                plaintextLength,
                ciphertext,
                ciphertextLength,
                tag,
                tagLength,
                bytesWritten);
        }

        _Must_inspect_result_
        NTSTATUS DecryptAesGcm(
            _In_opt_ const CngProviderCache* cache,
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(ciphertextLength) const UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(plaintextLength) UCHAR* plaintext,
            SIZE_T plaintextLength,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            AesGcmKey aesKey = {};
            aesKey.Key = key.Key;
            aesKey.KeyLength = key.KeyLength;

            AesGcmParameters aesParameters = {};
            aesParameters.Nonce = parameters.Nonce;
            aesParameters.Aad = parameters.Aad;
            aesParameters.Tag = parameters.Tag;

            return CngProvider::AesGcmDecrypt(
                cache,
                aesKey,
                aesParameters,
                ciphertext,
                ciphertextLength,
                plaintext,
                plaintextLength,
                bytesWritten);
        }
    }

    SIZE_T Aead::TagLength(AeadAlgorithm algorithm) noexcept
    {
        switch (algorithm) {
        case AeadAlgorithm::Aes128Gcm:
        case AeadAlgorithm::Aes256Gcm:
        case AeadAlgorithm::ChaCha20Poly1305:
        case AeadAlgorithm::Aes128Ccm:
            return 16;
        case AeadAlgorithm::Aes128Ccm8:
            return 8;
        default:
            return 0;
        }
    }

    NTSTATUS Aead::Encrypt(
        const CngProviderCache* cache,
        const AeadKey& key,
        const AeadParameters& parameters,
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

        switch (key.Algorithm) {
        case AeadAlgorithm::Aes128Gcm:
            if (key.KeyLength != 16) {
                return STATUS_INVALID_PARAMETER;
            }
            return EncryptAesGcm(cache, key, parameters, plaintext, plaintextLength, ciphertext, ciphertextLength, tag, tagLength, bytesWritten);
        case AeadAlgorithm::Aes256Gcm:
            if (key.KeyLength != 32) {
                return STATUS_INVALID_PARAMETER;
            }
            return EncryptAesGcm(cache, key, parameters, plaintext, plaintextLength, ciphertext, ciphertextLength, tag, tagLength, bytesWritten);
        case AeadAlgorithm::ChaCha20Poly1305:
            UNREFERENCED_PARAMETER(cache);
            return ChaCha20Poly1305Encrypt(key, parameters, plaintext, plaintextLength, ciphertext, ciphertextLength, tag, tagLength, bytesWritten);
        case AeadAlgorithm::Aes128Ccm:
        case AeadAlgorithm::Aes128Ccm8:
            return STATUS_NOT_SUPPORTED;
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }

    NTSTATUS Aead::Decrypt(
        const CngProviderCache* cache,
        const AeadKey& key,
        const AeadParameters& parameters,
        const UCHAR* ciphertext,
        SIZE_T ciphertextLength,
        UCHAR* plaintext,
        SIZE_T plaintextLength,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        switch (key.Algorithm) {
        case AeadAlgorithm::Aes128Gcm:
            if (key.KeyLength != 16) {
                return STATUS_INVALID_PARAMETER;
            }
            return DecryptAesGcm(cache, key, parameters, ciphertext, ciphertextLength, plaintext, plaintextLength, bytesWritten);
        case AeadAlgorithm::Aes256Gcm:
            if (key.KeyLength != 32) {
                return STATUS_INVALID_PARAMETER;
            }
            return DecryptAesGcm(cache, key, parameters, ciphertext, ciphertextLength, plaintext, plaintextLength, bytesWritten);
        case AeadAlgorithm::ChaCha20Poly1305:
            UNREFERENCED_PARAMETER(cache);
            return ChaCha20Poly1305Decrypt(key, parameters, ciphertext, ciphertextLength, plaintext, plaintextLength, bytesWritten);
        case AeadAlgorithm::Aes128Ccm:
        case AeadAlgorithm::Aes128Ccm8:
            return STATUS_NOT_SUPPORTED;
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }
}
}
