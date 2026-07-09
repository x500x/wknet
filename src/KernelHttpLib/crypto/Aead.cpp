#include <KernelHttp/crypto/Aead.h>
#include <KernelHttp/crypto/CngProviderCache.h>

namespace KernelHttp
{
namespace crypto
{
    namespace
    {
        constexpr SIZE_T AesBlockLength = 16;
        constexpr SIZE_T Aes128KeyLength = 16;
        constexpr SIZE_T Aes128RoundKeyLength = 176;
        constexpr SIZE_T ChaChaBlockLength = 64;

        struct Aes128Context final
        {
            UCHAR RoundKeys[Aes128RoundKeyLength] = {};
        };

        struct AeadScratch final
        {
            UCHAR AesTemp[4] = {};
            UCHAR AesState[AesBlockLength] = {};
            UCHAR CcmBlock[AesBlockLength] = {};
            UCHAR CcmCounter[AesBlockLength] = {};
            UCHAR CcmStream[AesBlockLength] = {};
            UCHAR CcmMac[AeadMaxTagLength] = {};
            UCHAR GcmHashSubkey[AesBlockLength] = {};
            UCHAR GcmState[AesBlockLength] = {};
            UCHAR GcmBlock[AesBlockLength] = {};
            UCHAR GcmCounter[AesBlockLength] = {};
            UCHAR GcmJ0[AesBlockLength] = {};
            UCHAR GcmStream[AesBlockLength] = {};
            UCHAR GcmProduct[AesBlockLength] = {};
            UCHAR GcmExpectedTag[AeadMaxTagLength] = {};
            ULONG ChaChaState[16] = {};
            ULONG ChaChaWorking[16] = {};
            UCHAR ChaChaBlock[ChaChaBlockLength] = {};
            ULONG PolyValues[5] = {};
            UCHAR PolyPadded[17] = {};
            ULONG PolyR[5] = {};
            ULONG PolyH[5] = {};
            ULONG PolyG[5] = {};
            UCHAR PolyKey[32] = {};
            UCHAR ExpectedTag[AeadMaxTagLength] = {};
        };

        class AeadScratchGuard final
        {
        public:
            AeadScratchGuard() noexcept = default;

            ~AeadScratchGuard() noexcept
            {
                if (scratch_.IsValid()) {
                    RtlSecureZeroMemory(scratch_.Get(), sizeof(AeadScratch));
                }
            }

            AeadScratchGuard(const AeadScratchGuard&) = delete;
            AeadScratchGuard& operator=(const AeadScratchGuard&) = delete;

            _Must_inspect_result_
            bool IsValid() const noexcept
            {
                return scratch_.IsValid();
            }

            AeadScratch& Get() noexcept
            {
                return *scratch_.Get();
            }

        private:
            HeapObject<AeadScratch> scratch_;
        };

        const UCHAR AesSBox[256] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
            0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
            0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
            0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
            0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
            0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
            0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
            0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
            0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
            0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
            0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
            0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
            0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        const UCHAR AesRcon[10] = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
            0x1b, 0x36
        };

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

        void WriteBigEndianLength(
            ULONGLONG value,
            _Out_writes_bytes_(length) UCHAR* data,
            SIZE_T length) noexcept
        {
            for (SIZE_T index = 0; index < length; ++index) {
                const SIZE_T shift = (length - 1 - index) * 8;
                data[index] = static_cast<UCHAR>((value >> shift) & 0xff);
            }
        }

        void Aes128EncryptBlock(
            _In_ const Aes128Context& context,
            _Inout_ AeadScratch& scratch,
            _In_reads_bytes_(AesBlockLength) const UCHAR* input,
            _Out_writes_bytes_(AesBlockLength) UCHAR* output) noexcept;

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        void IncrementGcmCounter(_Inout_updates_(AesBlockLength) UCHAR* counter) noexcept
        {
            for (SIZE_T index = AesBlockLength; index > AesBlockLength - sizeof(ULONG); --index) {
                ++counter[index - 1];
                if (counter[index - 1] != 0) {
                    break;
                }
            }
        }

        void ShiftRightBlock(_Inout_updates_(AesBlockLength) UCHAR* block) noexcept
        {
            UCHAR carry = 0;
            for (SIZE_T index = 0; index < AesBlockLength; ++index) {
                const UCHAR nextCarry = static_cast<UCHAR>(block[index] & 1U);
                block[index] = static_cast<UCHAR>((block[index] >> 1) | (carry << 7));
                carry = nextCarry;
            }
        }

        void GcmMultiply(
            _In_reads_bytes_(AesBlockLength) const UCHAR* left,
            _In_reads_bytes_(AesBlockLength) const UCHAR* hashSubkey,
            _Out_writes_bytes_(AesBlockLength) UCHAR* product,
            _Out_writes_bytes_(AesBlockLength) UCHAR* scratch) noexcept
        {
            RtlZeroMemory(product, AesBlockLength);
            RtlCopyMemory(scratch, hashSubkey, AesBlockLength);

            for (SIZE_T bit = 0; bit < AesBlockLength * 8; ++bit) {
                const SIZE_T byteIndex = bit / 8;
                const UCHAR mask = static_cast<UCHAR>(0x80U >> (bit % 8));
                if ((left[byteIndex] & mask) != 0) {
                    for (SIZE_T index = 0; index < AesBlockLength; ++index) {
                        product[index] = static_cast<UCHAR>(product[index] ^ scratch[index]);
                    }
                }

                const bool carry = (scratch[AesBlockLength - 1] & 1U) != 0;
                ShiftRightBlock(scratch);
                if (carry) {
                    scratch[0] = static_cast<UCHAR>(scratch[0] ^ 0xe1U);
                }
            }
        }

        void GcmHashBlock(
            _In_reads_bytes_(AesBlockLength) const UCHAR* hashSubkey,
            _In_reads_bytes_(AesBlockLength) const UCHAR* block,
            _Inout_ AeadScratch& scratch) noexcept
        {
            for (SIZE_T index = 0; index < AesBlockLength; ++index) {
                scratch.GcmBlock[index] = static_cast<UCHAR>(scratch.GcmState[index] ^ block[index]);
            }

            GcmMultiply(scratch.GcmBlock, hashSubkey, scratch.GcmState, scratch.GcmProduct);
            RtlSecureZeroMemory(scratch.GcmBlock, sizeof(scratch.GcmBlock));
            RtlSecureZeroMemory(scratch.GcmProduct, sizeof(scratch.GcmProduct));
        }

        void GcmHashBytes(
            _In_reads_bytes_(AesBlockLength) const UCHAR* hashSubkey,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Inout_ AeadScratch& scratch) noexcept
        {
            SIZE_T offset = 0;
            while (offset < dataLength) {
                RtlZeroMemory(scratch.GcmBlock, sizeof(scratch.GcmBlock));
                const SIZE_T chunk = dataLength - offset < AesBlockLength ? dataLength - offset : AesBlockLength;
                RtlCopyMemory(scratch.GcmBlock, data + offset, chunk);
                GcmHashBlock(hashSubkey, scratch.GcmBlock, scratch);
                offset += chunk;
            }
        }

        NTSTATUS GcmComputeTag(
            _In_ const Aes128Context& context,
            _In_reads_bytes_(AesBlockLength) const UCHAR* hashSubkey,
            _In_reads_bytes_(AesBlockLength) const UCHAR* j0,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(ciphertextLength) const UCHAR* ciphertext,
            SIZE_T ciphertextLength,
            _Out_writes_bytes_(tagLength) UCHAR* tag,
            SIZE_T tagLength,
            _Inout_ AeadScratch& scratch) noexcept
        {
            if (tag == nullptr || tagLength != AeadMaxTagLength) {
                return STATUS_INVALID_PARAMETER;
            }

            RtlZeroMemory(scratch.GcmState, sizeof(scratch.GcmState));
            GcmHashBytes(hashSubkey, parameters.Aad.Data, parameters.Aad.Length, scratch);
            GcmHashBytes(hashSubkey, ciphertext, ciphertextLength, scratch);

            RtlZeroMemory(scratch.GcmBlock, sizeof(scratch.GcmBlock));
            WriteBigEndianLength(static_cast<ULONGLONG>(parameters.Aad.Length) * 8ULL, scratch.GcmBlock, sizeof(ULONGLONG));
            WriteBigEndianLength(
                static_cast<ULONGLONG>(ciphertextLength) * 8ULL,
                scratch.GcmBlock + sizeof(ULONGLONG),
                sizeof(ULONGLONG));
            GcmHashBlock(hashSubkey, scratch.GcmBlock, scratch);

            Aes128EncryptBlock(context, scratch, j0, scratch.GcmStream);
            for (SIZE_T index = 0; index < tagLength; ++index) {
                tag[index] = static_cast<UCHAR>(scratch.GcmStream[index] ^ scratch.GcmState[index]);
            }

            RtlSecureZeroMemory(scratch.GcmState, sizeof(scratch.GcmState));
            RtlSecureZeroMemory(scratch.GcmBlock, sizeof(scratch.GcmBlock));
            RtlSecureZeroMemory(scratch.GcmStream, sizeof(scratch.GcmStream));
            return STATUS_SUCCESS;
        }

        NTSTATUS ValidateAes128GcmSoftware(
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(inputLength) const UCHAR* input,
            SIZE_T inputLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _In_reads_bytes_opt_(tagLength) const UCHAR* tag,
            SIZE_T tagLength) noexcept
        {
            if (key.Key == nullptr ||
                key.KeyLength != Aes128KeyLength ||
                parameters.Nonce.Data == nullptr ||
                parameters.Nonce.Length != 12 ||
                (parameters.Aad.Data == nullptr && parameters.Aad.Length != 0) ||
                (input == nullptr && inputLength != 0) ||
                output == nullptr ||
                outputLength < inputLength ||
                (tag == nullptr && tagLength != 0) ||
                tagLength != AeadMaxTagLength) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }
#endif

        _Must_inspect_result_
        UCHAR AesGfMul2(UCHAR value) noexcept
        {
            return static_cast<UCHAR>((value << 1) ^ ((value & 0x80) != 0 ? 0x1b : 0x00));
        }

        void AesAddRoundKey(
            _Inout_updates_(AesBlockLength) UCHAR* state,
            _In_reads_bytes_(AesBlockLength) const UCHAR* roundKey) noexcept
        {
            for (SIZE_T index = 0; index < AesBlockLength; ++index) {
                state[index] = static_cast<UCHAR>(state[index] ^ roundKey[index]);
            }
        }

        void AesSubBytes(_Inout_updates_(AesBlockLength) UCHAR* state) noexcept
        {
            for (SIZE_T index = 0; index < AesBlockLength; ++index) {
                state[index] = AesSBox[state[index]];
            }
        }

        void AesShiftRows(_Inout_updates_(AesBlockLength) UCHAR* state) noexcept
        {
            const UCHAR s1 = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = s1;

            const UCHAR s2 = state[2];
            const UCHAR s6 = state[6];
            state[2] = state[10];
            state[6] = state[14];
            state[10] = s2;
            state[14] = s6;

            const UCHAR s3 = state[3];
            state[3] = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = s3;
        }

        void AesMixColumns(_Inout_updates_(AesBlockLength) UCHAR* state) noexcept
        {
            for (SIZE_T column = 0; column < 4; ++column) {
                UCHAR* c = state + (column * 4);
                const UCHAR a0 = c[0];
                const UCHAR a1 = c[1];
                const UCHAR a2 = c[2];
                const UCHAR a3 = c[3];
                const UCHAR t = static_cast<UCHAR>(a0 ^ a1 ^ a2 ^ a3);
                const UCHAR u = a0;
                c[0] = static_cast<UCHAR>(a0 ^ t ^ AesGfMul2(static_cast<UCHAR>(a0 ^ a1)));
                c[1] = static_cast<UCHAR>(a1 ^ t ^ AesGfMul2(static_cast<UCHAR>(a1 ^ a2)));
                c[2] = static_cast<UCHAR>(a2 ^ t ^ AesGfMul2(static_cast<UCHAR>(a2 ^ a3)));
                c[3] = static_cast<UCHAR>(a3 ^ t ^ AesGfMul2(static_cast<UCHAR>(a3 ^ u)));
            }
        }

        _Must_inspect_result_
        NTSTATUS Aes128Initialize(
            _In_ const AeadKey& key,
            _Inout_ AeadScratch& scratch,
            _Out_ Aes128Context& context) noexcept
        {
            if (key.Key == nullptr || key.KeyLength != Aes128KeyLength) {
                return STATUS_INVALID_PARAMETER;
            }

            RtlCopyMemory(context.RoundKeys, key.Key, Aes128KeyLength);
            SIZE_T bytesGenerated = Aes128KeyLength;
            SIZE_T rconIndex = 0;
            UCHAR* temp = scratch.AesTemp;
            RtlZeroMemory(temp, sizeof(scratch.AesTemp));

            while (bytesGenerated < Aes128RoundKeyLength) {
                for (SIZE_T index = 0; index < sizeof(scratch.AesTemp); ++index) {
                    temp[index] = context.RoundKeys[bytesGenerated - 4 + index];
                }

                if ((bytesGenerated % Aes128KeyLength) == 0) {
                    const UCHAR rotate = temp[0];
                    temp[0] = AesSBox[temp[1]];
                    temp[1] = AesSBox[temp[2]];
                    temp[2] = AesSBox[temp[3]];
                    temp[3] = AesSBox[rotate];
                    temp[0] = static_cast<UCHAR>(temp[0] ^ AesRcon[rconIndex]);
                    ++rconIndex;
                }

                for (SIZE_T index = 0; index < sizeof(scratch.AesTemp); ++index) {
                    context.RoundKeys[bytesGenerated] =
                        static_cast<UCHAR>(context.RoundKeys[bytesGenerated - Aes128KeyLength] ^ temp[index]);
                    ++bytesGenerated;
                }
            }

            RtlSecureZeroMemory(temp, sizeof(scratch.AesTemp));
            return STATUS_SUCCESS;
        }

        void Aes128EncryptBlock(
            _In_ const Aes128Context& context,
            _Inout_ AeadScratch& scratch,
            _In_reads_bytes_(AesBlockLength) const UCHAR* input,
            _Out_writes_bytes_(AesBlockLength) UCHAR* output) noexcept
        {
            UCHAR* state = scratch.AesState;
            RtlZeroMemory(state, sizeof(scratch.AesState));
            RtlCopyMemory(state, input, sizeof(scratch.AesState));

            AesAddRoundKey(state, context.RoundKeys);
            for (SIZE_T round = 1; round < 10; ++round) {
                AesSubBytes(state);
                AesShiftRows(state);
                AesMixColumns(state);
                AesAddRoundKey(state, context.RoundKeys + (round * AesBlockLength));
            }

            AesSubBytes(state);
            AesShiftRows(state);
            AesAddRoundKey(state, context.RoundKeys + (10 * AesBlockLength));

            RtlCopyMemory(output, state, sizeof(scratch.AesState));
            RtlSecureZeroMemory(state, sizeof(scratch.AesState));
        }

        _Must_inspect_result_
        bool CcmPayloadLengthFits(SIZE_T payloadLength, SIZE_T lengthFieldLength) noexcept
        {
            if (lengthFieldLength >= sizeof(SIZE_T)) {
                return true;
            }

            const SIZE_T maxLength = (static_cast<SIZE_T>(1) << (lengthFieldLength * 8)) - 1;
            return payloadLength <= maxLength;
        }

        void BuildCcmCounterBlock(
            _In_reads_bytes_(nonceLength) const UCHAR* nonce,
            SIZE_T nonceLength,
            SIZE_T counterValue,
            _Out_writes_bytes_(AesBlockLength) UCHAR* counterBlock) noexcept
        {
            const SIZE_T lengthFieldLength = AesBlockLength - 1 - nonceLength;
            RtlZeroMemory(counterBlock, AesBlockLength);
            counterBlock[0] = static_cast<UCHAR>(lengthFieldLength - 1);
            RtlCopyMemory(counterBlock + 1, nonce, nonceLength);
            WriteBigEndianLength(static_cast<ULONGLONG>(counterValue), counterBlock + 1 + nonceLength, lengthFieldLength);
        }

        void CcmMacBlock(
            _In_ const Aes128Context& context,
            _Inout_ AeadScratch& scratch,
            _In_reads_bytes_(AesBlockLength) const UCHAR* block,
            _Inout_updates_(AesBlockLength) UCHAR* mac) noexcept
        {
            for (SIZE_T index = 0; index < AesBlockLength; ++index) {
                mac[index] = static_cast<UCHAR>(mac[index] ^ block[index]);
            }
            Aes128EncryptBlock(context, scratch, mac, mac);
        }

        _Must_inspect_result_
        NTSTATUS CcmComputeMac(
            _In_ const Aes128Context& context,
            _Inout_ AeadScratch& scratch,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(plaintextLength) const UCHAR* plaintext,
            SIZE_T plaintextLength,
            SIZE_T tagLength,
            _Out_writes_bytes_(AeadMaxTagLength) UCHAR* mac) noexcept
        {
            const SIZE_T nonceLength = parameters.Nonce.Length;
            const SIZE_T lengthFieldLength = AesBlockLength - 1 - nonceLength;
            if (!CcmPayloadLengthFits(plaintextLength, lengthFieldLength) ||
                parameters.Aad.Length >= 0xff00) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR* block = scratch.CcmBlock;
            RtlZeroMemory(block, sizeof(scratch.CcmBlock));
            block[0] = static_cast<UCHAR>(
                (parameters.Aad.Length != 0 ? 0x40 : 0) |
                (((tagLength - 2) / 2) << 3) |
                (lengthFieldLength - 1));
            RtlCopyMemory(block + 1, parameters.Nonce.Data, nonceLength);
            WriteBigEndianLength(static_cast<ULONGLONG>(plaintextLength), block + 1 + nonceLength, lengthFieldLength);
            CcmMacBlock(context, scratch, block, mac);

            SIZE_T aadOffset = 0;
            if (parameters.Aad.Length != 0) {
                RtlZeroMemory(block, sizeof(scratch.CcmBlock));
                block[0] = static_cast<UCHAR>((parameters.Aad.Length >> 8) & 0xff);
                block[1] = static_cast<UCHAR>(parameters.Aad.Length & 0xff);
                SIZE_T blockOffset = 2;
                while (aadOffset < parameters.Aad.Length) {
                    const SIZE_T chunk =
                        (parameters.Aad.Length - aadOffset) < (AesBlockLength - blockOffset) ?
                        (parameters.Aad.Length - aadOffset) :
                        (AesBlockLength - blockOffset);
                    RtlCopyMemory(block + blockOffset, parameters.Aad.Data + aadOffset, chunk);
                    blockOffset += chunk;
                    aadOffset += chunk;
                    if (blockOffset == AesBlockLength) {
                        CcmMacBlock(context, scratch, block, mac);
                        RtlZeroMemory(block, sizeof(scratch.CcmBlock));
                        blockOffset = 0;
                    }
                }
                if (blockOffset != 0) {
                    CcmMacBlock(context, scratch, block, mac);
                }
            }

            SIZE_T plaintextOffset = 0;
            while (plaintextOffset < plaintextLength) {
                RtlZeroMemory(block, sizeof(scratch.CcmBlock));
                const SIZE_T chunk =
                    (plaintextLength - plaintextOffset) < AesBlockLength ?
                    (plaintextLength - plaintextOffset) :
                    AesBlockLength;
                RtlCopyMemory(block, plaintext + plaintextOffset, chunk);
                CcmMacBlock(context, scratch, block, mac);
                plaintextOffset += chunk;
            }

            RtlSecureZeroMemory(block, sizeof(scratch.CcmBlock));
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS CcmCrypt(
            _In_ const Aes128Context& context,
            _Inout_ AeadScratch& scratch,
            _In_ const AeadParameters& parameters,
            _In_reads_bytes_opt_(inputLength) const UCHAR* input,
            SIZE_T inputLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept
        {
            if (!IsValidBuffer(input, inputLength) ||
                !IsValidMutableBuffer(output, outputLength) ||
                outputLength < inputLength) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR* counter = scratch.CcmCounter;
            UCHAR* stream = scratch.CcmStream;
            RtlZeroMemory(counter, sizeof(scratch.CcmCounter));
            RtlZeroMemory(stream, sizeof(scratch.CcmStream));
            SIZE_T offset = 0;
            SIZE_T counterValue = 1;
            while (offset < inputLength) {
                BuildCcmCounterBlock(parameters.Nonce.Data, parameters.Nonce.Length, counterValue, counter);
                Aes128EncryptBlock(context, scratch, counter, stream);

                const SIZE_T chunk =
                    (inputLength - offset) < AesBlockLength ?
                    (inputLength - offset) :
                    AesBlockLength;
                for (SIZE_T index = 0; index < chunk; ++index) {
                    output[offset + index] = static_cast<UCHAR>(input[offset + index] ^ stream[index]);
                }

                offset += chunk;
                if (counterValue == static_cast<SIZE_T>(-1)) {
                    RtlSecureZeroMemory(counter, sizeof(scratch.CcmCounter));
                    RtlSecureZeroMemory(stream, sizeof(scratch.CcmStream));
                    return STATUS_INTEGER_OVERFLOW;
                }
                ++counterValue;
            }

            RtlSecureZeroMemory(counter, sizeof(scratch.CcmCounter));
            RtlSecureZeroMemory(stream, sizeof(scratch.CcmStream));
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateAesCcm(
            _In_ const AeadKey& key,
            _In_ const AeadParameters& parameters,
            SIZE_T tagLength) noexcept
        {
            if (key.Key == nullptr ||
                key.KeyLength != Aes128KeyLength ||
                parameters.Nonce.Data == nullptr ||
                parameters.Nonce.Length < 7 ||
                parameters.Nonce.Length > 13 ||
                !IsValidBuffer(parameters.Aad.Data, parameters.Aad.Length) ||
                (tagLength != 8 && tagLength != 16)) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
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
            _Inout_ AeadScratch& scratch,
            _In_reads_bytes_(AeadChaCha20Poly1305KeyLength) const UCHAR* key,
            ULONG counter,
            _In_reads_bytes_(AeadChaCha20Poly1305NonceLength) const UCHAR* nonce,
            _Out_writes_bytes_(ChaChaBlockLength) UCHAR* output) noexcept
        {
            ULONG* state = scratch.ChaChaState;
            ULONG* working = scratch.ChaChaWorking;
            state[0] = 0x61707865UL;
            state[1] = 0x3320646eUL;
            state[2] = 0x79622d32UL;
            state[3] = 0x6b206574UL;
            state[4] = ReadLittleEndian32(key);
            state[5] = ReadLittleEndian32(key + 4);
            state[6] = ReadLittleEndian32(key + 8);
            state[7] = ReadLittleEndian32(key + 12);
            state[8] = ReadLittleEndian32(key + 16);
            state[9] = ReadLittleEndian32(key + 20);
            state[10] = ReadLittleEndian32(key + 24);
            state[11] = ReadLittleEndian32(key + 28);
            state[12] = counter;
            state[13] = ReadLittleEndian32(nonce);
            state[14] = ReadLittleEndian32(nonce + 4);
            state[15] = ReadLittleEndian32(nonce + 8);

            RtlZeroMemory(working, sizeof(scratch.ChaChaWorking));
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

            RtlSecureZeroMemory(state, sizeof(scratch.ChaChaState));
            RtlSecureZeroMemory(working, sizeof(scratch.ChaChaWorking));
        }

        _Must_inspect_result_
        NTSTATUS ChaCha20Xor(
            _Inout_ AeadScratch& scratch,
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

            UCHAR* block = scratch.ChaChaBlock;
            RtlZeroMemory(block, sizeof(scratch.ChaChaBlock));
            SIZE_T offset = 0;
            while (offset < inputLength) {
                ChaCha20Block(scratch, key, counter, nonce, block);
                ++counter;

                const SIZE_T remaining = inputLength - offset;
                const SIZE_T chunk = remaining < ChaChaBlockLength ? remaining : ChaChaBlockLength;
                for (SIZE_T index = 0; index < chunk; ++index) {
                    output[offset + index] = static_cast<UCHAR>(input[offset + index] ^ block[index]);
                }
                offset += chunk;
            }

            RtlSecureZeroMemory(block, sizeof(scratch.ChaChaBlock));
            return STATUS_SUCCESS;
        }

        void Poly1305ProcessBlock(
            _Inout_ AeadScratch& scratch,
            _Inout_updates_(5) ULONG h[5],
            _In_reads_(5) const ULONG r[5],
            _In_reads_bytes_(blockLength) const UCHAR* block,
            SIZE_T blockLength) noexcept
        {
            ULONG* values = scratch.PolyValues;
            UCHAR* padded = scratch.PolyPadded;
            RtlZeroMemory(values, sizeof(scratch.PolyValues));
            RtlZeroMemory(padded, sizeof(scratch.PolyPadded));
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

            RtlSecureZeroMemory(values, sizeof(scratch.PolyValues));
            RtlSecureZeroMemory(padded, sizeof(scratch.PolyPadded));
        }

        void Poly1305(
            _Inout_ AeadScratch& scratch,
            _In_reads_bytes_(32) const UCHAR* key,
            _In_reads_bytes_opt_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _Out_writes_bytes_(16) UCHAR* tag) noexcept
        {
            ULONG* r = scratch.PolyR;
            ULONG* h = scratch.PolyH;
            ULONG* g = scratch.PolyG;
            RtlZeroMemory(r, sizeof(scratch.PolyR));
            RtlZeroMemory(h, sizeof(scratch.PolyH));
            RtlZeroMemory(g, sizeof(scratch.PolyG));

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
                Poly1305ProcessBlock(scratch, h, r, message + offset, chunk);
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

            RtlSecureZeroMemory(r, sizeof(scratch.PolyR));
            RtlSecureZeroMemory(h, sizeof(scratch.PolyH));
            RtlSecureZeroMemory(g, sizeof(scratch.PolyG));
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

            AeadScratchGuard scratchGuard;
            if (!scratchGuard.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            AeadScratch& scratch = scratchGuard.Get();
            UCHAR* polyKey = scratch.PolyKey;
            UCHAR* block = scratch.ChaChaBlock;
            ChaCha20Block(scratch, key.Key, 0, parameters.Nonce.Data, block);
            RtlCopyMemory(polyKey, block, sizeof(scratch.PolyKey));
            RtlSecureZeroMemory(block, sizeof(scratch.ChaChaBlock));

            status = ChaCha20Xor(
                scratch,
                key.Key,
                1,
                parameters.Nonce.Data,
                plaintext,
                plaintextLength,
                ciphertext,
                ciphertextLength);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(polyKey, sizeof(scratch.PolyKey));
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
                Poly1305(scratch, polyKey, macInput.Get(), macInputLength, tag);
                if (bytesWritten != nullptr) {
                    *bytesWritten = plaintextLength;
                }
            }

            RtlSecureZeroMemory(polyKey, sizeof(scratch.PolyKey));
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

            AeadScratchGuard scratchGuard;
            if (!scratchGuard.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            AeadScratch& scratch = scratchGuard.Get();
            UCHAR* polyKey = scratch.PolyKey;
            UCHAR* block = scratch.ChaChaBlock;
            UCHAR* expectedTag = scratch.ExpectedTag;
            RtlZeroMemory(expectedTag, AeadChaCha20Poly1305TagLength);
            ChaCha20Block(scratch, key.Key, 0, parameters.Nonce.Data, block);
            RtlCopyMemory(polyKey, block, sizeof(scratch.PolyKey));
            RtlSecureZeroMemory(block, sizeof(scratch.ChaChaBlock));

            HeapArray<UCHAR> macInput;
            SIZE_T macInputLength = 0;
            status = BuildChaCha20Poly1305MacInput(
                parameters,
                ciphertext,
                ciphertextLength,
                macInput,
                &macInputLength);
            if (NT_SUCCESS(status)) {
                Poly1305(scratch, polyKey, macInput.Get(), macInputLength, expectedTag);
                if (!MemoryEquals(expectedTag, parameters.Tag.Data, AeadChaCha20Poly1305TagLength)) {
                    status = STATUS_INVALID_SIGNATURE;
                }
            }

            if (NT_SUCCESS(status)) {
                status = ChaCha20Xor(
                    scratch,
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

            RtlSecureZeroMemory(polyKey, sizeof(scratch.PolyKey));
            RtlSecureZeroMemory(expectedTag, AeadChaCha20Poly1305TagLength);
            if (macInput.IsValid()) {
                RtlSecureZeroMemory(macInput.Get(), macInput.Count());
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS AesCcmEncrypt(
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

            NTSTATUS status = ValidateAesCcm(key, parameters, tagLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!IsValidBuffer(plaintext, plaintextLength) ||
                !IsValidMutableBuffer(ciphertext, ciphertextLength) ||
                ciphertextLength < plaintextLength ||
                tag == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapObject<Aes128Context> context;
            if (!context.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            AeadScratchGuard scratchGuard;
            if (!scratchGuard.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            AeadScratch& scratch = scratchGuard.Get();

            status = Aes128Initialize(key, scratch, *context.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            UCHAR* mac = scratch.CcmMac;
            RtlZeroMemory(mac, sizeof(scratch.CcmMac));
            status = CcmComputeMac(
                *context.Get(),
                scratch,
                parameters,
                plaintext,
                plaintextLength,
                tagLength,
                mac);
            if (NT_SUCCESS(status)) {
                status = CcmCrypt(
                    *context.Get(),
                    scratch,
                    parameters,
                    plaintext,
                    plaintextLength,
                    ciphertext,
                    ciphertextLength);
            }
            if (NT_SUCCESS(status)) {
                UCHAR* counter = scratch.CcmCounter;
                UCHAR* stream = scratch.CcmStream;
                RtlZeroMemory(counter, sizeof(scratch.CcmCounter));
                RtlZeroMemory(stream, sizeof(scratch.CcmStream));
                BuildCcmCounterBlock(parameters.Nonce.Data, parameters.Nonce.Length, 0, counter);
                Aes128EncryptBlock(*context.Get(), scratch, counter, stream);
                for (SIZE_T index = 0; index < tagLength; ++index) {
                    tag[index] = static_cast<UCHAR>(mac[index] ^ stream[index]);
                }
                if (bytesWritten != nullptr) {
                    *bytesWritten = plaintextLength;
                }
                RtlSecureZeroMemory(counter, sizeof(scratch.CcmCounter));
                RtlSecureZeroMemory(stream, sizeof(scratch.CcmStream));
            }

            RtlSecureZeroMemory(mac, sizeof(scratch.CcmMac));
            RtlSecureZeroMemory(context->RoundKeys, sizeof(context->RoundKeys));
            return status;
        }

        _Must_inspect_result_
        NTSTATUS AesCcmDecrypt(
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
            if (parameters.Tag.Data == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = ValidateAesCcm(key, parameters, parameters.Tag.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!IsValidBuffer(ciphertext, ciphertextLength) ||
                !IsValidMutableBuffer(plaintext, plaintextLength) ||
                plaintextLength < ciphertextLength) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapObject<Aes128Context> context;
            if (!context.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            AeadScratchGuard scratchGuard;
            if (!scratchGuard.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            AeadScratch& scratch = scratchGuard.Get();

            status = Aes128Initialize(key, scratch, *context.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = CcmCrypt(
                *context.Get(),
                scratch,
                parameters,
                ciphertext,
                ciphertextLength,
                plaintext,
                plaintextLength);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(context->RoundKeys, sizeof(context->RoundKeys));
                return status;
            }

            UCHAR* mac = scratch.CcmMac;
            RtlZeroMemory(mac, sizeof(scratch.CcmMac));
            status = CcmComputeMac(
                *context.Get(),
                scratch,
                parameters,
                plaintext,
                ciphertextLength,
                parameters.Tag.Length,
                mac);
            if (NT_SUCCESS(status)) {
                UCHAR* counter = scratch.CcmCounter;
                UCHAR* stream = scratch.CcmStream;
                UCHAR* expectedTag = scratch.ExpectedTag;
                RtlZeroMemory(counter, sizeof(scratch.CcmCounter));
                RtlZeroMemory(stream, sizeof(scratch.CcmStream));
                RtlZeroMemory(expectedTag, sizeof(scratch.ExpectedTag));
                BuildCcmCounterBlock(parameters.Nonce.Data, parameters.Nonce.Length, 0, counter);
                Aes128EncryptBlock(*context.Get(), scratch, counter, stream);
                for (SIZE_T index = 0; index < parameters.Tag.Length; ++index) {
                    expectedTag[index] = static_cast<UCHAR>(mac[index] ^ stream[index]);
                }
                if (!MemoryEquals(expectedTag, parameters.Tag.Data, parameters.Tag.Length)) {
                    RtlSecureZeroMemory(plaintext, plaintextLength);
                    status = STATUS_INVALID_SIGNATURE;
                }
                else if (bytesWritten != nullptr) {
                    *bytesWritten = ciphertextLength;
                }
                RtlSecureZeroMemory(counter, sizeof(scratch.CcmCounter));
                RtlSecureZeroMemory(stream, sizeof(scratch.CcmStream));
                RtlSecureZeroMemory(expectedTag, sizeof(scratch.ExpectedTag));
            }

            RtlSecureZeroMemory(mac, sizeof(scratch.CcmMac));
            RtlSecureZeroMemory(context->RoundKeys, sizeof(context->RoundKeys));
            return status;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        NTSTATUS Aes128GcmEncryptSoftware(
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

            NTSTATUS status = ValidateAes128GcmSoftware(
                key,
                parameters,
                plaintext,
                plaintextLength,
                ciphertext,
                ciphertextLength,
                tag,
                tagLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (plaintextLength != 0 && plaintext == ciphertext) {
                return STATUS_INVALID_PARAMETER;
            }

            AeadScratchGuard scratchGuard;
            HeapObject<Aes128Context> context;
            if (!scratchGuard.IsValid() || !context.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            AeadScratch& scratch = scratchGuard.Get();
            status = Aes128Initialize(key, scratch, *context.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            RtlZeroMemory(scratch.GcmBlock, sizeof(scratch.GcmBlock));
            Aes128EncryptBlock(*context.Get(), scratch, scratch.GcmBlock, scratch.GcmHashSubkey);

            RtlZeroMemory(scratch.GcmJ0, sizeof(scratch.GcmJ0));
            RtlCopyMemory(scratch.GcmJ0, parameters.Nonce.Data, parameters.Nonce.Length);
            scratch.GcmJ0[AesBlockLength - 1] = 1;
            RtlCopyMemory(scratch.GcmCounter, scratch.GcmJ0, sizeof(scratch.GcmCounter));

            SIZE_T offset = 0;
            while (offset < plaintextLength) {
                IncrementGcmCounter(scratch.GcmCounter);
                Aes128EncryptBlock(*context.Get(), scratch, scratch.GcmCounter, scratch.GcmStream);
                const SIZE_T chunk = plaintextLength - offset < AesBlockLength ? plaintextLength - offset : AesBlockLength;
                for (SIZE_T index = 0; index < chunk; ++index) {
                    ciphertext[offset + index] = static_cast<UCHAR>(plaintext[offset + index] ^ scratch.GcmStream[index]);
                }
                offset += chunk;
            }

            status = GcmComputeTag(
                *context.Get(),
                scratch.GcmHashSubkey,
                scratch.GcmJ0,
                parameters,
                ciphertext,
                plaintextLength,
                tag,
                tagLength,
                scratch);
            if (NT_SUCCESS(status) && bytesWritten != nullptr) {
                *bytesWritten = plaintextLength;
            }

            RtlSecureZeroMemory(scratch.GcmHashSubkey, sizeof(scratch.GcmHashSubkey));
            RtlSecureZeroMemory(scratch.GcmCounter, sizeof(scratch.GcmCounter));
            RtlSecureZeroMemory(scratch.GcmJ0, sizeof(scratch.GcmJ0));
            RtlSecureZeroMemory(scratch.GcmStream, sizeof(scratch.GcmStream));
            RtlSecureZeroMemory(context->RoundKeys, sizeof(context->RoundKeys));
            return status;
        }

        NTSTATUS Aes128GcmDecryptSoftware(
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

            NTSTATUS status = ValidateAes128GcmSoftware(
                key,
                parameters,
                ciphertext,
                ciphertextLength,
                plaintext,
                plaintextLength,
                parameters.Tag.Data,
                parameters.Tag.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (ciphertextLength != 0 && ciphertext == plaintext) {
                return STATUS_INVALID_PARAMETER;
            }

            AeadScratchGuard scratchGuard;
            HeapObject<Aes128Context> context;
            if (!scratchGuard.IsValid() || !context.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            AeadScratch& scratch = scratchGuard.Get();
            status = Aes128Initialize(key, scratch, *context.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            RtlZeroMemory(scratch.GcmBlock, sizeof(scratch.GcmBlock));
            Aes128EncryptBlock(*context.Get(), scratch, scratch.GcmBlock, scratch.GcmHashSubkey);

            RtlZeroMemory(scratch.GcmJ0, sizeof(scratch.GcmJ0));
            RtlCopyMemory(scratch.GcmJ0, parameters.Nonce.Data, parameters.Nonce.Length);
            scratch.GcmJ0[AesBlockLength - 1] = 1;

            status = GcmComputeTag(
                *context.Get(),
                scratch.GcmHashSubkey,
                scratch.GcmJ0,
                parameters,
                ciphertext,
                ciphertextLength,
                scratch.GcmExpectedTag,
                sizeof(scratch.GcmExpectedTag),
                scratch);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(context->RoundKeys, sizeof(context->RoundKeys));
                return status;
            }
            if (!MemoryEquals(scratch.GcmExpectedTag, parameters.Tag.Data, parameters.Tag.Length)) {
                RtlSecureZeroMemory(scratch.GcmExpectedTag, sizeof(scratch.GcmExpectedTag));
                RtlSecureZeroMemory(context->RoundKeys, sizeof(context->RoundKeys));
                return STATUS_INVALID_SIGNATURE;
            }

            RtlCopyMemory(scratch.GcmCounter, scratch.GcmJ0, sizeof(scratch.GcmCounter));
            SIZE_T offset = 0;
            while (offset < ciphertextLength) {
                IncrementGcmCounter(scratch.GcmCounter);
                Aes128EncryptBlock(*context.Get(), scratch, scratch.GcmCounter, scratch.GcmStream);
                const SIZE_T chunk = ciphertextLength - offset < AesBlockLength ? ciphertextLength - offset : AesBlockLength;
                for (SIZE_T index = 0; index < chunk; ++index) {
                    plaintext[offset + index] = static_cast<UCHAR>(ciphertext[offset + index] ^ scratch.GcmStream[index]);
                }
                offset += chunk;
            }

            if (bytesWritten != nullptr) {
                *bytesWritten = ciphertextLength;
            }

            RtlSecureZeroMemory(scratch.GcmHashSubkey, sizeof(scratch.GcmHashSubkey));
            RtlSecureZeroMemory(scratch.GcmCounter, sizeof(scratch.GcmCounter));
            RtlSecureZeroMemory(scratch.GcmJ0, sizeof(scratch.GcmJ0));
            RtlSecureZeroMemory(scratch.GcmStream, sizeof(scratch.GcmStream));
            RtlSecureZeroMemory(scratch.GcmExpectedTag, sizeof(scratch.GcmExpectedTag));
            RtlSecureZeroMemory(context->RoundKeys, sizeof(context->RoundKeys));
            return STATUS_SUCCESS;
        }
#endif

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
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            if (key.KeyLength == Aes128KeyLength && parameters.Nonce.Length == 12 && tagLength == AeadMaxTagLength) {
                return Aes128GcmEncryptSoftware(
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
#endif
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
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            if (key.KeyLength == Aes128KeyLength &&
                parameters.Nonce.Length == 12 &&
                parameters.Tag.Length == AeadMaxTagLength) {
                return Aes128GcmDecryptSoftware(
                    key,
                    parameters,
                    ciphertext,
                    ciphertextLength,
                    plaintext,
                    plaintextLength,
                    bytesWritten);
            }
#endif
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
            if (tagLength != 16) {
                return STATUS_INVALID_PARAMETER;
            }
            return AesCcmEncrypt(key, parameters, plaintext, plaintextLength, ciphertext, ciphertextLength, tag, tagLength, bytesWritten);
        case AeadAlgorithm::Aes128Ccm8:
            if (tagLength != 8) {
                return STATUS_INVALID_PARAMETER;
            }
            return AesCcmEncrypt(key, parameters, plaintext, plaintextLength, ciphertext, ciphertextLength, tag, tagLength, bytesWritten);
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
            if (parameters.Tag.Length != 16) {
                return STATUS_INVALID_PARAMETER;
            }
            return AesCcmDecrypt(key, parameters, ciphertext, ciphertextLength, plaintext, plaintextLength, bytesWritten);
        case AeadAlgorithm::Aes128Ccm8:
            if (parameters.Tag.Length != 8) {
                return STATUS_INVALID_PARAMETER;
            }
            return AesCcmDecrypt(key, parameters, ciphertext, ciphertextLength, plaintext, plaintextLength, bytesWritten);
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }
}
}
