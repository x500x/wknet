#include "http1/HttpCoding.h"
#include <wknet/WknetLimits.h>
#include <wknet/crypto/Aead.h>
#include <wknet/crypto/CngProvider.h>
#include "HttpExiDecoder.h"
#include "HttpDeflateDecoder.h"
#include "HttpPack200Decoder.h"

#include <brotli/decode.h>
#include <brotli/shared_dictionary.h>

#if defined(WKNET_USER_MODE_TEST)
#include <stdlib.h>
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef COMPRESSION_FORMAT_DEFLATE
#define COMPRESSION_FORMAT_DEFLATE static_cast<USHORT>(0x0007)
#endif

namespace wknet
{
namespace http1
{
    extern "C"
    {
        typedef struct ZSTD_DCtx_s ZSTD_DCtx;
        ZSTD_DCtx* ZSTD_createDCtx(void);
        size_t ZSTD_freeDCtx(ZSTD_DCtx* dctx);
        size_t ZSTD_decompress_usingDict(
            ZSTD_DCtx* dctx,
            void* dst,
            size_t dstCapacity,
            const void* src,
            size_t srcSize,
            const void* dict,
            size_t dictSize);
        unsigned ZSTD_isError(size_t code);
    }

    namespace
    {
        constexpr SIZE_T MaxDecodedBytes = WKNET_HARD_MAX_DECODED_BYTES;
        constexpr SIZE_T MaxDecodeExpansionRatio = 64;
        constexpr UCHAR GzipFlagHeaderCrc = 0x02;
        constexpr UCHAR GzipFlagExtra = 0x04;
        constexpr UCHAR GzipFlagName = 0x08;
        constexpr UCHAR GzipFlagComment = 0x10;
        constexpr UCHAR GzipReservedFlags = 0xE0;
        constexpr UCHAR CompressMagic0 = 0x1F;
        constexpr UCHAR CompressMagic1 = 0x9D;
        constexpr UCHAR CompressBlockModeFlag = 0x80;
        constexpr UCHAR CompressMaxBitsMask = 0x1F;
        constexpr SIZE_T CompressClearCode = 256;
        constexpr SIZE_T CompressFirstFreeCode = 257;
        constexpr SIZE_T CompressInitialBits = 9;
        constexpr SIZE_T CompressMinBits = 9;
        constexpr SIZE_T CompressMaxBits = 16;
        constexpr UCHAR DeflateProbeRaw[] = {
            0x01, 0x05, 0x00, 0xfa, 0xff, 'k', 'h', 't', 't', 'p'
        };
        constexpr char DeflateProbePlain[] = { 'k', 'h', 't', 't', 'p' };
#if !defined(WKNET_USER_MODE_TEST)
        volatile LONG g_deflateRuntimeProbeState = 0;
#endif

        using RtlGetCompressionWorkSpaceSizeFn = NTSTATUS(NTAPI*)(
            USHORT compressionFormatAndEngine,
            ULONG* compressBufferWorkSpaceSize,
            ULONG* compressFragmentWorkSpaceSize);

        using RtlDecompressBufferExFn = NTSTATUS(NTAPI*)(
            USHORT compressionFormat,
            UCHAR* uncompressedBuffer,
            ULONG uncompressedBufferSize,
            UCHAR* compressedBuffer,
            ULONG compressedBufferSize,
            ULONG* finalUncompressedSize,
            void* workSpace);

#if defined(WKNET_USER_MODE_TEST)
        extern "C" __declspec(dllimport) void* __stdcall LoadLibraryA(const char* libraryName);
        extern "C" __declspec(dllimport) void* __stdcall GetProcAddress(void* module, const char* procedureName);
#else
        extern "C"
        {
            NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(
                USHORT compressionFormatAndEngine,
                ULONG* compressBufferWorkSpaceSize,
                ULONG* compressFragmentWorkSpaceSize);

            NTSTATUS NTAPI RtlDecompressBufferEx(
                USHORT compressionFormat,
                UCHAR* uncompressedBuffer,
                ULONG uncompressedBufferSize,
                UCHAR* compressedBuffer,
                ULONG compressedBufferSize,
                ULONG* finalUncompressedSize,
                void* workSpace);
        }
#endif

        _Must_inspect_result_
        bool SizeFitsUlong(SIZE_T value) noexcept
        {
            return value <= static_cast<SIZE_T>(0xFFFFFFFFUL);
        }

        ULONG ReadLittleEndian32(const UCHAR* data) noexcept
        {
            return static_cast<ULONG>(data[0]) |
                (static_cast<ULONG>(data[1]) << 8) |
                (static_cast<ULONG>(data[2]) << 16) |
                (static_cast<ULONG>(data[3]) << 24);
        }

        ULONG ReadBigEndian32(const UCHAR* data) noexcept
        {
            return (static_cast<ULONG>(data[0]) << 24) |
                (static_cast<ULONG>(data[1]) << 16) |
                (static_cast<ULONG>(data[2]) << 8) |
                static_cast<ULONG>(data[3]);
        }

        void CopyBytes(char* destination, const char* source, SIZE_T length) noexcept
        {
            for (SIZE_T index = 0; index < length; ++index) {
                destination[index] = source[index];
            }
        }

        _Must_inspect_result_
        bool IsDecodedSizeAllowed(SIZE_T encodedLength, SIZE_T decodedLength) noexcept
        {
            if (MaxDecodedBytes != 0 && decodedLength > MaxDecodedBytes) {
                return false;
            }

            if (encodedLength == 0) {
                return decodedLength == 0;
            }

            const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
            if (encodedLength > maxSize / MaxDecodeExpansionRatio) {
                return true;
            }

            const SIZE_T ratioLimit = encodedLength * MaxDecodeExpansionRatio;
            return decodedLength <= ratioLimit;
        }

        ULONG ComputeCrc32(const UCHAR* data, SIZE_T dataLength) noexcept
        {
            ULONG crc = 0xFFFFFFFFUL;
            for (SIZE_T index = 0; index < dataLength; ++index) {
                crc ^= data[index];
                for (UCHAR bit = 0; bit < 8; ++bit) {
                    const ULONG mask = static_cast<ULONG>(0) - (crc & 1UL);
                    crc = (crc >> 1) ^ (0xEDB88320UL & mask);
                }
            }

            return ~crc;
        }

        ULONG ComputeAdler32(const UCHAR* data, SIZE_T dataLength) noexcept
        {
            constexpr ULONG AdlerModulo = 65521UL;
            ULONG low = 1;
            ULONG high = 0;

            for (SIZE_T index = 0; index < dataLength; ++index) {
                low += data[index];
                if (low >= AdlerModulo) {
                    low -= AdlerModulo;
                }

                high += low;
                high %= AdlerModulo;
            }

            return (high << 16) | low;
        }

        void* AllocateMemory(SIZE_T size) noexcept
        {
            if (size == 0) {
                size = 1;
            }

#if defined(WKNET_USER_MODE_TEST)
            return malloc(size);
#else
            return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, PoolTag);
#endif
        }

        void FreeMemory(void* memory) noexcept
        {
            if (memory == nullptr) {
                return;
            }

#if defined(WKNET_USER_MODE_TEST)
            free(memory);
#else
            ExFreePoolWithTag(memory, PoolTag);
#endif
        }

        _Must_inspect_result_
        bool ResolveMaterial(
            const HttpCodingDecodeMaterials* materials,
            HttpCoding coding,
            HttpCodingExternalMaterial* material) noexcept
        {
            if (material == nullptr) {
                return false;
            }
            *material = {};
            material->Coding = coding;

            if (materials == nullptr) {
                return false;
            }

            if (materials->Items != nullptr) {
                for (SIZE_T index = 0; index < materials->ItemCount; ++index) {
                    const HttpCodingExternalMaterial& item = materials->Items[index];
                    if (item.Coding == coding) {
                        *material = item;
                        return true;
                    }
                }
            }

            if (materials->Callback != nullptr) {
                HttpCodingExternalMaterial callbackMaterial = {};
                const NTSTATUS status = materials->Callback(materials->CallbackContext, coding, &callbackMaterial);
                if (NT_SUCCESS(status) && callbackMaterial.Coding == coding) {
                    *material = callbackMaterial;
                    return true;
                }
            }

            return false;
        }

        void* BrotliAlloc(void* opaque, size_t size) noexcept
        {
            (void)opaque;
            return AllocateMemory(size);
        }

        void BrotliFree(void* opaque, void* address) noexcept
        {
            (void)opaque;
            FreeMemory(address);
        }

#if defined(WKNET_USER_MODE_TEST)
        _Must_inspect_result_
        bool ResolveRtlCompression(
            RtlGetCompressionWorkSpaceSizeFn* getWorkSpaceSize,
            RtlDecompressBufferExFn* decompressBufferEx) noexcept
        {
            if (getWorkSpaceSize == nullptr || decompressBufferEx == nullptr) {
                return false;
            }

            static RtlGetCompressionWorkSpaceSizeFn cachedGetWorkSpaceSize = nullptr;
            static RtlDecompressBufferExFn cachedDecompressBufferEx = nullptr;

            if (cachedGetWorkSpaceSize == nullptr || cachedDecompressBufferEx == nullptr) {
                void* ntdll = LoadLibraryA("ntdll.dll");
                if (ntdll == nullptr) {
                    return false;
                }

                cachedGetWorkSpaceSize = reinterpret_cast<RtlGetCompressionWorkSpaceSizeFn>(
                    GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize"));
                cachedDecompressBufferEx = reinterpret_cast<RtlDecompressBufferExFn>(
                    GetProcAddress(ntdll, "RtlDecompressBufferEx"));
            }

            *getWorkSpaceSize = cachedGetWorkSpaceSize;
            *decompressBufferEx = cachedDecompressBufferEx;
            return *getWorkSpaceSize != nullptr && *decompressBufferEx != nullptr;
        }
#endif

        _Must_inspect_result_
        NTSTATUS DecodeRawDeflateUnchecked(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (decodedLength == nullptr ||
                compressed == nullptr ||
                !SizeFitsUlong(compressedLength) ||
                !SizeFitsUlong(destinationCapacity)) {
                return STATUS_INVALID_PARAMETER;
            }

            *decodedLength = 0;

            UCHAR emptyOutput = 0;
            UCHAR* output = destination != nullptr ?
                reinterpret_cast<UCHAR*>(destination) :
                &emptyOutput;

            ULONG compressWorkSpaceSize = 0;
            ULONG fragmentWorkSpaceSize = 0;

#if defined(WKNET_USER_MODE_TEST)
            RtlGetCompressionWorkSpaceSizeFn getWorkSpaceSize = nullptr;
            RtlDecompressBufferExFn decompressBufferEx = nullptr;
            if (!ResolveRtlCompression(&getWorkSpaceSize, &decompressBufferEx)) {
                return STATUS_NOT_SUPPORTED;
            }
#else
            RtlGetCompressionWorkSpaceSizeFn getWorkSpaceSize = RtlGetCompressionWorkSpaceSize;
            RtlDecompressBufferExFn decompressBufferEx = RtlDecompressBufferEx;
#endif

            NTSTATUS status = getWorkSpaceSize(
                COMPRESSION_FORMAT_DEFLATE,
                &compressWorkSpaceSize,
                &fragmentWorkSpaceSize);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const ULONG workSpaceSize = fragmentWorkSpaceSize != 0 ?
                fragmentWorkSpaceSize :
                compressWorkSpaceSize;

            void* workSpace = AllocateMemory(workSpaceSize);
            if (workSpace == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ULONG finalSize = 0;
            status = decompressBufferEx(
                COMPRESSION_FORMAT_DEFLATE,
                output,
                static_cast<ULONG>(destinationCapacity),
                const_cast<UCHAR*>(compressed),
                static_cast<ULONG>(compressedLength),
                &finalSize,
                workSpace);

            FreeMemory(workSpace);

            if (status == STATUS_BUFFER_TOO_SMALL) {
                return status;
            }

            if (!NT_SUCCESS(status)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *decodedLength = finalSize;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool ProbeDeflateRuntime() noexcept
        {
            char* output = static_cast<char*>(AllocateMemory(sizeof(DeflateProbePlain)));
            if (output == nullptr) {
                return false;
            }

            RtlZeroMemory(output, sizeof(DeflateProbePlain));
            SIZE_T decodedLength = 0;
            const NTSTATUS status = DecodeRawDeflateUnchecked(
                DeflateProbeRaw,
                sizeof(DeflateProbeRaw),
                output,
                sizeof(DeflateProbePlain),
                &decodedLength);
            const bool available = NT_SUCCESS(status) &&
                decodedLength == sizeof(DeflateProbePlain) &&
                RtlCompareMemory(output, DeflateProbePlain, sizeof(DeflateProbePlain)) == sizeof(DeflateProbePlain);
            FreeMemory(output);
            return available;
        }

        _Must_inspect_result_
        NTSTATUS DecodeRawDeflate(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (!HttpCodingCodec::DeflateRuntimeAvailable()) {
                if (decodedLength != nullptr) {
                    *decodedLength = 0;
                }
                return STATUS_NOT_SUPPORTED;
            }

            return DecodeRawDeflateUnchecked(
                compressed,
                compressedLength,
                destination,
                destinationCapacity,
                decodedLength);
        }

        _Must_inspect_result_
        bool LooksLikeZlibHeader(const UCHAR* data, SIZE_T dataLength) noexcept
        {
            if (data == nullptr || dataLength < 2) {
                return false;
            }

            const UCHAR cmf = data[0];
            const UCHAR flg = data[1];
            const USHORT header = static_cast<USHORT>((static_cast<USHORT>(cmf) << 8) | flg);

            return (cmf & 0x0F) == 8 &&
                ((cmf >> 4) <= 7) &&
                (flg & 0x20) == 0 &&
                (header % 31) == 0;
        }

        _Must_inspect_result_
        NTSTATUS DecodeDeflate(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (decodedLength == nullptr || compressed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (LooksLikeZlibHeader(compressed, compressedLength)) {
                if (compressedLength < 6) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const UCHAR* rawDeflate = compressed + 2;
                const SIZE_T rawDeflateLength = compressedLength - 6;
                NTSTATUS status = DecodeRawDeflate(
                    rawDeflate,
                    rawDeflateLength,
                    destination,
                    destinationCapacity,
                    decodedLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                const ULONG expectedAdler = ReadBigEndian32(compressed + compressedLength - 4);
                const ULONG actualAdler = ComputeAdler32(
                    reinterpret_cast<const UCHAR*>(destination),
                    *decodedLength);
                return expectedAdler == actualAdler ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
            }

            return DecodeRawDeflate(
                compressed,
                compressedLength,
                destination,
                destinationCapacity,
                decodedLength);
        }

        _Must_inspect_result_
        bool SkipZeroTerminatedField(
            const UCHAR* data,
            SIZE_T dataLength,
            SIZE_T* cursor) noexcept
        {
            if (data == nullptr || cursor == nullptr || *cursor >= dataLength) {
                return false;
            }

            while (*cursor < dataLength) {
                if (data[*cursor] == 0) {
                    ++(*cursor);
                    return true;
                }

                ++(*cursor);
            }

            return false;
        }

        _Must_inspect_result_
        NTSTATUS DecodeGzip(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (decodedLength == nullptr || compressed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *decodedLength = 0;

            if (compressedLength < 18 ||
                compressed[0] != 0x1F ||
                compressed[1] != 0x8B ||
                compressed[2] != 8 ||
                (compressed[3] & GzipReservedFlags) != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T cursor = 10;
            const UCHAR flags = compressed[3];

            if ((flags & GzipFlagExtra) != 0) {
                if (cursor + 2 > compressedLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T extraLength =
                    static_cast<SIZE_T>(compressed[cursor]) |
                    (static_cast<SIZE_T>(compressed[cursor + 1]) << 8);
                cursor += 2;
                if (extraLength > (compressedLength - cursor)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                cursor += extraLength;
            }

            if ((flags & GzipFlagName) != 0 && !SkipZeroTerminatedField(compressed, compressedLength, &cursor)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if ((flags & GzipFlagComment) != 0 && !SkipZeroTerminatedField(compressed, compressedLength, &cursor)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if ((flags & GzipFlagHeaderCrc) != 0) {
                if (cursor + 2 > compressedLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const USHORT expectedHeaderCrc = static_cast<USHORT>(
                    static_cast<USHORT>(compressed[cursor]) |
                    (static_cast<USHORT>(compressed[cursor + 1]) << 8));
                const USHORT actualHeaderCrc = static_cast<USHORT>(ComputeCrc32(compressed, cursor) & 0xFFFF);
                if (expectedHeaderCrc != actualHeaderCrc) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                cursor += 2;
            }

            if (cursor + 8 > compressedLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T rawDeflateLength = compressedLength - cursor - 8;
            NTSTATUS status = DecodeRawDeflate(
                compressed + cursor,
                rawDeflateLength,
                destination,
                destinationCapacity,
                decodedLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const ULONG expectedCrc = ReadLittleEndian32(compressed + compressedLength - 8);
            const ULONG expectedSize = ReadLittleEndian32(compressed + compressedLength - 4);
            const ULONG actualCrc = ComputeCrc32(reinterpret_cast<const UCHAR*>(destination), *decodedLength);

            if (*decodedLength > 0xFFFFFFFFULL ||
                expectedCrc != actualCrc ||
                expectedSize != static_cast<ULONG>(*decodedLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS DecodeBrotli(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength,
            const UCHAR* dictionary = nullptr,
            SIZE_T dictionaryLength = 0) noexcept
        {
            if (decodedLength == nullptr || compressed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *decodedLength = 0;

            BrotliDecoderState* state = BrotliDecoderCreateInstance(BrotliAlloc, BrotliFree, nullptr);
            if (state == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (dictionary != nullptr && dictionaryLength != 0) {
                const BROTLI_BOOL attached = BrotliDecoderAttachDictionary(
                    state,
                    BROTLI_SHARED_DICTIONARY_RAW,
                    dictionaryLength,
                    dictionary);
                if (attached == BROTLI_FALSE) {
                    BrotliDecoderDestroyInstance(state);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            size_t availableIn = compressedLength;
            const uint8_t* nextIn = compressed;
            size_t availableOut = destinationCapacity;
            uint8_t* nextOut = reinterpret_cast<uint8_t*>(destination);
            size_t totalOut = 0;

            BrotliDecoderResult result = BrotliDecoderDecompressStream(
                state,
                &availableIn,
                &nextIn,
                &availableOut,
                &nextOut,
                &totalOut);

            NTSTATUS status = STATUS_SUCCESS;
            if (result == BROTLI_DECODER_RESULT_SUCCESS && availableIn == 0) {
                *decodedLength = totalOut;
            }
            else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            else if (result == BROTLI_DECODER_RESULT_ERROR) {
                const BrotliDecoderErrorCode error = BrotliDecoderGetErrorCode(state);
                status = (error <= BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES &&
                    error >= BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES) ?
                    STATUS_INSUFFICIENT_RESOURCES :
                    STATUS_INVALID_NETWORK_RESPONSE;
            }
            else {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            BrotliDecoderDestroyInstance(state);
            return status;
        }

        _Must_inspect_result_
        NTSTATUS DecodeZstd(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength,
            const UCHAR* dictionary = nullptr,
            SIZE_T dictionaryLength = 0) noexcept
        {
            if (decodedLength == nullptr || compressed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            *decodedLength = 0;

            ZSTD_DCtx* context = ZSTD_createDCtx();
            if (context == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            const size_t result = ZSTD_decompress_usingDict(
                context,
                destination,
                destinationCapacity,
                compressed,
                compressedLength,
                dictionary,
                dictionaryLength);
            const size_t freeResult = ZSTD_freeDCtx(context);
            UNREFERENCED_PARAMETER(freeResult);

            if (ZSTD_isError(result)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *decodedLength = result;
            return STATUS_SUCCESS;
        }

        void XorAes128GcmSequence(UCHAR* nonce, SIZE_T sequence) noexcept
        {
            if (nonce == nullptr) {
                return;
            }

            for (SIZE_T index = 0; index < 8; ++index) {
                const SIZE_T shift = (7 - index) * 8;
                nonce[4 + index] ^= static_cast<UCHAR>((sequence >> shift) & 0xFF);
            }
        }

        _Must_inspect_result_
        NTSTATUS AppendAes128GcmRecordPlaintext(
            const UCHAR* plaintext,
            SIZE_T plaintextLength,
            bool finalRecord,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (plaintext == nullptr || decodedLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T delimiterIndex = static_cast<SIZE_T>(-1);
            for (SIZE_T index = plaintextLength; index > 0; --index) {
                if (plaintext[index - 1] != 0) {
                    delimiterIndex = index - 1;
                    break;
                }
            }

            if (delimiterIndex == static_cast<SIZE_T>(-1)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const UCHAR expectedDelimiter = finalRecord ? 2 : 1;
            if (plaintext[delimiterIndex] != expectedDelimiter) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (delimiterIndex > destinationCapacity ||
                *decodedLength > destinationCapacity - delimiterIndex ||
                destination == nullptr) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            if (delimiterIndex != 0) {
                RtlCopyMemory(destination + *decodedLength, plaintext, delimiterIndex);
                *decodedLength += delimiterIndex;
            }
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS DecodeAes128Gcm(
            const UCHAR* encrypted,
            SIZE_T encryptedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength,
            const UCHAR* keyingMaterial,
            SIZE_T keyingMaterialLength) noexcept
        {
            constexpr SIZE_T SaltLength = 16;
            constexpr SIZE_T RecordTagLength = 16;
            constexpr SIZE_T NonceLength = 12;
            constexpr SIZE_T PrkLength = 32;
            constexpr SIZE_T CekLength = 16;
            constexpr SIZE_T HeaderFixedLength = SaltLength + 4 + 1;
            constexpr UCHAR CekInfo[] = {
                'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':',
                ' ', 'a', 'e', 's', '1', '2', '8', 'g', 'c', 'm', 0
            };
            constexpr UCHAR NonceInfo[] = {
                'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':',
                ' ', 'n', 'o', 'n', 'c', 'e', 0
            };

            if (decodedLength == nullptr ||
                encrypted == nullptr ||
                keyingMaterial == nullptr ||
                keyingMaterialLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            *decodedLength = 0;

            if (encryptedLength < HeaderFixedLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const UCHAR* salt = encrypted;
            const ULONG recordSize = ReadBigEndian32(encrypted + SaltLength);
            const UCHAR keyIdLength = encrypted[SaltLength + 4];
            SIZE_T cursor = HeaderFixedLength;
            if (cursor > encryptedLength ||
                keyIdLength > encryptedLength - cursor) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            cursor += keyIdLength;

            if (recordSize < RecordTagLength + 1 ||
                cursor >= encryptedLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            UCHAR prk[PrkLength] = {};
            UCHAR cek[CekLength] = {};
            UCHAR nonceBase[NonceLength] = {};
            SIZE_T bytesWritten = 0;
            NTSTATUS status = crypto::CngProvider::HkdfExtract(
                crypto::HashAlgorithm::Sha256,
                salt,
                SaltLength,
                keyingMaterial,
                keyingMaterialLength,
                prk,
                sizeof(prk),
                &bytesWritten);
            if (!NT_SUCCESS(status) || bytesWritten != sizeof(prk)) {
                RtlSecureZeroMemory(prk, sizeof(prk));
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            status = crypto::CngProvider::HkdfExpand(
                crypto::HashAlgorithm::Sha256,
                prk,
                sizeof(prk),
                CekInfo,
                sizeof(CekInfo),
                cek,
                sizeof(cek));
            if (NT_SUCCESS(status)) {
                status = crypto::CngProvider::HkdfExpand(
                    crypto::HashAlgorithm::Sha256,
                    prk,
                    sizeof(prk),
                    NonceInfo,
                    sizeof(NonceInfo),
                    nonceBase,
                    sizeof(nonceBase));
            }
            RtlSecureZeroMemory(prk, sizeof(prk));
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(cek, sizeof(cek));
                RtlSecureZeroMemory(nonceBase, sizeof(nonceBase));
                return status;
            }

            HeapArray<UCHAR> plaintext(recordSize - RecordTagLength);
            if (!plaintext.IsValid()) {
                RtlSecureZeroMemory(cek, sizeof(cek));
                RtlSecureZeroMemory(nonceBase, sizeof(nonceBase));
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T sequence = 0;
            while (cursor < encryptedLength) {
                const SIZE_T remaining = encryptedLength - cursor;
                const bool finalRecord = remaining <= recordSize;
                const SIZE_T recordLength = finalRecord ? remaining : recordSize;
                if (recordLength <= RecordTagLength ||
                    (!finalRecord && recordLength != recordSize)) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                    break;
                }

                const SIZE_T ciphertextLength = recordLength - RecordTagLength;
                if (ciphertextLength > plaintext.Count()) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                UCHAR nonce[NonceLength] = {};
                RtlCopyMemory(nonce, nonceBase, sizeof(nonce));
                XorAes128GcmSequence(nonce, sequence);

                crypto::AeadKey key = {};
                key.Algorithm = crypto::AeadAlgorithm::Aes128Gcm;
                key.Key = cek;
                key.KeyLength = sizeof(cek);
                crypto::AeadParameters parameters = {};
                parameters.Nonce = { nonce, sizeof(nonce) };
                parameters.Tag = { encrypted + cursor + ciphertextLength, RecordTagLength };

                SIZE_T plainLength = 0;
                status = crypto::Aead::Decrypt(
                    nullptr,
                    key,
                    parameters,
                    encrypted + cursor,
                    ciphertextLength,
                    plaintext.Get(),
                    plaintext.Count(),
                    &plainLength);
                RtlSecureZeroMemory(nonce, sizeof(nonce));
                if (!NT_SUCCESS(status)) {
                    break;
                }

                status = AppendAes128GcmRecordPlaintext(
                    plaintext.Get(),
                    plainLength,
                    finalRecord,
                    destination,
                    destinationCapacity,
                    decodedLength);
                if (!NT_SUCCESS(status)) {
                    break;
                }

                cursor += recordLength;
                ++sequence;
            }

            RtlSecureZeroMemory(plaintext.Get(), plaintext.Count());
            RtlSecureZeroMemory(cek, sizeof(cek));
            RtlSecureZeroMemory(nonceBase, sizeof(nonceBase));
            return status;
        }

        _Must_inspect_result_
        bool AppendOutputByte(
            UCHAR byte,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (decodedLength == nullptr) {
                return false;
            }

            if (*decodedLength >= destinationCapacity || destination == nullptr) {
                return false;
            }

            destination[*decodedLength] = static_cast<char>(byte);
            ++(*decodedLength);
            return true;
        }

        _Must_inspect_result_
        bool ReadCompressCode(
            const UCHAR* data,
            SIZE_T dataLength,
            SIZE_T bitOffset,
            SIZE_T codeBits,
            SIZE_T* code) noexcept
        {
            if (data == nullptr || code == nullptr || codeBits == 0 || codeBits > CompressMaxBits) {
                return false;
            }

            const SIZE_T dataBits = dataLength * 8;
            if (bitOffset > dataBits || codeBits > (dataBits - bitOffset)) {
                return false;
            }

            SIZE_T parsed = 0;
            for (SIZE_T bit = 0; bit < codeBits; ++bit) {
                const SIZE_T absoluteBit = bitOffset + bit;
                const UCHAR byte = data[absoluteBit / 8];
                const UCHAR bitValue = static_cast<UCHAR>((byte >> (absoluteBit % 8)) & 1U);
                parsed |= static_cast<SIZE_T>(bitValue) << bit;
            }

            *code = parsed;
            return true;
        }

        _Must_inspect_result_
        bool HasCompleteCompressCode(SIZE_T dataBits, SIZE_T bitOffset, SIZE_T codeBits) noexcept
        {
            if (codeBits == 0 || dataBits < (codeBits - 1)) {
                return false;
            }

            return bitOffset < dataBits - (codeBits - 1);
        }

        _Must_inspect_result_
        bool ExpandCompressCode(
            SIZE_T code,
            const USHORT* prefixes,
            const UCHAR* suffixes,
            SIZE_T nextCode,
            UCHAR* stack,
            SIZE_T stackCapacity,
            SIZE_T* stackLength,
            UCHAR* firstByte) noexcept
        {
            if (prefixes == nullptr ||
                suffixes == nullptr ||
                stack == nullptr ||
                stackLength == nullptr ||
                firstByte == nullptr ||
                stackCapacity == 0) {
                return false;
            }

            *stackLength = 0;
            SIZE_T current = code;
            while (current >= 256) {
                if (current >= nextCode || *stackLength >= stackCapacity) {
                    return false;
                }

                stack[*stackLength] = suffixes[current];
                ++(*stackLength);
                current = prefixes[current];
            }

            if (*stackLength >= stackCapacity) {
                return false;
            }

            stack[*stackLength] = static_cast<UCHAR>(current);
            ++(*stackLength);
            *firstByte = static_cast<UCHAR>(current);
            return true;
        }

        _Must_inspect_result_
        NTSTATUS EmitReverseStack(
            const UCHAR* stack,
            SIZE_T stackLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (stack == nullptr || decodedLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = stackLength; index > 0; --index) {
                if (!AppendOutputByte(stack[index - 1], destination, destinationCapacity, decodedLength)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
            }

            return STATUS_SUCCESS;
        }

        void AlignCompressBitOffset(SIZE_T* bitOffset, SIZE_T codeBits) noexcept
        {
            if (bitOffset == nullptr || codeBits == 0) {
                return;
            }

            const SIZE_T groupBits = codeBits << 3;
            const SIZE_T current = *bitOffset - 1 + groupBits;
            *bitOffset = current - (current % groupBits);
        }

        _Must_inspect_result_
        NTSTATUS DecodeCompressWithTables(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength,
            USHORT* prefixes,
            UCHAR* suffixes,
            UCHAR* stack,
            SIZE_T maxCodes) noexcept
        {
            if (compressed == nullptr ||
                decodedLength == nullptr ||
                prefixes == nullptr ||
                suffixes == nullptr ||
                stack == nullptr ||
                compressedLength < 3 ||
                maxCodes < (1UL << CompressInitialBits)) {
                return STATUS_INVALID_PARAMETER;
            }

            *decodedLength = 0;

            if (compressed[0] != CompressMagic0 || compressed[1] != CompressMagic1) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const UCHAR flags = compressed[2];
            const SIZE_T maxBits = flags & CompressMaxBitsMask;
            if (maxBits < CompressMinBits || maxBits > CompressMaxBits) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const bool blockMode = (flags & CompressBlockModeFlag) != 0;
            if ((static_cast<SIZE_T>(1) << maxBits) != maxCodes) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < 256; ++index) {
                prefixes[index] = 0;
                suffixes[index] = static_cast<UCHAR>(index);
            }

            const UCHAR* data = compressed + 3;
            const SIZE_T dataLength = compressedLength - 3;
            const SIZE_T dataBits = dataLength * 8;
            SIZE_T bitOffset = 0;
            SIZE_T codeBits = CompressInitialBits;
            SIZE_T maxCodeForBits = (static_cast<SIZE_T>(1) << codeBits) - 1;
            SIZE_T nextCode = blockMode ? CompressFirstFreeCode : CompressClearCode;
            SIZE_T oldCode = static_cast<SIZE_T>(-1);
            UCHAR firstByte = 0;

            while (HasCompleteCompressCode(dataBits, bitOffset, codeBits)) {
                if (nextCode > maxCodeForBits && codeBits < maxBits) {
                    AlignCompressBitOffset(&bitOffset, codeBits);
                    ++codeBits;
                    maxCodeForBits = (static_cast<SIZE_T>(1) << codeBits) - 1;
                    if (!HasCompleteCompressCode(dataBits, bitOffset, codeBits)) {
                        break;
                    }
                }

                SIZE_T code = 0;
                if (!ReadCompressCode(data, dataLength, bitOffset, codeBits, &code)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                bitOffset += codeBits;

                if (blockMode && code == CompressClearCode) {
                    codeBits = CompressInitialBits;
                    maxCodeForBits = (static_cast<SIZE_T>(1) << codeBits) - 1;
                    nextCode = CompressFirstFreeCode;
                    oldCode = static_cast<SIZE_T>(-1);
                    continue;
                }

                SIZE_T stackLength = 0;
                UCHAR currentFirst = 0;
                if (code < nextCode) {
                    if (!ExpandCompressCode(
                        code,
                        prefixes,
                        suffixes,
                        nextCode,
                        stack,
                        maxCodes,
                        &stackLength,
                        &currentFirst)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    NTSTATUS status = EmitReverseStack(
                        stack,
                        stackLength,
                        destination,
                        destinationCapacity,
                        decodedLength);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                else if (code == nextCode && oldCode != static_cast<SIZE_T>(-1)) {
                    if (!ExpandCompressCode(
                        oldCode,
                        prefixes,
                        suffixes,
                        nextCode,
                        stack,
                        maxCodes,
                        &stackLength,
                        &currentFirst)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    NTSTATUS status = EmitReverseStack(
                        stack,
                        stackLength,
                        destination,
                        destinationCapacity,
                        decodedLength);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    if (!AppendOutputByte(currentFirst, destination, destinationCapacity, decodedLength)) {
                        return STATUS_BUFFER_TOO_SMALL;
                    }
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (oldCode != static_cast<SIZE_T>(-1) && nextCode < maxCodes) {
                    prefixes[nextCode] = static_cast<USHORT>(oldCode);
                    suffixes[nextCode] = currentFirst;
                    ++nextCode;
                }

                oldCode = code;
                firstByte = currentFirst;
                UNREFERENCED_PARAMETER(firstByte);
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS DecodeCompress(
            const UCHAR* compressed,
            SIZE_T compressedLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (decodedLength == nullptr || compressed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *decodedLength = 0;
            if (compressedLength < 3 ||
                compressed[0] != CompressMagic0 ||
                compressed[1] != CompressMagic1) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T maxBits = compressed[2] & CompressMaxBitsMask;
            if (maxBits < CompressMinBits || maxBits > CompressMaxBits) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T maxCodes = static_cast<SIZE_T>(1) << maxBits;
            HeapArray<USHORT> prefixes(maxCodes);
            HeapArray<UCHAR> suffixes(maxCodes);
            HeapArray<UCHAR> stack(maxCodes);
            if (!prefixes.IsValid() || !suffixes.IsValid() || !stack.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = DecodeCompressWithTables(
                compressed,
                compressedLength,
                destination,
                destinationCapacity,
                decodedLength,
                prefixes.Get(),
                suffixes.Get(),
                stack.Get(),
                maxCodes);

            RtlSecureZeroMemory(prefixes.Get(), sizeof(USHORT) * maxCodes);
            RtlSecureZeroMemory(suffixes.Get(), sizeof(UCHAR) * maxCodes);
            RtlSecureZeroMemory(stack.Get(), sizeof(UCHAR) * maxCodes);
            return status;
        }

        _Must_inspect_result_
        bool HasTransform(HttpCoding coding) noexcept
        {
            return coding != HttpCoding::Identity;
        }

        void SelectDestination(
            const char* current,
            const HttpCodingDecodeBuffers& buffers,
            char** destination,
            SIZE_T* destinationCapacity) noexcept
        {
            if (destination == nullptr || destinationCapacity == nullptr) {
                return;
            }

            *destination = nullptr;
            *destinationCapacity = 0;

            if (buffers.DecodedBody != nullptr && current != buffers.DecodedBody) {
                *destination = buffers.DecodedBody;
                *destinationCapacity = buffers.DecodedBodyCapacity;
                return;
            }

            if (buffers.ScratchBody != nullptr && current != buffers.ScratchBody) {
                *destination = buffers.ScratchBody;
                *destinationCapacity = buffers.ScratchBodyCapacity;
                return;
            }
        }
    }

    NTSTATUS HttpDecodeRawDeflate(
        const UCHAR* compressed,
        SIZE_T compressedLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* decodedLength) noexcept
    {
        return DecodeRawDeflate(
            compressed,
            compressedLength,
            destination,
            destinationCapacity,
            decodedLength);
    }

    bool HttpCodingCodec::DeflateRuntimeAvailable() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        static bool probed = false;
        static bool available = false;
        if (!probed) {
            available = ProbeDeflateRuntime();
            probed = true;
        }
        return available;
#else
        LONG state = InterlockedCompareExchange(&g_deflateRuntimeProbeState, 0, 0);
        if (state == 1) {
            return true;
        }
        if (state == 2) {
            return false;
        }
        if (InterlockedCompareExchange(&g_deflateRuntimeProbeState, 3, 0) == 0) {
            const bool available = ProbeDeflateRuntime();
            InterlockedExchange(&g_deflateRuntimeProbeState, available ? 1 : 2);
            return available;
        }

        LARGE_INTEGER delay = {};
        delay.QuadPart = -10 * 1000;
        do {
            const NTSTATUS delayStatus = KeDelayExecutionThread(KernelMode, FALSE, &delay);
            UNREFERENCED_PARAMETER(delayStatus);
            state = InterlockedCompareExchange(&g_deflateRuntimeProbeState, 0, 0);
        } while (state == 3);

        return state == 1;
#endif
    }

    NTSTATUS HttpCodingCodec::DecodeOne(
        HttpCoding coding,
        const char* source,
        SIZE_T sourceLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* decodedLength,
        const HttpCodingDecodeMaterials* materials) noexcept
    {
        if (decodedLength == nullptr || (source == nullptr && sourceLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        const UCHAR* input = reinterpret_cast<const UCHAR*>(source);
        HttpCodingExternalMaterial material = {};
        switch (coding) {
        case HttpCoding::Gzip:
            return DecodeGzip(input, sourceLength, destination, destinationCapacity, decodedLength);
        case HttpCoding::Deflate:
            return DecodeDeflate(input, sourceLength, destination, destinationCapacity, decodedLength);
        case HttpCoding::Brotli:
            return DecodeBrotli(input, sourceLength, destination, destinationCapacity, decodedLength);
        case HttpCoding::Compress:
            return DecodeCompress(input, sourceLength, destination, destinationCapacity, decodedLength);
        case HttpCoding::Zstd:
            return DecodeZstd(input, sourceLength, destination, destinationCapacity, decodedLength);
        case HttpCoding::DictionaryCompressedBrotli:
            if (!ResolveMaterial(materials, coding, &material) ||
                material.Dictionary == nullptr ||
                material.DictionaryLength == 0) {
                return STATUS_NOT_SUPPORTED;
            }
            return DecodeBrotli(
                input,
                sourceLength,
                destination,
                destinationCapacity,
                decodedLength,
                material.Dictionary,
                material.DictionaryLength);
        case HttpCoding::DictionaryCompressedZstd:
            if (!ResolveMaterial(materials, coding, &material) ||
                material.Dictionary == nullptr ||
                material.DictionaryLength == 0) {
                return STATUS_NOT_SUPPORTED;
            }
            return DecodeZstd(
                input,
                sourceLength,
                destination,
                destinationCapacity,
                decodedLength,
                material.Dictionary,
                material.DictionaryLength);
        case HttpCoding::Aes128Gcm:
            if (!ResolveMaterial(materials, coding, &material) ||
                material.Aes128GcmKeyingMaterial == nullptr ||
                material.Aes128GcmKeyingMaterialLength == 0) {
                return STATUS_NOT_SUPPORTED;
            }
            return DecodeAes128Gcm(
                input,
                sourceLength,
                destination,
                destinationCapacity,
                decodedLength,
                material.Aes128GcmKeyingMaterial,
                material.Aes128GcmKeyingMaterialLength);
        case HttpCoding::Exi:
            return DecodeExiContent(input, sourceLength, destination, destinationCapacity, decodedLength);
        case HttpCoding::Pack200Gzip:
            return DecodePack200GzipContent(input, sourceLength, destination, destinationCapacity, decodedLength);
        case HttpCoding::Identity:
            *decodedLength = sourceLength;
            return STATUS_SUCCESS;
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }

    NTSTATUS HttpCodingCodec::DecodeChainReverse(
        const HttpCoding* codings,
        SIZE_T codingCount,
        const char* body,
        SIZE_T bodyLength,
        const HttpCodingDecodeBuffers& buffers,
        HttpCodingDecodeResult& result) noexcept
    {
        result = {};
        result.Body = bodyLength == 0 ? nullptr : body;
        result.BodyLength = bodyLength;

        if ((codings == nullptr && codingCount != 0) ||
            (body == nullptr && bodyLength != 0)) {
            result = {};
            return STATUS_INVALID_PARAMETER;
        }

        if (codingCount == 0 || bodyLength == 0) {
            return STATUS_SUCCESS;
        }

        const char* current = body;
        SIZE_T currentLength = bodyLength;
        bool transformed = false;

        for (SIZE_T reverseIndex = codingCount; reverseIndex > 0; --reverseIndex) {
            const HttpCoding coding = codings[reverseIndex - 1];
            if (!HasTransform(coding)) {
                continue;
            }

            char* destination = nullptr;
            SIZE_T destinationCapacity = 0;
            SelectDestination(current, buffers, &destination, &destinationCapacity);
            const SIZE_T decodeCapacity =
                MaxDecodedBytes != 0 && destinationCapacity > MaxDecodedBytes ?
                    MaxDecodedBytes :
                    destinationCapacity;

            SIZE_T decodedLength = 0;
            NTSTATUS status = DecodeOne(
                coding,
                current,
                currentLength,
                destination,
                decodeCapacity,
                &decodedLength,
                buffers.Materials);
            if (!NT_SUCCESS(status)) {
                result = {};
                return status;
            }

            if (!IsDecodedSizeAllowed(currentLength, decodedLength)) {
                result = {};
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            current = decodedLength == 0 ? nullptr : destination;
            currentLength = decodedLength;
            transformed = true;
        }

        if (transformed &&
            currentLength != 0 &&
            buffers.DecodedBody != nullptr &&
            current != buffers.DecodedBody) {
            if (currentLength > buffers.DecodedBodyCapacity) {
                result = {};
                return STATUS_BUFFER_TOO_SMALL;
            }

            CopyBytes(buffers.DecodedBody, current, currentLength);
            current = buffers.DecodedBody;
        }

        result.Body = currentLength == 0 ? nullptr : current;
        result.BodyLength = currentLength;
        result.AppliedCoding = transformed;
        return STATUS_SUCCESS;
    }
}
}

extern "C" void* WknetBrotliMalloc(size_t size)
{
    return wknet::http1::BrotliAlloc(nullptr, size);
}

extern "C" void WknetBrotliFree(void* address)
{
    wknet::http1::BrotliFree(nullptr, address);
}

extern "C" void* WknetBrotliMemcpy(void* destination, const void* source, size_t length)
{
    auto* out = static_cast<unsigned char*>(destination);
    const auto* in = static_cast<const unsigned char*>(source);
    for (size_t index = 0; index < length; ++index) {
        out[index] = in[index];
    }

    return destination;
}

extern "C" void* WknetBrotliMemmove(void* destination, const void* source, size_t length)
{
    auto* out = static_cast<unsigned char*>(destination);
    const auto* in = static_cast<const unsigned char*>(source);

    if (out == in || length == 0) {
        return destination;
    }

    if (out < in) {
        for (size_t index = 0; index < length; ++index) {
            out[index] = in[index];
        }
    }
    else {
        for (size_t index = length; index > 0; --index) {
            out[index - 1] = in[index - 1];
        }
    }

    return destination;
}

extern "C" void* WknetBrotliMemset(void* destination, int value, size_t length)
{
    auto* out = static_cast<unsigned char*>(destination);
    const unsigned char byte = static_cast<unsigned char>(value);
    for (size_t index = 0; index < length; ++index) {
        out[index] = byte;
    }

    return destination;
}

extern "C" int WknetBrotliMemcmp(const void* left, const void* right, size_t length)
{
    const auto* leftBytes = static_cast<const unsigned char*>(left);
    const auto* rightBytes = static_cast<const unsigned char*>(right);
    for (size_t index = 0; index < length; ++index) {
        if (leftBytes[index] != rightBytes[index]) {
            return static_cast<int>(leftBytes[index]) - static_cast<int>(rightBytes[index]);
        }
    }

    return 0;
}
