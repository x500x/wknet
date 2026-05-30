#include <KernelHttp/http/HttpContentEncoding.h>

#include <brotli/decode.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef COMPRESSION_FORMAT_DEFLATE
#define COMPRESSION_FORMAT_DEFLATE static_cast<USHORT>(0x0007)
#endif

namespace KernelHttp
{
namespace http
{
    namespace
    {
        constexpr SIZE_T MaxContentCodings = 8;
        constexpr UCHAR GzipFlagHeaderCrc = 0x02;
        constexpr UCHAR GzipFlagExtra = 0x04;
        constexpr UCHAR GzipFlagName = 0x08;
        constexpr UCHAR GzipFlagComment = 0x10;
        constexpr UCHAR GzipReservedFlags = 0xE0;

        enum class ContentCoding : UCHAR
        {
            Identity,
            Gzip,
            Deflate,
            Brotli
        };

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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

        bool IsOptionalWhitespace(char value) noexcept
        {
            return value == ' ' || value == '\t';
        }

        HttpText TrimOptionalWhitespace(HttpText text) noexcept
        {
            while (text.Length > 0 && IsOptionalWhitespace(text.Data[0])) {
                ++text.Data;
                --text.Length;
            }

            while (text.Length > 0 && IsOptionalWhitespace(text.Data[text.Length - 1])) {
                --text.Length;
            }

            return text;
        }

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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
            free(memory);
#else
            ExFreePoolWithTag(memory, PoolTag);
#endif
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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
        NTSTATUS DecodeRawDeflate(
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

            if (expectedCrc != actualCrc ||
                expectedSize != static_cast<ULONG>(*decodedLength & 0xFFFFFFFFUL)) {
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
            SIZE_T* decodedLength) noexcept
        {
            if (decodedLength == nullptr || compressed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *decodedLength = 0;

            BrotliDecoderState* state = BrotliDecoderCreateInstance(BrotliAlloc, BrotliFree, nullptr);
            if (state == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
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
        NTSTATUS DecodeOne(
            ContentCoding coding,
            const char* source,
            SIZE_T sourceLength,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* decodedLength) noexcept
        {
            if (decodedLength == nullptr || (source == nullptr && sourceLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            const UCHAR* input = reinterpret_cast<const UCHAR*>(source);
            switch (coding) {
            case ContentCoding::Gzip:
                return DecodeGzip(input, sourceLength, destination, destinationCapacity, decodedLength);
            case ContentCoding::Deflate:
                return DecodeDeflate(input, sourceLength, destination, destinationCapacity, decodedLength);
            case ContentCoding::Brotli:
                return DecodeBrotli(input, sourceLength, destination, destinationCapacity, decodedLength);
            case ContentCoding::Identity:
                *decodedLength = sourceLength;
                return STATUS_SUCCESS;
            default:
                return STATUS_NOT_SUPPORTED;
            }
        }

        _Must_inspect_result_
        NTSTATUS ParseCoding(HttpText token, ContentCoding* coding) noexcept
        {
            if (coding == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            token = TrimOptionalWhitespace(token);
            if (token.Length == 0 || token.Data == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (TextEqualsIgnoreCase(token, MakeText("identity"))) {
                *coding = ContentCoding::Identity;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("gzip"))) {
                *coding = ContentCoding::Gzip;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("deflate"))) {
                *coding = ContentCoding::Deflate;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("br"))) {
                *coding = ContentCoding::Brotli;
                return STATUS_SUCCESS;
            }

            return STATUS_NOT_SUPPORTED;
        }

        _Must_inspect_result_
        NTSTATUS AppendCodings(
            HttpText value,
            ContentCoding* codings,
            SIZE_T* codingCount) noexcept
        {
            if (codings == nullptr || codingCount == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T cursor = 0;
            for (;;) {
                const SIZE_T tokenStart = cursor;
                while (cursor < value.Length && value.Data[cursor] != ',') {
                    ++cursor;
                }

                if (*codingCount >= MaxContentCodings) {
                    return STATUS_NOT_SUPPORTED;
                }

                NTSTATUS status = ParseCoding(
                    { value.Data + tokenStart, cursor - tokenStart },
                    &codings[*codingCount]);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                ++(*codingCount);

                if (cursor == value.Length) {
                    return STATUS_SUCCESS;
                }

                ++cursor;
                if (cursor == value.Length) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }

        bool HasTransform(ContentCoding coding) noexcept
        {
            return coding != ContentCoding::Identity;
        }

        void SelectDestination(
            const char* current,
            const HttpContentDecodeBuffers& buffers,
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

            return;
        }
    }

    NTSTATUS HttpContentEncoding::Decode(
        const HttpHeader* headers,
        SIZE_T headerCount,
        const char* body,
        SIZE_T bodyLength,
        const HttpContentDecodeBuffers& buffers,
        HttpContentDecodeResult& result) noexcept
    {
        result = {};
        result.Body = bodyLength == 0 ? nullptr : body;
        result.BodyLength = bodyLength;

        if ((headers == nullptr && headerCount != 0) ||
            (body == nullptr && bodyLength != 0)) {
            result = {};
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<ContentCoding> codings(MaxContentCodings);
        if (!codings.IsValid()) {
            result = {};
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T codingCount = 0;

        for (SIZE_T index = 0; index < headerCount; ++index) {
            if (!TextEqualsIgnoreCase(headers[index].Name, MakeText("Content-Encoding"))) {
                continue;
            }

            NTSTATUS status = AppendCodings(headers[index].Value, codings.Get(), &codingCount);
            if (!NT_SUCCESS(status)) {
                result = {};
                return status;
            }
        }

        if (codingCount == 0 || bodyLength == 0) {
            return STATUS_SUCCESS;
        }

        const char* current = body;
        SIZE_T currentLength = bodyLength;
        bool transformed = false;

        for (SIZE_T reverseIndex = codingCount; reverseIndex > 0; --reverseIndex) {
            const ContentCoding coding = codings[reverseIndex - 1];
            if (!HasTransform(coding)) {
                continue;
            }

            char* destination = nullptr;
            SIZE_T destinationCapacity = 0;
            SelectDestination(current, buffers, &destination, &destinationCapacity);

            SIZE_T decodedLength = 0;
            NTSTATUS status = DecodeOne(
                coding,
                current,
                currentLength,
                destination,
                destinationCapacity,
                &decodedLength);
            if (!NT_SUCCESS(status)) {
                result = {};
                return status;
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
        result.AppliedContentCoding = transformed;
        return STATUS_SUCCESS;
    }
}
}

extern "C" void* KernelHttpBrotliMalloc(size_t size)
{
    return KernelHttp::http::BrotliAlloc(nullptr, size);
}

extern "C" void KernelHttpBrotliFree(void* address)
{
    KernelHttp::http::BrotliFree(nullptr, address);
}

extern "C" void* KernelHttpBrotliMemcpy(void* destination, const void* source, size_t length)
{
    auto* out = static_cast<unsigned char*>(destination);
    const auto* in = static_cast<const unsigned char*>(source);
    for (size_t index = 0; index < length; ++index) {
        out[index] = in[index];
    }

    return destination;
}

extern "C" void* KernelHttpBrotliMemmove(void* destination, const void* source, size_t length)
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

extern "C" void* KernelHttpBrotliMemset(void* destination, int value, size_t length)
{
    auto* out = static_cast<unsigned char*>(destination);
    const unsigned char byte = static_cast<unsigned char>(value);
    for (size_t index = 0; index < length; ++index) {
        out[index] = byte;
    }

    return destination;
}

extern "C" int KernelHttpBrotliMemcmp(const void* left, const void* right, size_t length)
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
