#include "HttpExiDecoder.h"

namespace KernelHttp
{
namespace http
{
namespace
{
    enum class ExiAlignment : UCHAR
    {
        BitPacked,
        BytePacked,
        PreCompression,
        Compression
    };

    struct ExiOptions final
    {
        ExiAlignment Alignment = ExiAlignment::BitPacked;
        bool HasCookie = false;
        bool HasOptions = false;
        bool PreviewVersion = false;
        UCHAR Version = 1;
        bool Fragment = false;
        bool Strict = false;
        bool PreserveComments = false;
        bool PreservePis = false;
        bool PreserveDtd = false;
        bool PreservePrefixes = false;
        bool PreserveLexicalValues = false;
        ULONG BlockSize = 1000000;
        ULONG ValueMaxLength = 0xffffffffUL;
        ULONG ValuePartitionCapacity = 0xffffffffUL;
    };

    class ExiBitReader final
    {
    public:
        ExiBitReader(const UCHAR* data, SIZE_T length) noexcept :
            data_(data),
            length_(length)
        {
        }

        _Must_inspect_result_
        bool ReadBits(UCHAR bitCount, _Out_ ULONG* value) noexcept
        {
            if (value == nullptr || bitCount > 32) {
                return false;
            }
            ULONG result = 0;
            for (UCHAR index = 0; index < bitCount; ++index) {
                if (bitOffset_ >= length_ * 8) {
                    return false;
                }
                const SIZE_T byteOffset = bitOffset_ / 8;
                const UCHAR bitInByte = static_cast<UCHAR>(7 - (bitOffset_ % 8));
                result = (result << 1) | ((data_[byteOffset] >> bitInByte) & 1U);
                ++bitOffset_;
            }
            *value = result;
            return true;
        }

        _Must_inspect_result_
        bool AlignByte() noexcept
        {
            const SIZE_T remainder = bitOffset_ % 8;
            if (remainder == 0) {
                return true;
            }
            bitOffset_ += 8 - remainder;
            return bitOffset_ <= length_ * 8;
        }

        _Must_inspect_result_
        bool ReadByte(_Out_ UCHAR* value) noexcept
        {
            ULONG parsed = 0;
            if (!ReadBits(8, &parsed) || value == nullptr) {
                return false;
            }
            *value = static_cast<UCHAR>(parsed);
            return true;
        }

        _Must_inspect_result_
        SIZE_T ByteOffset() const noexcept
        {
            return bitOffset_ / 8;
        }

        _Must_inspect_result_
        bool AtEnd() const noexcept
        {
            return bitOffset_ >= length_ * 8;
        }

    private:
        const UCHAR* data_ = nullptr;
        SIZE_T length_ = 0;
        SIZE_T bitOffset_ = 0;
    };

    _Must_inspect_result_
    bool ParseExiHeader(
        const UCHAR* source,
        SIZE_T sourceLength,
        _Out_ ExiOptions* options,
        _Out_ SIZE_T* bodyOffset) noexcept
    {
        if (source == nullptr || options == nullptr || bodyOffset == nullptr) {
            return false;
        }
        *options = {};
        *bodyOffset = 0;

        SIZE_T cursor = 0;
        if (sourceLength >= 4 &&
            source[0] == '$' &&
            source[1] == 'E' &&
            source[2] == 'X' &&
            source[3] == 'I') {
            options->HasCookie = true;
            cursor = 4;
        }
        if (cursor >= sourceLength) {
            return false;
        }

        ExiBitReader reader(source + cursor, sourceLength - cursor);
        ULONG distinguishing = 0;
        ULONG presence = 0;
        ULONG preview = 0;
        ULONG version = 0;
        if (!reader.ReadBits(2, &distinguishing) ||
            distinguishing != 2 ||
            !reader.ReadBits(1, &presence) ||
            !reader.ReadBits(1, &preview) ||
            !reader.ReadBits(4, &version)) {
            return false;
        }

        options->HasOptions = presence != 0;
        options->PreviewVersion = preview != 0;
        options->Version = static_cast<UCHAR>(version + 1);
        if (options->Version != 1) {
            return false;
        }

        if (options->HasOptions) {
            if (!reader.AlignByte()) {
                return false;
            }
            // Full EXI options documents are decoded by the body grammar. Keep the
            // parser entry explicit so options support can evolve without changing
            // the Content-Encoding surface.
            UCHAR firstOptionsByte = 0;
            if (!reader.ReadByte(&firstOptionsByte)) {
                return false;
            }
            UNREFERENCED_PARAMETER(firstOptionsByte);
            return false;
        }

        *bodyOffset = cursor + reader.ByteOffset();
        return *bodyOffset <= sourceLength;
    }
}

NTSTATUS DecodeExiContent(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    UNREFERENCED_PARAMETER(destination);
    UNREFERENCED_PARAMETER(destinationCapacity);
    if (decodedLength == nullptr || source == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *decodedLength = 0;

    ExiOptions options = {};
    SIZE_T bodyOffset = 0;
    if (!ParseExiHeader(source, sourceLength, &options, &bodyOffset)) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    UNREFERENCED_PARAMETER(options);
    UNREFERENCED_PARAMETER(bodyOffset);
    return STATUS_NOT_SUPPORTED;
}
}
}
