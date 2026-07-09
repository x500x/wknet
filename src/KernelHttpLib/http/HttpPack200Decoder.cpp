#include "HttpPack200Decoder.h"

namespace KernelHttp
{
namespace http
{
namespace
{
    constexpr ULONG Pack200Magic = 0xCAFED00DUL;
    constexpr ULONG Pack200MajorVersion = 170;
    constexpr ULONG Pack200MinorVersion = 1;

    enum class Pack200CodingKind : UCHAR
    {
        Byte1,
        Unsigned5,
        Signed5,
        Delta5,
        Bci5,
        Branch5
    };

    struct Pack200Coding final
    {
        UCHAR B = 1;
        USHORT H = 256;
        UCHAR S = 0;
        UCHAR D = 0;
    };

    struct SegmentOptions final
    {
        bool HaveSpecialFormats = false;
        bool HaveCpNumbers = false;
        bool HaveAllCodeFlags = false;
        bool HaveCpExtraCounts = false;
        bool HaveFileHeaders = false;
        bool DeflateHint = false;
        bool HaveFileModtime = false;
        bool HaveFileOptions = false;
        bool HaveFileSizeHi = false;
    };

    struct SegmentHeader final
    {
        ULONG MinorVersion = 0;
        ULONG MajorVersion = 0;
        ULONG ArchiveOptions = 0;
        SegmentOptions Options = {};

        ULONG ArchiveSizeHi = 0;
        ULONG ArchiveSizeLo = 0;
        ULONG ArchiveNextCount = 0;
        ULONG ArchiveModtime = 0;
        ULONG FileCount = 0;

        ULONG BandHeadersSize = 0;
        ULONG AttributeDefinitionCount = 0;

        ULONG CpUtf8Count = 0;
        ULONG CpIntCount = 0;
        ULONG CpFloatCount = 0;
        ULONG CpLongCount = 0;
        ULONG CpDoubleCount = 0;
        ULONG CpStringCount = 0;
        ULONG CpClassCount = 0;
        ULONG CpSignatureCount = 0;
        ULONG CpDescriptorCount = 0;
        ULONG CpFieldCount = 0;
        ULONG CpMethodCount = 0;
        ULONG CpInterfaceMethodCount = 0;
        ULONG CpMethodHandleCount = 0;
        ULONG CpMethodTypeCount = 0;
        ULONG CpBootstrapMethodCount = 0;
        ULONG CpInvokeDynamicCount = 0;

        ULONG InnerClassCount = 0;
        ULONG DefaultClassMinorVersion = 0;
        ULONG DefaultClassMajorVersion = 0;
        ULONG ClassCount = 0;
    };

    constexpr Pack200Coding CodingFor(Pack200CodingKind kind) noexcept
    {
        switch (kind) {
        case Pack200CodingKind::Byte1:
            return { 1, 256, 0, 0 };
        case Pack200CodingKind::Unsigned5:
            return { 5, 64, 0, 0 };
        case Pack200CodingKind::Signed5:
            return { 5, 64, 1, 0 };
        case Pack200CodingKind::Delta5:
            return { 5, 64, 2, 1 };
        case Pack200CodingKind::Bci5:
            return { 5, 4, 0, 0 };
        case Pack200CodingKind::Branch5:
            return { 5, 4, 2, 0 };
        default:
            return { 1, 256, 0, 0 };
        }
    }

    class Pack200Reader final
    {
    public:
        Pack200Reader(const UCHAR* data, SIZE_T length) noexcept :
            data_(data),
            length_(length)
        {
        }

        _Must_inspect_result_
        bool ReadByte(_Out_ UCHAR* value) noexcept
        {
            if (value == nullptr || cursor_ >= length_) {
                return false;
            }
            *value = data_[cursor_++];
            return true;
        }

        _Must_inspect_result_
        bool ReadMagic() noexcept
        {
            if (Remaining() < 4) {
                return false;
            }
            const ULONG magic =
                (static_cast<ULONG>(data_[cursor_]) << 24) |
                (static_cast<ULONG>(data_[cursor_ + 1]) << 16) |
                (static_cast<ULONG>(data_[cursor_ + 2]) << 8) |
                static_cast<ULONG>(data_[cursor_ + 3]);
            cursor_ += 4;
            return magic == Pack200Magic;
        }

        _Must_inspect_result_
        bool ReadInt(Pack200Coding coding, _Out_ LONG* value) noexcept
        {
            if (value == nullptr || coding.B == 0 || coding.B > 5 || coding.H == 0 || coding.H > 256) {
                return false;
            }

            const ULONG l = 256UL - static_cast<ULONG>(coding.H);
            ULONGLONG sum = 0;
            ULONGLONG factor = 1;
            UCHAR byte = 0;
            UCHAR count = 0;
            do {
                if (!ReadByte(&byte)) {
                    return false;
                }

                if (byte < l) {
                    sum += static_cast<ULONGLONG>(byte) * factor;
                    break;
                }

                sum += static_cast<ULONGLONG>(byte - l) * factor;
                factor *= coding.H;
                ++count;
                if (count >= coding.B) {
                    return false;
                }
            } while (true);

            if (sum > 0xffffffffULL) {
                return false;
            }

            LONG decoded = static_cast<LONG>(sum);
            if (coding.S != 0) {
                const ULONG mask = (1UL << coding.S) - 1UL;
                const ULONG unsignedValue = static_cast<ULONG>(sum);
                if ((unsignedValue & mask) == 0) {
                    decoded = static_cast<LONG>(unsignedValue >> coding.S);
                }
                else {
                    decoded = -static_cast<LONG>(unsignedValue >> coding.S) - 1;
                }
            }

            if (coding.D != 0) {
                const LONG previous = previousValue_;
                decoded += previous;
                previousValue_ = decoded;
            }

            *value = decoded;
            return true;
        }

        _Must_inspect_result_
        bool ReadUnsigned(Pack200CodingKind kind, _Out_ ULONG* value) noexcept
        {
            if (value == nullptr) {
                return false;
            }
            LONG signedValue = 0;
            if (!ReadInt(CodingFor(kind), &signedValue) || signedValue < 0) {
                return false;
            }
            *value = static_cast<ULONG>(signedValue);
            return true;
        }

        void ResetDelta() noexcept
        {
            previousValue_ = 0;
        }

        _Must_inspect_result_
        SIZE_T Remaining() const noexcept
        {
            return cursor_ <= length_ ? length_ - cursor_ : 0;
        }

        _Must_inspect_result_
        const UCHAR* Current() const noexcept
        {
            return cursor_ <= length_ ? data_ + cursor_ : nullptr;
        }

        _Must_inspect_result_
        bool Skip(SIZE_T length) noexcept
        {
            if (length > Remaining()) {
                return false;
            }
            cursor_ += length;
            return true;
        }

    private:
        const UCHAR* data_ = nullptr;
        SIZE_T length_ = 0;
        SIZE_T cursor_ = 0;
        LONG previousValue_ = 0;
    };

    _Must_inspect_result_
    bool DecodeSegmentOptions(ULONG value, _Out_ SegmentOptions* options) noexcept
    {
        if (options == nullptr) {
            return false;
        }

        constexpr ULONG KnownOptionsMask =
            (1UL << 0) |
            (1UL << 1) |
            (1UL << 2) |
            (1UL << 3) |
            (1UL << 4) |
            (1UL << 5) |
            (1UL << 6) |
            (1UL << 7) |
            (1UL << 8);
        if ((value & ~KnownOptionsMask) != 0) {
            return false;
        }

        options->HaveSpecialFormats = (value & (1UL << 0)) != 0;
        options->HaveCpNumbers = (value & (1UL << 1)) != 0;
        options->HaveAllCodeFlags = (value & (1UL << 2)) != 0;
        options->HaveCpExtraCounts = (value & (1UL << 3)) != 0;
        options->HaveFileHeaders = (value & (1UL << 4)) != 0;
        options->DeflateHint = (value & (1UL << 5)) != 0;
        options->HaveFileModtime = (value & (1UL << 6)) != 0;
        options->HaveFileOptions = (value & (1UL << 7)) != 0;
        options->HaveFileSizeHi = (value & (1UL << 8)) != 0;
        return true;
    }

    _Must_inspect_result_
    bool ReadUnsigned5(_Inout_ Pack200Reader* reader, _Out_ ULONG* value) noexcept
    {
        return reader != nullptr && reader->ReadUnsigned(Pack200CodingKind::Unsigned5, value);
    }

    _Must_inspect_result_
    bool ParseSegmentHeader(_Inout_ Pack200Reader* reader, _Out_ SegmentHeader* header) noexcept
    {
        if (reader == nullptr || header == nullptr) {
            return false;
        }
        *header = {};

        if (!reader->ReadMagic() ||
            !ReadUnsigned5(reader, &header->MinorVersion) ||
            !ReadUnsigned5(reader, &header->MajorVersion) ||
            !ReadUnsigned5(reader, &header->ArchiveOptions) ||
            header->MinorVersion != Pack200MinorVersion ||
            header->MajorVersion != Pack200MajorVersion ||
            !DecodeSegmentOptions(header->ArchiveOptions, &header->Options)) {
            return false;
        }

        if (header->Options.HaveFileHeaders) {
            if (!ReadUnsigned5(reader, &header->ArchiveSizeHi) ||
                !ReadUnsigned5(reader, &header->ArchiveSizeLo) ||
                !ReadUnsigned5(reader, &header->ArchiveNextCount) ||
                !ReadUnsigned5(reader, &header->ArchiveModtime) ||
                !ReadUnsigned5(reader, &header->FileCount)) {
                return false;
            }
        }

        if (header->Options.HaveSpecialFormats) {
            if (!ReadUnsigned5(reader, &header->BandHeadersSize) ||
                !ReadUnsigned5(reader, &header->AttributeDefinitionCount)) {
                return false;
            }
        }

        if (!ReadUnsigned5(reader, &header->CpUtf8Count)) {
            return false;
        }

        if (header->Options.HaveCpNumbers &&
            (!ReadUnsigned5(reader, &header->CpIntCount) ||
                !ReadUnsigned5(reader, &header->CpFloatCount) ||
                !ReadUnsigned5(reader, &header->CpLongCount) ||
                !ReadUnsigned5(reader, &header->CpDoubleCount))) {
            return false;
        }

        if (!ReadUnsigned5(reader, &header->CpStringCount) ||
            !ReadUnsigned5(reader, &header->CpClassCount) ||
            !ReadUnsigned5(reader, &header->CpSignatureCount) ||
            !ReadUnsigned5(reader, &header->CpDescriptorCount) ||
            !ReadUnsigned5(reader, &header->CpFieldCount) ||
            !ReadUnsigned5(reader, &header->CpMethodCount) ||
            !ReadUnsigned5(reader, &header->CpInterfaceMethodCount)) {
            return false;
        }

        if (header->Options.HaveCpExtraCounts &&
            (!ReadUnsigned5(reader, &header->CpMethodHandleCount) ||
                !ReadUnsigned5(reader, &header->CpMethodTypeCount) ||
                !ReadUnsigned5(reader, &header->CpBootstrapMethodCount) ||
                !ReadUnsigned5(reader, &header->CpInvokeDynamicCount))) {
            return false;
        }

        if (!ReadUnsigned5(reader, &header->InnerClassCount) ||
            !ReadUnsigned5(reader, &header->DefaultClassMinorVersion) ||
            !ReadUnsigned5(reader, &header->DefaultClassMajorVersion) ||
            !ReadUnsigned5(reader, &header->ClassCount)) {
            return false;
        }

        return true;
    }
}

NTSTATUS DecodePack200GzipContent(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    UNREFERENCED_PARAMETER(destination);
    UNREFERENCED_PARAMETER(destinationCapacity);
    if (decodedLength == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *decodedLength = 0;
    if (source == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    Pack200Reader reader(source, sourceLength);
    SegmentHeader header = {};
    if (reader.ReadMagic()) {
        reader = Pack200Reader(source, sourceLength);
        if (!ParseSegmentHeader(&reader, &header)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        UNREFERENCED_PARAMETER(header);
    }
    return STATUS_NOT_SUPPORTED;
}
}
}
