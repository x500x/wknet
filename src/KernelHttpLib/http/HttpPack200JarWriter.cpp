#include "HttpPack200JarWriter.h"

namespace KernelHttp
{
namespace http
{
namespace
{
    _Must_inspect_result_
    ULONG ComputeZipCrc32(const UCHAR* data, SIZE_T dataLength) noexcept
    {
        ULONG crc = 0xffffffffUL;
        for (SIZE_T index = 0; index < dataLength; ++index) {
            crc ^= data[index];
            for (UCHAR bit = 0; bit < 8; ++bit) {
                const ULONG mask = static_cast<ULONG>(0) - (crc & 1UL);
                crc = (crc >> 1) ^ (0xedb88320UL & mask);
            }
        }
        return ~crc;
    }

    _Must_inspect_result_
    bool IsValidUtf8(const char* data, SIZE_T length) noexcept
    {
        if (data == nullptr && length != 0) {
            return false;
        }
        SIZE_T index = 0;
        while (index < length) {
            const UCHAR first = static_cast<UCHAR>(data[index++]);
            if (first == 0 || first < 0x80) {
                if (first == 0) {
                    return false;
                }
                continue;
            }
            UCHAR continuationCount = 0;
            ULONG codePoint = 0;
            if (first >= 0xc2 && first <= 0xdf) {
                continuationCount = 1;
                codePoint = first & 0x1fU;
            }
            else if (first >= 0xe0 && first <= 0xef) {
                continuationCount = 2;
                codePoint = first & 0x0fU;
            }
            else if (first >= 0xf0 && first <= 0xf4) {
                continuationCount = 3;
                codePoint = first & 0x07U;
            }
            else {
                return false;
            }
            if (continuationCount > length - index) {
                return false;
            }
            for (UCHAR part = 0; part < continuationCount; ++part) {
                const UCHAR next = static_cast<UCHAR>(data[index++]);
                if ((next & 0xc0U) != 0x80U) {
                    return false;
                }
                codePoint = (codePoint << 6) | (next & 0x3fU);
            }
            if ((continuationCount == 2 && codePoint < 0x800) ||
                (continuationCount == 3 && codePoint < 0x10000) ||
                (codePoint >= 0xd800 && codePoint <= 0xdfff) ||
                codePoint > 0x10ffff) {
                return false;
            }
        }
        return true;
    }

    void UnixTimeToDos(ULONG unixTime, _Out_ USHORT* dosTime, _Out_ USHORT* dosDate) noexcept
    {
        if (dosTime == nullptr || dosDate == nullptr) {
            return;
        }
        ULONGLONG seconds = unixTime;
        const ULONGLONG minimumDosSeconds = 315532800ULL;
        if (seconds < minimumDosSeconds) {
            seconds = minimumDosSeconds;
        }
        const ULONGLONG daysSinceEpoch = seconds / 86400ULL;
        const ULONG secondsInDay = static_cast<ULONG>(seconds % 86400ULL);

        LONGLONG z = static_cast<LONGLONG>(daysSinceEpoch) + 719468;
        const LONGLONG era = (z >= 0 ? z : z - 146096) / 146097;
        const ULONG dayOfEra = static_cast<ULONG>(z - era * 146097);
        const ULONG yearOfEra =
            (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
        LONG year = static_cast<LONG>(yearOfEra) + static_cast<LONG>(era * 400);
        const ULONG dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
        const ULONG monthPrime = (5 * dayOfYear + 2) / 153;
        const ULONG day = dayOfYear - (153 * monthPrime + 2) / 5 + 1;
        const ULONG month = monthPrime < 10 ? monthPrime + 3 : monthPrime - 9;
        year += month <= 2 ? 1 : 0;
        if (year < 1980) year = 1980;
        if (year > 2107) year = 2107;

        const ULONG hour = secondsInDay / 3600;
        const ULONG minute = (secondsInDay % 3600) / 60;
        const ULONG second = secondsInDay % 60;
        *dosTime = static_cast<USHORT>((hour << 11) | (minute << 5) | (second / 2));
        *dosDate = static_cast<USHORT>(((static_cast<ULONG>(year) - 1980) << 9) | (month << 5) | day);
    }
}

    HttpPack200JarWriter::HttpPack200JarWriter(char* destination, SIZE_T capacity) noexcept :
        destination_(destination),
        capacity_(capacity)
    {
    }

    NTSTATUS HttpPack200JarWriter::Initialize(SIZE_T maxEntries) noexcept
    {
        entries_.Reset();
        entryCount_ = 0;
        length_ = 0;
        finished_ = false;
        return entries_.Allocate(maxEntries);
    }

    NTSTATUS HttpPack200JarWriter::AddStoredEntry(HttpXmlText name, const UCHAR* content, SIZE_T contentLength) noexcept
    {
        return AddEntry(name, content, contentLength, false, 0);
    }

    NTSTATUS HttpPack200JarWriter::AddEntry(
        HttpXmlText name,
        const UCHAR* content,
        SIZE_T contentLength,
        bool deflate,
        ULONG unixTime) noexcept
    {
        if (finished_ ||
            !entries_.IsValid() ||
            entryCount_ >= entries_.Count() ||
            !IsSafeEntryName(name) ||
            (content == nullptr && contentLength != 0) ||
            name.Length > 0xffffUL) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T blockCount = contentLength == 0 ?
            1 :
            contentLength / 65535 + (contentLength % 65535 != 0 ? 1 : 0);
        if (blockCount > (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - contentLength) / 5) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T compressedSize = deflate ? contentLength + blockCount * 5 : contentLength;

        Entry& entry = entries_[entryCount_];
        entry.Name = name;
        entry.Crc32 = ComputeZipCrc32(content, contentLength);
        entry.Size = static_cast<ULONGLONG>(contentLength);
        entry.CompressedSize = static_cast<ULONGLONG>(compressedSize);
        entry.LocalHeaderOffset = static_cast<ULONGLONG>(length_);
        entry.Method = deflate ? 8 : 0;
        UnixTimeToDos(unixTime, &entry.DosTime, &entry.DosDate);
        const bool zip64Sizes =
            entry.Size > 0xffffffffULL || entry.CompressedSize > 0xffffffffULL;

        NTSTATUS status = AppendLe32(0x04034b50UL);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(zip64Sizes ? 45 : 20);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(0x0800);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(entry.Method);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(entry.DosTime);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(entry.DosDate);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe32(entry.Crc32);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe32(zip64Sizes ? 0xffffffffUL : static_cast<ULONG>(entry.CompressedSize));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe32(zip64Sizes ? 0xffffffffUL : static_cast<ULONG>(entry.Size));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(static_cast<USHORT>(name.Length));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(zip64Sizes ? 20 : 0);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBytes(name.Data, name.Length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        entry.Name.Data = destination_ + static_cast<SIZE_T>(entry.LocalHeaderOffset) + 30;
        if (zip64Sizes) {
            status = AppendLe16(0x0001);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(16);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(entry.Size);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(entry.CompressedSize);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = deflate ?
            AppendRawDeflateStored(content, contentLength) :
            AppendBytes(content, contentLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ++entryCount_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200JarWriter::Finish(SIZE_T* jarLength) noexcept
    {
        if (jarLength == nullptr || finished_ || !entries_.IsValid()) {
            return STATUS_INVALID_PARAMETER;
        }

        const ULONGLONG centralDirectoryOffset = static_cast<ULONGLONG>(length_);
        bool needsZip64 = entryCount_ > 0xffffUL || centralDirectoryOffset > 0xffffffffULL;
        for (SIZE_T index = 0; index < entryCount_; ++index) {
            const Entry& entry = entries_[index];
            const bool zip64Size = entry.Size > 0xffffffffULL;
            const bool zip64CompressedSize = entry.CompressedSize > 0xffffffffULL;
            const bool zip64Offset = entry.LocalHeaderOffset > 0xffffffffULL;
            const UCHAR zip64ValueCount =
                static_cast<UCHAR>((zip64Size ? 1 : 0) +
                    (zip64CompressedSize ? 1 : 0) +
                    (zip64Offset ? 1 : 0));
            const USHORT zip64ExtraLength = zip64ValueCount == 0 ?
                0 :
                static_cast<USHORT>(4 + static_cast<USHORT>(zip64ValueCount) * 8);
            const bool entryNeedsZip64 = zip64ValueCount != 0;
            needsZip64 = needsZip64 || entryNeedsZip64;
            NTSTATUS status = AppendLe32(0x02014b50UL);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(entryNeedsZip64 ? 45 : 20);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(entryNeedsZip64 ? 45 : 20);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(0x0800);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(entry.Method);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(entry.DosTime);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(entry.DosDate);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(entry.Crc32);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(zip64CompressedSize ?
                0xffffffffUL :
                static_cast<ULONG>(entry.CompressedSize));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(zip64Size ? 0xffffffffUL : static_cast<ULONG>(entry.Size));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(static_cast<USHORT>(entry.Name.Length));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(zip64ExtraLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(zip64Offset ?
                0xffffffffUL :
                static_cast<ULONG>(entry.LocalHeaderOffset));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendBytes(entry.Name.Data, entry.Name.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (entryNeedsZip64) {
                status = AppendLe16(0x0001);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AppendLe16(static_cast<USHORT>(zip64ValueCount * 8));
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (zip64Size) {
                    status = AppendLe64(entry.Size);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                if (zip64CompressedSize) {
                    status = AppendLe64(entry.CompressedSize);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                if (zip64Offset) {
                    status = AppendLe64(entry.LocalHeaderOffset);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }
        }

        if (static_cast<ULONGLONG>(length_) < centralDirectoryOffset) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const ULONGLONG centralDirectorySize =
            static_cast<ULONGLONG>(length_) - centralDirectoryOffset;
        needsZip64 = needsZip64 || centralDirectorySize > 0xffffffffULL;

        NTSTATUS status = STATUS_SUCCESS;
        if (needsZip64) {
            const ULONGLONG zip64EndOffset = static_cast<ULONGLONG>(length_);
            status = AppendLe32(0x06064b50UL);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(44);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(45);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe16(45);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(static_cast<ULONGLONG>(entryCount_));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(static_cast<ULONGLONG>(entryCount_));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(centralDirectorySize);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(centralDirectoryOffset);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(0x07064b50UL);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe64(zip64EndOffset);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendLe32(1);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = AppendLe32(0x06054b50UL);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(0);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(0);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const USHORT legacyEntryCount = entryCount_ > 0xffffUL ?
            0xffffU :
            static_cast<USHORT>(entryCount_);
        status = AppendLe16(legacyEntryCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(legacyEntryCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe32(centralDirectorySize > 0xffffffffULL ?
            0xffffffffUL :
            static_cast<ULONG>(centralDirectorySize));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe32(centralDirectoryOffset > 0xffffffffULL ?
            0xffffffffUL :
            static_cast<ULONG>(centralDirectoryOffset));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendLe16(0);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        finished_ = true;
        *jarLength = length_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200JarWriter::AppendByte(UCHAR value) noexcept
    {
        if (destination_ == nullptr || length_ >= capacity_) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        destination_[length_] = static_cast<char>(value);
        ++length_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200JarWriter::AppendBytes(const void* value, SIZE_T valueLength) noexcept
    {
        if (valueLength == 0) {
            return STATUS_SUCCESS;
        }
        if (value == nullptr || destination_ == nullptr || valueLength > capacity_ || length_ > capacity_ - valueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(destination_ + length_, value, valueLength);
        length_ += valueLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200JarWriter::AppendLe16(USHORT value) noexcept
    {
        NTSTATUS status = AppendByte(static_cast<UCHAR>(value & 0xff));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendByte(static_cast<UCHAR>((value >> 8) & 0xff));
    }

    NTSTATUS HttpPack200JarWriter::AppendLe32(ULONG value) noexcept
    {
        NTSTATUS status = AppendLe16(static_cast<USHORT>(value & 0xffffUL));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendLe16(static_cast<USHORT>((value >> 16) & 0xffffUL));
    }

    NTSTATUS HttpPack200JarWriter::AppendLe64(ULONGLONG value) noexcept
    {
        NTSTATUS status = AppendLe32(static_cast<ULONG>(value & 0xffffffffULL));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendLe32(static_cast<ULONG>((value >> 32) & 0xffffffffULL));
    }

    NTSTATUS HttpPack200JarWriter::AppendRawDeflateStored(
        const UCHAR* content,
        SIZE_T contentLength) noexcept
    {
        if (content == nullptr && contentLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        SIZE_T offset = 0;
        do {
            const SIZE_T remaining = contentLength - offset;
            const USHORT blockLength = static_cast<USHORT>(
                remaining > 65535 ? 65535 : remaining);
            const bool finalBlock = remaining <= 65535;
            NTSTATUS status = AppendByte(finalBlock ? 1 : 0);
            if (NT_SUCCESS(status)) {
                status = AppendLe16(blockLength);
            }
            if (NT_SUCCESS(status)) {
                status = AppendLe16(static_cast<USHORT>(~blockLength));
            }
            if (NT_SUCCESS(status)) {
                status = AppendBytes(content == nullptr ? nullptr : content + offset, blockLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            offset += blockLength;
            if (finalBlock) {
                return STATUS_SUCCESS;
            }
        } while (offset < contentLength);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    bool HttpPack200JarWriter::IsSafeEntryName(HttpXmlText name) const noexcept
    {
        if (name.Data == nullptr || name.Length == 0 || name.Data[0] == '/' || name.Data[0] == '\\' ||
            !IsValidUtf8(name.Data, name.Length)) {
            return false;
        }
        bool segmentStart = true;
        bool segmentWasOnlyDots = false;
        for (SIZE_T index = 0; index < name.Length; ++index) {
            const UCHAR value = static_cast<UCHAR>(name.Data[index]);
            if (value < 0x20 || value == 0x7f || value == '\\' || value == ':') {
                return false;
            }
            if (value == '/') {
                if (segmentStart || segmentWasOnlyDots) {
                    return false;
                }
                segmentStart = true;
                segmentWasOnlyDots = false;
                continue;
            }
            if (segmentStart) {
                segmentWasOnlyDots = value == '.';
            }
            else if (segmentWasOnlyDots) {
                segmentWasOnlyDots = value == '.';
            }
            segmentStart = false;
        }
        if (segmentStart) {
            return name.Data[name.Length - 1] == '/';
        }
        return !segmentWasOnlyDots;
    }
}
}
