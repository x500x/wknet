#include "HttpPack200BandCodec.h"

namespace wknet
{
namespace http1
{
namespace
{
    _Must_inspect_result_
    bool CodingIsValid(HttpPack200Coding coding) noexcept
    {
        if (coding.B == 0 || coding.B > 5 ||
            coding.H == 0 || coding.H > 256 ||
            coding.S > 2 || coding.D > 1) {
            return false;
        }
        if (coding.B == 1 && coding.H != 256) {
            return false;
        }
        if (coding.H == 256 && coding.B == 5) {
            return false;
        }
        return true;
    }

    _Must_inspect_result_
    ULONGLONG CodingCardinality(HttpPack200Coding coding) noexcept
    {
        if (coding.H == 1) {
            return static_cast<ULONGLONG>(coding.B) * 255ULL + 1ULL;
        }

        const ULONGLONG low = 256ULL - coding.H;
        ULONGLONG power = 1;
        ULONGLONG cardinality = 0;
        for (UCHAR index = 0; index < coding.B; ++index) {
            cardinality += low * power;
            power *= coding.H;
        }
        cardinality += power;
        return cardinality;
    }
}

    HttpPack200BandReader::HttpPack200BandReader(const UCHAR* data, SIZE_T length) noexcept :
        data_(data),
        length_(length)
    {
    }

    bool HttpPack200BandReader::ReadByte(UCHAR* value) noexcept
    {
        if (value == nullptr || cursor_ >= length_) {
            return false;
        }
        *value = data_[cursor_++];
        return true;
    }

    bool HttpPack200BandReader::ReadBigEndian32(ULONG* value) noexcept
    {
        if (value == nullptr || Remaining() < 4) {
            return false;
        }
        *value =
            (static_cast<ULONG>(data_[cursor_]) << 24) |
            (static_cast<ULONG>(data_[cursor_ + 1]) << 16) |
            (static_cast<ULONG>(data_[cursor_ + 2]) << 8) |
            static_cast<ULONG>(data_[cursor_ + 3]);
        cursor_ += 4;
        return true;
    }

    bool HttpPack200BandReader::ReadInt(HttpPack200Coding coding, LONG* value) noexcept
    {
        if (value == nullptr || !CodingIsValid(coding)) {
            return false;
        }

        const ULONG l = 256UL - static_cast<ULONG>(coding.H);
        ULONGLONG decodedValue = 0;
        ULONGLONG power = 1;
        UCHAR byte = 0;
        for (UCHAR index = 0; index < coding.B; ++index) {
            if (!ReadByte(&byte)) {
                return false;
            }
            if (static_cast<ULONGLONG>(byte) >
                (static_cast<ULONGLONG>(~static_cast<ULONG>(0)) - decodedValue) / power) {
                return false;
            }
            decodedValue += static_cast<ULONGLONG>(byte) * power;
            if (byte < l || index + 1 == coding.B) {
                break;
            }
            if (power > 0xffffffffULL / coding.H) {
                return false;
            }
            power *= coding.H;
        }

        if (decodedValue > 0xffffffffULL) {
            return false;
        }

        LONGLONG signedValue = static_cast<LONGLONG>(decodedValue);
        if (coding.S != 0) {
            const ULONGLONG mask = (1ULL << coding.S) - 1ULL;
            if ((decodedValue & mask) == mask) {
                signedValue = ~static_cast<LONGLONG>(decodedValue >> coding.S);
            }
            else {
                signedValue = static_cast<LONGLONG>(decodedValue - (decodedValue >> coding.S));
            }
        }

        if (coding.D != 0) {
            signedValue += previousValue_;
            const ULONGLONG cardinality = CodingCardinality(coding);
            if (cardinality >= 0x100000000ULL) {
                signedValue = static_cast<LONG>(static_cast<ULONG>(signedValue));
            }
            else {
                const LONGLONG smallest = 0;
                const LONGLONG largest = static_cast<LONGLONG>(cardinality - 1);
                while (signedValue > largest) {
                    signedValue -= static_cast<LONGLONG>(cardinality);
                }
                while (signedValue < smallest) {
                    signedValue += static_cast<LONGLONG>(cardinality);
                }
            }
            previousValue_ = static_cast<LONG>(signedValue);
        }

        if (coding.S == 0 && coding.D == 0) {
            *value = static_cast<LONG>(static_cast<ULONG>(decodedValue));
            return true;
        }
        if (signedValue < static_cast<LONGLONG>(-2147483647L) - 1 ||
            signedValue > static_cast<LONGLONG>(2147483647L)) {
            return false;
        }
        *value = static_cast<LONG>(signedValue);
        return true;
    }

    bool HttpPack200BandReader::ReadUnsigned(HttpPack200CodingKind kind, ULONG* value) noexcept
    {
        if (value == nullptr) {
            return false;
        }
        LONG signedValue = 0;
        if (!ReadInt(HttpPack200CodingFor(kind), &signedValue) || signedValue < 0) {
            return false;
        }
        *value = static_cast<ULONG>(signedValue);
        return true;
    }

    void HttpPack200BandReader::ResetDelta() noexcept
    {
        previousValue_ = 0;
    }

    SIZE_T HttpPack200BandReader::Remaining() const noexcept
    {
        return cursor_ <= length_ ? length_ - cursor_ : 0;
    }

    const UCHAR* HttpPack200BandReader::Current() const noexcept
    {
        return cursor_ <= length_ ? data_ + cursor_ : nullptr;
    }

    bool HttpPack200BandReader::Skip(SIZE_T length) noexcept
    {
        if (length > Remaining()) {
            return false;
        }
        cursor_ += length;
        return true;
    }
}
}
