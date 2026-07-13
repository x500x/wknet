#include "qpack/QpackInteger.h"

namespace wknet::qpack
{
NTSTATUS QpackEncodeInteger(ULONGLONG value, UCHAR prefix, UCHAR prefixBits, UCHAR *destination, SIZE_T capacity,
                            SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (destination == nullptr || bytesWritten == nullptr || prefixBits == 0 || prefixBits > 8 ||
        value > QpackIntegerMaximum || capacity == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const UCHAR prefixMask = prefixBits == 8 ? 0xffU : static_cast<UCHAR>((1U << prefixBits) - 1U);
    prefix &= static_cast<UCHAR>(~prefixMask);
    if (value < prefixMask)
    {
        destination[0] = static_cast<UCHAR>(prefix | static_cast<UCHAR>(value));
        *bytesWritten = 1;
        return STATUS_SUCCESS;
    }

    destination[0] = static_cast<UCHAR>(prefix | prefixMask);
    SIZE_T offset = 1;
    value -= prefixMask;
    while (value >= 128)
    {
        if (offset >= capacity)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        destination[offset++] = static_cast<UCHAR>((value & 0x7fU) | 0x80U);
        value >>= 7;
    }
    if (offset >= capacity)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    destination[offset++] = static_cast<UCHAR>(value);
    *bytesWritten = offset;
    return STATUS_SUCCESS;
}

NTSTATUS QpackDecodeInteger(const UCHAR *source, SIZE_T length, UCHAR prefixBits, ULONGLONG *value,
                            SIZE_T *bytesConsumed) noexcept
{
    if (value != nullptr)
    {
        *value = 0;
    }
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (source == nullptr || value == nullptr || bytesConsumed == nullptr || length == 0 || prefixBits == 0 ||
        prefixBits > 8)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const UCHAR prefixMask = prefixBits == 8 ? 0xffU : static_cast<UCHAR>((1U << prefixBits) - 1U);
    ULONGLONG decoded = source[0] & prefixMask;
    if (decoded < prefixMask)
    {
        *value = decoded;
        *bytesConsumed = 1;
        return STATUS_SUCCESS;
    }

    UCHAR shift = 0;
    SIZE_T offset = 1;
    for (;;)
    {
        if (offset >= length)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        const UCHAR current = source[offset++];
        const ULONGLONG payload = current & 0x7fU;
        if (shift >= 63 || payload > ((QpackIntegerMaximum - decoded) >> shift))
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        decoded += payload << shift;
        if ((current & 0x80U) == 0)
        {
            *value = decoded;
            *bytesConsumed = offset;
            return STATUS_SUCCESS;
        }
        if (shift > 56)
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        shift = static_cast<UCHAR>(shift + 7);
    }
}
} // namespace wknet::qpack
