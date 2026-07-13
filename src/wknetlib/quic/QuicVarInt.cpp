#include "quic/QuicVarInt.h"

namespace wknet::quic {
    SIZE_T QuicVarIntEncodedLength(ULONGLONG value) noexcept
    {
        if (value <= 63) return 1;
        if (value <= 16383) return 2;
        if (value <= 1073741823ULL) return 4;
        if (value <= QuicVarIntMaximum) return 8;
        return 0;
    }

    NTSTATUS QuicDecodeVarInt(
        const UCHAR* data,
        SIZE_T dataLength,
        ULONGLONG* value,
        SIZE_T* bytesConsumed) noexcept
    {
        if (value != nullptr) *value = 0;
        if (bytesConsumed != nullptr) *bytesConsumed = 0;
        if (data == nullptr || value == nullptr || dataLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T encodedLength = static_cast<SIZE_T>(1) << (data[0] >> 6);
        if (dataLength < encodedLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONGLONG decoded = static_cast<ULONGLONG>(data[0] & 0x3fU);
        for (SIZE_T index = 1; index < encodedLength; ++index) {
            decoded = (decoded << 8) | data[index];
        }
        *value = decoded;
        if (bytesConsumed != nullptr) *bytesConsumed = encodedLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicEncodeVarInt(
        ULONGLONG value,
        SIZE_T encodedLength,
        UCHAR* output,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) *bytesWritten = 0;
        if (output == nullptr) return STATUS_INVALID_PARAMETER;
        if (value > QuicVarIntMaximum) return STATUS_INTEGER_OVERFLOW;
        if (encodedLength == 0) encodedLength = QuicVarIntEncodedLength(value);
        if (encodedLength != 1 && encodedLength != 2 && encodedLength != 4 && encodedLength != 8) {
            return STATUS_INVALID_PARAMETER;
        }
        const ULONGLONG maximum = encodedLength == 8
            ? QuicVarIntMaximum
            : ((1ULL << ((encodedLength * 8) - 2)) - 1ULL);
        if (value > maximum) return STATUS_INTEGER_OVERFLOW;
        if (capacity < encodedLength) return STATUS_BUFFER_TOO_SMALL;

        ULONGLONG remaining = value;
        for (SIZE_T index = encodedLength; index > 0; --index) {
            output[index - 1] = static_cast<UCHAR>(remaining & 0xffU);
            remaining >>= 8;
        }
        const UCHAR prefix = encodedLength == 1 ? 0x00U :
            (encodedLength == 2 ? 0x40U : (encodedLength == 4 ? 0x80U : 0xc0U));
        output[0] = static_cast<UCHAR>(output[0] | prefix);
        if (bytesWritten != nullptr) *bytesWritten = encodedLength;
        return STATUS_SUCCESS;
    }
}
