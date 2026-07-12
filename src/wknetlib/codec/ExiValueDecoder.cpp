#include "ExiValueDecoder.h"

namespace wknet
{
namespace codec
{
namespace
{
    _Must_inspect_result_
    SIZE_T WriteUnsignedDecimal(ULONG value, _Out_writes_(capacity) char* output, SIZE_T capacity) noexcept
    {
        if (output == nullptr || capacity == 0) {
            return 0;
        }
        ULONG divisor = 1;
        SIZE_T count = 1;
        while (value / divisor >= 10) {
            divisor *= 10;
            ++count;
        }
        if (count > capacity) {
            return 0;
        }
        for (SIZE_T index = 0; index < count; ++index) {
            output[index] = static_cast<char>('0' + (value / divisor) % 10);
            divisor /= 10;
        }
        return count;
    }

    _Must_inspect_result_
    SIZE_T WriteSignedDecimal(LONG value, _Out_writes_(capacity) char* output, SIZE_T capacity) noexcept
    {
        if (output == nullptr || capacity == 0) {
            return 0;
        }
        SIZE_T offset = 0;
        ULONGLONG magnitude = 0;
        if (value < 0) {
            output[offset++] = '-';
            magnitude = static_cast<ULONGLONG>(-static_cast<LONGLONG>(value));
        }
        else {
            magnitude = static_cast<ULONGLONG>(value);
        }
        if (magnitude > 0xffffffffULL || offset >= capacity) {
            return 0;
        }
        const SIZE_T digits = WriteUnsignedDecimal(
            static_cast<ULONG>(magnitude),
            output + offset,
            capacity - offset);
        return digits == 0 ? 0 : offset + digits;
    }

    _Must_inspect_result_
    SIZE_T WriteUnsignedDecimal64(
        ULONGLONG value,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity) noexcept
    {
        if (output == nullptr || capacity == 0) {
            return 0;
        }
        ULONGLONG divisor = 1;
        SIZE_T count = 1;
        while (value / divisor >= 10) {
            if (divisor > 0xffffffffffffffffULL / 10) {
                break;
            }
            divisor *= 10;
            ++count;
        }
        if (count > capacity) {
            return 0;
        }
        for (SIZE_T index = 0; index < count; ++index) {
            output[index] = static_cast<char>('0' + (value / divisor) % 10);
            divisor /= 10;
        }
        return count;
    }

    _Must_inspect_result_
    SIZE_T WriteSignedDecimal64(
        LONGLONG value,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity) noexcept
    {
        if (output == nullptr || capacity == 0) {
            return 0;
        }
        SIZE_T offset = 0;
        ULONGLONG magnitude = 0;
        if (value < 0) {
            output[offset++] = '-';
            magnitude = static_cast<ULONGLONG>(-(value + 1)) + 1;
        }
        else {
            magnitude = static_cast<ULONGLONG>(value);
        }
        if (offset >= capacity) {
            return 0;
        }
        const SIZE_T digits = WriteUnsignedDecimal64(
            magnitude,
            output + offset,
            capacity - offset);
        return digits == 0 ? 0 : offset + digits;
    }

    _Must_inspect_result_
    NTSTATUS AllocateTextStorage(
        _Inout_ HeapArray<char>* storage,
        SIZE_T capacity,
        _Out_ char** output) noexcept
    {
        if (storage == nullptr || output == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        const SIZE_T allocationSize = capacity == 0 ? 1 : capacity;
        const NTSTATUS status = storage->Allocate(allocationSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        *output = storage->Get();
        return *output != nullptr ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    }

    _Must_inspect_result_
    NTSTATUS ReadNBitUnsigned64(
        _Inout_ HttpExiBitInput* input,
        UCHAR bitCount,
        _Out_ ULONGLONG* value) noexcept
    {
        if (input == nullptr || value == nullptr || bitCount > 64) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = 0;
        if (bitCount <= 32) {
            ULONG parsed = 0;
            if (!input->ReadBits(bitCount, &parsed)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            *value = parsed;
            return STATUS_SUCCESS;
        }

        const UCHAR remainingBits = static_cast<UCHAR>(bitCount - 32);
        ULONG first = 0;
        ULONG second = 0;
        if (!input->ReadBits(32, &first) || !input->ReadBits(remainingBits, &second)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (input->Mode() == HttpExiInputMode::ByteAligned) {
            *value = static_cast<ULONGLONG>(first) |
                (static_cast<ULONGLONG>(second) << 32);
        }
        else {
            *value = (static_cast<ULONGLONG>(first) << remainingBits) | second;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadArbitraryUnsignedText(
        _Inout_ HttpExiBitInput* input,
        bool addOne,
        bool negative,
        _Inout_ HeapArray<char>* storage,
        _Out_ HttpXmlText* value) noexcept
    {
        if (input == nullptr || storage == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        const SIZE_T byteOffset = input->ByteOffset();
        const SIZE_T byteLength = input->ByteLength();
        if (byteOffset > byteLength || byteLength == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const SIZE_T maximumOctets = byteLength - byteOffset + 1;
        if (maximumOctets > (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 2) / 3) {
            return STATUS_INTEGER_OVERFLOW;
        }
        HeapArray<UCHAR> chunks(maximumOctets);
        HeapArray<UCHAR> digits(maximumOctets * 3 + 2);
        if (!chunks.IsValid() || !digits.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T chunkCount = 0;
        bool terminated = false;
        while (chunkCount < chunks.Count()) {
            UCHAR octet = 0;
            if (!input->ReadByte(&octet)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            chunks[chunkCount++] = static_cast<UCHAR>(octet & 0x7fU);
            if ((octet & 0x80U) == 0) {
                terminated = true;
                break;
            }
        }
        if (!terminated || chunkCount == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        digits[0] = 0;
        SIZE_T digitCount = 1;
        for (SIZE_T chunkIndex = chunkCount; chunkIndex > 0; --chunkIndex) {
            ULONG carry = chunks[chunkIndex - 1];
            for (SIZE_T digitIndex = 0; digitIndex < digitCount; ++digitIndex) {
                const ULONG expanded = static_cast<ULONG>(digits[digitIndex]) * 128 + carry;
                digits[digitIndex] = static_cast<UCHAR>(expanded % 10);
                carry = expanded / 10;
            }
            while (carry != 0) {
                if (digitCount >= digits.Count()) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                digits[digitCount++] = static_cast<UCHAR>(carry % 10);
                carry /= 10;
            }
        }
        if (addOne) {
            SIZE_T digitIndex = 0;
            ULONG carry = 1;
            while (carry != 0 && digitIndex < digitCount) {
                const ULONG expanded = static_cast<ULONG>(digits[digitIndex]) + carry;
                digits[digitIndex] = static_cast<UCHAR>(expanded % 10);
                carry = expanded / 10;
                ++digitIndex;
            }
            if (carry != 0) {
                if (digitCount >= digits.Count()) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                digits[digitCount++] = static_cast<UCHAR>(carry);
            }
        }

        if (digitCount == static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) ||
            (negative && digitCount == static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 1)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T textLength = digitCount + (negative ? 1 : 0);
        char* output = nullptr;
        NTSTATUS status = AllocateTextStorage(storage, textLength, &output);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T outputIndex = 0;
        if (negative) {
            output[outputIndex++] = '-';
        }
        for (SIZE_T digitIndex = digitCount; digitIndex > 0; --digitIndex) {
            output[outputIndex++] = static_cast<char>('0' + digits[digitIndex - 1]);
        }
        value->Data = output;
        value->Length = outputIndex;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadBoundedIntegerText(
        _Inout_ HttpExiBitInput* input,
        UCHAR bitCount,
        bool signedValue,
        _Inout_ HeapArray<char>* storage,
        _Out_ HttpXmlText* value) noexcept
    {
        ULONGLONG encoded = 0;
        NTSTATUS status = ReadNBitUnsigned64(input, bitCount, &encoded);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        char* output = nullptr;
        status = AllocateTextStorage(storage, 21, &output);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T length = 0;
        if (!signedValue) {
            length = WriteUnsignedDecimal64(encoded, output, 21);
        }
        else {
            const ULONGLONG signBoundary = 1ULL << (bitCount - 1);
            LONGLONG decoded = 0;
            if (encoded < signBoundary) {
                decoded = static_cast<LONGLONG>(encoded) - static_cast<LONGLONG>(signBoundary);
            }
            else {
                decoded = static_cast<LONGLONG>(encoded - signBoundary);
            }
            length = WriteSignedDecimal64(decoded, output, 21);
        }
        if (length == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        value->Data = output;
        value->Length = length;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool AppendCharacter(
        char character,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* length) noexcept
    {
        if (output == nullptr || length == nullptr || *length >= capacity) {
            return false;
        }
        output[(*length)++] = character;
        return true;
    }

    _Must_inspect_result_
    bool AppendTwoDigits(
        ULONG number,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* length) noexcept
    {
        return number <= 99 &&
            AppendCharacter(static_cast<char>('0' + number / 10), output, capacity, length) &&
            AppendCharacter(static_cast<char>('0' + number % 10), output, capacity, length);
    }

    _Must_inspect_result_
    bool AppendYear(
        LONGLONG year,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* length) noexcept
    {
        if (year == 0 || output == nullptr || length == nullptr) {
            return false;
        }
        ULONGLONG magnitude = 0;
        if (year < 0) {
            if (!AppendCharacter('-', output, capacity, length)) {
                return false;
            }
            magnitude = static_cast<ULONGLONG>(-(year + 1)) + 1;
        }
        else {
            magnitude = static_cast<ULONGLONG>(year);
        }
        SIZE_T digitCount = 1;
        ULONGLONG divisor = 1;
        while (magnitude / divisor >= 10) {
            if (divisor > 0xffffffffffffffffULL / 10) {
                break;
            }
            divisor *= 10;
            ++digitCount;
        }
        while (digitCount < 4) {
            if (!AppendCharacter('0', output, capacity, length)) {
                return false;
            }
            ++digitCount;
        }
        const SIZE_T written = WriteUnsignedDecimal64(
            magnitude,
            output + *length,
            capacity - *length);
        if (written == 0) {
            return false;
        }
        *length += written;
        return true;
    }

    _Must_inspect_result_
    bool IsLeapYear(LONGLONG year) noexcept
    {
        const LONGLONG positive = year < 0 ? -year : year;
        return (positive % 4 == 0 && positive % 100 != 0) || positive % 400 == 0;
    }

    _Must_inspect_result_
    bool IsValidMonthDay(LONGLONG year, ULONG month, ULONG day) noexcept
    {
        if (month < 1 || month > 12 || day < 1) {
            return false;
        }
        ULONG maximumDay = 31;
        if (month == 4 || month == 6 || month == 9 || month == 11) {
            maximumDay = 30;
        }
        else if (month == 2) {
            maximumDay = IsLeapYear(year) ? 29 : 28;
        }
        return day <= maximumDay;
    }

    _Must_inspect_result_
    NTSTATUS ReadDateTimeText(
        _Inout_ HttpExiBitInput* input,
        HttpExiDatatypeKind datatype,
        _Inout_ HeapArray<char>* storage,
        _Out_ HttpXmlText* value) noexcept
    {
        const bool hasYear = datatype == HttpExiDatatypeKind::GYear ||
            datatype == HttpExiDatatypeKind::GYearMonth ||
            datatype == HttpExiDatatypeKind::Date ||
            datatype == HttpExiDatatypeKind::DateTime;
        const bool hasMonthDay = datatype == HttpExiDatatypeKind::GYearMonth ||
            datatype == HttpExiDatatypeKind::Date ||
            datatype == HttpExiDatatypeKind::DateTime ||
            datatype == HttpExiDatatypeKind::GMonth ||
            datatype == HttpExiDatatypeKind::GMonthDay ||
            datatype == HttpExiDatatypeKind::GDay;
        const bool hasTime = datatype == HttpExiDatatypeKind::DateTime ||
            datatype == HttpExiDatatypeKind::Time;

        LONGLONG year = 2000;
        ULONG month = 0;
        ULONG day = 0;
        ULONG hour = 0;
        ULONG minute = 0;
        ULONG second = 0;
        HttpXmlText reversedFraction = {};
        HeapArray<char> fractionStorage = {};

        if (hasYear) {
            LONG yearOffset = 0;
            NTSTATUS status = HttpExiReadInteger(input, &yearOffset);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            year += yearOffset;
            if (year == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        if (hasMonthDay) {
            ULONGLONG monthDay = 0;
            NTSTATUS status = ReadNBitUnsigned64(input, 9, &monthDay);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            month = static_cast<ULONG>(monthDay >> 5);
            day = static_cast<ULONG>(monthDay & 0x1fU);
            if (datatype == HttpExiDatatypeKind::GMonth) {
                if (month < 1 || month > 12 || day != 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            else if (datatype == HttpExiDatatypeKind::GDay) {
                if (month != 0 || day < 1 || day > 31) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            else if (!IsValidMonthDay(year, month, day)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        if (hasTime) {
            ULONGLONG encodedTime = 0;
            NTSTATUS status = ReadNBitUnsigned64(input, 17, &encodedTime);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            hour = static_cast<ULONG>(encodedTime >> 12);
            minute = static_cast<ULONG>((encodedTime >> 6) & 0x3fU);
            second = static_cast<ULONG>(encodedTime & 0x3fU);
            if (hour > 24 || minute > 59 || second > 59 ||
                (hour == 24 && (minute != 0 || second != 0))) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            bool hasFraction = false;
            status = HttpExiReadBoolean(input, &hasFraction);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (hasFraction) {
                status = ReadArbitraryUnsignedText(
                    input,
                    false,
                    false,
                    &fractionStorage,
                    &reversedFraction);
                if (!NT_SUCCESS(status) || reversedFraction.Length == 0 || hour == 24) {
                    return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
                }
            }
        }

        bool hasTimezone = false;
        NTSTATUS status = HttpExiReadBoolean(input, &hasTimezone);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        LONG timezoneMinutes = 0;
        if (hasTimezone) {
            ULONGLONG timezone = 0;
            status = ReadNBitUnsigned64(input, 11, &timezone);
            if (!NT_SUCCESS(status) || timezone > 1792) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            timezoneMinutes = static_cast<LONG>(timezone) - 896;
            if (timezoneMinutes < -840 || timezoneMinutes > 840) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        char* output = nullptr;
        status = AllocateTextStorage(storage, 128, &output);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        SIZE_T length = 0;
        if (datatype == HttpExiDatatypeKind::GYear) {
            if (!AppendYear(year, output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else if (datatype == HttpExiDatatypeKind::GYearMonth) {
            if (!AppendYear(year, output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendTwoDigits(month, output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else if (datatype == HttpExiDatatypeKind::Date ||
            datatype == HttpExiDatatypeKind::DateTime) {
            if (!AppendYear(year, output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendTwoDigits(month, output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendTwoDigits(day, output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (datatype == HttpExiDatatypeKind::DateTime &&
                !AppendCharacter('T', output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else if (datatype == HttpExiDatatypeKind::GMonth) {
            if (!AppendCharacter('-', output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendTwoDigits(month, output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else if (datatype == HttpExiDatatypeKind::GMonthDay) {
            if (!AppendCharacter('-', output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendTwoDigits(month, output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendTwoDigits(day, output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else if (datatype == HttpExiDatatypeKind::GDay) {
            if (!AppendCharacter('-', output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendCharacter('-', output, 128, &length) ||
                !AppendTwoDigits(day, output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        if (hasTime) {
            if (!AppendTwoDigits(hour, output, 128, &length) ||
                !AppendCharacter(':', output, 128, &length) ||
                !AppendTwoDigits(minute, output, 128, &length) ||
                !AppendCharacter(':', output, 128, &length) ||
                !AppendTwoDigits(second, output, 128, &length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (reversedFraction.Length != 0) {
                if (!AppendCharacter('.', output, 128, &length) ||
                    reversedFraction.Length > 128 - length) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                for (SIZE_T index = reversedFraction.Length; index > 0; --index) {
                    output[length++] = reversedFraction.Data[index - 1];
                }
            }
        }

        if (hasTimezone) {
            if (timezoneMinutes == 0) {
                if (!AppendCharacter('Z', output, 128, &length)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
            }
            else {
                const bool negativeTimezone = timezoneMinutes < 0;
                const ULONG magnitude = static_cast<ULONG>(
                    negativeTimezone ? -timezoneMinutes : timezoneMinutes);
                if (!AppendCharacter(negativeTimezone ? '-' : '+', output, 128, &length) ||
                    !AppendTwoDigits(magnitude / 60, output, 128, &length) ||
                    !AppendCharacter(':', output, 128, &length) ||
                    !AppendTwoDigits(magnitude % 60, output, 128, &length)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
            }
        }
        value->Data = output;
        value->Length = length;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadBinary(
        _Inout_ HttpExiBitInput* input,
        bool base64,
        _Inout_ HeapArray<char>* storage,
        _Out_ HttpXmlText* value) noexcept
    {
        ULONG byteCount = 0;
        if (!input->ReadUnsignedInteger(&byteCount)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        SIZE_T textLength = 0;
        if (base64) {
            if (static_cast<SIZE_T>(byteCount) >
                (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 2) / 4 * 3) {
                return STATUS_INTEGER_OVERFLOW;
            }
            textLength = ((static_cast<SIZE_T>(byteCount) + 2) / 3) * 4;
        }
        else {
            if (static_cast<SIZE_T>(byteCount) >
                static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / 2) {
                return STATUS_INTEGER_OVERFLOW;
            }
            textLength = static_cast<SIZE_T>(byteCount) * 2;
        }
        char* output = nullptr;
        NTSTATUS status = AllocateTextStorage(storage, textLength, &output);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!base64) {
            constexpr char Hex[] = "0123456789ABCDEF";
            for (ULONG index = 0; index < byteCount; ++index) {
                UCHAR byte = 0;
                if (!input->ReadByte(&byte)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                output[static_cast<SIZE_T>(index) * 2] = Hex[byte >> 4];
                output[static_cast<SIZE_T>(index) * 2 + 1] = Hex[byte & 0x0fU];
            }
        }
        else {
            constexpr char Base64[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            SIZE_T outputIndex = 0;
            ULONG inputIndex = 0;
            while (inputIndex < byteCount) {
                UCHAR first = 0;
                UCHAR second = 0;
                UCHAR third = 0;
                if (!input->ReadByte(&first)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                ++inputIndex;
                const bool haveSecond = inputIndex < byteCount;
                if (haveSecond) {
                    if (!input->ReadByte(&second)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    ++inputIndex;
                }
                const bool haveThird = inputIndex < byteCount;
                if (haveThird) {
                    if (!input->ReadByte(&third)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    ++inputIndex;
                }
                output[outputIndex++] = Base64[first >> 2];
                output[outputIndex++] = Base64[((first & 0x03U) << 4) | (second >> 4)];
                output[outputIndex++] = haveSecond ?
                    Base64[((second & 0x0fU) << 2) | (third >> 6)] :
                    '=';
                output[outputIndex++] = haveThird ? Base64[third & 0x3fU] : '=';
            }
            if (outputIndex != textLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        value->Data = textLength == 0 ? nullptr : output;
        value->Length = textLength;
        return STATUS_SUCCESS;
    }
}

    NTSTATUS HttpExiReadBoolean(HttpExiBitInput* input, bool* value) noexcept
    {
        if (input == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ULONG bit = 0;
        if (!input->ReadBits(1, &bit)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *value = bit != 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiReadInteger(HttpExiBitInput* input, LONG* value) noexcept
    {
        if (input == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ULONG negative = 0;
        if (!input->ReadBits(1, &negative)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG magnitude = 0;
        if (!input->ReadUnsignedInteger(&magnitude) || magnitude > 0x7fffffffUL) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *value = negative != 0 ?
            static_cast<LONG>(-static_cast<LONGLONG>(magnitude) - 1) :
            static_cast<LONG>(magnitude);
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiReadDecimal(HttpExiBitInput* input, HttpExiDecimalValue* value) noexcept
    {
        if (input == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};
        ULONG negative = 0;
        if (!input->ReadBits(1, &negative)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        value->Negative = negative != 0;
        if (!input->ReadUnsignedInteger(&value->Integral) ||
            !input->ReadUnsignedInteger(&value->Fractional)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiReadFloat(HttpExiBitInput* input, HttpExiFloatValue* value) noexcept
    {
        if (input == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};
        NTSTATUS status = HttpExiReadInteger(input, &value->Mantissa);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return HttpExiReadInteger(input, &value->Exponent);
    }

    NTSTATUS HttpExiReadTypedValue(
        HttpExiBitInput* input,
        HttpExiDatatypeKind datatype,
        HeapArray<char>* storage,
        HttpXmlText* value) noexcept
    {
        if (input == nullptr || storage == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *value = {};

        switch (datatype) {
        case HttpExiDatatypeKind::Boolean:
            {
                bool parsed = false;
                NTSTATUS status = HttpExiReadBoolean(input, &parsed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                const char* literal = parsed ? "true" : "false";
                const SIZE_T length = parsed ? 4 : 5;
                char* output = nullptr;
                status = AllocateTextStorage(storage, length, &output);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                RtlCopyMemory(output, literal, length);
                value->Data = output;
                value->Length = length;
                return STATUS_SUCCESS;
            }

        case HttpExiDatatypeKind::Integer:
            {
                bool negative = false;
                NTSTATUS status = HttpExiReadBoolean(input, &negative);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                return ReadArbitraryUnsignedText(
                    input,
                    negative,
                    negative,
                    storage,
                    value);
            }

        case HttpExiDatatypeKind::Decimal:
            {
                HttpExiDecimalValue parsed = {};
                NTSTATUS status = HttpExiReadDecimal(input, &parsed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                char* output = nullptr;
                status = AllocateTextStorage(storage, 23, &output);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                SIZE_T length = 0;
                if (parsed.Negative) {
                    output[length++] = '-';
                }
                const SIZE_T integralLength = WriteUnsignedDecimal(
                    parsed.Integral,
                    output + length,
                    23 - length);
                if (integralLength == 0 || length + integralLength >= 23) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                length += integralLength;
                output[length++] = '.';
                ULONG reversedFractional = parsed.Fractional;
                do {
                    if (length >= 23) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    output[length++] = static_cast<char>('0' + reversedFractional % 10);
                    reversedFractional /= 10;
                } while (reversedFractional != 0);
                value->Data = output;
                value->Length = length;
                return STATUS_SUCCESS;
            }

        case HttpExiDatatypeKind::Float:
            {
                HttpExiFloatValue parsed = {};
                NTSTATUS status = HttpExiReadFloat(input, &parsed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                char* output = nullptr;
                status = AllocateTextStorage(storage, 32, &output);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                SIZE_T length = WriteSignedDecimal(parsed.Mantissa, output, 32);
                if (length == 0 || length >= 32) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                output[length++] = 'E';
                const SIZE_T exponentLength = WriteSignedDecimal(
                    parsed.Exponent,
                    output + length,
                    32 - length);
                if (exponentLength == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                length += exponentLength;
                value->Data = output;
                value->Length = length;
                return STATUS_SUCCESS;
            }

        case HttpExiDatatypeKind::Base64Binary:
            return ReadBinary(input, true, storage, value);

        case HttpExiDatatypeKind::HexBinary:
            return ReadBinary(input, false, storage, value);

        case HttpExiDatatypeKind::Byte:
            return ReadBoundedIntegerText(input, 8, true, storage, value);

        case HttpExiDatatypeKind::Short:
            return ReadBoundedIntegerText(input, 16, true, storage, value);

        case HttpExiDatatypeKind::Int:
            return ReadBoundedIntegerText(input, 32, true, storage, value);

        case HttpExiDatatypeKind::Long:
            return ReadBoundedIntegerText(input, 64, true, storage, value);

        case HttpExiDatatypeKind::UnsignedByte:
            return ReadBoundedIntegerText(input, 8, false, storage, value);

        case HttpExiDatatypeKind::UnsignedShort:
            return ReadBoundedIntegerText(input, 16, false, storage, value);

        case HttpExiDatatypeKind::UnsignedInt:
            return ReadBoundedIntegerText(input, 32, false, storage, value);

        case HttpExiDatatypeKind::UnsignedLong:
            return ReadBoundedIntegerText(input, 64, false, storage, value);

        case HttpExiDatatypeKind::NonNegativeInteger:
            return ReadArbitraryUnsignedText(input, false, false, storage, value);

        case HttpExiDatatypeKind::PositiveInteger:
            return ReadArbitraryUnsignedText(input, true, false, storage, value);

        case HttpExiDatatypeKind::GYear:
        case HttpExiDatatypeKind::GYearMonth:
        case HttpExiDatatypeKind::Date:
        case HttpExiDatatypeKind::DateTime:
        case HttpExiDatatypeKind::GMonth:
        case HttpExiDatatypeKind::GMonthDay:
        case HttpExiDatatypeKind::GDay:
        case HttpExiDatatypeKind::Time:
            return ReadDateTimeText(input, datatype, storage, value);

        case HttpExiDatatypeKind::String:
            return STATUS_INVALID_PARAMETER;

        case HttpExiDatatypeKind::None:
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }
}
}
