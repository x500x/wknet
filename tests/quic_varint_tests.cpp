#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "quic/QuicVarInt.h"

#include <stdio.h>

namespace
{
bool g_failed = false;

void Expect(bool condition, const char *message) noexcept
{
    if (!condition)
    {
        g_failed = true;
        printf("FAIL: %s\n", message);
    }
}

void TestRoundTrip(ULONGLONG value, SIZE_T encodedLength) noexcept
{
    UCHAR encoded[8] = {};
    SIZE_T written = 0;
    Expect(NT_SUCCESS(wknet::quic::QuicEncodeVarInt(value, encodedLength, encoded, sizeof(encoded), &written)),
           "varint encodes");
    Expect(written == encodedLength, "varint uses requested legal width");
    ULONGLONG decoded = 0;
    SIZE_T consumed = 0;
    Expect(NT_SUCCESS(wknet::quic::QuicDecodeVarInt(encoded, written, &decoded, &consumed)), "varint decodes");
    Expect(decoded == value && consumed == encodedLength, "varint round-trips");
}
} // namespace

int main()
{
    TestRoundTrip(0, 1);
    TestRoundTrip(63, 1);
    TestRoundTrip(64, 2);
    TestRoundTrip(16383, 2);
    TestRoundTrip(16384, 4);
    TestRoundTrip(1073741823ULL, 4);
    TestRoundTrip(1073741824ULL, 8);
    TestRoundTrip(wknet::quic::QuicVarIntMaximum, 8);

    TestRoundTrip(1, 2);
    TestRoundTrip(1, 4);
    TestRoundTrip(1, 8);

    UCHAR encoded[8] = {};
    SIZE_T written = 0;
    Expect(wknet::quic::QuicEncodeVarInt(wknet::quic::QuicVarIntMaximum + 1, 0, encoded, sizeof(encoded), &written) ==
               STATUS_INTEGER_OVERFLOW,
           "62-bit overflow is rejected");
    Expect(wknet::quic::QuicEncodeVarInt(64, 1, encoded, sizeof(encoded), &written) == STATUS_INTEGER_OVERFLOW,
           "value that does not fit requested width is rejected");
    Expect(wknet::quic::QuicEncodeVarInt(64, 2, encoded, 1, &written) == STATUS_BUFFER_TOO_SMALL,
           "encoding capacity is enforced");

    const UCHAR truncated[] = {0x40};
    ULONGLONG value = 0;
    SIZE_T consumed = 0;
    Expect(wknet::quic::QuicDecodeVarInt(truncated, sizeof(truncated), &value, &consumed) == STATUS_BUFFER_TOO_SMALL,
           "truncated varint is rejected");

    if (g_failed)
    {
        printf("QUIC VARINT TESTS FAILED\n");
        return 1;
    }
    printf("QUIC VARINT TESTS PASSED\n");
    return 0;
}
