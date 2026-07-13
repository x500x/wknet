#pragma once

#include "quic/QuicTypes.h"

namespace wknet::quic
{
SIZE_T QuicVarIntEncodedLength(ULONGLONG value) noexcept;

NTSTATUS QuicDecodeVarInt(_In_reads_bytes_(dataLength) const UCHAR *data, SIZE_T dataLength, _Out_ ULONGLONG *value,
                          _Out_opt_ SIZE_T *bytesConsumed) noexcept;

NTSTATUS QuicEncodeVarInt(ULONGLONG value, SIZE_T encodedLength, _Out_writes_bytes_(capacity) UCHAR *output,
                          SIZE_T capacity, _Out_opt_ SIZE_T *bytesWritten) noexcept;
} // namespace wknet::quic
