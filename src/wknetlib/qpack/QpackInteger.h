#pragma once

#include "qpack/QpackTypes.h"

namespace wknet::qpack
{
NTSTATUS QpackEncodeInteger(ULONGLONG value, UCHAR prefix, UCHAR prefixBits,
                            _Out_writes_bytes_(capacity) UCHAR *destination, SIZE_T capacity,
                            _Out_ SIZE_T *bytesWritten) noexcept;

NTSTATUS QpackDecodeInteger(_In_reads_bytes_(length) const UCHAR *source, SIZE_T length, UCHAR prefixBits,
                            _Out_ ULONGLONG *value, _Out_ SIZE_T *bytesConsumed) noexcept;
} // namespace wknet::qpack
