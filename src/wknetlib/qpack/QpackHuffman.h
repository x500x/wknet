#pragma once

#include "qpack/QpackTypes.h"

namespace wknet::qpack
{
SIZE_T QpackHuffmanEncodedLength(_In_reads_bytes_(sourceLength) const UCHAR *source, SIZE_T sourceLength) noexcept;

NTSTATUS QpackHuffmanEncode(_In_reads_bytes_(sourceLength) const UCHAR *source, SIZE_T sourceLength,
                            _Out_writes_bytes_(capacity) UCHAR *destination, SIZE_T capacity,
                            _Out_ SIZE_T *bytesWritten) noexcept;

NTSTATUS QpackHuffmanDecode(_In_reads_bytes_(sourceLength) const UCHAR *source, SIZE_T sourceLength,
                            _Out_writes_bytes_(capacity) UCHAR *destination, SIZE_T capacity,
                            _Out_ SIZE_T *bytesWritten) noexcept;
} // namespace wknet::qpack
