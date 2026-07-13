#include "qpack/QpackHuffman.h"
#include "http2/Hpack.h"

namespace wknet::qpack
{
SIZE_T QpackHuffmanEncodedLength(const UCHAR *source, SIZE_T sourceLength) noexcept
{
    return http2::HpackHuffmanEncodedLength(source, sourceLength);
}

NTSTATUS QpackHuffmanEncode(const UCHAR *source, SIZE_T sourceLength, UCHAR *destination, SIZE_T capacity,
                            SIZE_T *bytesWritten) noexcept
{
    return http2::HpackHuffmanEncode(source, sourceLength, destination, capacity, bytesWritten);
}

NTSTATUS QpackHuffmanDecode(const UCHAR *source, SIZE_T sourceLength, UCHAR *destination, SIZE_T capacity,
                            SIZE_T *bytesWritten) noexcept
{
    return http2::HpackHuffmanDecode(source, sourceLength, destination, capacity, bytesWritten);
}
} // namespace wknet::qpack
