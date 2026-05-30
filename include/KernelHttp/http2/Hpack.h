#pragma once

#include <KernelHttp/http/HttpTypes.h>
#include <KernelHttp/http2/HpackStaticTable.h>

namespace KernelHttp
{
namespace http2
{
    // HPACK integer encoding/decoding (RFC 7541 Section 5.1)
    _Must_inspect_result_
    NTSTATUS HpackEncodeInteger(
        ULONG value,
        UCHAR prefix,
        UCHAR prefixBits,
        _Out_writes_bytes_(capacity) UCHAR* dest,
        SIZE_T capacity,
        _Out_ SIZE_T* bytesWritten) noexcept;

    _Must_inspect_result_
    NTSTATUS HpackDecodeInteger(
        _In_reads_bytes_(length) const UCHAR* src,
        SIZE_T length,
        UCHAR prefixBits,
        _Out_ ULONG* value,
        _Out_ SIZE_T* bytesConsumed) noexcept;

    // HPACK Huffman encoding/decoding (RFC 7541 Section 5.2)
    _Must_inspect_result_
    NTSTATUS HpackHuffmanEncode(
        _In_reads_bytes_(srcLen) const UCHAR* src,
        SIZE_T srcLen,
        _Out_writes_bytes_(capacity) UCHAR* dest,
        SIZE_T capacity,
        _Out_ SIZE_T* bytesWritten) noexcept;

    _Must_inspect_result_
    NTSTATUS HpackHuffmanDecode(
        _In_reads_bytes_(srcLen) const UCHAR* src,
        SIZE_T srcLen,
        _Out_writes_bytes_(capacity) UCHAR* dest,
        SIZE_T capacity,
        _Out_ SIZE_T* bytesWritten) noexcept;

    // Returns encoded length without actually encoding (for size estimation)
    _Must_inspect_result_
    SIZE_T HpackHuffmanEncodedLength(
        _In_reads_bytes_(srcLen) const UCHAR* src,
        SIZE_T srcLen) noexcept;

    // Dynamic table (RFC 7541 Section 2.3.2)
    class HpackDynamicTable final
    {
    public:
        HpackDynamicTable() noexcept = default;
        ~HpackDynamicTable() noexcept;

        HpackDynamicTable(const HpackDynamicTable&) = delete;
        HpackDynamicTable& operator=(const HpackDynamicTable&) = delete;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxSize) noexcept;

        void Reset() noexcept;

        void UpdateMaxSize(SIZE_T newMaxSize) noexcept;

        _Must_inspect_result_
        NTSTATUS Insert(
            _In_reads_bytes_(nameLen) const UCHAR* name, SIZE_T nameLen,
            _In_reads_bytes_(valueLen) const UCHAR* value, SIZE_T valueLen) noexcept;

        // Index is 0-based (caller subtracts static table size)
        _Must_inspect_result_
        bool Lookup(SIZE_T index,
            _Out_ const UCHAR** name, _Out_ SIZE_T* nameLen,
            _Out_ const UCHAR** value, _Out_ SIZE_T* valueLen) const noexcept;

        SIZE_T EntryCount() const noexcept;
        SIZE_T CurrentSize() const noexcept;
        SIZE_T MaxSize() const noexcept;

    private:
        void Evict() noexcept;

        struct Entry
        {
            SIZE_T NameOffset;
            SIZE_T NameLength;
            SIZE_T ValueOffset;
            SIZE_T ValueLength;
        };

        UCHAR* dataBuffer_ = nullptr;
        SIZE_T dataCapacity_ = 0;
        SIZE_T dataUsed_ = 0;

        Entry* entries_ = nullptr;
        SIZE_T entryCapacity_ = 0;
        SIZE_T entryCount_ = 0;
        SIZE_T entryHead_ = 0;  // ring buffer head (newest)

        SIZE_T currentSize_ = 0;
        SIZE_T maxSize_ = 4096;
    };

    // HPACK Decoder (RFC 7541 Section 6)
    class HpackDecoder final
    {
    public:
        HpackDecoder() noexcept = default;
        ~HpackDecoder() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxTableSize = 4096) noexcept;

        void Reset() noexcept;

        // Decode a complete header block fragment into headers array
        _Must_inspect_result_
        NTSTATUS Decode(
            _In_reads_bytes_(blockLen) const UCHAR* block,
            SIZE_T blockLen,
            _Out_writes_(headerCapacity) http::HttpHeader* headers,
            SIZE_T headerCapacity,
            _Out_ SIZE_T* headerCount,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity,
            _Out_ SIZE_T* nameValueUsed) noexcept;

    private:
        HpackDynamicTable table_;
    };

    // HPACK Encoder (RFC 7541 Section 6)
    class HpackEncoder final
    {
    public:
        HpackEncoder() noexcept = default;
        ~HpackEncoder() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxTableSize = 4096) noexcept;

        void Reset() noexcept;

        // Encode headers into a header block fragment
        // Uses indexed representation for static table matches,
        // literal with incremental indexing for others
        _Must_inspect_result_
        NTSTATUS Encode(
            _In_reads_(headerCount) const http::HttpHeader* headers,
            SIZE_T headerCount,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

    private:
        // Find best match in static + dynamic table
        // Returns: 0 = no match, >0 = index (1-based)
        // nameMatch: true if only name matched (value differs)
        SIZE_T FindMatch(
            _In_reads_bytes_(nameLen) const char* name, SIZE_T nameLen,
            _In_reads_bytes_(valueLen) const char* value, SIZE_T valueLen,
            _Out_ bool* nameOnly) const noexcept;

        HpackDynamicTable table_;
    };
}
}
