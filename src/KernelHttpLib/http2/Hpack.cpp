#include <KernelHttp/http2/Hpack.h>
#include <KernelHttp/http2/HpackHuffman.h>

namespace KernelHttp
{
namespace http2
{
    namespace
    {
        bool NameEquals(
            const char* a, SIZE_T aLen,
            const char* b, SIZE_T bLen) noexcept
        {
            if (aLen != bLen) return false;
            for (SIZE_T i = 0; i < aLen; ++i) {
                char ca = a[i];
                char cb = b[i];
                // Case-insensitive compare for header names
                if (ca >= 'A' && ca <= 'Z') ca += 32;
                if (cb >= 'A' && cb <= 'Z') cb += 32;
                if (ca != cb) return false;
            }
            return true;
        }

        bool ValueEquals(
            const char* a, SIZE_T aLen,
            const char* b, SIZE_T bLen) noexcept
        {
            if (aLen != bLen) return false;
            for (SIZE_T i = 0; i < aLen; ++i) {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        void MemCopy(void* dst, const void* src, SIZE_T len) noexcept
        {
            auto* d = static_cast<UCHAR*>(dst);
            auto* s = static_cast<const UCHAR*>(src);
            for (SIZE_T i = 0; i < len; ++i) {
                d[i] = s[i];
            }
        }

        void MemMove(UCHAR* dst, const UCHAR* src, SIZE_T len) noexcept
        {
            if (dst == src || len == 0) {
                return;
            }

            if (dst < src) {
                for (SIZE_T i = 0; i < len; ++i) {
                    dst[i] = src[i];
                }
                return;
            }

            for (SIZE_T i = len; i > 0; --i) {
                dst[i - 1] = src[i - 1];
            }
        }

        _Must_inspect_result_
        bool RangeFits(SIZE_T offset, SIZE_T length, SIZE_T capacity) noexcept
        {
            return offset <= capacity && length <= capacity - offset;
        }

        _Must_inspect_result_
        bool MultiplySize(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
        {
            if (result == nullptr) {
                return false;
            }
            if (left != 0 && right > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / left) {
                *result = 0;
                return false;
            }
            *result = left * right;
            return true;
        }

        _Must_inspect_result_
        bool PointerInRange(const void* pointer, const void* base, SIZE_T length) noexcept
        {
            if (pointer == nullptr || base == nullptr || length == 0) {
                return false;
            }

            const SIZE_T start = reinterpret_cast<SIZE_T>(base);
            const SIZE_T end = start + length;
            if (end < start) {
                return false;
            }

            const SIZE_T address = reinterpret_cast<SIZE_T>(pointer);
            return address >= start && address < end;
        }

        _Must_inspect_result_
        NTSTATUS MaterializeHeaderPart(
            _In_reads_bytes_opt_(length) const UCHAR* source,
            SIZE_T length,
            _Out_writes_bytes_(capacity) char* buffer,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset,
            _Out_ const char** output) noexcept
        {
            if ((source == nullptr && length != 0) || buffer == nullptr ||
                offset == nullptr || output == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (PointerInRange(source, buffer, capacity)) {
                *output = reinterpret_cast<const char*>(source);
                return STATUS_SUCCESS;
            }

            if (!RangeFits(*offset, length, capacity)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            if (length != 0) {
                MemCopy(buffer + *offset, source, length);
            }
            *output = buffer + *offset;
            *offset += length;
            return STATUS_SUCCESS;
        }

        constexpr SIZE_T MaxSizeT = ~static_cast<SIZE_T>(0);

        _Must_inspect_result_
        bool AddHeaderListSize(
            SIZE_T nameLength,
            SIZE_T valueLength,
            SIZE_T maxHeaderListSize,
            _Inout_ SIZE_T* headerListSize) noexcept
        {
            if (headerListSize == nullptr) {
                return false;
            }

            if (nameLength > MaxSizeT - valueLength) {
                return false;
            }
            SIZE_T fieldSize = nameLength + valueLength;
            if (fieldSize > MaxSizeT - HpackEntryOverhead) {
                return false;
            }
            fieldSize += HpackEntryOverhead;

            if (*headerListSize > MaxSizeT - fieldSize) {
                return false;
            }
            if (maxHeaderListSize != MaxSizeT) {
                if (fieldSize > maxHeaderListSize ||
                    *headerListSize > maxHeaderListSize - fieldSize) {
                    return false;
                }
            }

            *headerListSize += fieldSize;
            return true;
        }

        _Must_inspect_result_
        bool IsSensitiveHeaderName(const char* name, SIZE_T nameLen) noexcept
        {
            return NameEquals(name, nameLen, "authorization", 13) ||
                NameEquals(name, nameLen, "cookie", 6) ||
                NameEquals(name, nameLen, "proxy-authorization", 19);
        }

        _Must_inspect_result_
        NTSTATUS EncodeHeaderString(
            _In_reads_bytes_(length) const char* data,
            SIZE_T length,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if ((data == nullptr && length != 0) || dest == nullptr || offset == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (*offset > capacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            const SIZE_T huffLen = HpackHuffmanEncodedLength(
                reinterpret_cast<const UCHAR*>(data), length);
            if (huffLen < length && length > 0) {
                SIZE_T written = 0;
                NTSTATUS status = HpackEncodeInteger(
                    static_cast<ULONG>(huffLen),
                    0x80,
                    7,
                    dest + *offset,
                    capacity - *offset,
                    &written);
                if (!NT_SUCCESS(status)) return status;
                *offset += written;

                status = HpackHuffmanEncode(
                    reinterpret_cast<const UCHAR*>(data),
                    length,
                    dest + *offset,
                    capacity - *offset,
                    &written);
                if (!NT_SUCCESS(status)) return status;
                *offset += written;
                return STATUS_SUCCESS;
            }

            SIZE_T written = 0;
            NTSTATUS status = HpackEncodeInteger(
                static_cast<ULONG>(length),
                0x00,
                7,
                dest + *offset,
                capacity - *offset,
                &written);
            if (!NT_SUCCESS(status)) return status;
            *offset += written;

            if (length != 0) {
                if (!RangeFits(*offset, length, capacity)) return STATUS_BUFFER_TOO_SMALL;
                MemCopy(dest + *offset, data, length);
                *offset += length;
            }
            return STATUS_SUCCESS;
        }
    }

    // ========================================================================
    // Integer encoding (RFC 7541 Section 5.1)
    // ========================================================================

    NTSTATUS HpackEncodeInteger(
        ULONG value,
        UCHAR prefix,
        UCHAR prefixBits,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr || prefixBits == 0 || prefixBits > 8) {
            return STATUS_INVALID_PARAMETER;
        }

        const UCHAR maxPrefix = static_cast<UCHAR>((1u << prefixBits) - 1);
        const UCHAR prefixMask = static_cast<UCHAR>(~maxPrefix);
        SIZE_T offset = 0;

        if (value < maxPrefix) {
            if (capacity < 1) return STATUS_BUFFER_TOO_SMALL;
            dest[0] = static_cast<UCHAR>((prefix & prefixMask) | (value & maxPrefix));
            *bytesWritten = 1;
            return STATUS_SUCCESS;
        }

        if (capacity < 1) return STATUS_BUFFER_TOO_SMALL;
        dest[offset++] = static_cast<UCHAR>((prefix & prefixMask) | maxPrefix);
        value -= maxPrefix;

        while (value >= 128) {
            if (offset >= capacity) return STATUS_BUFFER_TOO_SMALL;
            dest[offset++] = static_cast<UCHAR>((value & 0x7f) | 0x80);
            value >>= 7;
        }

        if (offset >= capacity) return STATUS_BUFFER_TOO_SMALL;
        dest[offset++] = static_cast<UCHAR>(value);

        *bytesWritten = offset;
        return STATUS_SUCCESS;
    }

    NTSTATUS HpackDecodeInteger(
        const UCHAR* src,
        SIZE_T length,
        UCHAR prefixBits,
        ULONG* value,
        SIZE_T* bytesConsumed) noexcept
    {
        if (src == nullptr || value == nullptr || bytesConsumed == nullptr ||
            prefixBits == 0 || prefixBits > 8 || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const UCHAR maxPrefix = static_cast<UCHAR>((1u << prefixBits) - 1);
        ULONG result = src[0] & maxPrefix;
        SIZE_T offset = 1;

        if (result < maxPrefix) {
            *value = result;
            *bytesConsumed = 1;
            return STATUS_SUCCESS;
        }

        ULONG m = 0;
        for (;;) {
            if (offset >= length) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }

            UCHAR b = src[offset++];
            const ULONG chunk = static_cast<ULONG>(b & 0x7f);
            if (m >= 32 || (m >= 28 && chunk > 0x0f)) {
                return STATUS_INTEGER_OVERFLOW;
            }

            const ULONG increment = chunk << m;
            if (result > static_cast<ULONG>(~0UL) - increment) {
                return STATUS_INTEGER_OVERFLOW;
            }

            result += increment;
            m += 7;

            if ((b & 0x80) == 0) {
                break;
            }
        }

        *value = result;
        *bytesConsumed = offset;
        return STATUS_SUCCESS;
    }

    // ========================================================================
    // Huffman encoding (RFC 7541 Section 5.2)
    // ========================================================================

    SIZE_T HpackHuffmanEncodedLength(
        const UCHAR* src,
        SIZE_T srcLen) noexcept
    {
        if (src == nullptr || srcLen == 0) return 0;

        SIZE_T totalBits = 0;
        for (SIZE_T i = 0; i < srcLen; ++i) {
            totalBits += HpackHuffmanEncodeTable[src[i]].BitLength;
        }
        return (totalBits + 7) / 8;
    }

    NTSTATUS HpackHuffmanEncode(
        const UCHAR* src,
        SIZE_T srcLen,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        *bytesWritten = 0;

        if (src == nullptr && srcLen > 0) return STATUS_INVALID_PARAMETER;
        if (dest == nullptr && capacity > 0) return STATUS_INVALID_PARAMETER;

        if (srcLen == 0) {
            return STATUS_SUCCESS;
        }

        SIZE_T destOffset = 0;
        UCHAR currentByte = 0;
        UCHAR bitCount = 0;

        for (SIZE_T i = 0; i < srcLen; ++i) {
            const HpackHuffmanSymbol& sym = HpackHuffmanEncodeTable[src[i]];
            const ULONG code = sym.Code;
            const UCHAR codeLen = sym.BitLength;

            for (UCHAR bitIndex = 0; bitIndex < codeLen; ++bitIndex) {
                const UCHAR bitShift = static_cast<UCHAR>(codeLen - bitIndex - 1);
                const UCHAR bit = static_cast<UCHAR>((code >> bitShift) & 0x01);
                currentByte = static_cast<UCHAR>((currentByte << 1) | bit);
                ++bitCount;

                if (bitCount == 8) {
                    if (destOffset >= capacity) return STATUS_BUFFER_TOO_SMALL;
                    dest[destOffset++] = currentByte;
                    currentByte = 0;
                    bitCount = 0;
                }
            }
        }

        // Pad remaining bits with 1s (EOS prefix)
        if (bitCount > 0) {
            if (destOffset >= capacity) return STATUS_BUFFER_TOO_SMALL;
            currentByte = static_cast<UCHAR>((currentByte << (8 - bitCount)) | ((1u << (8 - bitCount)) - 1u));
            dest[destOffset++] = currentByte;
        }

        *bytesWritten = destOffset;
        return STATUS_SUCCESS;
    }

    NTSTATUS HpackHuffmanDecode(
        const UCHAR* src,
        SIZE_T srcLen,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        *bytesWritten = 0;

        if (src == nullptr && srcLen > 0) return STATUS_INVALID_PARAMETER;
        if (dest == nullptr && capacity > 0) return STATUS_INVALID_PARAMETER;

        if (srcLen == 0) {
            return STATUS_SUCCESS;
        }

        // Bit-by-bit Huffman decoding using the code table directly
        // We walk through each bit and match against the Huffman tree
        SIZE_T destOffset = 0;
        ULONG currentCode = 0;
        UCHAR currentBitLen = 0;

        for (SIZE_T byteIdx = 0; byteIdx < srcLen; ++byteIdx) {
            UCHAR byte = src[byteIdx];

            for (int bitIdx = 7; bitIdx >= 0; --bitIdx) {
                currentCode = (currentCode << 1) | ((byte >> bitIdx) & 1);
                ++currentBitLen;

                // Search for a matching symbol
                // Optimization: only check symbols with matching bit length
                if (currentBitLen > 30) {
                    // No valid symbol is longer than 30 bits
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                // Linear search through the table for matching code/length
                // This is O(256) per symbol but correct; can be optimized later
                bool found = false;
                for (int sym = 0; sym < 256; ++sym) {
                    if (HpackHuffmanEncodeTable[sym].BitLength == currentBitLen &&
                        HpackHuffmanEncodeTable[sym].Code == currentCode) {
                        if (destOffset >= capacity) return STATUS_BUFFER_TOO_SMALL;
                        dest[destOffset++] = static_cast<UCHAR>(sym);
                        currentCode = 0;
                        currentBitLen = 0;
                        found = true;
                        break;
                    }
                }

                if (found) continue;

                // Check for EOS (symbol 256) - should not appear in data
                if (HpackHuffmanEncodeTable[256].BitLength == currentBitLen &&
                    HpackHuffmanEncodeTable[256].Code == currentCode) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }

        // Remaining bits must be padding (all 1s) and less than 8 bits
        if (currentBitLen > 7) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        // Verify padding is all 1s
        if (currentBitLen > 0) {
            ULONG paddingMask = (1u << currentBitLen) - 1;
            if ((currentCode & paddingMask) != paddingMask) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        *bytesWritten = destOffset;
        return STATUS_SUCCESS;
    }

    // ========================================================================
    // Dynamic Table
    // ========================================================================

    HpackDynamicTable::~HpackDynamicTable() noexcept
    {
        Reset();
    }

    NTSTATUS HpackDynamicTable::Initialize(SIZE_T maxSize) noexcept
    {
        Reset();

        maxSize_ = maxSize;
        if (maxSize == 0) return STATUS_SUCCESS;

        // Allocate data buffer - generous initial size
        dataCapacity_ = maxSize * 2;
        if (dataCapacity_ < 1024) dataCapacity_ = 1024;

        dataBuffer_ = new UCHAR[dataCapacity_];
        if (dataBuffer_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

        // Allocate entry array
        entryCapacity_ = 128;
        entries_ = new Entry[entryCapacity_];
        if (entries_ == nullptr) {
            delete[] dataBuffer_;
            dataBuffer_ = nullptr;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        return STATUS_SUCCESS;
    }

    void HpackDynamicTable::Reset() noexcept
    {
        if (dataBuffer_ != nullptr) {
            delete[] dataBuffer_;
            dataBuffer_ = nullptr;
        }
        if (entries_ != nullptr) {
            delete[] entries_;
            entries_ = nullptr;
        }
        dataCapacity_ = 0;
        dataUsed_ = 0;
        entryCapacity_ = 0;
        entryCount_ = 0;
        entryHead_ = 0;
        currentSize_ = 0;
    }

    void HpackDynamicTable::UpdateMaxSize(SIZE_T newMaxSize) noexcept
    {
        maxSize_ = newMaxSize;
        while (currentSize_ > maxSize_ && entryCount_ > 0) {
            Evict();
        }
        CompactData();
    }

    NTSTATUS HpackDynamicTable::Insert(
        const UCHAR* name, SIZE_T nameLen,
        const UCHAR* value, SIZE_T valueLen) noexcept
    {
        SIZE_T entrySize = nameLen + valueLen + HpackEntryOverhead;

        // If entry is larger than max table size, clear the table
        if (entrySize > maxSize_) {
            entryCount_ = 0;
            entryHead_ = 0;
            dataUsed_ = 0;
            currentSize_ = 0;
            return STATUS_SUCCESS;
        }

        // Evict until there's room
        while (currentSize_ + entrySize > maxSize_ && entryCount_ > 0) {
            Evict();
        }

        // Ensure data buffer has space
        SIZE_T dataNeeded = nameLen + valueLen;
        if (dataUsed_ + dataNeeded > dataCapacity_) {
            const bool nameFromTable = PointerInRange(name, dataBuffer_, dataUsed_);
            const bool valueFromTable = PointerInRange(value, dataBuffer_, dataUsed_);
            SIZE_T nameOffset = 0;
            SIZE_T valueOffset = 0;
            if (nameFromTable) {
                nameOffset = static_cast<SIZE_T>(name - dataBuffer_);
            }
            if (valueFromTable) {
                valueOffset = static_cast<SIZE_T>(value - dataBuffer_);
            }

            CompactData(nameFromTable ? &nameOffset : nullptr, valueFromTable ? &valueOffset : nullptr);

            if (nameFromTable) {
                name = dataBuffer_ + nameOffset;
            }
            if (valueFromTable) {
                value = dataBuffer_ + valueOffset;
            }
        }

        if (dataUsed_ + dataNeeded > dataCapacity_) {
            SIZE_T newCapacity = dataCapacity_ * 2;
            if (newCapacity < dataUsed_ + dataNeeded + 1024) {
                newCapacity = dataUsed_ + dataNeeded + 1024;
            }
            UCHAR* newBuffer = new UCHAR[newCapacity];
            if (newBuffer == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
            MemCopy(newBuffer, dataBuffer_, dataUsed_);
            if (PointerInRange(name, dataBuffer_, dataUsed_)) {
                name = newBuffer + (name - dataBuffer_);
            }
            if (PointerInRange(value, dataBuffer_, dataUsed_)) {
                value = newBuffer + (value - dataBuffer_);
            }
            delete[] dataBuffer_;
            dataBuffer_ = newBuffer;
            dataCapacity_ = newCapacity;
        }

        // Ensure entry array has space
        if (entryCount_ >= entryCapacity_) {
            SIZE_T newCapacity = entryCapacity_ * 2;
            Entry* newEntries = new Entry[newCapacity];
            if (newEntries == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
            // Copy existing entries maintaining logical order
            for (SIZE_T i = 0; i < entryCount_; ++i) {
                SIZE_T srcIdx = (entryHead_ + i) % entryCapacity_;
                newEntries[i] = entries_[srcIdx];
            }
            delete[] entries_;
            entries_ = newEntries;
            entryCapacity_ = newCapacity;
            entryHead_ = 0;
        }

        // Store data
        SIZE_T nameOffset = dataUsed_;
        if (nameLen > 0) {
            MemCopy(dataBuffer_ + dataUsed_, name, nameLen);
            dataUsed_ += nameLen;
        }
        SIZE_T valueOffset = dataUsed_;
        if (valueLen > 0) {
            MemCopy(dataBuffer_ + dataUsed_, value, valueLen);
            dataUsed_ += valueLen;
        }

        // Insert at front (newest entry is index 0)
        if (entryHead_ == 0) {
            entryHead_ = entryCapacity_ - 1;
        } else {
            --entryHead_;
        }

        entries_[entryHead_].NameOffset = nameOffset;
        entries_[entryHead_].NameLength = nameLen;
        entries_[entryHead_].ValueOffset = valueOffset;
        entries_[entryHead_].ValueLength = valueLen;

        ++entryCount_;
        currentSize_ += entrySize;

        return STATUS_SUCCESS;
    }

    bool HpackDynamicTable::Lookup(SIZE_T index,
        const UCHAR** name, SIZE_T* nameLen,
        const UCHAR** value, SIZE_T* valueLen) const noexcept
    {
        if (index >= entryCount_ || name == nullptr || nameLen == nullptr ||
            value == nullptr || valueLen == nullptr) {
            return false;
        }

        SIZE_T actualIdx = (entryHead_ + index) % entryCapacity_;
        const Entry& entry = entries_[actualIdx];

        *name = dataBuffer_ + entry.NameOffset;
        *nameLen = entry.NameLength;
        *value = dataBuffer_ + entry.ValueOffset;
        *valueLen = entry.ValueLength;
        return true;
    }

    SIZE_T HpackDynamicTable::EntryCount() const noexcept
    {
        return entryCount_;
    }

    SIZE_T HpackDynamicTable::CurrentSize() const noexcept
    {
        return currentSize_;
    }

    SIZE_T HpackDynamicTable::MaxSize() const noexcept
    {
        return maxSize_;
    }

    void HpackDynamicTable::Evict() noexcept
    {
        if (entryCount_ == 0) return;

        // Remove oldest entry (at tail)
        SIZE_T tailIdx = (entryHead_ + entryCount_ - 1) % entryCapacity_;
        const Entry& entry = entries_[tailIdx];
        SIZE_T entrySize = entry.NameLength + entry.ValueLength + HpackEntryOverhead;
        currentSize_ -= entrySize;
        --entryCount_;
        if (entryCount_ == 0) {
            entryHead_ = 0;
            dataUsed_ = 0;
        }
    }

    void HpackDynamicTable::CompactData(SIZE_T* firstOffset, SIZE_T* secondOffset) noexcept
    {
        if (entryCount_ == 0) {
            dataUsed_ = 0;
            entryHead_ = 0;
            return;
        }

        SIZE_T writeOffset = 0;
        SIZE_T previousStart = 0;
        bool havePreviousStart = false;

        for (SIZE_T processed = 0; processed < entryCount_; ++processed) {
            Entry* candidate = nullptr;
            SIZE_T candidateStart = MaxSizeT;

            for (SIZE_T i = 0; i < entryCount_; ++i) {
                Entry& entry = entries_[(entryHead_ + i) % entryCapacity_];
                const SIZE_T start = entry.NameOffset;
                if (havePreviousStart && start <= previousStart) {
                    continue;
                }
                if (start < candidateStart) {
                    candidateStart = start;
                    candidate = &entry;
                }
            }

            if (candidate == nullptr) {
                return;
            }

            const SIZE_T totalLength = candidate->NameLength + candidate->ValueLength;
            if (totalLength != 0) {
                MemMove(dataBuffer_ + writeOffset, dataBuffer_ + candidateStart, totalLength);
            }
            if (firstOffset != nullptr &&
                *firstOffset >= candidateStart &&
                *firstOffset < candidateStart + totalLength) {
                *firstOffset = writeOffset + (*firstOffset - candidateStart);
            }
            if (secondOffset != nullptr &&
                *secondOffset >= candidateStart &&
                *secondOffset < candidateStart + totalLength) {
                *secondOffset = writeOffset + (*secondOffset - candidateStart);
            }
            candidate->NameOffset = writeOffset;
            candidate->ValueOffset = writeOffset + candidate->NameLength;
            writeOffset += totalLength;
            previousStart = candidateStart;
            havePreviousStart = true;
        }

        dataUsed_ = writeOffset;
    }

    // ========================================================================
    // HPACK Decoder
    // ========================================================================

    NTSTATUS HpackDecoder::Initialize(SIZE_T maxTableSize) noexcept
    {
        maxTableSize_ = maxTableSize;
        return table_.Initialize(maxTableSize);
    }

    void HpackDecoder::Reset() noexcept
    {
        table_.Reset();
    }

    void HpackDecoder::UpdateMaxTableSize(SIZE_T maxTableSize) noexcept
    {
        maxTableSize_ = maxTableSize;
        table_.UpdateMaxSize(maxTableSize);
    }

    NTSTATUS HpackDecoder::Decode(
        const UCHAR* block,
        SIZE_T blockLen,
        http::HttpHeader* headers,
        SIZE_T headerCapacity,
        SIZE_T* headerCount,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        SIZE_T* nameValueUsed) noexcept
    {
        return Decode(
            block,
            blockLen,
            headers,
            headerCapacity,
            headerCount,
            nameValueBuffer,
            nameValueCapacity,
            nameValueUsed,
            MaxSizeT);
    }

    NTSTATUS HpackDecoder::Decode(
        const UCHAR* block,
        SIZE_T blockLen,
        http::HttpHeader* headers,
        SIZE_T headerCapacity,
        SIZE_T* headerCount,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        SIZE_T* nameValueUsed,
        SIZE_T maxHeaderListSize) noexcept
    {
        if (block == nullptr && blockLen > 0) return STATUS_INVALID_PARAMETER;
        if (headers == nullptr || headerCount == nullptr) return STATUS_INVALID_PARAMETER;
        if (nameValueBuffer == nullptr || nameValueUsed == nullptr) return STATUS_INVALID_PARAMETER;

        *headerCount = 0;
        *nameValueUsed = 0;

        SIZE_T offset = 0;
        SIZE_T hdrIdx = 0;
        SIZE_T nvOffset = 0;
        SIZE_T headerListSize = 0;
        bool allowTableSizeUpdate = true;

        while (offset < blockLen) {
            UCHAR byte = block[offset];

            const UCHAR* namePtr = nullptr;
            SIZE_T nameLen = 0;
            const UCHAR* valuePtr = nullptr;
            SIZE_T valueLen = 0;
            bool addToTable = false;

            if ((byte & 0x80) != 0) {
                // Indexed Header Field (Section 6.1)
                allowTableSizeUpdate = false;
                ULONG index = 0;
                SIZE_T consumed = 0;
                NTSTATUS status = HpackDecodeInteger(block + offset, blockLen - offset, 7, &index, &consumed);
                if (!NT_SUCCESS(status)) return status;
                offset += consumed;

                if (index == 0) return STATUS_INVALID_NETWORK_RESPONSE;

                // Look up in static or dynamic table
                if (index <= HpackStaticTableSize) {
                    const HpackStaticEntry& entry = HpackStaticTable[index - 1];
                    namePtr = reinterpret_cast<const UCHAR*>(entry.Name);
                    nameLen = entry.NameLength;
                    valuePtr = reinterpret_cast<const UCHAR*>(entry.Value);
                    valueLen = entry.ValueLength;
                } else {
                    SIZE_T dynIdx = index - HpackStaticTableSize - 1;
                    if (!table_.Lookup(dynIdx, &namePtr, &nameLen, &valuePtr, &valueLen)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
            }
            else if ((byte & 0xC0) == 0x40) {
                // Literal Header Field with Incremental Indexing (Section 6.2.1)
                allowTableSizeUpdate = false;
                ULONG index = 0;
                SIZE_T consumed = 0;
                NTSTATUS status = HpackDecodeInteger(block + offset, blockLen - offset, 6, &index, &consumed);
                if (!NT_SUCCESS(status)) return status;
                offset += consumed;

                if (index > 0) {
                    // Name from table
                    if (index <= HpackStaticTableSize) {
                        const HpackStaticEntry& entry = HpackStaticTable[index - 1];
                        namePtr = reinterpret_cast<const UCHAR*>(entry.Name);
                        nameLen = entry.NameLength;
                    } else {
                        SIZE_T dynIdx = index - HpackStaticTableSize - 1;
                        const UCHAR* dummyVal = nullptr;
                        SIZE_T dummyValLen = 0;
                        if (!table_.Lookup(dynIdx, &namePtr, &nameLen, &dummyVal, &dummyValLen)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                    }
                } else {
                    // Literal name
                    if (offset >= blockLen) return STATUS_INVALID_NETWORK_RESPONSE;
                    bool huffmanName = (block[offset] & 0x80) != 0;
                    ULONG nameStrLen = 0;
                    status = HpackDecodeInteger(block + offset, blockLen - offset, 7, &nameStrLen, &consumed);
                    if (!NT_SUCCESS(status)) return status;
                    offset += consumed;

                    if (!RangeFits(offset, static_cast<SIZE_T>(nameStrLen), blockLen)) return STATUS_INVALID_NETWORK_RESPONSE;

                    if (huffmanName) {
                        SIZE_T decoded = 0;
                        SIZE_T huffmanCapacityHint = 0;
                        if (!MultiplySize(static_cast<SIZE_T>(nameStrLen), 2, &huffmanCapacityHint) ||
                            !RangeFits(nvOffset, huffmanCapacityHint, nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                        status = HpackHuffmanDecode(block + offset, nameStrLen,
                            reinterpret_cast<UCHAR*>(nameValueBuffer + nvOffset),
                            nameValueCapacity - nvOffset, &decoded);
                        if (!NT_SUCCESS(status)) return status;
                        namePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                        nameLen = decoded;
                        nvOffset += decoded;
                    } else {
                        if (!RangeFits(nvOffset, static_cast<SIZE_T>(nameStrLen), nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                        MemCopy(nameValueBuffer + nvOffset, block + offset, nameStrLen);
                        namePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                        nameLen = nameStrLen;
                        nvOffset += nameStrLen;
                    }
                    offset += nameStrLen;
                }

                // Value
                if (offset >= blockLen) return STATUS_INVALID_NETWORK_RESPONSE;
                bool huffmanValue = (block[offset] & 0x80) != 0;
                ULONG valueStrLen = 0;
                NTSTATUS status2 = HpackDecodeInteger(block + offset, blockLen - offset, 7, &valueStrLen, &consumed);
                if (!NT_SUCCESS(status2)) return status2;
                offset += consumed;

                if (!RangeFits(offset, static_cast<SIZE_T>(valueStrLen), blockLen)) return STATUS_INVALID_NETWORK_RESPONSE;

                if (huffmanValue) {
                    SIZE_T decoded = 0;
                    SIZE_T huffmanCapacityHint = 0;
                    if (!MultiplySize(static_cast<SIZE_T>(valueStrLen), 2, &huffmanCapacityHint) ||
                        !RangeFits(nvOffset, huffmanCapacityHint, nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                    status2 = HpackHuffmanDecode(block + offset, valueStrLen,
                        reinterpret_cast<UCHAR*>(nameValueBuffer + nvOffset),
                        nameValueCapacity - nvOffset, &decoded);
                    if (!NT_SUCCESS(status2)) return status2;
                    valuePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                    valueLen = decoded;
                    nvOffset += decoded;
                } else {
                    if (!RangeFits(nvOffset, static_cast<SIZE_T>(valueStrLen), nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                    MemCopy(nameValueBuffer + nvOffset, block + offset, valueStrLen);
                    valuePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                    valueLen = valueStrLen;
                    nvOffset += valueStrLen;
                }
                offset += valueStrLen;

                addToTable = true;
            }
            else if ((byte & 0xF0) == 0x00 || (byte & 0xF0) == 0x10) {
                // Literal Header Field without Indexing (Section 6.2.2) - 0000xxxx
                // Literal Header Field Never Indexed (Section 6.2.3) - 0001xxxx
                allowTableSizeUpdate = false;
                UCHAR prefixBits = 4;
                ULONG index = 0;
                SIZE_T consumed = 0;
                NTSTATUS status = HpackDecodeInteger(block + offset, blockLen - offset, prefixBits, &index, &consumed);
                if (!NT_SUCCESS(status)) return status;
                offset += consumed;

                if (index > 0) {
                    if (index <= HpackStaticTableSize) {
                        const HpackStaticEntry& entry = HpackStaticTable[index - 1];
                        namePtr = reinterpret_cast<const UCHAR*>(entry.Name);
                        nameLen = entry.NameLength;
                    } else {
                        SIZE_T dynIdx = index - HpackStaticTableSize - 1;
                        const UCHAR* dummyVal = nullptr;
                        SIZE_T dummyValLen = 0;
                        if (!table_.Lookup(dynIdx, &namePtr, &nameLen, &dummyVal, &dummyValLen)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                    }
                } else {
                    // Literal name
                    if (offset >= blockLen) return STATUS_INVALID_NETWORK_RESPONSE;
                    bool huffmanName = (block[offset] & 0x80) != 0;
                    ULONG nameStrLen = 0;
                    status = HpackDecodeInteger(block + offset, blockLen - offset, 7, &nameStrLen, &consumed);
                    if (!NT_SUCCESS(status)) return status;
                    offset += consumed;

                    if (!RangeFits(offset, static_cast<SIZE_T>(nameStrLen), blockLen)) return STATUS_INVALID_NETWORK_RESPONSE;

                    if (huffmanName) {
                        SIZE_T decoded = 0;
                        SIZE_T huffmanCapacityHint = 0;
                        if (!MultiplySize(static_cast<SIZE_T>(nameStrLen), 2, &huffmanCapacityHint) ||
                            !RangeFits(nvOffset, huffmanCapacityHint, nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                        status = HpackHuffmanDecode(block + offset, nameStrLen,
                            reinterpret_cast<UCHAR*>(nameValueBuffer + nvOffset),
                            nameValueCapacity - nvOffset, &decoded);
                        if (!NT_SUCCESS(status)) return status;
                        namePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                        nameLen = decoded;
                        nvOffset += decoded;
                    } else {
                        if (!RangeFits(nvOffset, static_cast<SIZE_T>(nameStrLen), nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                        MemCopy(nameValueBuffer + nvOffset, block + offset, nameStrLen);
                        namePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                        nameLen = nameStrLen;
                        nvOffset += nameStrLen;
                    }
                    offset += nameStrLen;
                }

                // Value
                if (offset >= blockLen) return STATUS_INVALID_NETWORK_RESPONSE;
                bool huffmanValue = (block[offset] & 0x80) != 0;
                ULONG valueStrLen = 0;
                SIZE_T consumed2 = 0;
                NTSTATUS status2 = HpackDecodeInteger(block + offset, blockLen - offset, 7, &valueStrLen, &consumed2);
                if (!NT_SUCCESS(status2)) return status2;
                offset += consumed2;

                if (!RangeFits(offset, static_cast<SIZE_T>(valueStrLen), blockLen)) return STATUS_INVALID_NETWORK_RESPONSE;

                if (huffmanValue) {
                    SIZE_T decoded = 0;
                    SIZE_T huffmanCapacityHint = 0;
                    if (!MultiplySize(static_cast<SIZE_T>(valueStrLen), 2, &huffmanCapacityHint) ||
                        !RangeFits(nvOffset, huffmanCapacityHint, nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                    status2 = HpackHuffmanDecode(block + offset, valueStrLen,
                        reinterpret_cast<UCHAR*>(nameValueBuffer + nvOffset),
                        nameValueCapacity - nvOffset, &decoded);
                    if (!NT_SUCCESS(status2)) return status2;
                    valuePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                    valueLen = decoded;
                    nvOffset += decoded;
                } else {
                    if (!RangeFits(nvOffset, static_cast<SIZE_T>(valueStrLen), nameValueCapacity)) return STATUS_BUFFER_TOO_SMALL;
                    MemCopy(nameValueBuffer + nvOffset, block + offset, valueStrLen);
                    valuePtr = reinterpret_cast<const UCHAR*>(nameValueBuffer + nvOffset);
                    valueLen = valueStrLen;
                    nvOffset += valueStrLen;
                }
                offset += valueStrLen;

                addToTable = false;
            }
            else if ((byte & 0xE0) == 0x20) {
                // Dynamic Table Size Update (Section 6.3)
                if (!allowTableSizeUpdate) return STATUS_INVALID_NETWORK_RESPONSE;
                ULONG newSize = 0;
                SIZE_T consumed = 0;
                NTSTATUS status = HpackDecodeInteger(block + offset, blockLen - offset, 5, &newSize, &consumed);
                if (!NT_SUCCESS(status)) return status;
                offset += consumed;

                if (static_cast<SIZE_T>(newSize) > maxTableSize_) return STATUS_INVALID_NETWORK_RESPONSE;
                table_.UpdateMaxSize(static_cast<SIZE_T>(newSize));
                continue;
            }
            else {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const char* outName = nullptr;
            SIZE_T outNameLen = nameLen;
            const char* outValue = nullptr;
            SIZE_T outValueLen = valueLen;

            NTSTATUS materializeStatus = MaterializeHeaderPart(
                namePtr, nameLen, nameValueBuffer, nameValueCapacity, &nvOffset, &outName);
            if (!NT_SUCCESS(materializeStatus)) return materializeStatus;

            materializeStatus = MaterializeHeaderPart(
                valuePtr, valueLen, nameValueBuffer, nameValueCapacity, &nvOffset, &outValue);
            if (!NT_SUCCESS(materializeStatus)) return materializeStatus;

            if (!AddHeaderListSize(outNameLen, outValueLen, maxHeaderListSize, &headerListSize)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (addToTable) {
                NTSTATUS insertStatus = table_.Insert(
                    reinterpret_cast<const UCHAR*>(outName), outNameLen,
                    reinterpret_cast<const UCHAR*>(outValue), outValueLen);
                if (!NT_SUCCESS(insertStatus)) return insertStatus;
            }

            // Emit header
            if (hdrIdx >= headerCapacity) return STATUS_BUFFER_TOO_SMALL;
            headers[hdrIdx].Name.Data = outName;
            headers[hdrIdx].Name.Length = outNameLen;
            headers[hdrIdx].Value.Data = outValue;
            headers[hdrIdx].Value.Length = outValueLen;
            ++hdrIdx;
        }

        *headerCount = hdrIdx;
        *nameValueUsed = nvOffset;
        return STATUS_SUCCESS;
    }

    // ========================================================================
    // HPACK Encoder
    // ========================================================================

    NTSTATUS HpackEncoder::Initialize(SIZE_T maxTableSize) noexcept
    {
        maxTableSize_ = maxTableSize;
        pendingTableSize_ = maxTableSize;
        tableSizeUpdatePending_ = false;
        return table_.Initialize(maxTableSize);
    }

    void HpackEncoder::Reset() noexcept
    {
        table_.Reset();
        tableSizeUpdatePending_ = false;
    }

    void HpackEncoder::UpdateMaxTableSize(SIZE_T maxTableSize) noexcept
    {
        if (maxTableSize_ == maxTableSize) {
            return;
        }

        maxTableSize_ = maxTableSize;
        pendingTableSize_ = maxTableSize;
        tableSizeUpdatePending_ = true;
        table_.UpdateMaxSize(maxTableSize);
    }

    SIZE_T HpackEncoder::FindMatch(
        const char* name, SIZE_T nameLen,
        const char* value, SIZE_T valueLen,
        bool* nameOnly) const noexcept
    {
        *nameOnly = false;
        SIZE_T nameMatchIdx = 0;

        // Search static table
        for (SIZE_T i = 0; i < HpackStaticTableSize; ++i) {
            const HpackStaticEntry& entry = HpackStaticTable[i];
            if (NameEquals(name, nameLen, entry.Name, entry.NameLength)) {
                if (ValueEquals(value, valueLen, entry.Value, entry.ValueLength)) {
                    return i + 1; // Full match
                }
                if (nameMatchIdx == 0) {
                    nameMatchIdx = i + 1;
                }
            }
        }

        // Search dynamic table
        for (SIZE_T i = 0; i < table_.EntryCount(); ++i) {
            const UCHAR* eName = nullptr;
            SIZE_T eNameLen = 0;
            const UCHAR* eValue = nullptr;
            SIZE_T eValueLen = 0;
            if (table_.Lookup(i, &eName, &eNameLen, &eValue, &eValueLen)) {
                if (NameEquals(name, nameLen,
                    reinterpret_cast<const char*>(eName), eNameLen)) {
                    if (ValueEquals(value, valueLen,
                        reinterpret_cast<const char*>(eValue), eValueLen)) {
                        return HpackStaticTableSize + i + 1; // Full match
                    }
                    if (nameMatchIdx == 0) {
                        nameMatchIdx = HpackStaticTableSize + i + 1;
                    }
                }
            }
        }

        if (nameMatchIdx > 0) {
            *nameOnly = true;
            return nameMatchIdx;
        }

        return 0;
    }

    NTSTATUS HpackEncoder::Encode(
        const http::HttpHeader* headers,
        SIZE_T headerCount,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (headers == nullptr && headerCount > 0) return STATUS_INVALID_PARAMETER;
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;

        SIZE_T offset = 0;

        if (tableSizeUpdatePending_) {
            SIZE_T written = 0;
            NTSTATUS status = HpackEncodeInteger(
                static_cast<ULONG>(pendingTableSize_),
                0x20,
                5,
                dest + offset,
                capacity - offset,
                &written);
            if (!NT_SUCCESS(status)) return status;
            offset += written;
            tableSizeUpdatePending_ = false;
        }

        for (SIZE_T i = 0; i < headerCount; ++i) {
            const http::HttpHeader& hdr = headers[i];
            if (hdr.Name.Data == nullptr || hdr.Name.Length == 0 ||
                (hdr.Value.Data == nullptr && hdr.Value.Length != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            bool nameOnly = false;
            SIZE_T matchIdx = FindMatch(
                hdr.Name.Data, hdr.Name.Length,
                hdr.Value.Data, hdr.Value.Length,
                &nameOnly);
            const bool neverIndex = IsSensitiveHeaderName(hdr.Name.Data, hdr.Name.Length);

            if (matchIdx > 0 && !nameOnly && !neverIndex) {
                // Indexed Header Field (Section 6.1)
                SIZE_T written = 0;
                NTSTATUS status = HpackEncodeInteger(
                    static_cast<ULONG>(matchIdx), 0x80, 7,
                    dest + offset, capacity - offset, &written);
                if (!NT_SUCCESS(status)) return status;
                offset += written;
            }
            else {
                const UCHAR literalPrefix = neverIndex ? 0x10 : 0x40;
                const UCHAR literalPrefixBits = neverIndex ? 4 : 6;
                if (matchIdx > 0) {
                    // Name indexed
                    SIZE_T written = 0;
                    NTSTATUS status = HpackEncodeInteger(
                        static_cast<ULONG>(matchIdx), literalPrefix, literalPrefixBits,
                        dest + offset, capacity - offset, &written);
                    if (!NT_SUCCESS(status)) return status;
                    offset += written;
                } else {
                    // New name
                    if (offset >= capacity) return STATUS_BUFFER_TOO_SMALL;
                    dest[offset++] = literalPrefix;

                    NTSTATUS status = EncodeHeaderString(
                        hdr.Name.Data,
                        hdr.Name.Length,
                        dest,
                        capacity,
                        &offset);
                    if (!NT_SUCCESS(status)) return status;
                }

                NTSTATUS status = EncodeHeaderString(
                    hdr.Value.Data,
                    hdr.Value.Length,
                    dest,
                    capacity,
                    &offset);
                if (!NT_SUCCESS(status)) return status;

                if (!neverIndex) {
                    status = table_.Insert(
                        reinterpret_cast<const UCHAR*>(hdr.Name.Data), hdr.Name.Length,
                        reinterpret_cast<const UCHAR*>(hdr.Value.Data), hdr.Value.Length);
                    if (!NT_SUCCESS(status)) return status;
                }
            }
        }

        *bytesWritten = offset;
        return STATUS_SUCCESS;
    }
}
}
