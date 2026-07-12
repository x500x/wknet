#include <wknet\ws\WebSocketDeflate.h>

namespace wknet
{
namespace ws
{
    namespace
    {
        constexpr SIZE_T MaxExpansionRatio = 64;
        constexpr SIZE_T MaxLiteralLengthCodes = 288;
        constexpr SIZE_T MaxDistanceCodes = 32;
        constexpr SIZE_T MaxCodeLengthCodes = 19;
        constexpr SIZE_T MaxCodeBits = 15;
        constexpr UCHAR PerMessageDeflateTail[] = { 0x00, 0x00, 0xff, 0xff };

        constexpr USHORT LengthBase[] = {
            3, 4, 5, 6, 7, 8, 9, 10,
            11, 13, 15, 17, 19, 23, 27, 31,
            35, 43, 51, 59, 67, 83, 99, 115,
            131, 163, 195, 227, 258
        };

        constexpr UCHAR LengthExtra[] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 2, 2, 2, 2,
            3, 3, 3, 3, 4, 4, 4, 4,
            5, 5, 5, 5, 0
        };

        constexpr USHORT DistanceBase[] = {
            1, 2, 3, 4, 5, 7, 9, 13,
            17, 25, 33, 49, 65, 97, 129, 193,
            257, 385, 513, 769, 1025, 1537, 2049, 3073,
            4097, 6145, 8193, 12289, 16385, 24577
        };

        constexpr UCHAR DistanceExtra[] = {
            0, 0, 0, 0, 1, 1, 2, 2,
            3, 3, 4, 4, 5, 5, 6, 6,
            7, 7, 8, 8, 9, 9, 10, 10,
            11, 11, 12, 12, 13, 13
        };

        constexpr UCHAR CodeLengthOrder[] = {
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
            11, 4, 12, 3, 13, 2, 14, 1, 15
        };

        struct HuffmanEntry final
        {
            USHORT Code = 0;
            USHORT Symbol = 0;
            UCHAR Length = 0;
        };

        struct HuffmanTable final
        {
            HeapArray<HuffmanEntry> Entries = {};
            SIZE_T EntryCount = 0;
            UCHAR MaxBits = 0;
        };

        class BitReader final
        {
        public:
            BitReader(const UCHAR* data, SIZE_T dataLength) noexcept :
                data_(data),
                dataLength_(dataLength)
            {
            }

            _Must_inspect_result_
            bool ReadBits(UCHAR bitCount, ULONG* value) noexcept
            {
                if (value == nullptr || bitCount > 16) {
                    return false;
                }

                ULONG parsed = 0;
                for (UCHAR bit = 0; bit < bitCount; ++bit) {
                    if (byteOffset_ >= dataLength_ || data_ == nullptr) {
                        return false;
                    }

                    const UCHAR current = data_[byteOffset_];
                    parsed |= static_cast<ULONG>((current >> bitOffset_) & 1U) << bit;
                    ++bitOffset_;
                    if (bitOffset_ == 8) {
                        bitOffset_ = 0;
                        ++byteOffset_;
                    }
                }

                *value = parsed;
                return true;
            }

            void AlignByte() noexcept
            {
                if (bitOffset_ != 0) {
                    bitOffset_ = 0;
                    ++byteOffset_;
                }
            }

            _Must_inspect_result_
            bool ReadByte(UCHAR* value) noexcept
            {
                if (value == nullptr) {
                    return false;
                }
                AlignByte();
                if (byteOffset_ >= dataLength_ || data_ == nullptr) {
                    return false;
                }
                *value = data_[byteOffset_++];
                return true;
            }

            _Must_inspect_result_
            bool HasMoreInput() const noexcept
            {
                return byteOffset_ < dataLength_;
            }

        private:
            const UCHAR* data_ = nullptr;
            SIZE_T dataLength_ = 0;
            SIZE_T byteOffset_ = 0;
            UCHAR bitOffset_ = 0;
        };

        _Must_inspect_result_
        USHORT ReverseBits(USHORT code, UCHAR length) noexcept
        {
            USHORT reversed = 0;
            for (UCHAR index = 0; index < length; ++index) {
                reversed = static_cast<USHORT>((reversed << 1) | (code & 1U));
                code = static_cast<USHORT>(code >> 1);
            }
            return reversed;
        }

        _Must_inspect_result_
        NTSTATUS BuildHuffmanTable(
            const UCHAR* lengths,
            SIZE_T symbolCount,
            HuffmanTable& table) noexcept
        {
            table.EntryCount = 0;
            table.MaxBits = 0;
            table.Entries.Reset();

            if (lengths == nullptr || symbolCount == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<USHORT> bitCounts(MaxCodeBits + 1);
            HeapArray<USHORT> nextCode(MaxCodeBits + 1);
            if (!bitCounts.IsValid() || !nextCode.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(bitCounts.Get(), bitCounts.Count() * sizeof(USHORT));
            RtlZeroMemory(nextCode.Get(), nextCode.Count() * sizeof(USHORT));

            SIZE_T entryCount = 0;
            for (SIZE_T symbol = 0; symbol < symbolCount; ++symbol) {
                const UCHAR length = lengths[symbol];
                if (length > MaxCodeBits) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (length != 0) {
                    ++bitCounts[length];
                    ++entryCount;
                    if (length > table.MaxBits) {
                        table.MaxBits = length;
                    }
                }
            }

            if (entryCount == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            NTSTATUS status = table.Entries.Allocate(entryCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            USHORT code = 0;
            for (UCHAR bits = 1; bits <= MaxCodeBits; ++bits) {
                code = static_cast<USHORT>((code + bitCounts[bits - 1]) << 1);
                nextCode[bits] = code;
            }

            SIZE_T nextEntry = 0;
            for (SIZE_T symbol = 0; symbol < symbolCount; ++symbol) {
                const UCHAR length = lengths[symbol];
                if (length == 0) {
                    continue;
                }

                HuffmanEntry& entry = table.Entries[nextEntry++];
                entry.Length = length;
                entry.Symbol = static_cast<USHORT>(symbol);
                entry.Code = ReverseBits(nextCode[length], length);
                ++nextCode[length];
            }

            table.EntryCount = nextEntry;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS DecodeSymbol(BitReader& reader, const HuffmanTable& table, USHORT* symbol) noexcept
        {
            if (symbol == nullptr || table.EntryCount == 0 || !table.Entries.IsValid()) {
                return STATUS_INVALID_PARAMETER;
            }

            USHORT code = 0;
            for (UCHAR length = 1; length <= table.MaxBits; ++length) {
                ULONG bit = 0;
                if (!reader.ReadBits(1, &bit)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                code = static_cast<USHORT>(code | (static_cast<USHORT>(bit) << (length - 1)));

                for (SIZE_T index = 0; index < table.EntryCount; ++index) {
                    const HuffmanEntry& entry = table.Entries[index];
                    if (entry.Length == length && entry.Code == code) {
                        *symbol = entry.Symbol;
                        return STATUS_SUCCESS;
                    }
                }
            }

            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        NTSTATUS BuildFixedTables(HuffmanTable& literalTable, HuffmanTable& distanceTable) noexcept
        {
            HeapArray<UCHAR> literalLengths(MaxLiteralLengthCodes);
            HeapArray<UCHAR> distanceLengths(MaxDistanceCodes);
            if (!literalLengths.IsValid() || !distanceLengths.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            for (SIZE_T symbol = 0; symbol <= 143; ++symbol) {
                literalLengths[symbol] = 8;
            }
            for (SIZE_T symbol = 144; symbol <= 255; ++symbol) {
                literalLengths[symbol] = 9;
            }
            for (SIZE_T symbol = 256; symbol <= 279; ++symbol) {
                literalLengths[symbol] = 7;
            }
            for (SIZE_T symbol = 280; symbol <= 287; ++symbol) {
                literalLengths[symbol] = 8;
            }
            for (SIZE_T symbol = 0; symbol < MaxDistanceCodes; ++symbol) {
                distanceLengths[symbol] = 5;
            }

            NTSTATUS status = BuildHuffmanTable(literalLengths.Get(), literalLengths.Count(), literalTable);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return BuildHuffmanTable(distanceLengths.Get(), distanceLengths.Count(), distanceTable);
        }

        _Must_inspect_result_
        NTSTATUS ReadDynamicTables(
            BitReader& reader,
            HuffmanTable& literalTable,
            HuffmanTable& distanceTable) noexcept
        {
            ULONG hlitValue = 0;
            ULONG hdistValue = 0;
            ULONG hclenValue = 0;
            if (!reader.ReadBits(5, &hlitValue) ||
                !reader.ReadBits(5, &hdistValue) ||
                !reader.ReadBits(4, &hclenValue)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T literalCount = hlitValue + 257;
            const SIZE_T distanceCount = hdistValue + 1;
            const SIZE_T codeLengthCount = hclenValue + 4;
            if (literalCount > MaxLiteralLengthCodes || distanceCount > MaxDistanceCodes) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            HeapArray<UCHAR> codeLengthLengths(MaxCodeLengthCodes);
            HeapArray<UCHAR> allLengths(literalCount + distanceCount);
            if (!codeLengthLengths.IsValid() || !allLengths.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(codeLengthLengths.Get(), codeLengthLengths.Count());
            RtlZeroMemory(allLengths.Get(), allLengths.Count());

            for (SIZE_T index = 0; index < codeLengthCount; ++index) {
                ULONG length = 0;
                if (!reader.ReadBits(3, &length)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                codeLengthLengths[CodeLengthOrder[index]] = static_cast<UCHAR>(length);
            }

            HuffmanTable codeLengthTable = {};
            NTSTATUS status = BuildHuffmanTable(
                codeLengthLengths.Get(),
                codeLengthLengths.Count(),
                codeLengthTable);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T index = 0;
            while (index < allLengths.Count()) {
                USHORT symbol = 0;
                status = DecodeSymbol(reader, codeLengthTable, &symbol);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (symbol <= 15) {
                    allLengths[index++] = static_cast<UCHAR>(symbol);
                }
                else if (symbol == 16) {
                    if (index == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    ULONG extra = 0;
                    if (!reader.ReadBits(2, &extra)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T repeat = extra + 3;
                    if (repeat > allLengths.Count() - index) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const UCHAR previous = allLengths[index - 1];
                    for (SIZE_T repeatIndex = 0; repeatIndex < repeat; ++repeatIndex) {
                        allLengths[index++] = previous;
                    }
                }
                else if (symbol == 17 || symbol == 18) {
                    ULONG extra = 0;
                    const UCHAR extraBits = symbol == 17 ? 3 : 7;
                    if (!reader.ReadBits(extraBits, &extra)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T repeat = extra + (symbol == 17 ? 3 : 11);
                    if (repeat > allLengths.Count() - index) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    for (SIZE_T repeatIndex = 0; repeatIndex < repeat; ++repeatIndex) {
                        allLengths[index++] = 0;
                    }
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            status = BuildHuffmanTable(allLengths.Get(), literalCount, literalTable);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            bool hasDistanceCode = false;
            for (SIZE_T distanceIndex = 0; distanceIndex < distanceCount; ++distanceIndex) {
                if (allLengths[literalCount + distanceIndex] != 0) {
                    hasDistanceCode = true;
                    break;
                }
            }
            if (!hasDistanceCode) {
                distanceTable.EntryCount = 0;
                distanceTable.MaxBits = 0;
                distanceTable.Entries.Reset();
                return STATUS_SUCCESS;
            }

            return BuildHuffmanTable(allLengths.Get() + literalCount, distanceCount, distanceTable);
        }

        _Must_inspect_result_
        NTSTATUS DecodeCompressedBlock(
            BitReader& reader,
            HuffmanTable& literalTable,
            HuffmanTable& distanceTable,
            SIZE_T encodedLength,
            WebSocketDeflateContext& context,
            UCHAR* destination,
            SIZE_T destinationCapacity,
            SIZE_T* bytesWritten) noexcept
        {
            for (;;) {
                USHORT symbol = 0;
                NTSTATUS status = DecodeSymbol(reader, literalTable, &symbol);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (symbol < 256) {
                    status = context.EmitByte(
                        static_cast<UCHAR>(symbol),
                        encodedLength,
                        destination,
                        destinationCapacity,
                        bytesWritten);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                else if (symbol == 256) {
                    return STATUS_SUCCESS;
                }
                else if (symbol <= 285) {
                    const SIZE_T lengthIndex = symbol - 257;
                    SIZE_T length = LengthBase[lengthIndex];
                    const UCHAR lengthExtraBits = LengthExtra[lengthIndex];
                    if (lengthExtraBits != 0) {
                        ULONG extra = 0;
                        if (!reader.ReadBits(lengthExtraBits, &extra)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        length += extra;
                    }

                    if (distanceTable.EntryCount == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    USHORT distanceSymbol = 0;
                    status = DecodeSymbol(reader, distanceTable, &distanceSymbol);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (distanceSymbol >= 30) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    SIZE_T distance = DistanceBase[distanceSymbol];
                    const UCHAR distanceExtraBits = DistanceExtra[distanceSymbol];
                    if (distanceExtraBits != 0) {
                        ULONG extra = 0;
                        if (!reader.ReadBits(distanceExtraBits, &extra)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        distance += extra;
                    }

                    status = context.CopyFromHistory(
                        distance,
                        length,
                        encodedLength,
                        destination,
                        destinationCapacity,
                        bytesWritten);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }

        _Must_inspect_result_
        NTSTATUS DecodeStoredBlock(
            BitReader& reader,
            SIZE_T encodedLength,
            WebSocketDeflateContext& context,
            UCHAR* destination,
            SIZE_T destinationCapacity,
            SIZE_T* bytesWritten) noexcept
        {
            reader.AlignByte();

            UCHAR len0 = 0;
            UCHAR len1 = 0;
            UCHAR nlen0 = 0;
            UCHAR nlen1 = 0;
            if (!reader.ReadByte(&len0) ||
                !reader.ReadByte(&len1) ||
                !reader.ReadByte(&nlen0) ||
                !reader.ReadByte(&nlen1)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const USHORT length = static_cast<USHORT>(
                static_cast<USHORT>(len0) | (static_cast<USHORT>(len1) << 8));
            const USHORT negated = static_cast<USHORT>(
                static_cast<USHORT>(nlen0) | (static_cast<USHORT>(nlen1) << 8));
            if (static_cast<USHORT>(length ^ 0xffffU) != negated) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            for (USHORT index = 0; index < length; ++index) {
                UCHAR byte = 0;
                if (!reader.ReadByte(&byte)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                NTSTATUS status = context.EmitByte(
                    byte,
                    encodedLength,
                    destination,
                    destinationCapacity,
                    bytesWritten);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            return STATUS_SUCCESS;
        }
    }

    bool IsValidPerMessageDeflateOptions(const PerMessageDeflateOptions& options) noexcept
    {
        if (!options.Enable) {
            return true;
        }

        return options.ClientMaxWindowBits >= WebSocketDeflateMinWindowBits &&
            options.ClientMaxWindowBits <= WebSocketDeflateMaxWindowBits &&
            options.ServerMaxWindowBits >= WebSocketDeflateMinWindowBits &&
            options.ServerMaxWindowBits <= WebSocketDeflateMaxWindowBits;
    }

    NTSTATUS WebSocketDeflateContext::Initialize(UCHAR windowBits) noexcept
    {
        if (windowBits < WebSocketDeflateMinWindowBits ||
            windowBits > WebSocketDeflateMaxWindowBits) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T windowSize = static_cast<SIZE_T>(1) << windowBits;
        NTSTATUS status = window_.Allocate(windowSize);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlZeroMemory(window_.Get(), window_.Count());
        windowMask_ = windowSize - 1;
        windowPosition_ = 0;
        historyBytes_ = 0;
        return STATUS_SUCCESS;
    }

    void WebSocketDeflateContext::ResetHistory() noexcept
    {
        if (window_.IsValid()) {
            RtlZeroMemory(window_.Get(), window_.Count());
        }
        windowPosition_ = 0;
        historyBytes_ = 0;
    }

    void WebSocketDeflateContext::Release() noexcept
    {
        ResetHistory();
        window_.Reset();
        windowMask_ = 0;
    }

    bool WebSocketDeflateContext::IsInitialized() const noexcept
    {
        return window_.IsValid() && window_.Count() != 0;
    }

    NTSTATUS WebSocketDeflateContext::EmitByte(
        UCHAR byte,
        SIZE_T encodedLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (destination == nullptr || bytesWritten == nullptr || !IsInitialized()) {
            return STATUS_INVALID_PARAMETER;
        }
        if (*bytesWritten >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (encodedLength != 0 &&
            *bytesWritten >= encodedLength * MaxExpansionRatio) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        destination[*bytesWritten] = byte;
        ++(*bytesWritten);
        window_[windowPosition_] = byte;
        windowPosition_ = (windowPosition_ + 1) & windowMask_;
        if (historyBytes_ < window_.Count()) {
            ++historyBytes_;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketDeflateContext::CopyFromHistory(
        SIZE_T distance,
        SIZE_T length,
        SIZE_T encodedLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (!IsInitialized() ||
            distance == 0 ||
            distance > historyBytes_ ||
            distance > window_.Count()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T source = (windowPosition_ + window_.Count() - distance) & windowMask_;
        for (SIZE_T index = 0; index < length; ++index) {
            const UCHAR byte = window_[source];
            NTSTATUS status = EmitByte(
                byte,
                encodedLength,
                destination,
                destinationCapacity,
                bytesWritten);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            source = (source + 1) & windowMask_;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketDeflateContext::InflateMessage(
        const UCHAR* source,
        SIZE_T sourceLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }
        if ((source == nullptr && sourceLength != 0) ||
            destination == nullptr ||
            bytesWritten == nullptr ||
            !IsInitialized()) {
            return STATUS_INVALID_PARAMETER;
        }
        if (sourceLength > static_cast<SIZE_T>(-1) - sizeof(PerMessageDeflateTail)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        HeapArray<UCHAR> input(sourceLength + sizeof(PerMessageDeflateTail));
        if (!input.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (sourceLength != 0) {
            RtlCopyMemory(input.Get(), source, sourceLength);
        }
        RtlCopyMemory(input.Get() + sourceLength, PerMessageDeflateTail, sizeof(PerMessageDeflateTail));

        BitReader reader(input.Get(), input.Count());
        while (reader.HasMoreInput()) {
            ULONG finalBlock = 0;
            ULONG blockType = 0;
            if (!reader.ReadBits(1, &finalBlock) || !reader.ReadBits(2, &blockType)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            NTSTATUS status = STATUS_SUCCESS;
            if (blockType == 0) {
                status = DecodeStoredBlock(
                    reader,
                    sourceLength,
                    *this,
                    destination,
                    destinationCapacity,
                    bytesWritten);
            }
            else if (blockType == 1 || blockType == 2) {
                HuffmanTable literalTable = {};
                HuffmanTable distanceTable = {};
                if (blockType == 1) {
                    status = BuildFixedTables(literalTable, distanceTable);
                }
                else {
                    status = ReadDynamicTables(reader, literalTable, distanceTable);
                }
                if (NT_SUCCESS(status)) {
                    status = DecodeCompressedBlock(
                        reader,
                        literalTable,
                        distanceTable,
                        sourceLength,
                        *this,
                        destination,
                        destinationCapacity,
                        bytesWritten);
                }
            }
            else {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }
            UNREFERENCED_PARAMETER(finalBlock);
        }

        return STATUS_SUCCESS;
    }

    SIZE_T WebSocketDeflateContext::MaxStoredDeflateBytes(SIZE_T sourceLength, bool finalFragment) noexcept
    {
        const SIZE_T blockCount = sourceLength == 0 ? 0 : ((sourceLength + 65534) / 65535);
        if (blockCount > (static_cast<SIZE_T>(-1) - sourceLength - (finalFragment ? 1 : 0)) / 5) {
            return static_cast<SIZE_T>(-1);
        }
        return sourceLength + (blockCount * 5) + (finalFragment ? 1 : 0);
    }

    NTSTATUS WebSocketDeflateContext::DeflateMessage(
        const UCHAR* source,
        SIZE_T sourceLength,
        bool finalFragment,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }
        if ((source == nullptr && sourceLength != 0) ||
            destination == nullptr ||
            bytesWritten == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T required = MaxStoredDeflateBytes(sourceLength, finalFragment);
        if (required == static_cast<SIZE_T>(-1)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        if (destinationCapacity < required) {
            *bytesWritten = required;
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T inputOffset = 0;
        SIZE_T outputOffset = 0;
        while (inputOffset < sourceLength) {
            const SIZE_T remaining = sourceLength - inputOffset;
            const USHORT chunkLength = static_cast<USHORT>(
                remaining > 65535 ? 65535 : remaining);
            const USHORT negated = static_cast<USHORT>(chunkLength ^ 0xffffU);

            destination[outputOffset++] = 0x00;
            destination[outputOffset++] = static_cast<UCHAR>(chunkLength & 0xff);
            destination[outputOffset++] = static_cast<UCHAR>((chunkLength >> 8) & 0xff);
            destination[outputOffset++] = static_cast<UCHAR>(negated & 0xff);
            destination[outputOffset++] = static_cast<UCHAR>((negated >> 8) & 0xff);
            RtlCopyMemory(destination + outputOffset, source + inputOffset, chunkLength);
            outputOffset += chunkLength;
            inputOffset += chunkLength;
        }

        if (finalFragment) {
            destination[outputOffset++] = 0x00;
        }

        *bytesWritten = outputOffset;
        return STATUS_SUCCESS;
    }
}
}
