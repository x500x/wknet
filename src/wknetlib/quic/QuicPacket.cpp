#include "quic/QuicPacket.h"
#include "quic/QuicVarInt.h"

namespace wknet::quic
{
namespace
{
bool CanAdvance(SIZE_T offset, SIZE_T length, SIZE_T capacity) noexcept
{
    return offset <= capacity && length <= capacity - offset;
}

ULONG ReadBigEndian32(const UCHAR *data) noexcept
{
    return (static_cast<ULONG>(data[0]) << 24) | (static_cast<ULONG>(data[1]) << 16) |
           (static_cast<ULONG>(data[2]) << 8) | static_cast<ULONG>(data[3]);
}

NTSTATUS WriteBytes(const UCHAR *data, SIZE_T length, UCHAR *output, SIZE_T capacity, SIZE_T *offset) noexcept
{
    if ((data == nullptr && length != 0) || output == nullptr || offset == nullptr || *offset > capacity ||
        length > capacity - *offset)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (length != 0)
    {
        RtlCopyMemory(output + *offset, data, length);
    }
    *offset += length;
    return STATUS_SUCCESS;
}

NTSTATUS WriteVarInt(ULONGLONG value, UCHAR *output, SIZE_T capacity, SIZE_T *offset) noexcept
{
    if (output == nullptr || offset == nullptr || *offset > capacity)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    SIZE_T written = 0;
    const SIZE_T encodedLength = QuicVarIntEncodedLength(value);
    const NTSTATUS status =
        encodedLength == 0 ? STATUS_INTEGER_OVERFLOW
                           : QuicEncodeVarInt(value, encodedLength, output + *offset, capacity - *offset, &written);
    if (NT_SUCCESS(status))
    {
        *offset += written;
    }
    return status;
}

NTSTATUS WriteTruncatedPacketNumber(ULONGLONG packetNumber, SIZE_T packetNumberLength, UCHAR *output, SIZE_T capacity,
                                    SIZE_T *offset) noexcept
{
    if (packetNumber > QuicVarIntMaximum || packetNumberLength == 0 || packetNumberLength > 4 || output == nullptr ||
        offset == nullptr || *offset > capacity || packetNumberLength > capacity - *offset)
    {
        return STATUS_INVALID_PARAMETER;
    }
    for (SIZE_T index = packetNumberLength; index > 0; --index)
    {
        output[*offset + index - 1] = static_cast<UCHAR>(packetNumber & 0xffU);
        packetNumber >>= 8;
    }
    *offset += packetNumberLength;
    return STATUS_SUCCESS;
}
} // namespace

NTSTATUS QuicParsePacketHeader(const UCHAR *packet, SIZE_T packetLength,
                               SIZE_T shortHeaderDestinationConnectionIdLength, QuicPacketHeader *header) noexcept
{
    if (header != nullptr)
        *header = {};
    if (packet == nullptr || header == nullptr || packetLength == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    header->FirstByte = packet[0];
    header->IsLongHeader = (packet[0] & 0x80U) != 0;
    header->FixedBit = (packet[0] & 0x40U) != 0;

    if (!header->IsLongHeader)
    {
        if (!header->FixedBit)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (shortHeaderDestinationConnectionIdLength > QuicMaximumConnectionIdLength ||
            !CanAdvance(1, shortHeaderDestinationConnectionIdLength, packetLength))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        header->Type = QuicPacketType::OneRtt;
        header->DestinationConnectionId = {packet + 1, shortHeaderDestinationConnectionIdLength};
        header->PacketNumberLength = (packet[0] & 0x03U) + 1U;
        header->PacketNumberOffset = 1 + shortHeaderDestinationConnectionIdLength;
        if (!CanAdvance(header->PacketNumberOffset, header->PacketNumberLength, packetLength))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        header->PayloadOffset = header->PacketNumberOffset + header->PacketNumberLength;
        header->PayloadLength = packetLength - header->PayloadOffset;
        header->HeaderLength = header->PayloadOffset;
        header->PacketLength = packetLength;
        return STATUS_SUCCESS;
    }

    if (packetLength < 6)
        return STATUS_BUFFER_TOO_SMALL;
    SIZE_T offset = 1;
    header->Version = ReadBigEndian32(packet + offset);
    offset += 4;
    const SIZE_T dcidLength = packet[offset++];
    if (dcidLength > QuicMaximumConnectionIdLength || !CanAdvance(offset, dcidLength + 1, packetLength))
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    header->DestinationConnectionId = {packet + offset, dcidLength};
    offset += dcidLength;
    const SIZE_T scidLength = packet[offset++];
    if (scidLength > QuicMaximumConnectionIdLength || !CanAdvance(offset, scidLength, packetLength))
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    header->SourceConnectionId = {packet + offset, scidLength};
    offset += scidLength;

    if (header->Version == QuicVersionNegotiation)
    {
        const SIZE_T listLength = packetLength - offset;
        if (listLength == 0 || (listLength % sizeof(ULONG)) != 0)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        header->Type = QuicPacketType::VersionNegotiation;
        header->VersionList = {packet + offset, listLength};
        header->HeaderLength = offset;
        header->PacketLength = packetLength;
        return STATUS_SUCCESS;
    }

    if (!header->FixedBit)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (header->Version != QuicVersion1)
        return STATUS_NOT_SUPPORTED;
    const UCHAR longType = static_cast<UCHAR>((packet[0] >> 4) & 0x03U);
    header->Type = longType == 0
                       ? QuicPacketType::Initial
                       : (longType == 1 ? QuicPacketType::ZeroRtt
                                        : (longType == 2 ? QuicPacketType::Handshake : QuicPacketType::Retry));

    if (header->Type == QuicPacketType::Retry)
    {
        if (packetLength - offset < QuicRetryIntegrityTagLength)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        const SIZE_T tokenLength = packetLength - offset - QuicRetryIntegrityTagLength;
        header->Token = {packet + offset, tokenLength};
        header->RetryIntegrityTag = {packet + packetLength - QuicRetryIntegrityTagLength, QuicRetryIntegrityTagLength};
        header->HeaderLength = offset;
        header->PacketLength = packetLength;
        return STATUS_SUCCESS;
    }

    if (header->Type == QuicPacketType::Initial)
    {
        ULONGLONG tokenLength = 0;
        SIZE_T consumed = 0;
        NTSTATUS status = QuicDecodeVarInt(packet + offset, packetLength - offset, &tokenLength, &consumed);
        if (!NT_SUCCESS(status))
            return status;
        offset += consumed;
        if (tokenLength > static_cast<ULONGLONG>(packetLength) ||
            !CanAdvance(offset, static_cast<SIZE_T>(tokenLength), packetLength))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        header->Token = {packet + offset, static_cast<SIZE_T>(tokenLength)};
        offset += static_cast<SIZE_T>(tokenLength);
    }

    ULONGLONG protectedLength = 0;
    SIZE_T consumed = 0;
    NTSTATUS status = QuicDecodeVarInt(packet + offset, packetLength - offset, &protectedLength, &consumed);
    if (!NT_SUCCESS(status))
        return status;
    offset += consumed;
    if (protectedLength > static_cast<ULONGLONG>(packetLength) ||
        !CanAdvance(offset, static_cast<SIZE_T>(protectedLength), packetLength))
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    header->PacketNumberLength = (packet[0] & 0x03U) + 1U;
    if (protectedLength < header->PacketNumberLength)
        return STATUS_INVALID_NETWORK_RESPONSE;
    header->PacketNumberOffset = offset;
    header->PayloadOffset = offset + header->PacketNumberLength;
    header->PayloadLength = static_cast<SIZE_T>(protectedLength) - header->PacketNumberLength;
    header->HeaderLength = header->PayloadOffset;
    header->PacketLength = offset + static_cast<SIZE_T>(protectedLength);
    return STATUS_SUCCESS;
}

NTSTATUS QuicEncodePacketNumber(ULONGLONG packetNumber, SIZE_T packetNumberLength, UCHAR *output, SIZE_T capacity,
                                SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
        *bytesWritten = 0;
    if (output == nullptr || packetNumberLength == 0 || packetNumberLength > 4)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (packetNumber > QuicVarIntMaximum)
        return STATUS_INTEGER_OVERFLOW;
    const ULONGLONG maximum = (1ULL << (packetNumberLength * 8)) - 1ULL;
    if (packetNumber > maximum)
        return STATUS_INTEGER_OVERFLOW;
    if (capacity < packetNumberLength)
        return STATUS_BUFFER_TOO_SMALL;
    for (SIZE_T index = packetNumberLength; index > 0; --index)
    {
        output[index - 1] = static_cast<UCHAR>(packetNumber & 0xffU);
        packetNumber >>= 8;
    }
    if (bytesWritten != nullptr)
        *bytesWritten = packetNumberLength;
    return STATUS_SUCCESS;
}

NTSTATUS QuicReconstructPacketNumber(ULONGLONG truncatedPacketNumber, SIZE_T packetNumberLength,
                                     ULONGLONG expectedPacketNumber, ULONGLONG *packetNumber) noexcept
{
    if (packetNumber != nullptr)
        *packetNumber = 0;
    if (packetNumber == nullptr || packetNumberLength == 0 || packetNumberLength > 4 ||
        expectedPacketNumber > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONGLONG window = 1ULL << (packetNumberLength * 8);
    const ULONGLONG halfWindow = window / 2;
    const ULONGLONG mask = window - 1;
    if (truncatedPacketNumber > mask)
        return STATUS_INVALID_PARAMETER;
    ULONGLONG candidate = (expectedPacketNumber & ~mask) | truncatedPacketNumber;
    if (candidate + halfWindow <= expectedPacketNumber && candidate <= QuicVarIntMaximum - window)
    {
        candidate += window;
    }
    else if (candidate > expectedPacketNumber + halfWindow && candidate >= window)
    {
        candidate -= window;
    }
    if (candidate > QuicVarIntMaximum)
        return STATUS_INTEGER_OVERFLOW;
    *packetNumber = candidate;
    return STATUS_SUCCESS;
}

void QuicPacketIteratorInitialize(QuicPacketIterator *iterator, const UCHAR *datagram, SIZE_T datagramLength,
                                  SIZE_T shortHeaderDestinationConnectionIdLength) noexcept
{
    if (iterator == nullptr)
        return;
    iterator->Datagram = datagram;
    iterator->DatagramLength = datagramLength;
    iterator->Offset = 0;
    iterator->ShortHeaderDestinationConnectionIdLength = shortHeaderDestinationConnectionIdLength;
}

NTSTATUS QuicPacketIteratorNext(QuicPacketIterator *iterator, QuicPacketHeader *header, QuicBufferView *packet) noexcept
{
    if (packet != nullptr)
        *packet = {};
    if (iterator == nullptr || header == nullptr || packet == nullptr ||
        (iterator->Datagram == nullptr && iterator->DatagramLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (iterator->Offset == iterator->DatagramLength)
        return STATUS_NOT_FOUND;
    if (iterator->Offset > iterator->DatagramLength)
        return STATUS_INVALID_NETWORK_RESPONSE;
    const UCHAR *current = iterator->Datagram + iterator->Offset;
    const SIZE_T remaining = iterator->DatagramLength - iterator->Offset;
    NTSTATUS status =
        QuicParsePacketHeader(current, remaining, iterator->ShortHeaderDestinationConnectionIdLength, header);
    if (!NT_SUCCESS(status))
        return status;
    if (header->PacketLength == 0 || header->PacketLength > remaining)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    packet->Data = current;
    packet->Length = header->PacketLength;
    iterator->Offset += header->PacketLength;
    return STATUS_SUCCESS;
}

NTSTATUS QuicValidateInitialDatagramLength(SIZE_T datagramLength) noexcept
{
    return datagramLength >= 1200 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS QuicEncodeLongPacketHeader(const QuicLongHeaderEncodeOptions &options, UCHAR *output, SIZE_T capacity,
                                    SIZE_T *packetNumberOffset, SIZE_T *headerLength) noexcept
{
    if (packetNumberOffset != nullptr)
    {
        *packetNumberOffset = 0;
    }
    if (headerLength != nullptr)
    {
        *headerLength = 0;
    }
    if (output == nullptr || packetNumberOffset == nullptr || headerLength == nullptr ||
        options.Version != QuicVersion1 || options.PacketNumberLength == 0 || options.PacketNumberLength > 4 ||
        options.DestinationConnectionId.Length > QuicMaximumConnectionIdLength ||
        options.SourceConnectionId.Length > QuicMaximumConnectionIdLength ||
        (options.DestinationConnectionId.Data == nullptr && options.DestinationConnectionId.Length != 0) ||
        (options.SourceConnectionId.Data == nullptr && options.SourceConnectionId.Length != 0) ||
        (options.Token.Data == nullptr && options.Token.Length != 0) ||
        options.ProtectedPayloadLength < options.PacketNumberLength ||
        options.ProtectedPayloadLength > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }

    UCHAR typeBits = 0;
    if (options.Type == QuicPacketType::ZeroRtt)
    {
        typeBits = 1;
    }
    else if (options.Type == QuicPacketType::Handshake)
    {
        typeBits = 2;
    }
    else if (options.Type != QuicPacketType::Initial)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T offset = 0;
    if (capacity == 0)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    output[offset++] = static_cast<UCHAR>(0xc0U | (typeBits << 4) | (options.PacketNumberLength - 1));
    if (capacity - offset < 4)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    output[offset++] = static_cast<UCHAR>((options.Version >> 24) & 0xff);
    output[offset++] = static_cast<UCHAR>((options.Version >> 16) & 0xff);
    output[offset++] = static_cast<UCHAR>((options.Version >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(options.Version & 0xff);
    if (offset >= capacity)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    output[offset++] = static_cast<UCHAR>(options.DestinationConnectionId.Length);
    NTSTATUS status = WriteBytes(options.DestinationConnectionId.Data, options.DestinationConnectionId.Length, output,
                                 capacity, &offset);
    if (NT_SUCCESS(status))
    {
        if (offset >= capacity)
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            output[offset++] = static_cast<UCHAR>(options.SourceConnectionId.Length);
        }
    }
    if (NT_SUCCESS(status))
    {
        status =
            WriteBytes(options.SourceConnectionId.Data, options.SourceConnectionId.Length, output, capacity, &offset);
    }
    if (NT_SUCCESS(status) && options.Type == QuicPacketType::Initial)
    {
        status = WriteVarInt(options.Token.Length, output, capacity, &offset);
        if (NT_SUCCESS(status))
        {
            status = WriteBytes(options.Token.Data, options.Token.Length, output, capacity, &offset);
        }
    }
    if (NT_SUCCESS(status))
    {
        status = WriteVarInt(options.ProtectedPayloadLength, output, capacity, &offset);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *packetNumberOffset = offset;
    status = WriteTruncatedPacketNumber(options.PacketNumber, options.PacketNumberLength, output, capacity, &offset);
    if (NT_SUCCESS(status))
    {
        *headerLength = offset;
    }
    return status;
}

NTSTATUS QuicEncodeShortPacketHeader(const QuicShortHeaderEncodeOptions &options, UCHAR *output, SIZE_T capacity,
                                     SIZE_T *packetNumberOffset, SIZE_T *headerLength) noexcept
{
    if (packetNumberOffset != nullptr)
    {
        *packetNumberOffset = 0;
    }
    if (headerLength != nullptr)
    {
        *headerLength = 0;
    }
    if (output == nullptr || packetNumberOffset == nullptr || headerLength == nullptr || capacity == 0 ||
        options.PacketNumberLength == 0 || options.PacketNumberLength > 4 ||
        options.DestinationConnectionId.Length > QuicMaximumConnectionIdLength ||
        (options.DestinationConnectionId.Data == nullptr && options.DestinationConnectionId.Length != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T offset = 0;
    output[offset++] = static_cast<UCHAR>(0x40U | (options.KeyPhase ? 0x04U : 0U) |
                                          static_cast<UCHAR>(options.PacketNumberLength - 1));
    NTSTATUS status = WriteBytes(options.DestinationConnectionId.Data, options.DestinationConnectionId.Length, output,
                                 capacity, &offset);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *packetNumberOffset = offset;
    status = WriteTruncatedPacketNumber(options.PacketNumber, options.PacketNumberLength, output, capacity, &offset);
    if (NT_SUCCESS(status))
    {
        *headerLength = offset;
    }
    return status;
}
} // namespace wknet::quic
