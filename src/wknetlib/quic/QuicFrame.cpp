#include "quic/QuicFrame.h"
#include "quic/QuicVarInt.h"

namespace wknet::quic
{
namespace
{
NTSTATUS ReadValue(const UCHAR *data, SIZE_T length, SIZE_T *offset, ULONGLONG *value) noexcept
{
    if (*offset > length)
        return STATUS_INVALID_NETWORK_RESPONSE;
    SIZE_T consumed = 0;
    const NTSTATUS status = QuicDecodeVarInt(data + *offset, length - *offset, value, &consumed);
    if (!NT_SUCCESS(status))
        return status;
    *offset += consumed;
    return STATUS_SUCCESS;
}

bool HasBytes(SIZE_T offset, SIZE_T count, SIZE_T length) noexcept
{
    return offset <= length && count <= length - offset;
}

NTSTATUS WriteValue(ULONGLONG value, UCHAR *output, SIZE_T capacity, SIZE_T *offset) noexcept
{
    if (output == nullptr || offset == nullptr || *offset > capacity)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    SIZE_T written = 0;
    const SIZE_T encodedLength = QuicVarIntEncodedLength(value);
    NTSTATUS status = encodedLength == 0
                          ? STATUS_INTEGER_OVERFLOW
                          : QuicEncodeVarInt(value, encodedLength, output + *offset, capacity - *offset, &written);
    if (NT_SUCCESS(status))
    {
        *offset += written;
    }
    return status;
}

NTSTATUS WriteBytes(const UCHAR *data, SIZE_T length, UCHAR *output, SIZE_T capacity, SIZE_T *offset) noexcept
{
    if ((data == nullptr && length != 0) || *offset > capacity || length > capacity - *offset)
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
} // namespace

NTSTATUS QuicParseFrame(const UCHAR *data, SIZE_T dataLength, QuicFrame *frame, SIZE_T *bytesConsumed) noexcept
{
    if (frame != nullptr)
        *frame = {};
    if (bytesConsumed != nullptr)
        *bytesConsumed = 0;
    if (data == nullptr || dataLength == 0 || frame == nullptr)
        return STATUS_INVALID_PARAMETER;
    SIZE_T offset = 0;
    NTSTATUS status = ReadValue(data, dataLength, &offset, &frame->WireType);
    if (!NT_SUCCESS(status))
        return status;
    const ULONGLONG type = frame->WireType;

    if (type == 0x00)
        frame->Kind = QuicFrameKind::Padding;
    else if (type == 0x01)
        frame->Kind = QuicFrameKind::Ping;
    else if (type == 0x02 || type == 0x03)
    {
        frame->Kind = QuicFrameKind::Ack;
        status = ReadValue(data, dataLength, &offset, &frame->LargestAcknowledged);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->AckDelay);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->AckRangeCount);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->FirstAckRange);
        if (!NT_SUCCESS(status))
            return status;
        if (frame->AckRangeCount >= WKNET_HARD_MAX_QUIC_ACK_RANGES)
            return STATUS_INVALID_NETWORK_RESPONSE;
        const SIZE_T rangeDataOffset = offset;
        for (ULONGLONG index = 0; index < frame->AckRangeCount; ++index)
        {
            ULONGLONG gap = 0;
            ULONGLONG range = 0;
            status = ReadValue(data, dataLength, &offset, &gap);
            if (NT_SUCCESS(status))
                status = ReadValue(data, dataLength, &offset, &range);
            if (!NT_SUCCESS(status))
                return status;
        }
        frame->AckRangeData = {data + rangeDataOffset, offset - rangeDataOffset};
        if (type == 0x03)
        {
            ULONGLONG ecn = 0;
            for (SIZE_T index = 0; index < 3; ++index)
            {
                status = ReadValue(data, dataLength, &offset, &ecn);
                if (!NT_SUCCESS(status))
                    return status;
            }
        }
    }
    else if (type == 0x04)
    {
        frame->Kind = QuicFrameKind::ResetStream;
        status = ReadValue(data, dataLength, &offset, &frame->StreamId);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->ErrorCode);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->FinalSize);
        if (!NT_SUCCESS(status))
            return status;
    }
    else if (type == 0x05)
    {
        frame->Kind = QuicFrameKind::StopSending;
        status = ReadValue(data, dataLength, &offset, &frame->StreamId);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->ErrorCode);
        if (!NT_SUCCESS(status))
            return status;
    }
    else if (type == 0x06 || type == 0x07)
    {
        frame->Kind = type == 0x06 ? QuicFrameKind::Crypto : QuicFrameKind::NewToken;
        if (type == 0x06)
        {
            status = ReadValue(data, dataLength, &offset, &frame->Offset);
            if (!NT_SUCCESS(status))
                return status;
        }
        status = ReadValue(data, dataLength, &offset, &frame->Length);
        if (!NT_SUCCESS(status) || frame->Length > dataLength ||
            !HasBytes(offset, static_cast<SIZE_T>(frame->Length), dataLength))
        {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        frame->Data = {data + offset, static_cast<SIZE_T>(frame->Length)};
        offset += static_cast<SIZE_T>(frame->Length);
    }
    else if (type >= 0x08 && type <= 0x0f)
    {
        frame->Kind = QuicFrameKind::Stream;
        frame->Fin = (type & 0x01U) != 0;
        status = ReadValue(data, dataLength, &offset, &frame->StreamId);
        if (!NT_SUCCESS(status))
            return status;
        if ((type & 0x04U) != 0)
        {
            status = ReadValue(data, dataLength, &offset, &frame->Offset);
            if (!NT_SUCCESS(status))
                return status;
        }
        if ((type & 0x02U) != 0)
        {
            status = ReadValue(data, dataLength, &offset, &frame->Length);
            if (!NT_SUCCESS(status) || frame->Length > dataLength ||
                !HasBytes(offset, static_cast<SIZE_T>(frame->Length), dataLength))
            {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
        }
        else
            frame->Length = dataLength - offset;
        frame->Data = {data + offset, static_cast<SIZE_T>(frame->Length)};
        offset += static_cast<SIZE_T>(frame->Length);
    }
    else if (type >= 0x10 && type <= 0x17)
    {
        if (type == 0x10)
            frame->Kind = QuicFrameKind::MaxData;
        else if (type == 0x11)
            frame->Kind = QuicFrameKind::MaxStreamData;
        else if (type <= 0x13)
        {
            frame->Kind = QuicFrameKind::MaxStreams;
            frame->Bidirectional = type == 0x12;
        }
        else if (type == 0x14)
            frame->Kind = QuicFrameKind::DataBlocked;
        else if (type == 0x15)
            frame->Kind = QuicFrameKind::StreamDataBlocked;
        else
        {
            frame->Kind = QuicFrameKind::StreamsBlocked;
            frame->Bidirectional = type == 0x16;
        }
        if (type == 0x11 || type == 0x15)
        {
            status = ReadValue(data, dataLength, &offset, &frame->StreamId);
            if (!NT_SUCCESS(status))
                return status;
        }
        status = ReadValue(data, dataLength, &offset, &frame->Maximum);
        if (!NT_SUCCESS(status))
            return status;
    }
    else if (type == 0x18)
    {
        frame->Kind = QuicFrameKind::NewConnectionId;
        status = ReadValue(data, dataLength, &offset, &frame->Sequence);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->RetirePriorTo);
        if (!NT_SUCCESS(status) || frame->RetirePriorTo > frame->Sequence || !HasBytes(offset, 1, dataLength))
        {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        const SIZE_T cidLength = data[offset++];
        if (cidLength == 0 || cidLength > QuicMaximumConnectionIdLength ||
            !HasBytes(offset, cidLength + 16, dataLength))
            return STATUS_INVALID_NETWORK_RESPONSE;
        frame->ConnectionId = {data + offset, cidLength};
        offset += cidLength;
        frame->StatelessResetToken = {data + offset, 16};
        offset += 16;
    }
    else if (type == 0x19)
    {
        frame->Kind = QuicFrameKind::RetireConnectionId;
        status = ReadValue(data, dataLength, &offset, &frame->Sequence);
        if (!NT_SUCCESS(status))
            return status;
    }
    else if (type == 0x1a || type == 0x1b)
    {
        frame->Kind = type == 0x1a ? QuicFrameKind::PathChallenge : QuicFrameKind::PathResponse;
        if (!HasBytes(offset, 8, dataLength))
            return STATUS_BUFFER_TOO_SMALL;
        frame->Data = {data + offset, 8};
        offset += 8;
    }
    else if (type == 0x1c || type == 0x1d)
    {
        frame->Kind = QuicFrameKind::ConnectionClose;
        status = ReadValue(data, dataLength, &offset, &frame->ErrorCode);
        if (NT_SUCCESS(status) && type == 0x1c)
            status = ReadValue(data, dataLength, &offset, &frame->TriggerFrameType);
        if (NT_SUCCESS(status))
            status = ReadValue(data, dataLength, &offset, &frame->Length);
        if (!NT_SUCCESS(status) || frame->Length > dataLength ||
            !HasBytes(offset, static_cast<SIZE_T>(frame->Length), dataLength))
        {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        frame->ReasonPhrase = {data + offset, static_cast<SIZE_T>(frame->Length)};
        offset += static_cast<SIZE_T>(frame->Length);
    }
    else if (type == 0x1e)
        frame->Kind = QuicFrameKind::HandshakeDone;
    else
        return STATUS_NOT_SUPPORTED;

    if (bytesConsumed != nullptr)
        *bytesConsumed = offset;
    return STATUS_SUCCESS;
}

NTSTATUS QuicDecodeAckRanges(const QuicFrame &frame, QuicAckRange *ranges, SIZE_T rangeCapacity,
                             SIZE_T *rangeCount) noexcept
{
    if (rangeCount != nullptr)
    {
        *rangeCount = 0;
    }
    const SIZE_T required = static_cast<SIZE_T>(frame.AckRangeCount) + 1;
    if (frame.Kind != QuicFrameKind::Ack || ranges == nullptr || rangeCount == nullptr || required > rangeCapacity ||
        required > WKNET_HARD_MAX_QUIC_ACK_RANGES || frame.FirstAckRange > frame.LargestAcknowledged)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ranges[0].Largest = frame.LargestAcknowledged;
    ranges[0].Smallest = frame.LargestAcknowledged - frame.FirstAckRange;
    SIZE_T offset = 0;
    for (SIZE_T index = 1; index < required; ++index)
    {
        ULONGLONG gap = 0;
        ULONGLONG rangeLength = 0;
        NTSTATUS status = ReadValue(frame.AckRangeData.Data, frame.AckRangeData.Length, &offset, &gap);
        if (NT_SUCCESS(status))
        {
            status = ReadValue(frame.AckRangeData.Data, frame.AckRangeData.Length, &offset, &rangeLength);
        }
        if (!NT_SUCCESS(status) || ranges[index - 1].Smallest < 2 || gap > ranges[index - 1].Smallest - 2)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ranges[index].Largest = ranges[index - 1].Smallest - gap - 2;
        if (rangeLength > ranges[index].Largest)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ranges[index].Smallest = ranges[index].Largest - rangeLength;
    }
    if (offset != frame.AckRangeData.Length)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    *rangeCount = required;
    return STATUS_SUCCESS;
}

NTSTATUS QuicEncodeFrame(const QuicFrame &frame, const QuicAckRange *ackRanges, SIZE_T ackRangeCount, UCHAR *output,
                         SIZE_T capacity, SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (output == nullptr || bytesWritten == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T offset = 0;
    NTSTATUS status = STATUS_SUCCESS;
    switch (frame.Kind)
    {
    case QuicFrameKind::Padding:
    {
        const SIZE_T paddingLength = frame.Length == 0 ? 1 : static_cast<SIZE_T>(frame.Length);
        if (paddingLength > capacity)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlZeroMemory(output, paddingLength);
        offset = paddingLength;
        break;
    }
    case QuicFrameKind::Ping:
        status = WriteValue(0x01, output, capacity, &offset);
        break;
    case QuicFrameKind::Ack:
        if (ackRanges == nullptr || ackRangeCount == 0 || ackRangeCount > WKNET_HARD_MAX_QUIC_ACK_RANGES)
        {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T index = 0; index < ackRangeCount; ++index)
        {
            if (ackRanges[index].Smallest > ackRanges[index].Largest ||
                (index != 0 &&
                 (ackRanges[index - 1].Smallest < 2 || ackRanges[index].Largest > ackRanges[index - 1].Smallest - 2)))
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
        status = WriteValue(0x02, output, capacity, &offset);
        if (NT_SUCCESS(status))
        {
            status = WriteValue(ackRanges[0].Largest, output, capacity, &offset);
        }
        if (NT_SUCCESS(status))
        {
            status = WriteValue(frame.AckDelay, output, capacity, &offset);
        }
        if (NT_SUCCESS(status))
        {
            status = WriteValue(ackRangeCount - 1, output, capacity, &offset);
        }
        if (NT_SUCCESS(status))
        {
            status = WriteValue(ackRanges[0].Largest - ackRanges[0].Smallest, output, capacity, &offset);
        }
        for (SIZE_T index = 1; NT_SUCCESS(status) && index < ackRangeCount; ++index)
        {
            const ULONGLONG gap = ackRanges[index - 1].Smallest - ackRanges[index].Largest - 2;
            status = WriteValue(gap, output, capacity, &offset);
            if (NT_SUCCESS(status))
            {
                status = WriteValue(ackRanges[index].Largest - ackRanges[index].Smallest, output, capacity, &offset);
            }
        }
        break;
    case QuicFrameKind::ResetStream:
        status = WriteValue(0x04, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.StreamId, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.ErrorCode, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.FinalSize, output, capacity, &offset);
        break;
    case QuicFrameKind::StopSending:
        status = WriteValue(0x05, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.StreamId, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.ErrorCode, output, capacity, &offset);
        break;
    case QuicFrameKind::Crypto:
    case QuicFrameKind::NewToken:
        status = WriteValue(frame.Kind == QuicFrameKind::Crypto ? 0x06 : 0x07, output, capacity, &offset);
        if (NT_SUCCESS(status) && frame.Kind == QuicFrameKind::Crypto)
            status = WriteValue(frame.Offset, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.Data.Length, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteBytes(frame.Data.Data, frame.Data.Length, output, capacity, &offset);
        break;
    case QuicFrameKind::Stream:
    {
        const ULONGLONG wireType = 0x0e | (frame.Fin ? 1ULL : 0ULL);
        status = WriteValue(wireType, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.StreamId, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.Offset, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.Data.Length, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteBytes(frame.Data.Data, frame.Data.Length, output, capacity, &offset);
        break;
    }
    case QuicFrameKind::MaxData:
    case QuicFrameKind::MaxStreamData:
    case QuicFrameKind::MaxStreams:
    case QuicFrameKind::DataBlocked:
    case QuicFrameKind::StreamDataBlocked:
    case QuicFrameKind::StreamsBlocked:
    {
        ULONGLONG wireType = 0;
        if (frame.Kind == QuicFrameKind::MaxData)
            wireType = 0x10;
        else if (frame.Kind == QuicFrameKind::MaxStreamData)
            wireType = 0x11;
        else if (frame.Kind == QuicFrameKind::MaxStreams)
            wireType = frame.Bidirectional ? 0x12 : 0x13;
        else if (frame.Kind == QuicFrameKind::DataBlocked)
            wireType = 0x14;
        else if (frame.Kind == QuicFrameKind::StreamDataBlocked)
            wireType = 0x15;
        else
            wireType = frame.Bidirectional ? 0x16 : 0x17;
        status = WriteValue(wireType, output, capacity, &offset);
        if (NT_SUCCESS(status) &&
            (frame.Kind == QuicFrameKind::MaxStreamData || frame.Kind == QuicFrameKind::StreamDataBlocked))
            status = WriteValue(frame.StreamId, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.Maximum, output, capacity, &offset);
        break;
    }
    case QuicFrameKind::NewConnectionId:
        if (frame.ConnectionId.Data == nullptr || frame.ConnectionId.Length == 0 ||
            frame.ConnectionId.Length > QuicMaximumConnectionIdLength || frame.StatelessResetToken.Length != 16 ||
            frame.RetirePriorTo > frame.Sequence)
            return STATUS_INVALID_PARAMETER;
        status = WriteValue(0x18, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.Sequence, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.RetirePriorTo, output, capacity, &offset);
        if (NT_SUCCESS(status))
        {
            if (offset >= capacity)
                status = STATUS_BUFFER_TOO_SMALL;
            else
                output[offset++] = static_cast<UCHAR>(frame.ConnectionId.Length);
        }
        if (NT_SUCCESS(status))
            status = WriteBytes(frame.ConnectionId.Data, frame.ConnectionId.Length, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status =
                WriteBytes(frame.StatelessResetToken.Data, frame.StatelessResetToken.Length, output, capacity, &offset);
        break;
    case QuicFrameKind::RetireConnectionId:
        status = WriteValue(0x19, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.Sequence, output, capacity, &offset);
        break;
    case QuicFrameKind::PathChallenge:
    case QuicFrameKind::PathResponse:
        if (frame.Data.Length != 8)
            return STATUS_INVALID_PARAMETER;
        status = WriteValue(frame.Kind == QuicFrameKind::PathChallenge ? 0x1a : 0x1b, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteBytes(frame.Data.Data, frame.Data.Length, output, capacity, &offset);
        break;
    case QuicFrameKind::ConnectionClose:
        status = WriteValue(0x1c, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.ErrorCode, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.TriggerFrameType, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteValue(frame.ReasonPhrase.Length, output, capacity, &offset);
        if (NT_SUCCESS(status))
            status = WriteBytes(frame.ReasonPhrase.Data, frame.ReasonPhrase.Length, output, capacity, &offset);
        break;
    case QuicFrameKind::HandshakeDone:
        status = WriteValue(0x1e, output, capacity, &offset);
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }
    if (NT_SUCCESS(status))
    {
        *bytesWritten = offset;
    }
    return status;
}
} // namespace wknet::quic
