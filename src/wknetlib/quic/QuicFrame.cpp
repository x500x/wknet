#include "quic/QuicFrame.h"
#include "quic/QuicVarInt.h"

namespace wknet::quic {
    namespace
    {
        NTSTATUS ReadValue(const UCHAR* data, SIZE_T length, SIZE_T* offset, ULONGLONG* value) noexcept
        {
            if (*offset > length) return STATUS_INVALID_NETWORK_RESPONSE;
            SIZE_T consumed = 0;
            const NTSTATUS status = QuicDecodeVarInt(data + *offset, length - *offset, value, &consumed);
            if (!NT_SUCCESS(status)) return status;
            *offset += consumed;
            return STATUS_SUCCESS;
        }

        bool HasBytes(SIZE_T offset, SIZE_T count, SIZE_T length) noexcept
        {
            return offset <= length && count <= length - offset;
        }
    }

    NTSTATUS QuicParseFrame(
        const UCHAR* data,
        SIZE_T dataLength,
        QuicFrame* frame,
        SIZE_T* bytesConsumed) noexcept
    {
        if (frame != nullptr) *frame = {};
        if (bytesConsumed != nullptr) *bytesConsumed = 0;
        if (data == nullptr || dataLength == 0 || frame == nullptr) return STATUS_INVALID_PARAMETER;
        SIZE_T offset = 0;
        NTSTATUS status = ReadValue(data, dataLength, &offset, &frame->WireType);
        if (!NT_SUCCESS(status)) return status;
        const ULONGLONG type = frame->WireType;

        if (type == 0x00) frame->Kind = QuicFrameKind::Padding;
        else if (type == 0x01) frame->Kind = QuicFrameKind::Ping;
        else if (type == 0x02 || type == 0x03) {
            frame->Kind = QuicFrameKind::Ack;
            status = ReadValue(data, dataLength, &offset, &frame->LargestAcknowledged);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->AckDelay);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->AckRangeCount);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->FirstAckRange);
            if (!NT_SUCCESS(status)) return status;
            if (frame->AckRangeCount > WKNET_HARD_MAX_QUIC_ACK_RANGES) return STATUS_INVALID_NETWORK_RESPONSE;
            for (ULONGLONG index = 0; index < frame->AckRangeCount; ++index) {
                ULONGLONG gap = 0;
                ULONGLONG range = 0;
                status = ReadValue(data, dataLength, &offset, &gap);
                if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &range);
                if (!NT_SUCCESS(status)) return status;
            }
            if (type == 0x03) {
                ULONGLONG ecn = 0;
                for (SIZE_T index = 0; index < 3; ++index) {
                    status = ReadValue(data, dataLength, &offset, &ecn);
                    if (!NT_SUCCESS(status)) return status;
                }
            }
        }
        else if (type == 0x04) {
            frame->Kind = QuicFrameKind::ResetStream;
            status = ReadValue(data, dataLength, &offset, &frame->StreamId);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->ErrorCode);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->FinalSize);
            if (!NT_SUCCESS(status)) return status;
        }
        else if (type == 0x05) {
            frame->Kind = QuicFrameKind::StopSending;
            status = ReadValue(data, dataLength, &offset, &frame->StreamId);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->ErrorCode);
            if (!NT_SUCCESS(status)) return status;
        }
        else if (type == 0x06 || type == 0x07) {
            frame->Kind = type == 0x06 ? QuicFrameKind::Crypto : QuicFrameKind::NewToken;
            if (type == 0x06) {
                status = ReadValue(data, dataLength, &offset, &frame->Offset);
                if (!NT_SUCCESS(status)) return status;
            }
            status = ReadValue(data, dataLength, &offset, &frame->Length);
            if (!NT_SUCCESS(status) || frame->Length > dataLength ||
                !HasBytes(offset, static_cast<SIZE_T>(frame->Length), dataLength)) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            frame->Data = { data + offset, static_cast<SIZE_T>(frame->Length) };
            offset += static_cast<SIZE_T>(frame->Length);
        }
        else if (type >= 0x08 && type <= 0x0f) {
            frame->Kind = QuicFrameKind::Stream;
            frame->Fin = (type & 0x01U) != 0;
            status = ReadValue(data, dataLength, &offset, &frame->StreamId);
            if (!NT_SUCCESS(status)) return status;
            if ((type & 0x04U) != 0) {
                status = ReadValue(data, dataLength, &offset, &frame->Offset);
                if (!NT_SUCCESS(status)) return status;
            }
            if ((type & 0x02U) != 0) {
                status = ReadValue(data, dataLength, &offset, &frame->Length);
                if (!NT_SUCCESS(status) || frame->Length > dataLength ||
                    !HasBytes(offset, static_cast<SIZE_T>(frame->Length), dataLength)) {
                    return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
                }
            }
            else frame->Length = dataLength - offset;
            frame->Data = { data + offset, static_cast<SIZE_T>(frame->Length) };
            offset += static_cast<SIZE_T>(frame->Length);
        }
        else if (type >= 0x10 && type <= 0x17) {
            if (type == 0x10) frame->Kind = QuicFrameKind::MaxData;
            else if (type == 0x11) frame->Kind = QuicFrameKind::MaxStreamData;
            else if (type <= 0x13) { frame->Kind = QuicFrameKind::MaxStreams; frame->Bidirectional = type == 0x12; }
            else if (type == 0x14) frame->Kind = QuicFrameKind::DataBlocked;
            else if (type == 0x15) frame->Kind = QuicFrameKind::StreamDataBlocked;
            else { frame->Kind = QuicFrameKind::StreamsBlocked; frame->Bidirectional = type == 0x16; }
            if (type == 0x11 || type == 0x15) {
                status = ReadValue(data, dataLength, &offset, &frame->StreamId);
                if (!NT_SUCCESS(status)) return status;
            }
            status = ReadValue(data, dataLength, &offset, &frame->Maximum);
            if (!NT_SUCCESS(status)) return status;
        }
        else if (type == 0x18) {
            frame->Kind = QuicFrameKind::NewConnectionId;
            status = ReadValue(data, dataLength, &offset, &frame->Sequence);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->RetirePriorTo);
            if (!NT_SUCCESS(status) || frame->RetirePriorTo > frame->Sequence || !HasBytes(offset, 1, dataLength)) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            const SIZE_T cidLength = data[offset++];
            if (cidLength == 0 || cidLength > QuicMaximumConnectionIdLength ||
                !HasBytes(offset, cidLength + 16, dataLength)) return STATUS_INVALID_NETWORK_RESPONSE;
            frame->ConnectionId = { data + offset, cidLength };
            offset += cidLength;
            frame->StatelessResetToken = { data + offset, 16 };
            offset += 16;
        }
        else if (type == 0x19) {
            frame->Kind = QuicFrameKind::RetireConnectionId;
            status = ReadValue(data, dataLength, &offset, &frame->Sequence);
            if (!NT_SUCCESS(status)) return status;
        }
        else if (type == 0x1a || type == 0x1b) {
            frame->Kind = type == 0x1a ? QuicFrameKind::PathChallenge : QuicFrameKind::PathResponse;
            if (!HasBytes(offset, 8, dataLength)) return STATUS_BUFFER_TOO_SMALL;
            frame->Data = { data + offset, 8 };
            offset += 8;
        }
        else if (type == 0x1c || type == 0x1d) {
            frame->Kind = QuicFrameKind::ConnectionClose;
            status = ReadValue(data, dataLength, &offset, &frame->ErrorCode);
            if (NT_SUCCESS(status) && type == 0x1c) status = ReadValue(data, dataLength, &offset, &frame->TriggerFrameType);
            if (NT_SUCCESS(status)) status = ReadValue(data, dataLength, &offset, &frame->Length);
            if (!NT_SUCCESS(status) || frame->Length > dataLength ||
                !HasBytes(offset, static_cast<SIZE_T>(frame->Length), dataLength)) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            frame->ReasonPhrase = { data + offset, static_cast<SIZE_T>(frame->Length) };
            offset += static_cast<SIZE_T>(frame->Length);
        }
        else if (type == 0x1e) frame->Kind = QuicFrameKind::HandshakeDone;
        else return STATUS_NOT_SUPPORTED;

        if (bytesConsumed != nullptr) *bytesConsumed = offset;
        return STATUS_SUCCESS;
    }
}
