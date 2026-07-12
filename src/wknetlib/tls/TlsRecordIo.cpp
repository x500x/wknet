#include "tls/TlsConnectionInternal.hpp"

namespace wknet
{
namespace tls
{
    NTSTATUS TlsConnection::SendPlainRecord(
        core::ITransport& transport,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        return SendPlainRecordWithVersion(transport, context_.Version(), contentType, fragment, fragmentLength);
    }

    NTSTATUS TlsConnection::SendPlainRecordWithVersion(
        core::ITransport& transport,
        TlsProtocolVersion version,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = version;
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;

        NTSTATUS status = TlsRecordLayer::EncodePlaintext(record, outputBuffer_, TlsIoBufferLength, &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(transport, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        return status;
    }

    NTSTATUS TlsConnection::SendProtectedRecord(
        core::ITransport& transport,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = context_.Version();
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;

        NTSTATUS status = clientWriteState_.EncryptThenMac ?
            TlsRecordLayer::ProtectAesCbcEncryptThenMac(
                record,
                clientWriteState_,
                outputBuffer_,
                TlsIoBufferLength,
                &written) :
            TlsRecordLayer::ProtectAesGcm(record, clientWriteState_, outputBuffer_, TlsIoBufferLength, &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(transport, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        return status;
    }

    NTSTATUS TlsConnection::SendPendingTls13KeyUpdate(core::ITransport& transport) noexcept
    {
        if (ExchangeTlsFlag(&tls13PeerRequestedKeyUpdate_, 0) == 0) {
            return STATUS_SUCCESS;
        }

        SIZE_T messageLength = 0;
        NTSTATUS status = TlsHandshake13::EncodeKeyUpdate(
            Tls13KeyUpdateRequest::UpdateNotRequested,
            tls13KeyUpdateMessage_,
            sizeof(tls13KeyUpdateMessage_),
            &messageLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendProtectedRecord13(transport, TlsContentType::Handshake, tls13KeyUpdateMessage_, messageLength);
        RtlSecureZeroMemory(tls13KeyUpdateMessage_, sizeof(tls13KeyUpdateMessage_));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return context_.UpdateTls13ApplicationTrafficSecret(true, clientWriteState_);
    }

    NTSTATUS TlsConnection::SendProtectedRecord13(
        core::ITransport& transport,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = { 3, 3 };
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;
        record.Tls13PaddingLength = tls13RecordPaddingLength_;

        if (tls13InnerPlaintextBuffer_ == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13WithScratch(
            record,
            clientWriteState_,
            tls13InnerPlaintextBuffer_,
            TlsMaxPlaintextLength + 1,
            outputBuffer_,
            TlsIoBufferLength,
            &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(transport, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        return status;
    }

    NTSTATUS TlsConnection::ReadRecord(
        core::ITransport& transport,
        TlsMutablePlaintextRecord& record,
        ULONG receiveTimeoutMilliseconds,
        const TlsReceiveDeadline* receiveDeadline) noexcept
    {
        record = {};

        for (;;) {
            TlsRecordView view = {};
            NTSTATUS status = TlsRecordLayer::Parse(inputBuffer_, inputLength_, view);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (inputLength_ < TlsRecordHeaderLength) {
                    status = ReadExact(
                        transport,
                        inputBuffer_ + inputLength_,
                        TlsRecordHeaderLength - inputLength_,
                        receiveTimeoutMilliseconds,
                        receiveDeadline);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    inputLength_ = TlsRecordHeaderLength;
                    continue;
                }

                const SIZE_T fragmentLength =
                    (static_cast<SIZE_T>(inputBuffer_[3]) << 8) | inputBuffer_[4];
                if (fragmentLength > TlsMaxPlaintextLength + 2048) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T recordLength = TlsRecordHeaderLength + fragmentLength;
                if (recordLength > TlsIoBufferLength) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                status = RecordReceivedTlsRecord(recordLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = ReadExact(
                    transport,
                    inputBuffer_ + inputLength_,
                    recordLength - inputLength_,
                    receiveTimeoutMilliseconds,
                    receiveDeadline);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                inputLength_ = recordLength;
                continue;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (encrypted_ &&
                !(tls13RecordProtection_ && view.ContentType == TlsContentType::ChangeCipherSpec)) {
                if (tls13RecordProtection_) {
                    status = TlsRecordLayer::UnprotectAesGcm13(
                        view,
                        serverWriteState_,
                        plaintextBuffer_,
                        TlsApplicationBufferLength,
                        record);
                }
                else if (serverWriteState_.EncryptThenMac) {
                    status = TlsRecordLayer::UnprotectAesCbcEncryptThenMac(
                        view,
                        serverWriteState_,
                        plaintextBuffer_,
                        TlsApplicationBufferLength,
                        record);
                }
                else {
                    status = TlsRecordLayer::UnprotectAesGcm(
                        view,
                        serverWriteState_,
                        plaintextBuffer_,
                        TlsApplicationBufferLength,
                        record);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                plaintextLength_ = 0;
            }
            else {
                if (view.FragmentLength > TlsMaxPlaintextLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (view.FragmentLength > TlsApplicationBufferLength) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                record.ContentType = view.ContentType;
                record.Version = view.Version;
                record.FragmentLength = view.FragmentLength;

                if (view.FragmentLength != 0) {
                    RtlCopyMemory(plaintextBuffer_, view.Fragment, view.FragmentLength);
                }

                record.Fragment = plaintextBuffer_;
                plaintextLength_ = 0;
            }

            const SIZE_T consumed = view.BytesConsumed;
            if (consumed < inputLength_) {
                RtlMoveMemory(inputBuffer_, inputBuffer_ + consumed, inputLength_ - consumed);
            }

            inputLength_ -= consumed;
            if (record.ContentType == TlsContentType::Alert) {
                RecordPeerAlertFailure(record);
            }
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS TlsConnection::RecordReceivedTlsRecord(SIZE_T recordLength) noexcept
    {
        const ULONGLONG recordBytes = static_cast<ULONGLONG>(recordLength);
        if (tlsConnectionRecordsRead_ >= WKNET_HARD_MAX_CONNECTION_FRAMES ||
            (WKNET_HARD_MAX_CONNECTION_BYTES != 0 &&
                (recordBytes > WKNET_HARD_MAX_CONNECTION_BYTES ||
                    tlsConnectionBytesRead_ > WKNET_HARD_MAX_CONNECTION_BYTES - recordBytes))) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ++tlsConnectionRecordsRead_;
        tlsConnectionBytesRead_ += recordBytes;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::ReadServerChangeCipherSpec(
        core::ITransport& transport,
        bool allowNewSessionTicket) noexcept
    {
        ULONG recordsRead = 0;
        for (;;) {
            if (++recordsRead > TlsHandshakeMaxRecords) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            TlsMutablePlaintextRecord record = {};
            NTSTATUS status = ReadRecord(
                transport,
                record,
                handshakeReceiveTimeoutMilliseconds_,
                &handshakeReceiveDeadline_);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection ReadServerChangeCipherSpec ReadRecord failed: 0x%08X\r\n",
                    static_cast<ULONG>(status));
                return status;
            }

            if (record.ContentType == TlsContentType::Alert) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Warning, "TlsConnection ReadServerChangeCipherSpec alert length=%Iu\r\n", record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (record.ContentType == TlsContentType::ChangeCipherSpec) {
                if (handshakeLength_ != 0 ||
                    handshakeConsumed_ != 0 ||
                    record.FragmentLength != 1 ||
                    record.Fragment == nullptr ||
                    record.Fragment[0] != 1) {
                    WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection invalid server ChangeCipherSpec len=%Iu hs=%Iu consumed=%Iu\r\n",
                        record.FragmentLength,
                        handshakeLength_,
                        handshakeConsumed_);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                return STATUS_SUCCESS;
            }

            if (record.ContentType != TlsContentType::Handshake) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection expected ChangeCipherSpec got type=%u length=%Iu\r\n",
                    static_cast<unsigned>(record.ContentType),
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!allowNewSessionTicket) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Warning, "TlsConnection got unnegotiated handshake before ChangeCipherSpec length=%Iu\r\n",
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = ConsumeOptionalPlainHandshakeRecord(record.Fragment, record.FragmentLength);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection consume NewSessionTicket failed: 0x%08X length=%Iu\r\n",
                    static_cast<ULONG>(status),
                    record.FragmentLength);
                return status;
            }
        }
    }

    NTSTATUS TlsConnection::ReadOptionalCompatibilityChangeCipherSpec(core::ITransport& transport) noexcept
    {
        TlsRecordView view = {};
        NTSTATUS status = TlsRecordLayer::Parse(inputBuffer_, inputLength_, view);
        if (status == STATUS_MORE_PROCESSING_REQUIRED) {
            if (inputLength_ < TlsRecordHeaderLength) {
                status = ReadExact(
                    transport,
                    inputBuffer_ + inputLength_,
                    TlsRecordHeaderLength - inputLength_,
                    handshakeReceiveTimeoutMilliseconds_,
                    &handshakeReceiveDeadline_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                inputLength_ = TlsRecordHeaderLength;
            }

            const SIZE_T fragmentLength =
                (static_cast<SIZE_T>(inputBuffer_[3]) << 8) | inputBuffer_[4];
            const SIZE_T recordLength = TlsRecordHeaderLength + fragmentLength;
            if (recordLength > TlsIoBufferLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            status = ReadExact(
                transport,
                inputBuffer_ + inputLength_,
                recordLength - inputLength_,
                handshakeReceiveTimeoutMilliseconds_,
                &handshakeReceiveDeadline_);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            inputLength_ = recordLength;
            status = TlsRecordLayer::Parse(inputBuffer_, inputLength_, view);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (view.ContentType != TlsContentType::ChangeCipherSpec) {
            return STATUS_SUCCESS;
        }

        if (view.FragmentLength != 1 || view.Fragment == nullptr || view.Fragment[0] != 1) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T consumed = view.BytesConsumed;
        if (consumed < inputLength_) {
            RtlMoveMemory(inputBuffer_, inputBuffer_ + consumed, inputLength_ - consumed);
        }
        inputLength_ -= consumed;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::ConsumeOptionalPlainHandshakeRecord(const UCHAR* fragment, SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr ||
            fragmentLength == 0 ||
            fragmentLength > TlsHandshakeBufferLength - handshakeLength_) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (fragmentLength != 0) {
            RtlCopyMemory(handshakeBuffer_ + handshakeLength_, fragment, fragmentLength);
            handshakeLength_ += fragmentLength;
        }

        SIZE_T messageCount = 0;
        for (;;) {
            TlsHandshakeMessageView parsed = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                handshakeBuffer_ + handshakeConsumed_,
                handshakeLength_ - handshakeConsumed_,
                parsed);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (handshakeConsumed_ != 0) {
                    if (handshakeConsumed_ < handshakeLength_) {
                        RtlMoveMemory(
                            handshakeBuffer_,
                            handshakeBuffer_ + handshakeConsumed_,
                            handshakeLength_ - handshakeConsumed_);
                    }

                    handshakeLength_ -= handshakeConsumed_;
                    handshakeConsumed_ = 0;
                }

                return STATUS_SUCCESS;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (++messageCount > TlsMaxPostHandshakeMessagesPerRecord) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            Tls12NewSessionTicketView ticket = {};
            status = TlsHandshake12::ParseNewSessionTicket(parsed, ticket);
            if (!NT_SUCCESS(status)) {
                if (status == STATUS_NOT_SUPPORTED) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                return status;
            }
            if (ticket.Ticket != nullptr &&
                ticket.TicketLength != 0 &&
                ticket.TicketLength <= Tls12MaxTicketLength) {
                RtlSecureZeroMemory(tls12PendingTicket_, sizeof(tls12PendingTicket_));
                RtlCopyMemory(tls12PendingTicket_, ticket.Ticket, ticket.TicketLength);
                tls12PendingTicketLength_ = ticket.TicketLength;
                tls12PendingTicketLifetimeHintSeconds_ = ticket.LifetimeHintSeconds;
            }

            // TLS 1.2 NewSessionTicket is sent before ChangeCipherSpec and remains
            // part of the handshake transcript used by Finished.
            status = AppendTranscript(handshakeBuffer_ + handshakeConsumed_, parsed.BytesConsumed);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            handshakeConsumed_ += parsed.BytesConsumed;
            if (handshakeConsumed_ == handshakeLength_) {
                handshakeLength_ = 0;
                handshakeConsumed_ = 0;
                return STATUS_SUCCESS;
            }
        }
    }

    NTSTATUS TlsConnection::ReadHandshakeMessage(
        core::ITransport& transport,
        TlsHandshakeMessageView& message,
        bool updateTranscript) noexcept
    {
        message = {};
        lastHandshakeLength_ = 0;
        lastHandshakeOffset_ = handshakeConsumed_;
        ULONG recordsRead = 0;

        for (;;) {
            TlsHandshakeMessageView parsed = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                handshakeBuffer_ + handshakeConsumed_,
                handshakeLength_ - handshakeConsumed_,
                parsed);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (handshakeConsumed_ != 0) {
                    if (handshakeConsumed_ < handshakeLength_) {
                        RtlMoveMemory(
                            handshakeBuffer_,
                            handshakeBuffer_ + handshakeConsumed_,
                            handshakeLength_ - handshakeConsumed_);
                    }

                    handshakeLength_ -= handshakeConsumed_;
                    handshakeConsumed_ = 0;
                }

                TlsMutablePlaintextRecord record = {};
                if (++recordsRead > TlsHandshakeMaxRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                status = ReadRecord(
                    transport,
                    record,
                    handshakeReceiveTimeoutMilliseconds_,
                    &handshakeReceiveDeadline_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (record.ContentType == TlsContentType::Alert) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (record.ContentType != TlsContentType::Handshake ||
                    record.FragmentLength > (TlsHandshakeBufferLength - handshakeLength_)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                RtlCopyMemory(handshakeBuffer_ + handshakeLength_, record.Fragment, record.FragmentLength);
                handshakeLength_ += record.FragmentLength;
                continue;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (updateTranscript) {
                status = AppendTranscript(handshakeBuffer_ + handshakeConsumed_, parsed.BytesConsumed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            lastHandshakeOffset_ = handshakeConsumed_;
            lastHandshakeLength_ = parsed.BytesConsumed;
            message = parsed;
            handshakeConsumed_ += parsed.BytesConsumed;
            if (handshakeConsumed_ == handshakeLength_) {
                handshakeLength_ = 0;
                handshakeConsumed_ = 0;
            }

            return STATUS_SUCCESS;
        }
    }
}
}
