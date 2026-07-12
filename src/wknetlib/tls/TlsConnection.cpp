#include "tls/TlsConnectionInternal.hpp"

namespace wknet
{
namespace tls
{
    TlsConnection::~TlsConnection() noexcept
    {
        Reset();
        FreeNonPagedArray(inputBuffer_);
        FreeNonPagedArray(outputBuffer_);
        FreeNonPagedArray(tls13InnerPlaintextBuffer_);
        FreeNonPagedArray(plaintextBuffer_);
        FreeNonPagedArray(negotiatedAlpn_);
        inputBuffer_ = nullptr;
        outputBuffer_ = nullptr;
        tls13InnerPlaintextBuffer_ = nullptr;
        plaintextBuffer_ = nullptr;
        handshakeBuffer_ = nullptr;
        negotiatedAlpn_ = nullptr;
    }

    void TlsConnection::Reset() noexcept
    {
        context_.Reset();
        clientWriteState_.Reset();
        serverWriteState_.Reset();
        tls12PendingClientWriteState_.Reset();
        tls12PendingServerWriteState_.Reset();
        transcript_.Reset();
        if (inputBuffer_ != nullptr) {
            RtlSecureZeroMemory(inputBuffer_, TlsIoBufferLength);
        }
        if (outputBuffer_ != nullptr) {
            RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        }
        if (tls13InnerPlaintextBuffer_ != nullptr) {
            RtlSecureZeroMemory(tls13InnerPlaintextBuffer_, TlsMaxPlaintextLength + 1);
        }
        if (plaintextBuffer_ != nullptr) {
            RtlSecureZeroMemory(plaintextBuffer_, TlsApplicationBufferLength);
        }
        if (handshakeBuffer_ != nullptr) {
            RtlSecureZeroMemory(handshakeBuffer_, TlsScratchHandshakeBufferLength);
        }
        ReleaseHandshakeScratch();
        certificateScratchAllocator_ = nullptr;
        providerCache_ = nullptr;
        inputLength_ = 0;
        plaintextLength_ = 0;
        tlsConnectionBytesRead_ = 0;
        tlsConnectionRecordsRead_ = 0;
        handshakeBuffer_ = nullptr;
        handshakeLength_ = 0;
        handshakeConsumed_ = 0;
        lastHandshakeOffset_ = 0;
        lastHandshakeLength_ = 0;
        handshakeReceiveTimeoutMilliseconds_ = TlsHandshakeReceiveTimeoutMilliseconds;
        handshakeReceiveDeadline_ = {};
        encrypted_ = false;
        tls13RecordProtection_ = false;
        tls13RecordPaddingLength_ = 0;
        tls13PostHandshakeClientAuthAllowed_ = false;
        ExchangeTlsFlag(&tls13PeerRequestedKeyUpdate_, 0);
        clientCredential_ = nullptr;
        tls12SessionCache_ = nullptr;
        tls13ExternalSessionCache_ = nullptr;
        tls12RenegotiationOptions_ = {};
        tlsPolicy_ = {};
        tlsPolicyIdentity_ = 0;
        tls12MaxRenegotiations_ = Tls12DefaultMaxRenegotiations;
        tls12RenegotiationCount_ = 0;
        tls12Renegotiating_ = false;
        RtlSecureZeroMemory(tls12LastClientVerifyData_, sizeof(tls12LastClientVerifyData_));
        tls12LastClientVerifyDataLength_ = 0;
        RtlSecureZeroMemory(tls12LastServerVerifyData_, sizeof(tls12LastServerVerifyData_));
        tls12LastServerVerifyDataLength_ = 0;
        serverCertificatePublicKeyAlgorithm_ = CertificatePublicKeyAlgorithm::Unknown;
        RtlSecureZeroMemory(serverEd25519PublicKey_, sizeof(serverEd25519PublicKey_));
        serverEd25519PublicKeyLength_ = 0;
        RtlSecureZeroMemory(serverEd448PublicKey_, sizeof(serverEd448PublicKey_));
        serverEd448PublicKeyLength_ = 0;
        if (tlsKeyBlockScratch_.IsValid()) {
            RtlSecureZeroMemory(tlsKeyBlockScratch_.Get(), sizeof(TlsKeyBlock));
        }
        if (tls12SessionScratch_.IsValid()) {
            RtlSecureZeroMemory(tls12SessionScratch_.Get(), sizeof(Tls12Session));
        }
        if (tls13SessionTicketScratch_.IsValid()) {
            RtlSecureZeroMemory(tls13SessionTicketScratch_.Get(), sizeof(Tls13SessionTicket));
        }
        RtlSecureZeroMemory(tls12PendingTicket_, sizeof(tls12PendingTicket_));
        tls12PendingTicketLength_ = 0;
        tls12PendingTicketLifetimeHintSeconds_ = 0;
        RtlSecureZeroMemory(tls13TicketServerName_, sizeof(tls13TicketServerName_));
        tls13TicketServerNameLength_ = 0;
        tls13TicketServerNameCacheable_ = false;
        if (negotiatedAlpn_ != nullptr) {
            RtlSecureZeroMemory(negotiatedAlpn_, 16);
        }
        negotiatedAlpnLength_ = 0;
        ClearHandshakeFailure();
    }

    NTSTATUS TlsConnection::EnsureBuffers() noexcept
    {
        if (inputBuffer_ == nullptr) {
            inputBuffer_ = AllocateNonPagedArray<UCHAR>(TlsIoBufferLength);
            if (inputBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (outputBuffer_ == nullptr) {
            outputBuffer_ = AllocateNonPagedArray<UCHAR>(TlsIoBufferLength);
            if (outputBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (tls13InnerPlaintextBuffer_ == nullptr) {
            tls13InnerPlaintextBuffer_ = AllocateNonPagedArray<UCHAR>(TlsMaxPlaintextLength + 1);
            if (tls13InnerPlaintextBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (plaintextBuffer_ == nullptr) {
            plaintextBuffer_ = AllocateNonPagedArray<UCHAR>(TlsApplicationBufferLength);
            if (plaintextBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (handshakeBuffer_ == nullptr) {
            NTSTATUS status = GetHandshakeScratch(
                TlsScratchHandshakeBufferOffset,
                TlsScratchHandshakeBufferLength,
                &handshakeBuffer_);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            RtlSecureZeroMemory(handshakeBuffer_, TlsScratchHandshakeBufferLength);
        }
        if (negotiatedAlpn_ == nullptr) {
            negotiatedAlpn_ = AllocateNonPagedArray<char>(16);
            if (negotiatedAlpn_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::PrepareScratch(const TlsClientConnectionOptions& options) noexcept
    {
        ReleaseHandshakeScratch();

        handshakeScratchAllocator_ = options.HandshakeScratchAllocator;
        certificateScratchAllocator_ = options.CertificateScratchAllocator;
        providerCache_ = options.ProviderCache;

        if (handshakeScratchAllocator_ != nullptr) {
            void* buffer = nullptr;
            const NTSTATUS status = handshakeScratchAllocator_->Acquire(
                TlsScratchRequiredLength,
                &buffer);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            handshakeScratch_ = static_cast<UCHAR*>(buffer);
            handshakeScratchLength_ = TlsScratchRequiredLength;
            RtlSecureZeroMemory(handshakeScratch_, handshakeScratchLength_);
            return STATUS_SUCCESS;
        }

        if (ownedTlsScratch_ == nullptr || ownedTlsScratchLength_ < TlsScratchRequiredLength) {
            if (ownedTlsScratch_ != nullptr) {
                RtlSecureZeroMemory(ownedTlsScratch_, ownedTlsScratchLength_);
                FreeNonPagedArray(ownedTlsScratch_);
                ownedTlsScratch_ = nullptr;
                ownedTlsScratchLength_ = 0;
            }

            ownedTlsScratch_ = AllocateNonPagedArray<UCHAR>(TlsScratchRequiredLength);
            if (ownedTlsScratch_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ownedTlsScratchLength_ = TlsScratchRequiredLength;
        }

        RtlSecureZeroMemory(ownedTlsScratch_, ownedTlsScratchLength_);
        handshakeScratch_ = ownedTlsScratch_;
        handshakeScratchLength_ = ownedTlsScratchLength_;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::GetHandshakeScratch(
        SIZE_T offset,
        SIZE_T length,
        UCHAR** buffer) noexcept
    {
        if (buffer != nullptr) {
            *buffer = nullptr;
        }

        if (buffer == nullptr || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        UCHAR* base = handshakeScratch_;
        SIZE_T capacity = handshakeScratchLength_;

        if (base == nullptr || offset > capacity || length > capacity - offset) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        *buffer = base + offset;
        return STATUS_SUCCESS;
    }

    void TlsConnection::ReleaseHandshakeScratch() noexcept
    {
        if (handshakeScratch_ != nullptr && handshakeScratchLength_ != 0) {
            RtlSecureZeroMemory(handshakeScratch_, handshakeScratchLength_);
        }

        if (handshakeScratchAllocator_ != nullptr && handshakeScratch_ != nullptr) {
            handshakeScratchAllocator_->Release(handshakeScratch_);
        }

        if (ownedTlsScratch_ != nullptr) {
            RtlSecureZeroMemory(ownedTlsScratch_, ownedTlsScratchLength_);
            FreeNonPagedArray(ownedTlsScratch_);
            ownedTlsScratch_ = nullptr;
            ownedTlsScratchLength_ = 0;
        }

        handshakeScratchAllocator_ = nullptr;
        handshakeScratch_ = nullptr;
        handshakeScratchLength_ = 0;
        handshakeBuffer_ = nullptr;
    }

    NTSTATUS TlsConnection::Connect(
        transport::Transport* transport,
        const TlsClientConnectionOptions& options) noexcept
    {
        ClearHandshakeFailure();
        if (options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            !IsValidBuffer(options.EarlyData, options.EarlyDataLength) ||
            options.HandshakeReceiveTimeoutMilliseconds == 0 ||
            options.Tls13RecordPaddingLength > Tls13MaxRecordPaddingLength ||
            options.MaxTls12Renegotiations > Tls12HardMaxRenegotiations ||
            (options.VerifyCertificate && options.CertificateStore == nullptr) ||
            !NT_SUCCESS(TlsValidatePolicy(options.Policy)) ||
            static_cast<UCHAR>(options.MinimumProtocol) > static_cast<UCHAR>(options.MaximumProtocol)) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
        if (options.EnableEarlyData &&
            options.EarlyData != nullptr &&
            options.EarlyDataLength != 0 &&
            !options.EarlyDataReplaySafe) {
            if (options.EarlyDataBytesSent != nullptr) {
                *options.EarlyDataBytesSent = 0;
            }
            if (options.EarlyDataAccepted != nullptr) {
                *options.EarlyDataAccepted = false;
            }
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }

        Reset();
        ClearHandshakeFailure();
        handshakeReceiveTimeoutMilliseconds_ = options.HandshakeReceiveTimeoutMilliseconds;
        handshakeReceiveDeadline_ = MakeReceiveDeadline(handshakeReceiveTimeoutMilliseconds_);
        tls13RecordPaddingLength_ = options.Tls13RecordPaddingLength;
        tls13PostHandshakeClientAuthAllowed_ = options.Policy.EnablePostHandshakeClientAuth;
        clientCredential_ = options.ClientCredential;
        tls12SessionCache_ = options.Tls12SessionCache;
        tls13ExternalSessionCache_ = options.SessionCache;
        tls12RenegotiationOptions_ = options;
        tlsPolicy_ = options.Policy;
        tls12MaxRenegotiations_ = options.MaxTls12Renegotiations;
        tlsPolicyIdentity_ =
            (static_cast<ULONG>(options.Policy.Profile) << 24) |
            (options.Policy.EnableTls12RsaKeyExchange ? 0x00000001UL : 0) |
            (options.Policy.EnableTls12Cbc ? 0x00000002UL : 0) |
            (options.Policy.EnableTls12Renegotiation ? 0x00000004UL : 0) |
            (options.Policy.EnablePostHandshakeClientAuth ? 0x00000008UL : 0) |
            (options.Policy.RequireRevocationCheck ? 0x00000010UL : 0);
        serverCertificatePublicKeyAlgorithm_ = CertificatePublicKeyAlgorithm::Unknown;
        RtlSecureZeroMemory(serverEd25519PublicKey_, sizeof(serverEd25519PublicKey_));
        serverEd25519PublicKeyLength_ = 0;
        RtlSecureZeroMemory(serverEd448PublicKey_, sizeof(serverEd448PublicKey_));
        serverEd448PublicKeyLength_ = 0;

        NTSTATUS status = PrepareScratch(options);
        if (NT_SUCCESS(status)) {
            status = EnsureBuffers();
        }
        if (!NT_SUCCESS(status)) {
            ReleaseHandshakeScratch();
            certificateScratchAllocator_ = nullptr;
            return status;
        }

        if (ProtocolAllowed(options, TlsProtocol::Tls13)) {
            status = ConnectTls13(transport, options);
        }
        else if (ProtocolAllowed(options, TlsProtocol::Tls12)) {
            status = ConnectTls12(transport, options);
        }
        else {
            status = STATUS_NOT_SUPPORTED;
        }

        ReleaseHandshakeScratch();
        certificateScratchAllocator_ = nullptr;
        if (!NT_SUCCESS(status) &&
            lastHandshakeFailure_.Category == TlsHandshakeFailureCategory::None) {
            RecordHandshakeFailure(CategoryForStatus(status), status);
        }
        return status;
    }

    NTSTATUS TlsConnection::Send(
        transport::Transport* transport,
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }

        if (!IsEstablished() || !IsValidBuffer(data, length)) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T sent = 0;
        const UCHAR* bytes = static_cast<const UCHAR*>(data);
        while (sent < length) {
            const SIZE_T fragmentLimit =
                tls13RecordProtection_ ? TlsMaxPlaintextLength - tls13RecordPaddingLength_ : TlsMaxPlaintextLength;
            const SIZE_T chunk = (length - sent) > fragmentLimit ? fragmentLimit : (length - sent);
            NTSTATUS status = STATUS_SUCCESS;
            if (tls13RecordProtection_) {
                status = SendPendingTls13KeyUpdate(transport);
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::ApplicationData, bytes + sent, chunk);
                }
            }
            else {
                status = SendProtectedRecord(transport, TlsContentType::ApplicationData, bytes + sent, chunk);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            sent += chunk;
        }

        if (bytesSent != nullptr) {
            *bytesSent = sent;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::Receive(
        transport::Transport* transport,
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG receiveTimeoutMilliseconds) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (!IsEstablished() || data == nullptr || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (plaintextLength_ != 0) {
            const SIZE_T copyLength = plaintextLength_ < length ? plaintextLength_ : length;
            RtlCopyMemory(data, plaintextBuffer_, copyLength);

            if (copyLength < plaintextLength_) {
                RtlMoveMemory(plaintextBuffer_, plaintextBuffer_ + copyLength, plaintextLength_ - copyLength);
            }

            plaintextLength_ -= copyLength;
            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }

            return STATUS_SUCCESS;
        }

        TlsReceiveDeadline receiveDeadline = MakeReceiveDeadline(receiveTimeoutMilliseconds);
        ULONG emptyApplicationRecords = 0;
        ULONG postHandshakeRecords = 0;
        for (;;) {
            TlsMutablePlaintextRecord record = {};
            NTSTATUS status = ReadRecord(transport, record, receiveTimeoutMilliseconds, &receiveDeadline);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read record failed before HTTP: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }

            if (tls13RecordProtection_ && record.ContentType == TlsContentType::Handshake) {
                if (++postHandshakeRecords > TlsApplicationMaxPostHandshakeRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = ConsumeTls13PostHandshakeRecord(transport, record.Fragment, record.FragmentLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                continue;
            }

            if (!tls13RecordProtection_ &&
                context_.Protocol() == TlsProtocol::Tls12 &&
                record.ContentType == TlsContentType::Handshake) {
                if (++postHandshakeRecords > TlsApplicationMaxPostHandshakeRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = ConsumeTls12PostHandshakeRecord(transport, record.Fragment, record.FragmentLength);
                if (!NT_SUCCESS(status)) {
                    WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection consume TLS1.2 post-handshake message during HTTP read failed: 0x%08X length=%Iu\r\n",
                        static_cast<ULONG>(status),
                        record.FragmentLength);
                    return status;
                }
                continue;
            }

            if (record.ContentType == TlsContentType::Alert) {
                TlsAlert alert = {};
                status = TlsRecordLayer::DecodeAlert(record.Fragment, record.FragmentLength, alert);
                if (!NT_SUCCESS(status)) {
                    WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection decode alert during HTTP read failed: 0x%08X length=%Iu\r\n",
                        static_cast<ULONG>(status),
                        record.FragmentLength);
                    return status;
                }

                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Warning, "TlsConnection receive alert during HTTP read level=%u description=%u\r\n",
                    static_cast<unsigned>(alert.Level),
                    static_cast<unsigned>(alert.Description));
                return alert.CloseNotify ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!tls13RecordProtection_ &&
                context_.Protocol() == TlsProtocol::Tls12 &&
                (handshakeLength_ != 0 || handshakeConsumed_ != 0)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection incomplete TLS1.2 handshake before application data length=%Iu consumed=%Iu\r\n",
                    handshakeLength_,
                    handshakeConsumed_);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (record.ContentType != TlsContentType::ApplicationData) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection unexpected record during HTTP read type=%u length=%Iu\r\n",
                    static_cast<unsigned>(record.ContentType),
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (record.FragmentLength == 0) {
                ++emptyApplicationRecords;
                if (emptyApplicationRecords > TlsApplicationMaxEmptyRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                continue;
            }

            emptyApplicationRecords = 0;
            postHandshakeRecords = 0;
            const SIZE_T copyLength = record.FragmentLength < length ? record.FragmentLength : length;
            RtlCopyMemory(data, record.Fragment, copyLength);

            if (copyLength < record.FragmentLength) {
                plaintextLength_ = record.FragmentLength - copyLength;
                RtlMoveMemory(plaintextBuffer_, record.Fragment + copyLength, plaintextLength_);
            }

            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }

            return STATUS_SUCCESS;
        }
    }

    bool TlsConnection::IsEstablished() const noexcept
    {
        return context_.State() == TlsHandshakeState::Established;
    }

    const TlsContext& TlsConnection::Context() const noexcept
    {
        return context_;
    }

    void TlsConnection::RecordTls13FirstServerHelloFailure(
        const TlsClientConnectionOptions& options,
        NTSTATUS status) noexcept
    {
        if (!CanConfirmTls12FromTls13Attempt(options)) {
            return;
        }

        lastHandshakeFailure_.BeforeTls13FirstServerHello = true;
        if (status == STATUS_INVALID_NETWORK_RESPONSE &&
            lastHandshakeFailure_.HasPeerAlert &&
            (lastHandshakeFailure_.PeerAlert.Description == TlsAlertDescription::HandshakeFailure ||
                lastHandshakeFailure_.PeerAlert.CloseNotify)) {
            lastHandshakeFailure_.Category = TlsHandshakeFailureCategory::VersionNegotiation;
            lastHandshakeFailure_.Status = status;
        }
    }

    void TlsConnection::ClearHandshakeFailure() noexcept
    {
        lastHandshakeFailure_ = {};
    }

    void TlsConnection::RecordHandshakeFailure(
        TlsHandshakeFailureCategory category,
        NTSTATUS status) noexcept
    {
        if (category == TlsHandshakeFailureCategory::None) {
            return;
        }

        lastHandshakeFailure_.Category = category;
        lastHandshakeFailure_.Status = status;
        lastHandshakeFailure_.PeerAlert = {};
        lastHandshakeFailure_.HasPeerAlert = false;
    }

    void TlsConnection::RecordPeerAlertFailure(const TlsMutablePlaintextRecord& record) noexcept
    {
        TlsAlert alert = {};
        const NTSTATUS status = TlsRecordLayer::DecodeAlert(record.Fragment, record.FragmentLength, alert);
        if (!NT_SUCCESS(status)) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::DecodeError, status);
            return;
        }

        lastHandshakeFailure_.Category = CategoryForPeerAlert(alert);
        lastHandshakeFailure_.Status = STATUS_INVALID_NETWORK_RESPONSE;
        lastHandshakeFailure_.PeerAlert = alert;
        lastHandshakeFailure_.HasPeerAlert = true;
    }

    NTSTATUS TlsConnection::AppendTranscript(const UCHAR* data, SIZE_T length) noexcept
    {
        return transcript_.Update(data, length);
    }

    NTSTATUS TlsConnection::FinishTranscript(UCHAR* digest, SIZE_T capacity, SIZE_T* digestLength) const noexcept
    {
        return transcript_.Finish(digest, capacity, digestLength);
    }

    const char* TlsConnection::NegotiatedAlpn() const noexcept
    {
        return negotiatedAlpnLength_ > 0 ? negotiatedAlpn_ : nullptr;
    }

    SIZE_T TlsConnection::NegotiatedAlpnLength() const noexcept
    {
        return negotiatedAlpnLength_;
    }

    const TlsHandshakeFailure& TlsConnection::LastHandshakeFailure() const noexcept
    {
        return lastHandshakeFailure_;
    }

    NTSTATUS TlsConnectionCreate(TlsConnection** connection) noexcept
    {
        if (connection != nullptr) {
            *connection = nullptr;
        }
        if (connection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        auto* created = AllocateNonPagedObject<TlsConnection>();
        if (created == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        *connection = created;
        return STATUS_SUCCESS;
    }

    void TlsConnectionClose(TlsConnection* connection) noexcept
    {
        FreeNonPagedObject(connection);
    }

    NTSTATUS TlsConnectionConnect(
        TlsConnection* connection,
        transport::Transport* transport,
        const TlsClientConnectionOptions* options) noexcept
    {
        return connection != nullptr && options != nullptr
            ? connection->Connect(transport, *options)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS TlsConnectionSend(
        TlsConnection* connection,
        transport::Transport* transport,
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent) noexcept
    {
        return connection != nullptr
            ? connection->Send(transport, data, length, bytesSent)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS TlsConnectionReceive(
        TlsConnection* connection,
        transport::Transport* transport,
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG timeoutMilliseconds) noexcept
    {
        return connection != nullptr
            ? connection->Receive(transport, data, length, bytesReceived, timeoutMilliseconds)
            : STATUS_INVALID_PARAMETER;
    }

    bool TlsConnectionIsEstablished(const TlsConnection* connection) noexcept
    {
        return connection != nullptr && connection->IsEstablished();
    }

    const char* TlsConnectionNegotiatedAlpn(const TlsConnection* connection) noexcept
    {
        return connection != nullptr ? connection->NegotiatedAlpn() : nullptr;
    }

    SIZE_T TlsConnectionNegotiatedAlpnLength(const TlsConnection* connection) noexcept
    {
        return connection != nullptr ? connection->NegotiatedAlpnLength() : 0;
    }

    TlsHandshakeFailure TlsConnectionLastHandshakeFailure(const TlsConnection* connection) noexcept
    {
        return connection != nullptr ? connection->LastHandshakeFailure() : TlsHandshakeFailure{};
    }
}
}
