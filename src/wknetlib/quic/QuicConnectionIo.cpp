#if !defined(WKNET_USER_MODE_TEST)
#include <ntifs.h>
#endif
#include "quic/QuicConnectionPrivate.hpp"
#include <wknet/crypto/CngProvider.h>
namespace wknet::quic
{
    namespace
    {
        constexpr ULONGLONG QuicKeyUpdatePacketThreshold = 1ULL << 20;

        ULONGLONG DeadlineAfter(ULONGLONG now, ULONGLONG duration, ULONGLONG multiplier = 1) noexcept
        {
            if (multiplier == 0)
            {
                return now;
            }
            if (duration > (~0ULL / multiplier))
            {
                return ~0ULL;
            }
            const ULONGLONG total = duration * multiplier;
            return now > ~0ULL - total ? ~0ULL : now + total;
        }
    } // namespace

    NTSTATUS QuicConnection::StartNetwork() noexcept
    {
        NTSTATUS status = recovery_.Initialize();
        for (SIZE_T index = 0; NT_SUCCESS(status) && index < 3; ++index)
        {
            status = ackTrackers_[index].Initialize();
        }
        if (NT_SUCCESS(status))
        {
            status = flowControl_.Initialize(0, WKNET_HARD_MAX_QUIC_CONNECTION_REASSEMBLY_BYTES);
        }
        if (NT_SUCCESS(status))
        {
            status = attempt_.Initialize(QuicVersion1,
                                         {initialDestinationConnectionId_, initialDestinationConnectionIdLength_},
                                         {sourceConnectionId_, sourceConnectionIdLength_});
        }
        if (NT_SUCCESS(status))
        {
            status = QuicDeriveInitialKeySets({initialDestinationConnectionId_, initialDestinationConnectionIdLength_},
                                              &initialWriteKey_, &initialReadKey_);
        }

        SIZE_T transportParametersLength = 0;
        if (NT_SUCCESS(status))
        {
            QuicClientTransportParameterOptions transportParameterOptions = {};
            transportParameterOptions.InitialSourceConnectionId = {sourceConnectionId_, sourceConnectionIdLength_};
            transportParameterOptions.MaxIdleTimeout = 30000;
            transportParameterOptions.InitialMaxData = WKNET_HARD_MAX_QUIC_CONNECTION_REASSEMBLY_BYTES;
            transportParameterOptions.InitialMaxStreamDataBidiLocal = WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES;
            transportParameterOptions.InitialMaxStreamDataBidiRemote = WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES;
            transportParameterOptions.InitialMaxStreamDataUni = WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES;
            transportParameterOptions.InitialMaxStreamsBidi = WKNET_HARD_MAX_QUIC_PEER_BIDI_STREAMS;
            transportParameterOptions.InitialMaxStreamsUni = WKNET_HARD_MAX_QUIC_PEER_UNI_STREAMS;
            transportParameterOptions.ActiveConnectionIdLimit = WKNET_HARD_MAX_QUIC_CONNECTION_IDS;
            status = QuicEncodeClientTransportParametersWithLimits(transportParameterOptions, frameBuffer_.Get(),
                                                                   frameBuffer_.Count(), &transportParametersLength);
        }
        if (NT_SUCCESS(status))
        {
            QuicTlsClientOptions tlsOptions = {};
            tlsOptions.ServerName = serverName_.Get();
            tlsOptions.ServerNameLength = serverName_.Count() - 1;
            tlsOptions.LocalTransportParameters = {frameBuffer_.Get(), transportParametersLength};
            tlsOptions.CertificateStore = certificateStore_;
            tlsOptions.CertificateScratchAllocator = certificateScratchAllocator_;
            tlsOptions.ProviderCache = providerCache_;
            tlsOptions.SessionCache = sessionCache_;
            tlsOptions.ClientCredential = clientCredential_;
            tlsOptions.VerifyCertificate = verifyCertificate_;
            tlsOptions.RequireRevocationCheck = requireRevocationCheck_;
            status = tls_.Initialize(tlsOptions);
        }
        if (NT_SUCCESS(status))
        {
            status = net::WskDatagramSocketCreate(datagramClient_, remoteAddress_.ss_family, &datagramSocket_);
        }
        if (NT_SUCCESS(status))
        {
            net::WskDatagramSocketSetConnectionId(datagramSocket_, QuicClockNow100ns());
            status =
                net::WskDatagramSocketConnectPeer(datagramSocket_, reinterpret_cast<const SOCKADDR*>(&remoteAddress_));
        }
        if (NT_SUCCESS(status))
        {
            status = net::WskDatagramSocketSetReceiveNotification(datagramSocket_, ReceiveNotification, this);
        }
        if (NT_SUCCESS(status))
        {
            status = ArmReceive();
        }
        if (NT_SUCCESS(status))
        {
            status = SendInitialClientHello();
        }
        if (NT_SUCCESS(status))
        {
            lastActivityTime100ns_ = QuicClockNow100ns();
        }
        if (!NT_SUCCESS(status))
        {
            StopNetwork();
        }
        return status;
    }

    void QuicConnection::StopNetwork() noexcept
    {
        if (datagramSocket_ != nullptr)
        {
            (void)net::WskDatagramSocketSetReceiveNotification(datagramSocket_, nullptr, nullptr);
            if (receivePending_)
            {
                (void)net::WskDatagramSocketCancelReceive(datagramSocket_);
                net::WskDatagramReceiveResult result = {};
                (void)net::WskDatagramSocketCompleteReceive(datagramSocket_, 0xffffffffUL, &result);
                receivePending_ = false;
            }
            (void)net::WskDatagramSocketClose(datagramSocket_);
            net::WskDatagramSocketDestroy(datagramSocket_);
            datagramSocket_ = nullptr;
        }
        tls_.Clear();
        attempt_.Reset();
        QuicClearPacketKeySet(&initialWriteKey_);
        QuicClearPacketKeySet(&initialReadKey_);
        QuicClearPacketKeySet(&applicationWriteKey_);
        QuicClearPacketKeySet(&previousApplicationWriteKey_);
        QuicClearPacketKeySet(&applicationReadKey_);
        QuicClearPacketKeySet(&nextApplicationReadKey_);
        QuicClearPacketKeySet(&previousApplicationReadKey_);
        applicationKeysInstalled_ = false;
        sendKeyUpdateAwaitingAck_ = false;
        previousReadKeyValid_ = false;
        previousReadKeyDeadline100ns_ = 0;
        receiveKeyPhaseStartPacketNumber_ = 0;
        receiveReady_ = false;
    }

    NTSTATUS QuicConnection::ArmReceive() noexcept
    {
        if (datagramSocket_ == nullptr || receivePending_)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        RtlZeroMemory(receiveBuffer_.Get(), receiveBuffer_.Count());
        const NTSTATUS status =
            net::WskDatagramSocketStartReceive(datagramSocket_, receiveBuffer_.Get(), receiveBuffer_.Count());
        if (NT_SUCCESS(status))
        {
            receivePending_ = true;
        }
        return status;
    }

    NTSTATUS QuicConnection::SendInitialClientHello() noexcept
    {
        clientHelloLength_ = 0;
        NTSTATUS status = tls_.Start(clientHelloBuffer_.Get(), clientHelloBuffer_.Count(), &clientHelloLength_);
        if (NT_SUCCESS(status))
        {
            status = SendCryptoPacket(QuicPacketType::Initial, QuicPacketNumberSpace::Initial, initialWriteKey_, 0,
                                      clientHelloBuffer_.Get(), clientHelloLength_, true);
        }
        if (NT_SUCCESS(status))
        {
            initialCryptoSendOffset_ = clientHelloLength_;
        }
        return status;
    }

    NTSTATUS QuicConnection::SendCryptoPacket(QuicPacketType type, QuicPacketNumberSpace space,
                                              const QuicPacketKeySet& key, ULONGLONG cryptoOffset,
                                              const UCHAR* cryptoData, SIZE_T cryptoLength, bool padInitial) noexcept
    {
        QuicFrame frame = {};
        frame.Kind = QuicFrameKind::Crypto;
        frame.Offset = cryptoOffset;
        frame.Data = {cryptoData, cryptoLength};
        return SendFramePacket(type, space, key, frame, nullptr, 0, padInitial, true);
    }

    NTSTATUS QuicConnection::SendFramePacket(QuicPacketType type, QuicPacketNumberSpace space,
                                             const QuicPacketKeySet& key, const QuicFrame& frame,
                                             const QuicAckRange* ackRanges, SIZE_T ackRangeCount, bool padInitial,
                                             bool ackEliciting) noexcept
    {
        if (datagramSocket_ == nullptr || key.SecretLength == 0)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        SIZE_T frameLength = 0;
        NTSTATUS status =
            QuicEncodeFrame(frame, ackRanges, ackRangeCount, frameBuffer_.Get(), frameBuffer_.Count(), &frameLength);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        const SIZE_T spaceIndex = static_cast<SIZE_T>(space);
        if (type == QuicPacketType::OneRtt)
        {
            if (!applicationKeysInstalled_)
            {
                return STATUS_INVALID_DEVICE_STATE;
            }
            if (nextPacketNumber_[spaceIndex] >= QuicVarIntMaximum)
            {
                return STATUS_INTEGER_OVERFLOW;
            }
            else if (oneRttPacketsInSendPhase_ >= QuicKeyUpdatePacketThreshold && !sendKeyUpdateAwaitingAck_)
            {
                const NTSTATUS updateStatus = InitiateKeyUpdate();
                if (!NT_SUCCESS(updateStatus))
                {
                    return updateStatus;
                }
            }
        }
        const ULONGLONG packetNumber = nextPacketNumber_[spaceIndex];
        constexpr SIZE_T packetNumberLength = 2;
        constexpr SIZE_T minimumProtectedPlaintextLength = 4 - packetNumberLength;
        SIZE_T packetNumberOffset = 0;
        SIZE_T headerLength = 0;
        SIZE_T plaintextLength =
            frameLength < minimumProtectedPlaintextLength ? minimumProtectedPlaintextLength : frameLength;

        if (type == QuicPacketType::Initial || type == QuicPacketType::Handshake)
        {
            for (SIZE_T iteration = 0; iteration < 3; ++iteration)
            {
                QuicLongHeaderEncodeOptions headerOptions = {};
                headerOptions.Type = type;
                headerOptions.DestinationConnectionId = {peerConnectionId_, peerConnectionIdLength_};
                headerOptions.SourceConnectionId = {sourceConnectionId_, sourceConnectionIdLength_};
                if (type == QuicPacketType::Initial)
                {
                    headerOptions.Token = attempt_.RetryAccepted()
                                              ? attempt_.RetryToken()
                                              : (tokenCache_ != nullptr ? tokenCache_->Latest() : QuicBufferView{});
                }
                headerOptions.PacketNumber = packetNumber;
                headerOptions.PacketNumberLength = packetNumberLength;
                headerOptions.ProtectedPayloadLength =
                    packetNumberLength + plaintextLength + QuicRetryIntegrityTagLength;
                status = QuicEncodeLongPacketHeader(headerOptions, packetBuffer_.Get(), packetBuffer_.Count(),
                                                    &packetNumberOffset, &headerLength);
                if (!NT_SUCCESS(status) || !padInitial)
                {
                    break;
                }
                if (headerLength + QuicRetryIntegrityTagLength > WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                const SIZE_T targetPlaintext =
                    WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES - headerLength - QuicRetryIntegrityTagLength;
                if (targetPlaintext < frameLength)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if (targetPlaintext == plaintextLength)
                {
                    break;
                }
                plaintextLength = targetPlaintext;
            }
        }
        else if (type == QuicPacketType::OneRtt)
        {
            QuicShortHeaderEncodeOptions headerOptions = {};
            headerOptions.DestinationConnectionId = {peerConnectionId_, peerConnectionIdLength_};
            headerOptions.PacketNumber = packetNumber;
            headerOptions.PacketNumberLength = packetNumberLength;
            headerOptions.KeyPhase = sendKeyPhase_;
            status = QuicEncodeShortPacketHeader(headerOptions, packetBuffer_.Get(), packetBuffer_.Count(),
                                                 &packetNumberOffset, &headerLength);
        }
        else
        {
            return STATUS_NOT_SUPPORTED;
        }
        if (!NT_SUCCESS(status) || plaintextLength > packetBuffer_.Count() - headerLength)
        {
            return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
        }
        RtlCopyMemory(packetBuffer_.Get() + headerLength, frameBuffer_.Get(), frameLength);
        if (plaintextLength > frameLength)
        {
            RtlZeroMemory(packetBuffer_.Get() + headerLength + frameLength, plaintextLength - frameLength);
        }
        SIZE_T packetLength = 0;
        status = QuicProtectPacket(key, packetBuffer_.Get(), packetBuffer_.Count(), packetNumberOffset,
                                   packetNumberLength, packetNumber, plaintextLength, &packetLength);
        SIZE_T bytesSent = 0;
        if (NT_SUCCESS(status))
        {
            status = net::WskDatagramSocketSend(datagramSocket_, packetBuffer_.Get(), packetLength, &bytesSent);
        }
        if (NT_SUCCESS(status) && bytesSent != packetLength)
        {
            status = STATUS_CONNECTION_DISCONNECTED;
        }
        if (NT_SUCCESS(status))
        {
            status = recovery_.OnPacketSent(space, packetNumber, packetLength, ackEliciting);
        }
        if (NT_SUCCESS(status) && ackEliciting)
        {
            lastActivityTime100ns_ = QuicClockNow100ns();
        }
        if (NT_SUCCESS(status))
        {
            ++nextPacketNumber_[spaceIndex];
            if (type == QuicPacketType::OneRtt)
            {
                ++oneRttPacketsInSendPhase_;
            }
            if (type == QuicPacketType::Handshake && !tls_.InitialKeysDiscarded())
            {
                status = tls_.DiscardInitialKeys();
                QuicClearPacketKeySet(&initialWriteKey_);
                QuicClearPacketKeySet(&initialReadKey_);
            }
        }
        return status;
    }

    NTSTATUS QuicConnection::ProcessReceiveCompletion() noexcept
    {
        if (!receivePending_ || datagramSocket_ == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        net::WskDatagramReceiveResult result = {};
        NTSTATUS status = net::WskDatagramSocketCompleteReceive(datagramSocket_, 0xffffffffUL, &result);
        receivePending_ = false;
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (result.RemoteAddressLength != remoteAddressLength_ ||
            RtlCompareMemory(&result.RemoteAddress, &remoteAddress_, remoteAddressLength_) != remoteAddressLength_)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        status = ProcessDatagram(receiveBuffer_.Get(), result.BytesReceived);
        if (NT_SUCCESS(status) && State() != QuicConnectionState::Closing && State() != QuicConnectionState::Draining &&
            State() != QuicConnectionState::Closed && State() != QuicConnectionState::Failed)
        {
            status = ArmReceive();
        }
        return status;
    }

    NTSTATUS QuicConnection::ProcessDatagram(UCHAR* data, SIZE_T length) noexcept
    {
        if (data == nullptr || length == 0 || length > WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        QuicPacketIterator iterator = {};
        QuicPacketIteratorInitialize(&iterator, data, length, sourceConnectionIdLength_);
        for (;;)
        {
            QuicPacketHeader& header = packetHeaderScratch_[0];
            header = {};
            QuicBufferView packet = {};
            NTSTATUS status = QuicPacketIteratorNext(&iterator, &header, &packet);
            if (status == STATUS_NOT_FOUND)
            {
                return STATUS_SUCCESS;
            }
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            status = ProcessPacket(const_cast<UCHAR*>(packet.Data), packet.Length, header);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
    }

    NTSTATUS QuicConnection::ProcessPacket(UCHAR* packet, SIZE_T packetLength, QuicPacketHeader& header) noexcept
    {
        if (header.Type == QuicPacketType::VersionNegotiation)
        {
            const ULONG supportedVersions[] = {QuicVersion1};
            const NTSTATUS status = attempt_.ValidateVersionNegotiation(header, supportedVersions, 1, nullptr);
            return status == STATUS_INVALID_NETWORK_RESPONSE ? STATUS_SUCCESS : status;
        }
        if (header.Type == QuicPacketType::Retry)
        {
            NTSTATUS status = attempt_.ValidateRetry(header, packet, packetLength);
            if (!NT_SUCCESS(status))
            {
                return status == STATUS_INVALID_NETWORK_RESPONSE ? STATUS_SUCCESS : status;
            }
            const QuicBufferView retrySource = attempt_.RetrySourceConnectionId();
            RtlCopyMemory(peerConnectionId_, retrySource.Data, retrySource.Length);
            peerConnectionIdLength_ = retrySource.Length;
            if (peerConnectionIdCount_ != 0)
            {
                peerConnectionIds_[0].ConnectionIdLength = retrySource.Length;
                RtlCopyMemory(peerConnectionIds_[0].ConnectionId, retrySource.Data, retrySource.Length);
            }
            QuicClearPacketKeySet(&initialWriteKey_);
            QuicClearPacketKeySet(&initialReadKey_);
            status = QuicDeriveInitialKeySets(retrySource, &initialWriteKey_, &initialReadKey_);
            if (NT_SUCCESS(status))
            {
                nextPacketNumber_[static_cast<SIZE_T>(QuicPacketNumberSpace::Initial)] = 0;
                expectedPacketNumber_[static_cast<SIZE_T>(QuicPacketNumberSpace::Initial)] = 0;
                status = recovery_.Initialize();
            }
            if (NT_SUCCESS(status))
            {
                status = ackTrackers_[static_cast<SIZE_T>(QuicPacketNumberSpace::Initial)].Initialize();
            }
            if (NT_SUCCESS(status))
            {
                status = SendCryptoPacket(QuicPacketType::Initial, QuicPacketNumberSpace::Initial, initialWriteKey_, 0,
                                          clientHelloBuffer_.Get(), clientHelloLength_, true);
            }
            return status;
        }
        if (!IsLocalConnectionId(header.DestinationConnectionId))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        QuicEncryptionLevel level = QuicEncryptionLevel::Initial;
        QuicPacketNumberSpace space = QuicPacketNumberSpace::Initial;
        const QuicPacketKeySet* key = nullptr;
        if (header.Type == QuicPacketType::Initial)
        {
            key = &initialReadKey_;
        }
        else if (header.Type == QuicPacketType::Handshake)
        {
            level = QuicEncryptionLevel::Handshake;
            space = QuicPacketNumberSpace::Handshake;
            key = &tls_.HandshakeReadKey();
        }
        else if (header.Type == QuicPacketType::OneRtt)
        {
            level = QuicEncryptionLevel::Application;
            space = QuicPacketNumberSpace::Application;
            DiscardExpiredReadKey(QuicClockNow100ns());
            key = &applicationReadKey_;
        }
        else
        {
            return STATUS_NOT_SUPPORTED;
        }
        if (key == nullptr || key->SecretLength == 0)
        {
            return STATUS_SUCCESS;
        }

        const SIZE_T spaceIndex = static_cast<SIZE_T>(space);
        ULONGLONG packetNumber = 0;
        SIZE_T plaintextLength = 0;
        if (packetLength > decryptBuffer_.Count())
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        enum class ReadKeySelection : UCHAR
        {
            Current,
            Next,
            Previous
        };
        ReadKeySelection selection = ReadKeySelection::Current;

        if (header.Type == QuicPacketType::OneRtt)
        {
            UCHAR unprotectedFirstByte = 0;
            ULONGLONG inspectedPacketNumber = 0;
            const NTSTATUS inspectStatus = QuicInspectProtectedPacketHeader(
                applicationReadKey_, packet, packetLength, header.PacketNumberOffset, expectedPacketNumber_[spaceIndex],
                &unprotectedFirstByte, &inspectedPacketNumber);
            if (!NT_SUCCESS(inspectStatus))
            {
                return inspectStatus == STATUS_INSUFFICIENT_RESOURCES ? inspectStatus : STATUS_SUCCESS;
            }
            const bool inspectedKeyPhase = (unprotectedFirstByte & 0x04U) != 0;
            if (inspectedKeyPhase != receiveKeyPhase_)
            {
                if (previousReadKeyValid_ && inspectedPacketNumber < receiveKeyPhaseStartPacketNumber_)
                {
                    selection = ReadKeySelection::Previous;
                    key = &previousApplicationReadKey_;
                }
                else
                {
                    selection = ReadKeySelection::Next;
                    key = &nextApplicationReadKey_;
                }
            }
        }

        auto tryKey = [&](const QuicPacketKeySet& candidate) noexcept -> NTSTATUS
        {
            RtlCopyMemory(decryptBuffer_.Get(), packet, packetLength);
            return QuicUnprotectPacket(candidate, decryptBuffer_.Get(), packetLength, header.PacketNumberOffset,
                                       expectedPacketNumber_[spaceIndex], &packetNumber, &plaintextLength);
        };

        NTSTATUS status = tryKey(*key);
        if (!NT_SUCCESS(status))
        {
            if (header.Type == QuicPacketType::OneRtt && MatchesStatelessReset(packet, packetLength))
            {
                EnterDraining();
                WKNET_TRACE(ComponentQuic, TraceLevel::Warning, "quic.connection.stateless_reset");
            }
            return STATUS_SUCCESS;
        }
        packet = decryptBuffer_.Get();
        status = QuicParsePacketHeader(packet, packetLength, sourceConnectionIdLength_, &header);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (header.Type == QuicPacketType::OneRtt)
        {
            const bool packetKeyPhase = (header.FirstByte & 0x04U) != 0;
            if (selection == ReadKeySelection::Current && packetKeyPhase != receiveKeyPhase_)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (selection == ReadKeySelection::Previous &&
                (!previousReadKeyValid_ || packetKeyPhase != previousReceiveKeyPhase_))
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (selection == ReadKeySelection::Next)
            {
                if (packetKeyPhase == receiveKeyPhase_)
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                QuicClearPacketKeySet(&previousApplicationReadKey_);
                previousApplicationReadKey_ = applicationReadKey_;
                previousReceiveKeyPhase_ = receiveKeyPhase_;
                previousReadKeyValid_ = true;
                applicationReadKey_ = nextApplicationReadKey_;
                RtlSecureZeroMemory(&nextApplicationReadKey_, sizeof(nextApplicationReadKey_));
                receiveKeyPhase_ = packetKeyPhase;
                receiveKeyPhaseStartPacketNumber_ = packetNumber;
                status = QuicDeriveNextPacketKeySet(applicationReadKey_, &nextApplicationReadKey_);
                if (!NT_SUCCESS(status))
                {
                    return status;
                }
                const ULONGLONG retentionBase =
                    recovery_.SmoothedRtt100ns() == 0 ? 10000000ULL : recovery_.SmoothedRtt100ns();
                previousReadKeyDeadline100ns_ = DeadlineAfter(QuicClockNow100ns(), retentionBase, 3);
            }
        }
        if (header.IsLongHeader && header.SourceConnectionId.Length != 0 && !peerConnectionIdAuthenticated_)
        {
            RtlCopyMemory(peerConnectionId_, header.SourceConnectionId.Data, header.SourceConnectionId.Length);
            peerConnectionIdLength_ = header.SourceConnectionId.Length;
            if (peerConnectionIdCount_ != 0)
            {
                peerConnectionIds_[0].ConnectionIdLength = header.SourceConnectionId.Length;
                RtlCopyMemory(peerConnectionIds_[0].ConnectionId, header.SourceConnectionId.Data,
                              header.SourceConnectionId.Length);
            }
            peerConnectionIdAuthenticated_ = true;
        }
        bool ackEliciting = false;
        pendingTransportError_ = 0;
        status = ValidateFrames(packet + header.PayloadOffset, plaintextLength, &ackEliciting);
        if (!NT_SUCCESS(status))
        {
            pendingTransportError_ = 0x7;
        }
        bool duplicate = false;
        if (NT_SUCCESS(status))
        {
            status = ackTrackers_[spaceIndex].OnPacketReceived(packetNumber, ackEliciting,
                                                               space != QuicPacketNumberSpace::Application,
                                                               QuicClockNow100ns(), &duplicate);
        }
        if (!NT_SUCCESS(status) || duplicate)
        {
            return status;
        }
        if (packetNumber >= expectedPacketNumber_[spaceIndex])
        {
            expectedPacketNumber_[spaceIndex] = packetNumber + 1;
        }
        status = DispatchFrames(level, space, packet + header.PayloadOffset, plaintextLength);
        if (!NT_SUCCESS(status) && pendingTransportError_ == 0)
        {
            pendingTransportError_ = tls_.TransportError() != 0 ? tls_.TransportError()
                                                                : (status == STATUS_INSUFFICIENT_RESOURCES ? 0x1 : 0xA);
        }
        if (NT_SUCCESS(status))
        {
            status = HandleTlsProgress();
            if (!NT_SUCCESS(status) && pendingTransportError_ == 0)
            {
                pendingTransportError_ = tls_.TransportError() != 0 ? tls_.TransportError() : 0xA;
            }
        }
        if (NT_SUCCESS(status) && ackTrackers_[spaceIndex].AckPending() &&
            ackTrackers_[spaceIndex].AckDeadline100ns(tls_.PeerTransportParameters().MaxAckDelay) <=
                QuicClockNow100ns())
        {
            status = SendAck(space);
        }
        return status;
    }

    NTSTATUS QuicConnection::ValidateFrames(const UCHAR* payload, SIZE_T payloadLength, bool* ackEliciting) noexcept
    {
        if (ackEliciting != nullptr)
        {
            *ackEliciting = false;
        }
        if ((payload == nullptr && payloadLength != 0) || ackEliciting == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        SIZE_T offset = 0;
        while (offset < payloadLength)
        {
            QuicFrame& frame = frameParseScratch_[0];
            frame = {};
            SIZE_T consumed = 0;
            NTSTATUS status = QuicParseFrame(payload + offset, payloadLength - offset, &frame, &consumed);
            if (!NT_SUCCESS(status) || consumed == 0)
            {
                WKNET_TRACE(ComponentQuic, TraceLevel::Warning,
                            "quic.frame.parse_failed type=%I64u status=0x%08X remaining=%Iu", frame.WireType,
                            static_cast<ULONG>(status), payloadLength - offset);
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            if (frame.Kind != QuicFrameKind::Padding && frame.Kind != QuicFrameKind::Ack &&
                frame.Kind != QuicFrameKind::ConnectionClose)
            {
                *ackEliciting = true;
            }
            offset += consumed;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicConnection::DispatchFrames(QuicEncryptionLevel level, QuicPacketNumberSpace space,
                                            const UCHAR* payload, SIZE_T payloadLength) noexcept
    {
        SIZE_T offset = 0;
        while (offset < payloadLength)
        {
            QuicFrame& frame = frameParseScratch_[0];
            frame = {};
            SIZE_T consumed = 0;
            NTSTATUS status = QuicParseFrame(payload + offset, payloadLength - offset, &frame, &consumed);
            if (NT_SUCCESS(status))
            {
                status = DispatchFrame(level, space, frame);
            }
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            offset += consumed;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicConnection::DispatchFrame(QuicEncryptionLevel level, QuicPacketNumberSpace space,
                                           const QuicFrame& frame) noexcept
    {
        if (frame.Kind == QuicFrameKind::Padding || frame.Kind == QuicFrameKind::Ping)
        {
            return STATUS_SUCCESS;
        }
        if (frame.Kind == QuicFrameKind::Ack)
        {
            SIZE_T rangeCount = 0;
            NTSTATUS status = QuicDecodeAckRanges(frame, ackRangeScratch_.Get(), ackRangeScratch_.Count(), &rangeCount);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            ULONGLONG ackDelay100ns = 0;
            if (space == QuicPacketNumberSpace::Application)
            {
                const ULONGLONG exponent = tls_.PeerTransportParameters().AckDelayExponent;
                if (exponent > 20 || frame.AckDelay > (~0ULL >> exponent) ||
                    (frame.AckDelay << exponent) > (~0ULL / 10ULL))
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                ackDelay100ns = (frame.AckDelay << exponent) * 10ULL;
            }
            status = recovery_.OnAckRangesReceived(space, ackRangeScratch_.Get(), rangeCount, ackDelay100ns);
            if (NT_SUCCESS(status) && space == QuicPacketNumberSpace::Application)
            {
                ConfirmSendKeyUpdate(ackRangeScratch_.Get(), rangeCount);
                NotifyWritableStreams();
            }
            return status;
        }
        if (frame.Kind == QuicFrameKind::Crypto)
        {
            return tls_.ReceiveCrypto(level, frame.Offset, frame.Data.Data, frame.Data.Length);
        }
        lastActivityTime100ns_ = QuicClockNow100ns();
        if (frame.Kind == QuicFrameKind::NewToken)
        {
            if (level != QuicEncryptionLevel::Application || tokenCache_ == nullptr)
            {
                return level == QuicEncryptionLevel::Application ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
            }
            return tokenCache_->Store(frame.Data);
        }
        if (frame.Kind == QuicFrameKind::MaxData)
        {
            if (level != QuicEncryptionLevel::Application)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            NTSTATUS status = flowControl_.OnMaxData(frame.Maximum);
            if (NT_SUCCESS(status))
            {
                NotifyWritableStreams();
            }
            return status;
        }
        if (frame.Kind == QuicFrameKind::Stream)
        {
            if (level != QuicEncryptionLevel::Application)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            QuicStream* stream = FindStream(frame.StreamId);
            if (stream == nullptr)
            {
                if (QuicStreamIsClientInitiated(frame.StreamId))
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                NTSTATUS status = CreateStream(frame.StreamId, &stream);
                if (!NT_SUCCESS(status))
                {
                    return status;
                }
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.stream.open stream_id=%I64u", frame.StreamId);
            }
            const ULONGLONG previousMaximumOffset = stream->ReceiveFlowControlBytes();
            NTSTATUS status = stream->Receive(frame.Offset, frame.Data.Data, frame.Data.Length, frame.Fin, false);
            if (NT_SUCCESS(status))
            {
                status = flowControl_.OnStreamReceiveProgress(previousMaximumOffset, stream->ReceiveFlowControlBytes());
            }
            if (NT_SUCCESS(status))
            {
                stream->NotifyApplicationReadable();
            }
            return status;
        }
        if (frame.Kind == QuicFrameKind::ResetStream)
        {
            if (level != QuicEncryptionLevel::Application)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            QuicStream* stream = FindStream(frame.StreamId);
            if (stream == nullptr)
            {
                if (QuicStreamIsClientInitiated(frame.StreamId))
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                NTSTATUS status = CreateStream(frame.StreamId, &stream);
                if (!NT_SUCCESS(status))
                {
                    return status;
                }
            }
            const ULONGLONG previousMaximumOffset = stream->ReceiveFlowControlBytes();
            NTSTATUS status = stream->OnResetReceived(frame.ErrorCode, frame.FinalSize);
            if (NT_SUCCESS(status))
            {
                status = flowControl_.OnStreamReceiveProgress(previousMaximumOffset, frame.FinalSize);
            }
            if (NT_SUCCESS(status))
            {
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.stream.reset stream_id=%I64u", frame.StreamId);
            }
            return status;
        }
        if (frame.Kind == QuicFrameKind::StopSending)
        {
            if (level != QuicEncryptionLevel::Application)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            QuicStream* stream = FindStream(frame.StreamId);
            if (stream == nullptr)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const bool resetAlreadySent = stream->SendReset();
            NTSTATUS status = stream->StopSending(frame.ErrorCode);
            if (NT_SUCCESS(status) && !resetAlreadySent)
            {
                QuicFrame reset = {};
                reset.Kind = QuicFrameKind::ResetStream;
                reset.StreamId = frame.StreamId;
                reset.ErrorCode = frame.ErrorCode;
                reset.FinalSize = stream->SendOffset();
                status = SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application,
                                         applicationWriteKey_, reset, nullptr, 0, false, true);
                if (NT_SUCCESS(status))
                {
                    status = stream->Reset(frame.ErrorCode, stream->SendOffset());
                }
            }
            return status;
        }
        if (frame.Kind == QuicFrameKind::MaxStreamData)
        {
            if (level != QuicEncryptionLevel::Application)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            QuicStream* stream = FindStream(frame.StreamId);
            return stream == nullptr ? STATUS_INVALID_NETWORK_RESPONSE : stream->OnMaxStreamData(frame.Maximum);
        }
        if (frame.Kind == QuicFrameKind::MaxStreams)
        {
            if (level != QuicEncryptionLevel::Application || frame.Maximum > (1ULL << 60))
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ULONGLONG& limit = frame.Bidirectional ? peerMaxStreamsBidi_ : peerMaxStreamsUni_;
            const ULONGLONG localLimit =
                frame.Bidirectional ? WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS : WKNET_HARD_MAX_QUIC_LOCAL_UNI_STREAMS;
            if (frame.Maximum > limit)
            {
                limit = frame.Maximum < localLimit ? frame.Maximum : localLimit;
            }
            return STATUS_SUCCESS;
        }
        if (frame.Kind == QuicFrameKind::DataBlocked || frame.Kind == QuicFrameKind::StreamDataBlocked ||
            frame.Kind == QuicFrameKind::StreamsBlocked)
        {
            return level == QuicEncryptionLevel::Application ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (frame.Kind == QuicFrameKind::NewConnectionId)
        {
            return level == QuicEncryptionLevel::Application ? HandleNewConnectionId(frame)
                                                             : STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (frame.Kind == QuicFrameKind::RetireConnectionId)
        {
            return level == QuicEncryptionLevel::Application ? HandleRetireConnectionId(frame)
                                                             : STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (frame.Kind == QuicFrameKind::PathChallenge)
        {
            if (level != QuicEncryptionLevel::Application || frame.Data.Data == nullptr || frame.Data.Length != 8)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            QuicFrame response = {};
            response.Kind = QuicFrameKind::PathResponse;
            response.Data = frame.Data;
            return SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                   response, nullptr, 0, false, true);
        }
        if (frame.Kind == QuicFrameKind::PathResponse)
        {
            return level == QuicEncryptionLevel::Application ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (frame.Kind == QuicFrameKind::ConnectionClose)
        {
            if (frame.WireType == 0x1d && level != QuicEncryptionLevel::Application)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            EnterDraining();
            return STATUS_SUCCESS;
        }
        if (frame.Kind == QuicFrameKind::HandshakeDone)
        {
            if (level != QuicEncryptionLevel::Application || tls_.State() != QuicTlsState::Established)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            NTSTATUS status = tls_.ConfirmHandshake();
            if (NT_SUCCESS(status))
            {
#if defined(WKNET_USER_MODE_TEST)
                {
                    std::lock_guard<std::mutex> guard(lock_);
                    state_ = QuicConnectionState::Established;
                }
#else
                KIRQL irql;
                KeAcquireSpinLock(&lock_, &irql);
                state_ = QuicConnectionState::Established;
                KeReleaseSpinLock(&lock_, irql);
#endif
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.established");
                CompleteEstablishedWaiter(STATUS_SUCCESS);
            }
            return status;
        }
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS QuicConnection::HandleTlsProgress() noexcept
    {
        SIZE_T initialOutputLength = 0;
        NTSTATUS initialOutputStatus =
            tls_.TakeInitialOutput(clientHelloBuffer_.Get(), clientHelloBuffer_.Count(), &initialOutputLength);
        if (NT_SUCCESS(initialOutputStatus))
        {
            initialOutputStatus =
                SendCryptoPacket(QuicPacketType::Initial, QuicPacketNumberSpace::Initial, initialWriteKey_,
                                 initialCryptoSendOffset_, clientHelloBuffer_.Get(), initialOutputLength, true);
            if (NT_SUCCESS(initialOutputStatus))
            {
                initialCryptoSendOffset_ += initialOutputLength;
            }
            return initialOutputStatus;
        }
        if (initialOutputStatus != STATUS_NOT_FOUND)
        {
            return initialOutputStatus;
        }

        if (!peerTransportParametersApplied_ && tls_.State() >= QuicTlsState::AwaitCertificate)
        {
            const QuicTransportParameters& parameters = tls_.PeerTransportParameters();
            if (parameters.OriginalDestinationConnectionId.Length != initialDestinationConnectionIdLength_ ||
                RtlCompareMemory(parameters.OriginalDestinationConnectionId.Data, initialDestinationConnectionId_,
                                 initialDestinationConnectionIdLength_) != initialDestinationConnectionIdLength_ ||
                parameters.InitialSourceConnectionId.Length != peerConnectionIdLength_ ||
                RtlCompareMemory(parameters.InitialSourceConnectionId.Data, peerConnectionId_,
                                 peerConnectionIdLength_) != peerConnectionIdLength_)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const QuicBufferView retrySourceConnectionId = attempt_.RetrySourceConnectionId();
            if (attempt_.RetryAccepted())
            {
                if (parameters.RetrySourceConnectionId.Length != retrySourceConnectionId.Length ||
                    RtlCompareMemory(parameters.RetrySourceConnectionId.Data, retrySourceConnectionId.Data,
                                     retrySourceConnectionId.Length) != retrySourceConnectionId.Length)
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            else if (parameters.RetrySourceConnectionId.Length != 0)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            NTSTATUS status = flowControl_.OnMaxData(parameters.InitialMaxData);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            peerMaxStreamsBidi_ = parameters.InitialMaxStreamsBidi < WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS
                                      ? parameters.InitialMaxStreamsBidi
                                      : WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS;
            peerMaxStreamsUni_ = parameters.InitialMaxStreamsUni < WKNET_HARD_MAX_QUIC_LOCAL_UNI_STREAMS
                                     ? parameters.InitialMaxStreamsUni
                                     : WKNET_HARD_MAX_QUIC_LOCAL_UNI_STREAMS;
            WKNET_TRACE(
                ComponentQuic, TraceLevel::Info,
                "quic.transport_parameters.applied max_data=%I64u max_stream_bidi_local=%I64u "
                "max_stream_bidi_remote=%I64u max_stream_uni=%I64u max_streams_bidi=%I64u max_streams_uni=%I64u",
                parameters.InitialMaxData, parameters.InitialMaxStreamDataBidiLocal,
                parameters.InitialMaxStreamDataBidiRemote, parameters.InitialMaxStreamDataUni, peerMaxStreamsBidi_,
                peerMaxStreamsUni_);
            if (parameters.StatelessResetToken.Length == 16 && peerConnectionIdCount_ != 0)
            {
                RtlCopyMemory(peerConnectionIds_[0].StatelessResetToken, parameters.StatelessResetToken.Data, 16);
                peerConnectionIds_[0].HasStatelessResetToken = true;
            }
            if (parameters.MaxIdleTimeout != 0)
            {
                if (parameters.MaxIdleTimeout > (~0ULL / 10000ULL))
                {
                    return STATUS_INTEGER_OVERFLOW;
                }
                const ULONGLONG peerIdleTimeout = parameters.MaxIdleTimeout * 10000ULL;
                if (idleTimeout100ns_ == 0 || peerIdleTimeout < idleTimeout100ns_)
                {
                    idleTimeout100ns_ = peerIdleTimeout;
                }
            }
            peerTransportParametersApplied_ = true;
        }
        if (tls_.State() == QuicTlsState::Failed)
        {
            return STATUS_CONNECTION_ABORTED;
        }
        if (tls_.State() == QuicTlsState::Established && !clientFinishedSent_)
        {
            NTSTATUS status = InstallApplicationKeys();
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            SIZE_T outputLength = 0;
            status = tls_.TakeHandshakeOutput(clientHelloBuffer_.Get(), clientHelloBuffer_.Count(), &outputLength);
            if (status == STATUS_INVALID_PARAMETER)
            {
                return STATUS_SUCCESS;
            }
            if (NT_SUCCESS(status))
            {
                status = SendCryptoPacket(QuicPacketType::Handshake, QuicPacketNumberSpace::Handshake,
                                          tls_.HandshakeWriteKey(), handshakeCryptoSendOffset_,
                                          clientHelloBuffer_.Get(), outputLength, false);
                if (NT_SUCCESS(status))
                {
                    handshakeCryptoSendOffset_ += outputLength;
                    clientFinishedSent_ = true;
                }
            }
            return status;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicConnection::SendAck(QuicPacketNumberSpace space) noexcept
    {
        const SIZE_T spaceIndex = static_cast<SIZE_T>(space);
        SIZE_T rangeCount = 0;
        NTSTATUS status =
            ackTrackers_[spaceIndex].CopyRanges(ackRangeScratch_.Get(), ackRangeScratch_.Count(), &rangeCount);
        if (!NT_SUCCESS(status) || rangeCount == 0)
        {
            return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        }
        QuicFrame frame = {};
        frame.Kind = QuicFrameKind::Ack;
        QuicPacketType packetType = QuicPacketType::Initial;
        const QuicPacketKeySet* key = &initialWriteKey_;
        bool padInitial = true;
        if (space == QuicPacketNumberSpace::Handshake)
        {
            packetType = QuicPacketType::Handshake;
            key = &tls_.HandshakeWriteKey();
            padInitial = false;
        }
        else if (space == QuicPacketNumberSpace::Application)
        {
            packetType = QuicPacketType::OneRtt;
            key = &applicationWriteKey_;
            padInitial = false;
        }
        status = SendFramePacket(packetType, space, *key, frame, ackRangeScratch_.Get(), rangeCount, padInitial, false);
        if (NT_SUCCESS(status))
        {
            ackTrackers_[spaceIndex].OnAckSent();
        }
        return status;
    }

} // namespace wknet::quic
