#if !defined(WKNET_USER_MODE_TEST)
#include <ntifs.h>
#endif
#include "quic/QuicConnectionPrivate.hpp"
#include <wknet/crypto/CngProvider.h>
namespace wknet::quic
{
#if defined(WKNET_USER_MODE_TEST)
    bool g_failWorkerStart = false;
#endif

    namespace
    {
        constexpr LONG OperationPending = 0;
        constexpr LONG OperationQueued = 1;
        constexpr LONG OperationCompleting = 2;
        constexpr LONG OperationCompleted = 3;

        ULONG SocketAddressLength(USHORT family) noexcept
        {
            return family == AF_INET ? sizeof(SOCKADDR_IN) : (family == AF_INET6 ? sizeof(SOCKADDR_IN6) : 0);
        }

        bool TryClaimOperation(QuicOperation* operation) noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            std::lock_guard<std::mutex> guard(operation->Lock);
            if (operation->CompletionState != OperationPending)
            {
                return false;
            }

            operation->CompletionState = OperationQueued;
            return true;
#else
            return InterlockedCompareExchange(&operation->CompletionState, OperationQueued, OperationPending) ==
                   OperationPending;
#endif
        }

        void ReleaseOperationClaim(QuicOperation* operation) noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            std::lock_guard<std::mutex> guard(operation->Lock);
            if (operation->CompletionState == OperationQueued)
            {
                operation->CompletionState = OperationPending;
            }
#else
            InterlockedCompareExchange(&operation->CompletionState, OperationPending, OperationQueued);
#endif
        }

        ULONGLONG EarlierDeadline(ULONGLONG current, ULONGLONG candidate) noexcept
        {
            return candidate != 0 && (current == 0 || candidate < current) ? candidate : current;
        }

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

    void QuicOperationInitialize(QuicOperation* op) noexcept
    {
        if (op == nullptr)
        {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        std::lock_guard<std::mutex> guard(op->Lock);
#endif
        op->Status = STATUS_PENDING;
        op->StreamId = 0;
        op->BytesTransferred = 0;
        op->Fin = false;
        op->CompletionState = OperationPending;
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeEvent(&op->Event, NotificationEvent, FALSE);
#endif
    }
    NTSTATUS QuicOperationWait(QuicOperation* op, ULONG timeoutMs) noexcept
    {
        if (op == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(WKNET_USER_MODE_TEST)
        std::unique_lock<std::mutex> lock(op->Lock);
        const bool done =
            timeoutMs == 0xffffffffUL
                ? (op->Event.wait(lock, [op]() { return op->CompletionState == OperationCompleted; }), true)
                : op->Event.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                                     [op]() { return op->CompletionState == OperationCompleted; });
        return done ? op->Status : STATUS_IO_TIMEOUT;
#else
        LARGE_INTEGER timeout = {};
        timeout.QuadPart = -static_cast<LONGLONG>(timeoutMs) * 10000LL;
        NTSTATUS s = KeWaitForSingleObject(&op->Event, Executive, KernelMode, FALSE,
                                           timeoutMs == 0xffffffffUL ? nullptr : &timeout);
        return s == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : (NT_SUCCESS(s) ? op->Status : s);
#endif
    }
    QuicConnection::~QuicConnection() noexcept { Shutdown(); }
    NTSTATUS QuicConnection::Initialize(const QuicConnectionCreateOptions& o) noexcept
    {
        if (o.CommandCapacity == 0 || o.CommandCapacity > WKNET_HARD_MAX_QUIC_COMMANDS)
        {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS s = queue_.Allocate(o.CommandCapacity);
        if (!NT_SUCCESS(s))
        {
            return s;
        }

        constexpr SIZE_T streamCapacity = WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS +
                                          WKNET_HARD_MAX_QUIC_PEER_BIDI_STREAMS +
                                          WKNET_HARD_MAX_QUIC_LOCAL_UNI_STREAMS + WKNET_HARD_MAX_QUIC_PEER_UNI_STREAMS;
        s = streams_.Allocate(streamCapacity);
        if (!NT_SUCCESS(s))
        {
            return s;
        }
        s = localConnectionIds_.Allocate(WKNET_HARD_MAX_QUIC_CONNECTION_IDS);
        if (NT_SUCCESS(s))
        {
            s = peerConnectionIds_.Allocate(WKNET_HARD_MAX_QUIC_CONNECTION_IDS);
        }
        if (!NT_SUCCESS(s))
        {
            return s;
        }
        if (o.ApplicationEventSink != nullptr)
        {
            applicationEventSink_ = *o.ApplicationEventSink;
        }

        if (o.DatagramClient != nullptr)
        {
            if (o.RemoteAddress == nullptr || o.ServerName == nullptr || o.ServerNameLength == 0 ||
                o.ServerNameLength > 253 || o.InitialDestinationConnectionId.Data == nullptr ||
                o.InitialDestinationConnectionId.Length == 0 ||
                o.InitialDestinationConnectionId.Length > QuicMaximumConnectionIdLength ||
                o.InitialSourceConnectionId.Data == nullptr || o.InitialSourceConnectionId.Length == 0 ||
                o.InitialSourceConnectionId.Length > QuicMaximumConnectionIdLength ||
                o.RemoteAddressLength != SocketAddressLength(o.RemoteAddress->sa_family))
            {
                return STATUS_INVALID_PARAMETER;
            }
            s = serverName_.Allocate(o.ServerNameLength + 1);
            if (NT_SUCCESS(s))
            {
                s = receiveBuffer_.Allocate(WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES);
            }
            if (NT_SUCCESS(s))
            {
                s = packetBuffer_.Allocate(WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES);
            }
            if (NT_SUCCESS(s))
            {
                s = packetHeaderScratch_.Allocate(1);
            }
            if (NT_SUCCESS(s))
            {
                s = decryptBuffer_.Allocate(WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES);
            }
            if (NT_SUCCESS(s))
            {
                s = frameBuffer_.Allocate(WKNET_HARD_MAX_QUIC_FRAME_BYTES);
            }
            if (NT_SUCCESS(s))
            {
                s = frameParseScratch_.Allocate(1);
            }
            if (NT_SUCCESS(s))
            {
                s = clientHelloBuffer_.Allocate(tls::Tls13MaxExtensionsLength + 4096);
            }
            if (NT_SUCCESS(s))
            {
                s = ackRangeScratch_.Allocate(WKNET_HARD_MAX_QUIC_ACK_RANGES);
            }
            if (!NT_SUCCESS(s))
            {
                return s;
            }
            RtlCopyMemory(serverName_.Get(), o.ServerName, o.ServerNameLength);
            serverName_[o.ServerNameLength] = '\0';
            RtlCopyMemory(&remoteAddress_, o.RemoteAddress, o.RemoteAddressLength);
            remoteAddressLength_ = o.RemoteAddressLength;
            RtlCopyMemory(initialDestinationConnectionId_, o.InitialDestinationConnectionId.Data,
                          o.InitialDestinationConnectionId.Length);
            initialDestinationConnectionIdLength_ = o.InitialDestinationConnectionId.Length;
            RtlCopyMemory(sourceConnectionId_, o.InitialSourceConnectionId.Data, o.InitialSourceConnectionId.Length);
            sourceConnectionIdLength_ = o.InitialSourceConnectionId.Length;
            RtlCopyMemory(peerConnectionId_, initialDestinationConnectionId_, initialDestinationConnectionIdLength_);
            peerConnectionIdLength_ = initialDestinationConnectionIdLength_;
            QuicConnectionIdEntry& localConnectionId = localConnectionIds_[localConnectionIdCount_++];
            localConnectionId.Sequence = 0;
            localConnectionId.ConnectionIdLength = sourceConnectionIdLength_;
            RtlCopyMemory(localConnectionId.ConnectionId, sourceConnectionId_, sourceConnectionIdLength_);
            QuicConnectionIdEntry& peerConnectionId = peerConnectionIds_[peerConnectionIdCount_++];
            peerConnectionId.Sequence = 0;
            peerConnectionId.ConnectionIdLength = peerConnectionIdLength_;
            RtlCopyMemory(peerConnectionId.ConnectionId, peerConnectionId_, peerConnectionIdLength_);
            datagramClient_ = o.DatagramClient;
            certificateStore_ = o.CertificateStore;
            certificateScratchAllocator_ = o.CertificateScratchAllocator;
            providerCache_ = o.ProviderCache;
            sessionCache_ = o.SessionCache;
            tokenCache_ = o.TokenCache;
            clientCredential_ = o.ClientCredential;
            verifyCertificate_ = o.VerifyCertificate;
            requireRevocationCheck_ = o.RequireRevocationCheck;
            networkEnabled_ = true;
        }
        else
        {
            peerMaxStreamsBidi_ = WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS;
            peerMaxStreamsUni_ = WKNET_HARD_MAX_QUIC_LOCAL_UNI_STREAMS;
            s = flowControl_.Initialize(WKNET_HARD_MAX_QUIC_CONNECTION_REASSEMBLY_BYTES,
                                        WKNET_HARD_MAX_QUIC_CONNECTION_REASSEMBLY_BYTES);
            if (!NT_SUCCESS(s))
            {
                return s;
            }
        }

        suspended_ = o.StartWorkerSuspended;
#if defined(WKNET_USER_MODE_TEST)
        if (g_failWorkerStart)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        worker_ = std::thread(WorkerEntry, this);
#else
        KeInitializeSpinLock(&lock_);
        KeInitializeEvent(&wake_, NotificationEvent, FALSE);
        HANDLE handle = nullptr;
        s = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, WorkerEntry, this);
        if (!NT_SUCCESS(s))
        {
            return s;
        }

        s = ObReferenceObjectByHandle(handle, SYNCHRONIZE, *PsThreadType, KernelMode,
                                      reinterpret_cast<void**>(&worker_), nullptr);
        if (!NT_SUCCESS(s))
        {
            KIRQL irql;
            KeAcquireSpinLock(&lock_, &irql);
            stop_ = true;
            suspended_ = false;
            KeReleaseSpinLock(&lock_, irql);
            KeSetEvent(&wake_, IO_NO_INCREMENT, FALSE);
            ZwWaitForSingleObject(handle, FALSE, nullptr);
            ZwClose(handle);
            return s;
        }
        ZwClose(handle);
#endif
        return STATUS_SUCCESS;
    }
    void QuicConnection::Complete(QuicOperation* op, NTSTATUS status, ULONGLONG streamId, SIZE_T bytesTransferred,
                                  bool fin) noexcept
    {
        if (op == nullptr)
        {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        std::lock_guard<std::mutex> guard(op->Lock);
        if (op->CompletionState != OperationQueued)
        {
            return;
        }

        op->CompletionState = OperationCompleting;
        op->Status = status;
        op->StreamId = streamId;
        op->BytesTransferred = bytesTransferred;
        op->Fin = fin;
        op->CompletionState = OperationCompleted;
        op->Event.notify_all();
#else
        if (InterlockedCompareExchange(&op->CompletionState, OperationCompleting, OperationQueued) != OperationQueued)
        {
            return;
        }

        op->Status = status;
        op->StreamId = streamId;
        op->BytesTransferred = bytesTransferred;
        op->Fin = fin;
        KeMemoryBarrier();
        InterlockedExchange(&op->CompletionState, OperationCompleted);
        KeSetEvent(&op->Event, IO_NO_INCREMENT, FALSE);
#endif
    }

    void QuicConnection::CompleteEstablishedWaiter(NTSTATUS status) noexcept
    {
        QuicOperation* operation = nullptr;
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            terminalConnectionStatus_ = status;
            operation = establishedOperation_;
            establishedOperation_ = nullptr;
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        terminalConnectionStatus_ = status;
        operation = establishedOperation_;
        establishedOperation_ = nullptr;
        KeReleaseSpinLock(&lock_, irql);
#endif
        Complete(operation, status);
    }

    NTSTATUS QuicConnection::WaitEstablished(QuicOperation* operation) noexcept
    {
        if (operation == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (!TryClaimOperation(operation))
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        NTSTATUS registrationStatus = STATUS_PENDING;
        NTSTATUS completionStatus = STATUS_SUCCESS;
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            if (state_ == QuicConnectionState::Established)
            {
                registrationStatus = STATUS_SUCCESS;
            }
            else if (state_ == QuicConnectionState::Failed || state_ == QuicConnectionState::Closing ||
                     state_ == QuicConnectionState::Draining || state_ == QuicConnectionState::Closed || stop_)
            {
                registrationStatus = STATUS_SUCCESS;
                completionStatus = terminalConnectionStatus_;
            }
            else if ((state_ == QuicConnectionState::Idle && !connectQueued_) || establishedOperation_ != nullptr)
            {
                registrationStatus = STATUS_INVALID_DEVICE_STATE;
            }
            else
            {
                establishedOperation_ = operation;
            }
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        if (state_ == QuicConnectionState::Established)
        {
            registrationStatus = STATUS_SUCCESS;
        }
        else if (state_ == QuicConnectionState::Failed || state_ == QuicConnectionState::Closing ||
                 state_ == QuicConnectionState::Draining || state_ == QuicConnectionState::Closed || stop_)
        {
            registrationStatus = STATUS_SUCCESS;
            completionStatus = terminalConnectionStatus_;
        }
        else if ((state_ == QuicConnectionState::Idle && !connectQueued_) || establishedOperation_ != nullptr)
        {
            registrationStatus = STATUS_INVALID_DEVICE_STATE;
        }
        else
        {
            establishedOperation_ = operation;
        }
        KeReleaseSpinLock(&lock_, irql);
#endif

        if (registrationStatus == STATUS_PENDING)
        {
            return STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(registrationStatus))
        {
            ReleaseOperationClaim(operation);
            return registrationStatus;
        }
        Complete(operation, completionStatus);
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicConnection::Enqueue(QuicCommandType type, QuicOperation* op, ULONGLONG streamId, const UCHAR* data,
                                     SIZE_T dataLength, UCHAR* output, bool fin, ULONGLONG errorCode,
                                     QuicApplicationCommandCallback applicationCallback,
                                     void* applicationContext) noexcept
    {
        if (op == nullptr || streamId > QuicVarIntMaximum || errorCode > QuicVarIntMaximum ||
            (type == QuicCommandType::WriteStream && data == nullptr && dataLength != 0) ||
            (type == QuicCommandType::ConsumeStream && output == nullptr && dataLength != 0) ||
            (type == QuicCommandType::Application && applicationCallback == nullptr))
        {
            return STATUS_INVALID_PARAMETER;
        }

        QuicCommand* command =
            AllocateProtocolNonPagedObject<QuicCommand>(rtl::ProtocolAllocationSite::QuicCommandObject);
        if (command == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (!TryClaimOperation(op))
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, command);
            return STATUS_INVALID_DEVICE_STATE;
        }

        command->Type = type;
        command->Operation = op;
        command->StreamId = streamId;
        command->ErrorCode = errorCode;
        command->ApplicationCallback = applicationCallback;
        command->ApplicationContext = applicationContext;
        command->Output = output;
        command->Length = dataLength;
        command->Fin = fin;
        if (type == QuicCommandType::WriteStream && dataLength != 0)
        {
            const NTSTATUS allocationStatus = command->Data.Allocate(dataLength);
            if (!NT_SUCCESS(allocationStatus))
            {
                ReleaseOperationClaim(op);
                FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, command);
                return allocationStatus;
            }
            RtlCopyMemory(command->Data.Get(), data, dataLength);
        }
        if (type == QuicCommandType::InjectFrame)
        {
            if (data == nullptr || dataLength != sizeof(QuicFrame) ||
                streamId > static_cast<ULONGLONG>(QuicEncryptionLevel::Application) ||
                errorCode > static_cast<ULONGLONG>(QuicPacketNumberSpace::Application))
            {
                ReleaseOperationClaim(op);
                FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, command);
                return STATUS_INVALID_PARAMETER;
            }
            command->Frame = *reinterpret_cast<const QuicFrame*>(data);
            command->Level = static_cast<QuicEncryptionLevel>(streamId);
            command->Space = static_cast<QuicPacketNumberSpace>(errorCode);
            const QuicBufferView primary = command->Frame.Data.Length != 0 ? command->Frame.Data
                                                                           : (command->Frame.ConnectionId.Length != 0
                                                                                  ? command->Frame.ConnectionId
                                                                                  : command->Frame.ReasonPhrase);
            if (primary.Length != 0)
            {
                NTSTATUS allocationStatus = command->Data.Allocate(primary.Length);
                if (!NT_SUCCESS(allocationStatus))
                {
                    ReleaseOperationClaim(op);
                    FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, command);
                    return allocationStatus;
                }
                RtlCopyMemory(command->Data.Get(), primary.Data, primary.Length);
                if (command->Frame.Data.Length != 0)
                {
                    command->Frame.Data = {command->Data.Get(), command->Data.Count()};
                }
                else if (command->Frame.ConnectionId.Length != 0)
                {
                    command->Frame.ConnectionId = {command->Data.Get(), command->Data.Count()};
                }
                else
                {
                    command->Frame.ReasonPhrase = {command->Data.Get(), command->Data.Count()};
                }
            }
            if (command->Frame.StatelessResetToken.Length != 0)
            {
                NTSTATUS allocationStatus = command->AuxiliaryData.Allocate(command->Frame.StatelessResetToken.Length);
                if (!NT_SUCCESS(allocationStatus))
                {
                    ReleaseOperationClaim(op);
                    FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, command);
                    return allocationStatus;
                }
                RtlCopyMemory(command->AuxiliaryData.Get(), command->Frame.StatelessResetToken.Data,
                              command->Frame.StatelessResetToken.Length);
                command->Frame.StatelessResetToken = {command->AuxiliaryData.Get(), command->AuxiliaryData.Count()};
            }
        }
        NTSTATUS status = STATUS_SUCCESS;
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            if (stop_ || state_ == QuicConnectionState::Closed || state_ == QuicConnectionState::Failed ||
                ((closeQueued_ || state_ == QuicConnectionState::Closing || state_ == QuicConnectionState::Draining) &&
                 type != QuicCommandType::ProcessTimer))
            {
                status = STATUS_DEVICE_NOT_READY;
            }
            else if (type == QuicCommandType::Connect && (state_ != QuicConnectionState::Idle || connectQueued_))
            {
                status = STATUS_INVALID_DEVICE_STATE;
            }
            else if ((type == QuicCommandType::Close || type == QuicCommandType::CloseApplication) &&
                     state_ != QuicConnectionState::Connecting && state_ != QuicConnectionState::Handshaking &&
                     state_ != QuicConnectionState::Established)
            {
                status = STATUS_INVALID_DEVICE_STATE;
            }
            else if (count_ >= queue_.Count())
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else
            {
                queue_[(head_ + count_) % queue_.Count()] = command;
                ++count_;
                connectQueued_ = type == QuicCommandType::Connect ? true : connectQueued_;
                closeQueued_ =
                    type == QuicCommandType::Close || type == QuicCommandType::CloseApplication ? true : closeQueued_;
            }
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        if (stop_ || state_ == QuicConnectionState::Closed || state_ == QuicConnectionState::Failed ||
            ((closeQueued_ || state_ == QuicConnectionState::Closing || state_ == QuicConnectionState::Draining) &&
             type != QuicCommandType::ProcessTimer))
        {
            status = STATUS_DEVICE_NOT_READY;
        }
        else if (type == QuicCommandType::Connect && (state_ != QuicConnectionState::Idle || connectQueued_))
        {
            status = STATUS_INVALID_DEVICE_STATE;
        }
        else if ((type == QuicCommandType::Close || type == QuicCommandType::CloseApplication) &&
                 state_ != QuicConnectionState::Connecting && state_ != QuicConnectionState::Handshaking &&
                 state_ != QuicConnectionState::Established)
        {
            status = STATUS_INVALID_DEVICE_STATE;
        }
        else if (count_ >= queue_.Count())
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            queue_[(head_ + count_) % queue_.Count()] = command;
            ++count_;
            connectQueued_ = type == QuicCommandType::Connect ? true : connectQueued_;
            closeQueued_ =
                type == QuicCommandType::Close || type == QuicCommandType::CloseApplication ? true : closeQueued_;
        }
        KeReleaseSpinLock(&lock_, irql);
#endif

        if (!NT_SUCCESS(status))
        {
            ReleaseOperationClaim(op);
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, command);
            return status;
        }

#if defined(WKNET_USER_MODE_TEST)
        wake_.notify_all();
#else
        KeSetEvent(&wake_, IO_NO_INCREMENT, FALSE);
#endif
        return status;
    }
    bool QuicConnection::Dequeue(QuicCommand** out) noexcept
    {
        *out = nullptr;
#if defined(WKNET_USER_MODE_TEST)
        std::lock_guard<std::mutex> guard(lock_);
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
#endif
        if (count_ != 0)
        {
            *out = queue_[head_];
            queue_[head_] = nullptr;
            head_ = (head_ + 1) % queue_.Count();
            --count_;
        }
#if !defined(WKNET_USER_MODE_TEST)
        if (count_ == 0 && !receiveReady_)
            KeClearEvent(&wake_);
        KeReleaseSpinLock(&lock_, irql);
#endif
        return *out != nullptr;
    }

    bool QuicConnection::ShouldStop() const noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        std::lock_guard<std::mutex> guard(lock_);
        return stop_;
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        const bool stop = stop_;
        KeReleaseSpinLock(&lock_, irql);
        return stop;
#endif
    }

    bool QuicConnection::IsWorkerThread() const noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return worker_.joinable() && std::this_thread::get_id() == worker_.get_id();
#else
        return worker_ != nullptr && PsGetCurrentThread() == worker_;
#endif
    }

    QuicStream* QuicConnection::FindStream(ULONGLONG streamId) noexcept
    {
        for (SIZE_T index = 0; index < streamCount_; ++index)
        {
            if (streams_[index] != nullptr && streams_[index]->Id() == streamId)
            {
                return streams_[index];
            }
        }
        return nullptr;
    }

    NTSTATUS QuicConnection::CreateStream(ULONGLONG streamId, QuicStream** stream) noexcept
    {
        if (stream != nullptr)
        {
            *stream = nullptr;
        }
        if (stream == nullptr || streamId > QuicVarIntMaximum || FindStream(streamId) != nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (streamCount_ >= streams_.Count())
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const bool clientInitiated = QuicStreamIsClientInitiated(streamId);
        const bool bidirectional = QuicStreamIsBidirectional(streamId);
        const ULONGLONG ordinal = streamId >> 2;
        if (clientInitiated)
        {
            const ULONGLONG limit = bidirectional ? peerMaxStreamsBidi_ : peerMaxStreamsUni_;
            if (ordinal >= limit)
            {
                return STATUS_DEVICE_BUSY;
            }
        }
        else
        {
            const ULONGLONG limit =
                bidirectional ? WKNET_HARD_MAX_QUIC_PEER_BIDI_STREAMS : WKNET_HARD_MAX_QUIC_PEER_UNI_STREAMS;
            if (ordinal >= limit)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        QuicStream* created = AllocateProtocolNonPagedObject<QuicStream>(rtl::ProtocolAllocationSite::QuicStreamObject);
        if (created == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NTSTATUS status = created->Initialize(streamId);
        if (NT_SUCCESS(status) && (bidirectional || !clientInitiated))
        {
            status = created->SetReceiveLimit(WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES);
        }
        if (NT_SUCCESS(status) && (bidirectional || clientInitiated))
        {
            ULONGLONG sendLimit = WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES;
            if (networkEnabled_ && peerTransportParametersApplied_)
            {
                const QuicTransportParameters& parameters = tls_.PeerTransportParameters();
                sendLimit = bidirectional ? (clientInitiated ? parameters.InitialMaxStreamDataBidiRemote
                                                             : parameters.InitialMaxStreamDataBidiLocal)
                                          : parameters.InitialMaxStreamDataUni;
            }
            status = created->SetSendLimit(sendLimit);
        }
        if (!NT_SUCCESS(status))
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicStreamObject, created);
            return status;
        }

        streams_[streamCount_++] = created;
        *stream = created;
        created->SetApplicationEventSink(&applicationEventSink_);
        return STATUS_SUCCESS;
    }

    void QuicConnection::ClearStreams() noexcept
    {
        for (SIZE_T index = 0; index < streamCount_; ++index)
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicStreamObject, streams_[index]);
            streams_[index] = nullptr;
        }
        streamCount_ = 0;
    }

    bool QuicConnection::IsLocalConnectionId(QuicBufferView connectionId) const noexcept
    {
        for (SIZE_T index = 0; index < localConnectionIdCount_; ++index)
        {
            const QuicConnectionIdEntry& entry = localConnectionIds_[index];
            const bool accepted =
                !entry.Retired || (entry.RetireDeadline100ns != 0 && QuicClockNow100ns() < entry.RetireDeadline100ns);
            if (accepted && entry.ConnectionIdLength == connectionId.Length &&
                RtlCompareMemory(entry.ConnectionId, connectionId.Data, connectionId.Length) == connectionId.Length)
            {
                return true;
            }
        }
        return false;
    }

    bool QuicConnection::MatchesStatelessReset(const UCHAR* packet, SIZE_T packetLength) const noexcept
    {
        if (packet == nullptr || packetLength < 21)
        {
            return false;
        }
        const UCHAR* candidate = packet + packetLength - 16;
        for (SIZE_T index = 0; index < peerConnectionIdCount_; ++index)
        {
            const QuicConnectionIdEntry& entry = peerConnectionIds_[index];
            const bool tokenActive =
                !entry.Retired || (entry.RetireDeadline100ns != 0 && QuicClockNow100ns() < entry.RetireDeadline100ns);
            if (tokenActive && entry.HasStatelessResetToken)
            {
                UCHAR difference = 0;
                for (SIZE_T byteIndex = 0; byteIndex < sizeof(entry.StatelessResetToken); ++byteIndex)
                {
                    difference |= static_cast<UCHAR>(entry.StatelessResetToken[byteIndex] ^ candidate[byteIndex]);
                }
                if (difference == 0)
                {
                    return true;
                }
            }
        }
        return false;
    }

    NTSTATUS QuicConnection::IssueConnectionId() noexcept
    {
        if (localConnectionIdCount_ >= localConnectionIds_.Count() || sourceConnectionIdLength_ == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T activeCount = 0;
        for (SIZE_T index = 0; index < localConnectionIdCount_; ++index)
        {
            activeCount += localConnectionIds_[index].Retired ? 0 : 1;
        }
        const ULONGLONG peerLimit =
            peerTransportParametersApplied_ ? tls_.PeerTransportParameters().ActiveConnectionIdLimit : 2;
        const ULONGLONG activeLimit =
            peerLimit < WKNET_HARD_MAX_QUIC_CONNECTION_IDS ? peerLimit : WKNET_HARD_MAX_QUIC_CONNECTION_IDS;
        if (activeCount >= activeLimit)
        {
            return STATUS_DEVICE_BUSY;
        }

        QuicConnectionIdEntry candidate = {};
        candidate.Sequence = nextLocalConnectionIdSequence_;
        candidate.ConnectionIdLength = sourceConnectionIdLength_;
        NTSTATUS status = crypto::CngProvider::GenerateRandom(candidate.ConnectionId, candidate.ConnectionIdLength);
        if (NT_SUCCESS(status))
        {
            status = crypto::CngProvider::GenerateRandom(candidate.StatelessResetToken,
                                                         sizeof(candidate.StatelessResetToken));
        }
        if (!NT_SUCCESS(status))
        {
            RtlSecureZeroMemory(&candidate, sizeof(candidate));
            return status;
        }
        candidate.HasStatelessResetToken = true;

        for (SIZE_T index = 0; index < localConnectionIdCount_; ++index)
        {
            if (localConnectionIds_[index].ConnectionIdLength == candidate.ConnectionIdLength &&
                RtlCompareMemory(localConnectionIds_[index].ConnectionId, candidate.ConnectionId,
                                 candidate.ConnectionIdLength) == candidate.ConnectionIdLength)
            {
                RtlSecureZeroMemory(&candidate, sizeof(candidate));
                return STATUS_RETRY;
            }
        }

        QuicFrame frame = {};
        frame.Kind = QuicFrameKind::NewConnectionId;
        frame.Sequence = candidate.Sequence;
        frame.RetirePriorTo = 0;
        frame.ConnectionId = {candidate.ConnectionId, candidate.ConnectionIdLength};
        frame.StatelessResetToken = {candidate.StatelessResetToken, sizeof(candidate.StatelessResetToken)};
        status = SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                 frame, nullptr, 0, false, true);
        if (NT_SUCCESS(status))
        {
            localConnectionIds_[localConnectionIdCount_++] = candidate;
            ++nextLocalConnectionIdSequence_;
        }
        RtlSecureZeroMemory(&candidate, sizeof(candidate));
        return status;
    }

    NTSTATUS QuicConnection::HandleNewConnectionId(const QuicFrame& frame) noexcept
    {
        if (frame.ConnectionId.Data == nullptr || frame.ConnectionId.Length == 0 ||
            frame.ConnectionId.Length > QuicMaximumConnectionIdLength || frame.StatelessResetToken.Data == nullptr ||
            frame.StatelessResetToken.Length != 16 || frame.RetirePriorTo > frame.Sequence)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        for (SIZE_T index = 0; index < peerConnectionIdCount_; ++index)
        {
            QuicConnectionIdEntry& entry = peerConnectionIds_[index];
            if (entry.Sequence == frame.Sequence)
            {
                const bool sameConnectionId = entry.ConnectionIdLength == frame.ConnectionId.Length &&
                                              RtlCompareMemory(entry.ConnectionId, frame.ConnectionId.Data,
                                                               frame.ConnectionId.Length) == frame.ConnectionId.Length;
                const bool sameToken =
                    entry.HasStatelessResetToken &&
                    RtlCompareMemory(entry.StatelessResetToken, frame.StatelessResetToken.Data, 16) == 16;
                return sameConnectionId && sameToken ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
            }
            if ((entry.ConnectionIdLength == frame.ConnectionId.Length &&
                 RtlCompareMemory(entry.ConnectionId, frame.ConnectionId.Data, frame.ConnectionId.Length) ==
                     frame.ConnectionId.Length) ||
                (entry.HasStatelessResetToken &&
                 RtlCompareMemory(entry.StatelessResetToken, frame.StatelessResetToken.Data, 16) == 16))
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        if (peerConnectionIdCount_ >= peerConnectionIds_.Count())
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        QuicConnectionIdEntry& added = peerConnectionIds_[peerConnectionIdCount_++];
        added.Sequence = frame.Sequence;
        added.ConnectionIdLength = frame.ConnectionId.Length;
        RtlCopyMemory(added.ConnectionId, frame.ConnectionId.Data, frame.ConnectionId.Length);
        RtlCopyMemory(added.StatelessResetToken, frame.StatelessResetToken.Data, 16);
        added.HasStatelessResetToken = true;

        SIZE_T activeCount = 0;
        QuicConnectionIdEntry* replacement = nullptr;
        for (SIZE_T index = 0; index < peerConnectionIdCount_; ++index)
        {
            QuicConnectionIdEntry& entry = peerConnectionIds_[index];
            if (entry.Sequence < frame.RetirePriorTo && !entry.Retired)
            {
                QuicFrame retire = {};
                retire.Kind = QuicFrameKind::RetireConnectionId;
                retire.Sequence = entry.Sequence;
                const NTSTATUS retireStatus =
                    SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                    retire, nullptr, 0, false, true);
                if (!NT_SUCCESS(retireStatus))
                {
                    return retireStatus;
                }
                entry.Retired = true;
                const ULONGLONG pto = recovery_.PtoPeriod100ns(
                    QuicPacketNumberSpace::Application,
                    peerTransportParametersApplied_ ? tls_.PeerTransportParameters().MaxAckDelay : 25);
                entry.RetireDeadline100ns = DeadlineAfter(QuicClockNow100ns(), pto, 3);
            }
            if (!entry.Retired)
            {
                ++activeCount;
                if (replacement == nullptr || entry.Sequence < replacement->Sequence)
                {
                    replacement = &entry;
                }
            }
        }
        if (activeCount == 0 || activeCount > WKNET_HARD_MAX_QUIC_CONNECTION_IDS)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        QuicConnectionIdEntry* current = nullptr;
        for (SIZE_T index = 0; index < peerConnectionIdCount_; ++index)
        {
            if (peerConnectionIds_[index].Sequence == currentPeerConnectionIdSequence_)
            {
                current = &peerConnectionIds_[index];
                break;
            }
        }
        if (current == nullptr || current->Retired)
        {
            currentPeerConnectionIdSequence_ = replacement->Sequence;
            peerConnectionIdLength_ = replacement->ConnectionIdLength;
            RtlCopyMemory(peerConnectionId_, replacement->ConnectionId, replacement->ConnectionIdLength);
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicConnection::HandleRetireConnectionId(const QuicFrame& frame) noexcept
    {
        if (frame.Sequence >= nextLocalConnectionIdSequence_)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        QuicConnectionIdEntry* retired = nullptr;
        for (SIZE_T index = 0; index < localConnectionIdCount_; ++index)
        {
            if (localConnectionIds_[index].Sequence == frame.Sequence)
            {
                retired = &localConnectionIds_[index];
                break;
            }
        }
        if (retired == nullptr)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (retired->Retired)
        {
            return STATUS_SUCCESS;
        }

        const bool isCurrent = retired->ConnectionIdLength == sourceConnectionIdLength_ &&
                               RtlCompareMemory(retired->ConnectionId, sourceConnectionId_,
                                                sourceConnectionIdLength_) == sourceConnectionIdLength_;
        if (isCurrent)
        {
            bool issuedReplacement = false;
            QuicConnectionIdEntry* replacement = nullptr;
            for (SIZE_T index = 0; index < localConnectionIdCount_; ++index)
            {
                if (!localConnectionIds_[index].Retired && &localConnectionIds_[index] != retired)
                {
                    replacement = &localConnectionIds_[index];
                    break;
                }
            }
            if (replacement == nullptr)
            {
                NTSTATUS status = IssueConnectionId();
                if (!NT_SUCCESS(status))
                {
                    return status;
                }
                replacement = &localConnectionIds_[localConnectionIdCount_ - 1];
                issuedReplacement = true;
            }
            sourceConnectionIdLength_ = replacement->ConnectionIdLength;
            RtlCopyMemory(sourceConnectionId_, replacement->ConnectionId, replacement->ConnectionIdLength);
            retired->Retired = true;
            const ULONGLONG pto = recovery_.PtoPeriod100ns(
                QuicPacketNumberSpace::Application,
                peerTransportParametersApplied_ ? tls_.PeerTransportParameters().MaxAckDelay : 25);
            retired->RetireDeadline100ns = DeadlineAfter(QuicClockNow100ns(), pto, 3);
            return issuedReplacement ? STATUS_SUCCESS : IssueConnectionId();
        }
        retired->Retired = true;
        const ULONGLONG pto =
            recovery_.PtoPeriod100ns(QuicPacketNumberSpace::Application,
                                     peerTransportParametersApplied_ ? tls_.PeerTransportParameters().MaxAckDelay : 25);
        retired->RetireDeadline100ns = DeadlineAfter(QuicClockNow100ns(), pto, 3);
        return IssueConnectionId();
    }

    NTSTATUS QuicConnection::InstallApplicationKeys() noexcept
    {
        if (applicationKeysInstalled_)
        {
            return STATUS_SUCCESS;
        }
        if (tls_.ApplicationWriteKey().SecretLength == 0 || tls_.ApplicationReadKey().SecretLength == 0)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        applicationWriteKey_ = tls_.ApplicationWriteKey();
        applicationReadKey_ = tls_.ApplicationReadKey();
        NTSTATUS status = QuicDeriveNextPacketKeySet(applicationReadKey_, &nextApplicationReadKey_);
        if (!NT_SUCCESS(status))
        {
            QuicClearPacketKeySet(&applicationWriteKey_);
            QuicClearPacketKeySet(&applicationReadKey_);
            return status;
        }
        applicationKeysInstalled_ = true;
        sendKeyPhase_ = false;
        receiveKeyPhase_ = false;
        oneRttPacketsInSendPhase_ = 0;
        receiveKeyPhaseStartPacketNumber_ = 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicConnection::InitiateKeyUpdate() noexcept
    {
        if (!applicationKeysInstalled_ || sendKeyUpdateAwaitingAck_)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        QuicPacketKeySet next = {};
        NTSTATUS status = QuicDeriveNextPacketKeySet(applicationWriteKey_, &next);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        QuicClearPacketKeySet(&previousApplicationWriteKey_);
        previousApplicationWriteKey_ = applicationWriteKey_;
        applicationWriteKey_ = next;
        RtlSecureZeroMemory(&next, sizeof(next));
        sendKeyPhase_ = !sendKeyPhase_;
        sendKeyPhaseStartPacketNumber_ = nextPacketNumber_[static_cast<SIZE_T>(QuicPacketNumberSpace::Application)];
        oneRttPacketsInSendPhase_ = 0;
        sendKeyUpdateAwaitingAck_ = true;
        return STATUS_SUCCESS;
    }

    void QuicConnection::ConfirmSendKeyUpdate(const QuicAckRange* ranges, SIZE_T rangeCount) noexcept
    {
        if (!sendKeyUpdateAwaitingAck_ || ranges == nullptr)
        {
            return;
        }
        for (SIZE_T index = 0; index < rangeCount; ++index)
        {
            if (ranges[index].Largest >= sendKeyPhaseStartPacketNumber_)
            {
                QuicClearPacketKeySet(&previousApplicationWriteKey_);
                sendKeyUpdateAwaitingAck_ = false;
                return;
            }
        }
    }

    void QuicConnection::DiscardExpiredReadKey(ULONGLONG now100ns) noexcept
    {
        if (previousReadKeyValid_ && previousReadKeyDeadline100ns_ != 0 && now100ns >= previousReadKeyDeadline100ns_)
        {
            QuicClearPacketKeySet(&previousApplicationReadKey_);
            previousReadKeyValid_ = false;
            previousReadKeyDeadline100ns_ = 0;
        }
    }

    void QuicConnection::WakeWorker() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        wake_.notify_all();
#else
        KeSetEvent(&wake_, IO_NO_INCREMENT, FALSE);
#endif
    }

    ULONGLONG QuicConnection::NextDeadline100ns() const noexcept
    {
        ULONGLONG deadline = 0;
        const ULONGLONG maxAckDelay = peerTransportParametersApplied_ ? tls_.PeerTransportParameters().MaxAckDelay : 25;
        const QuicConnectionState state = state_;
        if (state == QuicConnectionState::Closing || state == QuicConnectionState::Draining ||
            state == QuicConnectionState::Failed)
        {
            deadline = EarlierDeadline(deadline, closingDeadline100ns_);
            deadline = EarlierDeadline(deadline, drainingDeadline100ns_);
            return deadline;
        }
        for (SIZE_T index = 0; index < 3; ++index)
        {
            if (ackTrackers_[index].AckPending())
            {
                deadline = EarlierDeadline(deadline, ackTrackers_[index].AckDeadline100ns(maxAckDelay));
            }
            const QuicPacketNumberSpace space = static_cast<QuicPacketNumberSpace>(index);
            deadline = EarlierDeadline(deadline, recovery_.LossDeadline100ns(space));
            deadline = EarlierDeadline(deadline, recovery_.PtoDeadline100ns(space, maxAckDelay));
        }
        if (networkEnabled_ && lastActivityTime100ns_ != 0 &&
            (state == QuicConnectionState::Connecting || state == QuicConnectionState::Handshaking ||
             state == QuicConnectionState::Established) &&
            idleTimeout100ns_ != 0)
        {
            deadline = EarlierDeadline(deadline, DeadlineAfter(lastActivityTime100ns_, idleTimeout100ns_));
        }
        deadline = EarlierDeadline(deadline, closingDeadline100ns_);
        deadline = EarlierDeadline(deadline, drainingDeadline100ns_);
        deadline = EarlierDeadline(deadline, previousReadKeyDeadline100ns_);
        if (deferredCommand_ != nullptr || applicationPacingPending_)
        {
            deadline = EarlierDeadline(deadline, recovery_.Congestion().PacingDeadline100ns());
        }
        return deadline;
    }

    NTSTATUS QuicConnection::SendProbe(QuicPacketNumberSpace space) noexcept
    {
        QuicFrame ping = {};
        ping.Kind = QuicFrameKind::Ping;
        if (space == QuicPacketNumberSpace::Initial && initialWriteKey_.SecretLength != 0)
        {
            return SendFramePacket(QuicPacketType::Initial, space, initialWriteKey_, ping, nullptr, 0, true, true);
        }
        if (space == QuicPacketNumberSpace::Handshake && tls_.HandshakeWriteKey().SecretLength != 0)
        {
            return SendFramePacket(QuicPacketType::Handshake, space, tls_.HandshakeWriteKey(), ping, nullptr, 0, false,
                                   true);
        }
        if (space == QuicPacketNumberSpace::Application && applicationKeysInstalled_)
        {
            return SendFramePacket(QuicPacketType::OneRtt, space, applicationWriteKey_, ping, nullptr, 0, false, true);
        }
        return STATUS_NOT_FOUND;
    }

    NTSTATUS QuicConnection::EnterClosing(ULONGLONG errorCode, bool sendCloseFrame, bool applicationError) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            state_ = QuicConnectionState::Closing;
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        state_ = QuicConnectionState::Closing;
        KeReleaseSpinLock(&lock_, irql);
#endif

        NTSTATUS status = STATUS_SUCCESS;
        QuicPacketNumberSpace closeSpace = QuicPacketNumberSpace::Initial;
        if (sendCloseFrame && datagramSocket_ != nullptr)
        {
            QuicFrame close = {};
            close.Kind = QuicFrameKind::ConnectionClose;
            close.ErrorCode = errorCode;
            close.ApplicationClose = applicationError;
            if (applicationKeysInstalled_)
            {
                closeSpace = QuicPacketNumberSpace::Application;
                status = SendFramePacket(QuicPacketType::OneRtt, closeSpace, applicationWriteKey_, close, nullptr, 0,
                                         false, false);
            }
            else if (tls_.HandshakeWriteKey().SecretLength != 0)
            {
                closeSpace = QuicPacketNumberSpace::Handshake;
                status = SendFramePacket(QuicPacketType::Handshake, closeSpace, tls_.HandshakeWriteKey(), close,
                                         nullptr, 0, false, false);
            }
            else if (initialWriteKey_.SecretLength != 0)
            {
                status = SendFramePacket(QuicPacketType::Initial, closeSpace, initialWriteKey_, close, nullptr, 0, true,
                                         false);
            }
        }
        const ULONGLONG now = QuicClockNow100ns();
        const ULONGLONG maxAckDelay = peerTransportParametersApplied_ ? tls_.PeerTransportParameters().MaxAckDelay : 25;
        const ULONGLONG pto = recovery_.PtoPeriod100ns(closeSpace, maxAckDelay);
        closingDeadline100ns_ = DeadlineAfter(now, pto, 3);
        WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.closing");
        return status;
    }

    void QuicConnection::EnterDraining() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            state_ = QuicConnectionState::Draining;
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        state_ = QuicConnectionState::Draining;
        KeReleaseSpinLock(&lock_, irql);
#endif
        const ULONGLONG now = QuicClockNow100ns();
        const ULONGLONG maxAckDelay = peerTransportParametersApplied_ ? tls_.PeerTransportParameters().MaxAckDelay : 25;
        const ULONGLONG pto = recovery_.PtoPeriod100ns(QuicPacketNumberSpace::Application, maxAckDelay);
        drainingDeadline100ns_ = DeadlineAfter(now, pto, 3);
        CompleteEstablishedWaiter(STATUS_CONNECTION_DISCONNECTED);
    }

    void QuicConnection::FailConnection(NTSTATUS status, ULONGLONG transportError) noexcept
    {
        const NTSTATUS closeStatus = EnterClosing(transportError, true);
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            state_ = QuicConnectionState::Failed;
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        state_ = QuicConnectionState::Failed;
        KeReleaseSpinLock(&lock_, irql);
#endif
        CompleteEstablishedWaiter(status);
        WKNET_TRACE(ComponentQuic, TraceLevel::Error,
                    "quic.connection.failed status=0x%08X transport_error=%I64u close_status=0x%08X", status,
                    transportError, closeStatus);
    }

    void QuicConnection::TransitionToClosed() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            state_ = QuicConnectionState::Closed;
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        state_ = QuicConnectionState::Closed;
        KeReleaseSpinLock(&lock_, irql);
#endif
        CompleteEstablishedWaiter(STATUS_CONNECTION_DISCONNECTED);
        StopNetwork();
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            stop_ = true;
        }
#else
        KeAcquireSpinLock(&lock_, &irql);
        stop_ = true;
        KeReleaseSpinLock(&lock_, irql);
#endif
        WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.closed");
        WakeWorker();
    }

    NTSTATUS QuicConnection::ProcessDeadlines() noexcept
    {
        const ULONGLONG now = QuicClockNow100ns();
        DiscardExpiredReadKey(now);

        if (applicationPacingPending_ && recovery_.Congestion().PacingDeadline100ns() <= now)
        {
            WKNET_TRACE(ComponentQuic, TraceLevel::Max, "quic.stream.writable pacing_ready=1 stream_count=%Iu",
                        streamCount_);
            NotifyWritableStreams();
        }
        const ULONGLONG maxAckDelay = peerTransportParametersApplied_ ? tls_.PeerTransportParameters().MaxAckDelay : 25;

        if (state_ == QuicConnectionState::Closing || state_ == QuicConnectionState::Draining ||
            state_ == QuicConnectionState::Failed)
        {
            if ((closingDeadline100ns_ != 0 && closingDeadline100ns_ <= now) ||
                (drainingDeadline100ns_ != 0 && drainingDeadline100ns_ <= now))
            {
                TransitionToClosed();
            }
            return STATUS_SUCCESS;
        }

        for (SIZE_T index = 0; index < 3; ++index)
        {
            if (ackTrackers_[index].AckPending() && ackTrackers_[index].AckDeadline100ns(maxAckDelay) <= now)
            {
                const NTSTATUS ackStatus = SendAck(static_cast<QuicPacketNumberSpace>(index));
                if (!NT_SUCCESS(ackStatus) && ackStatus != STATUS_NOT_FOUND && ackStatus != STATUS_INVALID_DEVICE_STATE)
                {
                    return ackStatus;
                }
            }
        }

        for (SIZE_T index = 0; index < 3; ++index)
        {
            const QuicPacketNumberSpace space = static_cast<QuicPacketNumberSpace>(index);
            const ULONGLONG lossDeadline = recovery_.LossDeadline100ns(space);
            if (lossDeadline != 0 && lossDeadline <= now)
            {
                const NTSTATUS lossStatus = recovery_.OnLossTimerExpired(space);
                if (NT_SUCCESS(lossStatus))
                {
                    WKNET_TRACE(ComponentQuic, TraceLevel::Warning, "quic.loss.detected space=%u",
                                static_cast<ULONG>(index));
                }
                else if (lossStatus != STATUS_NOT_FOUND)
                {
                    return lossStatus;
                }
            }
        }

        ULONGLONG earliestPto = 0;
        QuicPacketNumberSpace ptoSpace = QuicPacketNumberSpace::Initial;
        for (SIZE_T index = 0; index < 3; ++index)
        {
            const QuicPacketNumberSpace space = static_cast<QuicPacketNumberSpace>(index);
            const ULONGLONG ptoDeadline = recovery_.PtoDeadline100ns(space, maxAckDelay);
            if (ptoDeadline != 0 && (earliestPto == 0 || ptoDeadline < earliestPto))
            {
                earliestPto = ptoDeadline;
                ptoSpace = space;
            }
        }
        if (earliestPto != 0 && earliestPto <= now)
        {
            recovery_.OnPtoFired();
            WKNET_TRACE(ComponentQuic, TraceLevel::Warning, "quic.pto.fired space=%u", static_cast<ULONG>(ptoSpace));
            const NTSTATUS probeStatus = SendProbe(ptoSpace);
            if (!NT_SUCCESS(probeStatus) && probeStatus != STATUS_NOT_FOUND)
            {
                return probeStatus;
            }
        }

        if (networkEnabled_ && lastActivityTime100ns_ != 0 && idleTimeout100ns_ != 0 &&
            (state_ == QuicConnectionState::Connecting || state_ == QuicConnectionState::Handshaking ||
             state_ == QuicConnectionState::Established) &&
            now >= lastActivityTime100ns_ && now - lastActivityTime100ns_ >= idleTimeout100ns_)
        {
            const NTSTATUS closeStatus = EnterClosing(0, true);
            if (!NT_SUCCESS(closeStatus))
            {
                return closeStatus;
            }
            WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.idle_timeout");
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS QuicConnection::SendStreamFrame(QuicStream& stream, const UCHAR* data, SIZE_T length, bool fin) noexcept
    {
        NTSTATUS status = stream.CanWrite(length, fin);
        if (NT_SUCCESS(status))
        {
            status = flowControl_.CanReserveSend(length);
        }
        if (status == STATUS_DEVICE_BUSY)
        {
            stream.MarkApplicationWriteBlocked();
            return STATUS_RETRY;
        }
        const ULONGLONG offset = stream.SendOffset();
        if (NT_SUCCESS(status) && networkEnabled_)
        {
            const ULONGLONG estimatedPacketBytes = length > 1100 ? 1200 : static_cast<ULONGLONG>(length + 100);
            if (!recovery_.Congestion().CanSend(estimatedPacketBytes, QuicClockNow100ns()))
            {
                stream.MarkApplicationWriteBlocked();
                applicationPacingPending_ = true;
                WKNET_TRACE(ComponentQuic, TraceLevel::Max,
                            "quic.stream.write_blocked stream_id=%I64u reason=pacing deadline=%I64u", stream.Id(),
                            recovery_.Congestion().PacingDeadline100ns());
                return STATUS_RETRY;
            }
            QuicFrame frame = {};
            frame.Kind = QuicFrameKind::Stream;
            frame.StreamId = stream.Id();
            frame.Offset = offset;
            frame.Data = {data, length};
            frame.Fin = fin;
            status = SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                     frame, nullptr, 0, false, true);
        }
        SIZE_T accepted = 0;
        if (NT_SUCCESS(status))
        {
            status = stream.Write(data, length, fin, &accepted);
        }
        if (NT_SUCCESS(status))
        {
            status = flowControl_.ReserveSend(accepted);
        }
        return status;
    }

    void QuicConnection::NotifyWritableStreams() noexcept
    {
        applicationPacingPending_ = false;
        for (SIZE_T index = 0; index < streamCount_; ++index)
        {
            if (streams_[index] != nullptr)
            {
                streams_[index]->TryNotifyApplicationWritable();
            }
        }
    }

    NTSTATUS QuicConnection::ApplicationOpenBidirectionalStream(QuicStream** stream) noexcept
    {
        if (stream != nullptr)
        {
            *stream = nullptr;
        }
        if (stream == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (!IsWorkerThread())
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (state_ != QuicConnectionState::Established)
        {
            return STATUS_DEVICE_NOT_READY;
        }
        NTSTATUS status = CreateStream(nextBidiStreamId_, stream);
        if (NT_SUCCESS(status))
        {
            nextBidiStreamId_ += 4;
            WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.stream.open stream_id=%I64u", (*stream)->Id());
        }
        return status;
    }

    NTSTATUS QuicConnection::ApplicationOpenUnidirectionalStream(QuicStream** stream) noexcept
    {
        if (stream != nullptr)
        {
            *stream = nullptr;
        }
        if (stream == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (!IsWorkerThread())
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (state_ != QuicConnectionState::Established)
        {
            return STATUS_DEVICE_NOT_READY;
        }
        NTSTATUS status = CreateStream(nextUniStreamId_, stream);
        if (NT_SUCCESS(status))
        {
            nextUniStreamId_ += 4;
            WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.stream.open stream_id=%I64u", (*stream)->Id());
        }
        return status;
    }

    NTSTATUS QuicConnection::ApplicationWriteStream(ULONGLONG streamId, const UCHAR* data, SIZE_T dataLength, bool fin,
                                                    SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr)
        {
            *bytesWritten = 0;
        }
        if (!IsWorkerThread() || bytesWritten == nullptr || (data == nullptr && dataLength != 0))
        {
            return STATUS_INVALID_PARAMETER;
        }
        QuicStream* stream = FindStream(streamId);
        if (stream == nullptr)
        {
            return STATUS_NOT_FOUND;
        }

        SIZE_T offset = 0;
        while (offset < dataLength)
        {
            const SIZE_T remaining = dataLength - offset;
            const SIZE_T chunkLength = remaining > 1024 ? 1024 : remaining;
            const bool chunkFin = fin && chunkLength == remaining;
            const NTSTATUS status = SendStreamFrame(*stream, data + offset, chunkLength, chunkFin);
            if (!NT_SUCCESS(status))
            {
                *bytesWritten = offset;
                return status;
            }
            offset += chunkLength;
        }
        NTSTATUS status = STATUS_SUCCESS;
        if (dataLength == 0 && fin)
        {
            status = SendStreamFrame(*stream, nullptr, 0, true);
        }
        *bytesWritten = offset;
        return status;
    }

    NTSTATUS QuicConnection::ApplicationConsumeStream(ULONGLONG streamId, UCHAR* output, SIZE_T capacity,
                                                      SIZE_T* bytesConsumed, bool* fin) noexcept
    {
        if (bytesConsumed != nullptr)
        {
            *bytesConsumed = 0;
        }
        if (fin != nullptr)
        {
            *fin = false;
        }
        if (!IsWorkerThread() || bytesConsumed == nullptr || fin == nullptr || (output == nullptr && capacity != 0))
        {
            return STATUS_INVALID_PARAMETER;
        }
        QuicStream* stream = FindStream(streamId);
        if (stream == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        NTSTATUS status = stream->Consume(output, capacity, bytesConsumed, fin);
        if (NT_SUCCESS(status) && *bytesConsumed != 0)
        {
            status = flowControl_.OnStreamConsumed(*bytesConsumed);
        }
        return status;
    }

    NTSTATUS QuicConnection::ApplicationResetStream(ULONGLONG streamId, ULONGLONG applicationError) noexcept
    {
        if (!IsWorkerThread() || applicationError > QuicVarIntMaximum)
        {
            return STATUS_INVALID_PARAMETER;
        }
        QuicStream* stream = FindStream(streamId);
        if (stream == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        NTSTATUS status = STATUS_SUCCESS;
        if (networkEnabled_)
        {
            QuicFrame frame = {};
            frame.Kind = QuicFrameKind::ResetStream;
            frame.StreamId = streamId;
            frame.ErrorCode = applicationError;
            frame.FinalSize = stream->SendOffset();
            status = SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                     frame, nullptr, 0, false, true);
        }
        return NT_SUCCESS(status) ? stream->Reset(applicationError, stream->SendOffset()) : status;
    }

    NTSTATUS QuicConnection::ApplicationStopSending(ULONGLONG streamId, ULONGLONG applicationError) noexcept
    {
        if (!IsWorkerThread() || applicationError > QuicVarIntMaximum)
        {
            return STATUS_INVALID_PARAMETER;
        }
        QuicStream* stream = FindStream(streamId);
        if (stream == nullptr)
        {
            return STATUS_NOT_FOUND;
        }
        NTSTATUS status = STATUS_SUCCESS;
        if (networkEnabled_)
        {
            QuicFrame frame = {};
            frame.Kind = QuicFrameKind::StopSending;
            frame.StreamId = streamId;
            frame.ErrorCode = applicationError;
            status = SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                     frame, nullptr, 0, false, true);
        }
        return NT_SUCCESS(status) ? stream->StopSending(applicationError) : status;
    }

    NTSTATUS QuicConnection::ApplicationClose(ULONGLONG applicationError) noexcept
    {
        if (!IsWorkerThread() || applicationError > QuicVarIntMaximum)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return EnterClosing(applicationError, true, true);
    }

    void QuicConnection::Process(QuicCommand* c) noexcept
    {
        NTSTATUS s = STATUS_SUCCESS;
        ULONGLONG stream = 0;
        SIZE_T bytesTransferred = 0;
        bool fin = false;
        if (c->Type == QuicCommandType::Connect)
        {
#if defined(WKNET_USER_MODE_TEST)
            {
                std::lock_guard<std::mutex> guard(lock_);
                connectQueued_ = false;
                state_ = QuicConnectionState::Connecting;
            }
#else
            KIRQL irql;
            KeAcquireSpinLock(&lock_, &irql);
            connectQueued_ = false;
            state_ = QuicConnectionState::Connecting;
            KeReleaseSpinLock(&lock_, irql);
#endif
            WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.start");
            if (networkEnabled_)
            {
                s = StartNetwork();
            }
#if defined(WKNET_USER_MODE_TEST)
            {
                std::lock_guard<std::mutex> guard(lock_);
                state_ = NT_SUCCESS(s) ? QuicConnectionState::Handshaking : QuicConnectionState::Failed;
            }
#else
            KeAcquireSpinLock(&lock_, &irql);
            state_ = NT_SUCCESS(s) ? QuicConnectionState::Handshaking : QuicConnectionState::Failed;
            KeReleaseSpinLock(&lock_, irql);
#endif
            if (!NT_SUCCESS(s))
            {
                CompleteEstablishedWaiter(s);
                WKNET_TRACE(ComponentQuic, TraceLevel::Error, "quic.connection.failed status=0x%08X", s);
            }
        }
        else if (c->Type == QuicCommandType::ConfirmHandshake)
        {
#if defined(WKNET_USER_MODE_TEST)
            {
                std::lock_guard<std::mutex> guard(lock_);
                if (state_ != QuicConnectionState::Handshaking)
                {
                    s = STATUS_INVALID_DEVICE_STATE;
                }
                else
                {
                    state_ = QuicConnectionState::Established;
                }
            }
#else
            KIRQL irql;
            KeAcquireSpinLock(&lock_, &irql);
            if (state_ != QuicConnectionState::Handshaking)
            {
                s = STATUS_INVALID_DEVICE_STATE;
            }
            else
            {
                state_ = QuicConnectionState::Established;
            }
            KeReleaseSpinLock(&lock_, irql);
#endif
            if (NT_SUCCESS(s))
            {
                CompleteEstablishedWaiter(STATUS_SUCCESS);
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.handshake.complete");
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.established");
            }
        }
        else if (c->Type == QuicCommandType::OpenBidirectionalStream ||
                 c->Type == QuicCommandType::OpenUnidirectionalStream)
        {
            const bool bidirectional = c->Type == QuicCommandType::OpenBidirectionalStream;
#if defined(WKNET_USER_MODE_TEST)
            {
                std::lock_guard<std::mutex> guard(lock_);
                if (state_ != QuicConnectionState::Established)
                {
                    s = STATUS_DEVICE_NOT_READY;
                }
                else
                {
                    stream = bidirectional ? nextBidiStreamId_ : nextUniStreamId_;
                }
            }
#else
            KIRQL irql;
            KeAcquireSpinLock(&lock_, &irql);
            if (state_ != QuicConnectionState::Established)
            {
                s = STATUS_DEVICE_NOT_READY;
            }
            else
            {
                stream = bidirectional ? nextBidiStreamId_ : nextUniStreamId_;
            }
            KeReleaseSpinLock(&lock_, irql);
#endif
            QuicStream* created = nullptr;
            if (NT_SUCCESS(s))
            {
                s = CreateStream(stream, &created);
            }
            if (NT_SUCCESS(s))
            {
                if (bidirectional)
                {
                    nextBidiStreamId_ += 4;
                }
                else
                {
                    nextUniStreamId_ += 4;
                }
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.stream.open stream_id=%I64u", stream);
            }
        }
        else if (c->Type == QuicCommandType::WriteStream)
        {
            QuicStream* target = FindStream(c->StreamId);
            if (target == nullptr)
            {
                s = STATUS_NOT_FOUND;
            }
            SIZE_T offset = c->Progress;
            while (NT_SUCCESS(s) && offset < c->Length)
            {
                const SIZE_T remaining = c->Length - offset;
                const SIZE_T chunkLength = remaining > 1024 ? 1024 : remaining;
                const bool chunkFin = c->Fin && chunkLength == remaining;
                s = SendStreamFrame(*target, c->Data.Get() + offset, chunkLength, chunkFin);
                if (NT_SUCCESS(s))
                {
                    offset += chunkLength;
                    bytesTransferred = offset;
                    c->Progress = offset;
                }
            }
            if (s == STATUS_RETRY)
            {
                deferredCommand_ = c;
                return;
            }
            if (NT_SUCCESS(s) && c->Length == 0 && c->Fin)
            {
                s = SendStreamFrame(*target, nullptr, 0, true);
            }
            if (s == STATUS_RETRY)
            {
                deferredCommand_ = c;
                return;
            }
            fin = NT_SUCCESS(s) && c->Fin;
        }
        else if (c->Type == QuicCommandType::ConsumeStream)
        {
            QuicStream* target = FindStream(c->StreamId);
            if (target == nullptr)
            {
                s = STATUS_NOT_FOUND;
            }
            if (NT_SUCCESS(s))
            {
                s = target->Consume(c->Output, c->Length, &bytesTransferred, &fin);
            }
            if (NT_SUCCESS(s) && bytesTransferred != 0)
            {
                s = flowControl_.OnStreamConsumed(bytesTransferred);
            }
            if (NT_SUCCESS(s) && fin)
            {
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.stream.complete stream_id=%I64u", c->StreamId);
            }
        }
        else if (c->Type == QuicCommandType::ResetStream)
        {
            QuicStream* target = FindStream(c->StreamId);
            if (target == nullptr)
            {
                s = STATUS_NOT_FOUND;
            }
            if (NT_SUCCESS(s) && networkEnabled_)
            {
                QuicFrame frame = {};
                frame.Kind = QuicFrameKind::ResetStream;
                frame.StreamId = c->StreamId;
                frame.ErrorCode = c->ErrorCode;
                frame.FinalSize = target->SendOffset();
                s = SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                    frame, nullptr, 0, false, true);
            }
            if (NT_SUCCESS(s))
            {
                s = target->Reset(c->ErrorCode, target->SendOffset());
                if (NT_SUCCESS(s))
                {
                    WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.stream.reset stream_id=%I64u", c->StreamId);
                }
            }
        }
        else if (c->Type == QuicCommandType::StopSending)
        {
            QuicStream* target = FindStream(c->StreamId);
            if (target == nullptr)
            {
                s = STATUS_NOT_FOUND;
            }
            if (NT_SUCCESS(s) && networkEnabled_)
            {
                QuicFrame frame = {};
                frame.Kind = QuicFrameKind::StopSending;
                frame.StreamId = c->StreamId;
                frame.ErrorCode = c->ErrorCode;
                s = SendFramePacket(QuicPacketType::OneRtt, QuicPacketNumberSpace::Application, applicationWriteKey_,
                                    frame, nullptr, 0, false, true);
            }
            if (NT_SUCCESS(s))
            {
                s = target->StopSending(c->ErrorCode);
            }
        }
        else if (c->Type == QuicCommandType::Application)
        {
            s = c->ApplicationCallback != nullptr ? c->ApplicationCallback(c->ApplicationContext, this)
                                                  : STATUS_INVALID_DEVICE_STATE;
        }
        else if (c->Type == QuicCommandType::SelfClose)
        {
            s = STATUS_INVALID_DEVICE_STATE;
        }
        else if (c->Type == QuicCommandType::ProcessTimer)
        {
            s = ProcessDeadlines();
        }
        else if (c->Type == QuicCommandType::InjectFrame)
        {
            s = DispatchFrame(c->Level, c->Space, c->Frame);
        }
        else if (c->Type == QuicCommandType::Close || c->Type == QuicCommandType::CloseApplication)
        {
#if defined(WKNET_USER_MODE_TEST)
            {
                std::lock_guard<std::mutex> guard(lock_);
                closeQueued_ = false;
            }
#else
            KIRQL irql;
            KeAcquireSpinLock(&lock_, &irql);
            closeQueued_ = false;
            KeReleaseSpinLock(&lock_, irql);
#endif
            if (networkEnabled_)
            {
                const bool applicationError = c->Type == QuicCommandType::CloseApplication;
                s = EnterClosing(applicationError ? c->ErrorCode : 0, true, applicationError);
                CompleteEstablishedWaiter(STATUS_CONNECTION_DISCONNECTED);
            }
            else
            {
#if defined(WKNET_USER_MODE_TEST)
                {
                    std::lock_guard<std::mutex> guard(lock_);
                    state_ = QuicConnectionState::Closed;
                    stop_ = true;
                }
#else
                KeAcquireSpinLock(&lock_, &irql);
                state_ = QuicConnectionState::Closed;
                stop_ = true;
                KeReleaseSpinLock(&lock_, irql);
#endif
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.closing");
                WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.connection.closed");
            }
        }
        Complete(c->Operation, s, stream == 0 ? c->StreamId : stream, bytesTransferred, fin);
        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, c);
    }
    void QuicConnection::WorkerLoop() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            workerActive_ = true;
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        workerActive_ = true;
        KeReleaseSpinLock(&lock_, irql);
#endif
        for (;;)
        {
#if defined(WKNET_USER_MODE_TEST)
            {
                std::unique_lock<std::mutex> lock(lock_);
                const auto ready = [this]() noexcept
                {
                    return stop_ || (!suspended_ &&
                                     ((deferredCommand_ == nullptr && count_ != 0) || receiveReady_ || timerReady_));
                };
                const ULONGLONG deadline = NextDeadline100ns();
                if (deadline == 0)
                {
                    wake_.wait(lock, ready);
                }
                else
                {
                    const ULONGLONG now = QuicClockNow100ns();
                    const ULONGLONG delay100ns = deadline > now ? deadline - now : 0;
                    constexpr ULONGLONG MaximumNanoseconds = ~0ULL >> 1;
                    const ULONGLONG delayNanoseconds =
                        delay100ns > MaximumNanoseconds / 100 ? MaximumNanoseconds : delay100ns * 100;
                    (void)wake_.wait_for(lock, std::chrono::nanoseconds(delayNanoseconds), ready);
                }
                timerReady_ = false;
            }
#else
            LARGE_INTEGER timeout = {};
            LARGE_INTEGER* timeoutPointer = nullptr;
            const ULONGLONG deadline = NextDeadline100ns();
            if (deadline != 0)
            {
                const ULONGLONG now = QuicClockNow100ns();
                const ULONGLONG delay = deadline > now ? deadline - now : 0;
                timeout.QuadPart =
                    delay > static_cast<ULONGLONG>(MAXLONGLONG) ? -MAXLONGLONG : -static_cast<LONGLONG>(delay);
                timeoutPointer = &timeout;
            }
            KeWaitForSingleObject(&wake_, Executive, KernelMode, FALSE, timeoutPointer);
            KeAcquireSpinLock(&lock_, &irql);
            const bool stop = stop_;
            const bool suspended = suspended_;
            if (suspended && !stop)
            {
                KeClearEvent(&wake_);
            }
            KeReleaseSpinLock(&lock_, irql);
            if (stop)
            {
                break;
            }
            if (suspended)
            {
                continue;
            }
#endif
            if (ShouldStop())
            {
                break;
            }

            if (deferredCommand_ != nullptr && recovery_.Congestion().PacingDeadline100ns() <= QuicClockNow100ns())
            {
                QuicCommand* deferred = deferredCommand_;
                deferredCommand_ = nullptr;
                Process(deferred);
            }
            QuicCommand* c = nullptr;
            while (deferredCommand_ == nullptr && Dequeue(&c))
            {
                Process(c);
                if (ShouldStop() || deferredCommand_ != nullptr)
                {
                    break;
                }
            }
            bool processReceive = false;
#if defined(WKNET_USER_MODE_TEST)
            {
                std::lock_guard<std::mutex> guard(lock_);
                processReceive = receiveReady_;
                receiveReady_ = false;
            }
#else
            KeAcquireSpinLock(&lock_, &irql);
            processReceive = receiveReady_;
            receiveReady_ = false;
            if (count_ == 0)
            {
                KeClearEvent(&wake_);
            }
            KeReleaseSpinLock(&lock_, irql);
#endif
            if (deferredCommand_ != nullptr)
            {
#if !defined(WKNET_USER_MODE_TEST)
                KeAcquireSpinLock(&lock_, &irql);
                if (!receiveReady_)
                {
                    KeClearEvent(&wake_);
                }
                KeReleaseSpinLock(&lock_, irql);
#endif
            }
            if (processReceive && !ShouldStop())
            {
                const NTSTATUS receiveStatus = ProcessReceiveCompletion();
                if (!NT_SUCCESS(receiveStatus) && receiveStatus != STATUS_CANCELLED)
                {
                    const ULONGLONG transportError = pendingTransportError_ != 0
                                                         ? pendingTransportError_
                                                         : (tls_.TransportError() != 0 ? tls_.TransportError() : 0xA);
                    FailConnection(receiveStatus, transportError);
                }
            }
            if (!ShouldStop())
            {
                const NTSTATUS deadlineStatus = ProcessDeadlines();
                if (!NT_SUCCESS(deadlineStatus))
                {
                    FailConnection(deadlineStatus, pendingTransportError_ != 0 ? pendingTransportError_ : 0xA);
                }
            }
        }
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            workerActive_ = false;
        }
#else
        KeAcquireSpinLock(&lock_, &irql);
        workerActive_ = false;
        KeReleaseSpinLock(&lock_, irql);
#endif
    }
#if defined(WKNET_USER_MODE_TEST)
    void QuicConnection::WakeTimerForTest() noexcept
    {
        {
            std::lock_guard<std::mutex> guard(lock_);
            timerReady_ = true;
        }
        WakeWorker();
    }

    NTSTATUS QuicConnection::ConfigureApplicationKeysForTest(const QuicPacketKeySet& writeKey,
                                                             const QuicPacketKeySet& readKey) noexcept
    {
        QuicClearPacketKeySet(&applicationWriteKey_);
        QuicClearPacketKeySet(&applicationReadKey_);
        QuicClearPacketKeySet(&nextApplicationReadKey_);
        applicationWriteKey_ = writeKey;
        applicationReadKey_ = readKey;
        NTSTATUS status = QuicDeriveNextPacketKeySet(applicationReadKey_, &nextApplicationReadKey_);
        if (NT_SUCCESS(status))
        {
            applicationKeysInstalled_ = true;
            sendKeyPhase_ = false;
            receiveKeyPhase_ = false;
            sendKeyUpdateAwaitingAck_ = false;
            oneRttPacketsInSendPhase_ = 0;
            receiveKeyPhaseStartPacketNumber_ = 0;
        }
        return status;
    }

    NTSTATUS QuicConnection::ForceKeyUpdateForTest() noexcept { return InitiateKeyUpdate(); }

    void QuicConnection::ConfirmKeyUpdateForTest(ULONGLONG packetNumber) noexcept
    {
        const QuicAckRange range = {packetNumber, packetNumber};
        ConfirmSendKeyUpdate(&range, 1);
    }

    bool QuicConnection::SendKeyPhaseForTest() const noexcept { return sendKeyPhase_; }

    bool QuicConnection::SendKeyUpdatePendingForTest() const noexcept { return sendKeyUpdateAwaitingAck_; }

    NTSTATUS QuicConnection::InjectFrameForTest(QuicEncryptionLevel level, QuicPacketNumberSpace space,
                                                const QuicFrame& frame) noexcept
    {
        QuicOperation operation;
        QuicOperationInitialize(&operation);
        const NTSTATUS status = Enqueue(QuicCommandType::InjectFrame, &operation, static_cast<ULONGLONG>(level),
                                        reinterpret_cast<const UCHAR*>(&frame), sizeof(frame), nullptr, false,
                                        static_cast<ULONGLONG>(space));
        return NT_SUCCESS(status) ? QuicOperationWait(&operation, 1000) : status;
    }

    void QuicConnection::WorkerEntry(QuicConnection* c) noexcept { c->WorkerLoop(); }
#else
    void QuicConnection::WorkerEntry(void* context)
    {
        static_cast<QuicConnection*>(context)->WorkerLoop();
        PsTerminateSystemThread(STATUS_SUCCESS);
    }
#endif
    void QuicConnection::Resume() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            suspended_ = false;
        }
        wake_.notify_all();
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        suspended_ = false;
        KeReleaseSpinLock(&lock_, irql);
        KeSetEvent(&wake_, IO_NO_INCREMENT, FALSE);
#endif
    }
    QuicConnectionState QuicConnection::State() const noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        std::lock_guard<std::mutex> guard(lock_);
        return state_;
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        QuicConnectionState s = state_;
        KeReleaseSpinLock(&lock_, irql);
        return s;
#endif
    }

    void QuicConnection::ReceiveNotification(void* context) noexcept
    {
        QuicConnection* connection = static_cast<QuicConnection*>(context);
        if (connection == nullptr)
        {
            return;
        }
#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(connection->lock_);
            connection->receiveReady_ = true;
        }
        connection->wake_.notify_all();
#else
        KIRQL irql;
        KeAcquireSpinLock(&connection->lock_, &irql);
        connection->receiveReady_ = true;
        KeReleaseSpinLock(&connection->lock_, irql);
        KeSetEvent(&connection->wake_, IO_NO_INCREMENT, FALSE);
#endif
    }

    void QuicConnection::Shutdown() noexcept
    {
        if (!queue_.IsValid())
        {
            return;
        }

        if (IsWorkerThread())
        {
            WKNET_TRACE(ComponentQuic, TraceLevel::Error, "quic.connection.shutdown_self_rejected");
            return;
        }

        CompleteEstablishedWaiter(STATUS_CANCELLED);

#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(lock_);
            stop_ = true;
            suspended_ = false;
        }
        wake_.notify_all();
        if (datagramSocket_ != nullptr && receivePending_)
        {
            (void)net::WskDatagramSocketCancelReceive(datagramSocket_);
        }
        if (worker_.joinable())
        {
            worker_.join();
        }
#else
        KIRQL irql;
        KeAcquireSpinLock(&lock_, &irql);
        stop_ = true;
        suspended_ = false;
        KeReleaseSpinLock(&lock_, irql);
        KeSetEvent(&wake_, IO_NO_INCREMENT, FALSE);
        if (datagramSocket_ != nullptr && receivePending_)
        {
            (void)net::WskDatagramSocketCancelReceive(datagramSocket_);
        }
        if (worker_ != nullptr)
        {
            KeWaitForSingleObject(worker_, Executive, KernelMode, FALSE, nullptr);
            ObDereferenceObject(worker_);
            worker_ = nullptr;
        }
#endif
        StopNetwork();
        if (deferredCommand_ != nullptr)
        {
            Complete(deferredCommand_->Operation, STATUS_CANCELLED);
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, deferredCommand_);
            deferredCommand_ = nullptr;
        }
        QuicCommand* c = nullptr;
        while (Dequeue(&c))
        {
            Complete(c->Operation, STATUS_CANCELLED);
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicCommandObject, c);
        }
        queue_.Reset();
        ClearStreams();
        streams_.Reset();
    }
} // namespace wknet::quic
