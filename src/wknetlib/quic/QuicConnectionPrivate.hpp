#pragma once
#include "quic/QuicAckTracker.h"
#include "quic/QuicAttemptValidation.h"
#include "quic/QuicConnection.h"
#include "quic/QuicFlowControl.h"
#include "quic/QuicFrame.h"
#include "quic/QuicPacket.h"
#include "quic/QuicRecovery.h"
#include "quic/QuicStream.h"
#include "quic/QuicTokenCache.h"
#if defined(WKNET_USER_MODE_TEST)
#include <chrono>
#include <thread>
#endif
namespace wknet::quic
{
enum class QuicCommandType : UCHAR
{
    Connect,
    OpenBidirectionalStream,
    OpenUnidirectionalStream,
    WriteStream,
    ConsumeStream,
    ResetStream,
    StopSending,
    Close,
    CloseApplication,
    Noop,
    ConfirmHandshake,
    ProcessTimer,
    InjectFrame,
    SelfClose
};
struct QuicCommand final
{
    QuicCommandType Type = QuicCommandType::Noop;
    QuicOperation *Operation = nullptr;
    ULONGLONG StreamId = 0;
    ULONGLONG ErrorCode = 0;
    HeapArray<UCHAR> Data;
    UCHAR *Output = nullptr;
    SIZE_T Length = 0;
    SIZE_T Progress = 0;
    bool Fin = false;
    QuicFrame Frame = {};
    QuicEncryptionLevel Level = QuicEncryptionLevel::Application;
    QuicPacketNumberSpace Space = QuicPacketNumberSpace::Application;
    HeapArray<UCHAR> AuxiliaryData;
};

struct QuicConnectionIdEntry final
{
    ULONGLONG Sequence = 0;
    UCHAR ConnectionId[QuicMaximumConnectionIdLength] = {};
    SIZE_T ConnectionIdLength = 0;
    UCHAR StatelessResetToken[16] = {};
    bool HasStatelessResetToken = false;
    bool Retired = false;
    ULONGLONG RetireDeadline100ns = 0;
};
class QuicConnection final
{
  public:
    QuicConnection() noexcept = default;
    QuicConnection(const QuicConnection &) = delete;
    QuicConnection &operator=(const QuicConnection &) = delete;
    ~QuicConnection() noexcept;
    NTSTATUS Initialize(const QuicConnectionCreateOptions &options) noexcept;
    NTSTATUS Enqueue(QuicCommandType type, QuicOperation *operation, ULONGLONG streamId = 0,
                     const UCHAR *data = nullptr, SIZE_T dataLength = 0, UCHAR *output = nullptr, bool fin = false,
                     ULONGLONG errorCode = 0) noexcept;
    void Resume() noexcept;
    void Shutdown() noexcept;
    QuicConnectionState State() const noexcept;
    NTSTATUS ApplicationOpenBidirectionalStream(QuicStream **stream) noexcept;
    NTSTATUS ApplicationOpenUnidirectionalStream(QuicStream **stream) noexcept;
    NTSTATUS ApplicationWriteStream(ULONGLONG streamId, const UCHAR *data, SIZE_T dataLength, bool fin,
                                    SIZE_T *bytesWritten) noexcept;
    NTSTATUS ApplicationConsumeStream(ULONGLONG streamId, UCHAR *output, SIZE_T capacity, SIZE_T *bytesConsumed,
                                      bool *fin) noexcept;
    NTSTATUS ApplicationResetStream(ULONGLONG streamId, ULONGLONG applicationError) noexcept;
    NTSTATUS ApplicationStopSending(ULONGLONG streamId, ULONGLONG applicationError) noexcept;
    NTSTATUS ApplicationClose(ULONGLONG applicationError) noexcept;
#if defined(WKNET_USER_MODE_TEST)
    void WakeTimerForTest() noexcept;
    NTSTATUS ConfigureApplicationKeysForTest(const QuicPacketKeySet &writeKey,
                                             const QuicPacketKeySet &readKey) noexcept;
    NTSTATUS ForceKeyUpdateForTest() noexcept;
    void ConfirmKeyUpdateForTest(ULONGLONG packetNumber) noexcept;
    bool SendKeyPhaseForTest() const noexcept;
    bool SendKeyUpdatePendingForTest() const noexcept;
    NTSTATUS InjectFrameForTest(QuicEncryptionLevel level, QuicPacketNumberSpace space,
                                const QuicFrame &frame) noexcept;
#endif

  private:
    void WorkerLoop() noexcept;
    void Process(QuicCommand *command) noexcept;
    void Complete(QuicOperation *operation, NTSTATUS status, ULONGLONG streamId = 0, SIZE_T bytesTransferred = 0,
                  bool fin = false) noexcept;
    bool Dequeue(QuicCommand **command) noexcept;
    bool ShouldStop() const noexcept;
    bool IsWorkerThread() const noexcept;
    NTSTATUS StartNetwork() noexcept;
    void StopNetwork() noexcept;
    NTSTATUS ArmReceive() noexcept;
    NTSTATUS ProcessReceiveCompletion() noexcept;
    NTSTATUS ProcessDatagram(UCHAR *data, SIZE_T length) noexcept;
    NTSTATUS ProcessPacket(UCHAR *packet, SIZE_T packetLength, QuicPacketHeader &header) noexcept;
    NTSTATUS ValidateFrames(const UCHAR *payload, SIZE_T payloadLength, bool *ackEliciting) noexcept;
    NTSTATUS DispatchFrames(QuicEncryptionLevel level, QuicPacketNumberSpace space, const UCHAR *payload,
                            SIZE_T payloadLength) noexcept;
    NTSTATUS DispatchFrame(QuicEncryptionLevel level, QuicPacketNumberSpace space, const QuicFrame &frame) noexcept;
    NTSTATUS SendInitialClientHello() noexcept;
    NTSTATUS SendCryptoPacket(QuicPacketType type, QuicPacketNumberSpace space, const QuicPacketKeySet &key,
                              ULONGLONG cryptoOffset, const UCHAR *cryptoData, SIZE_T cryptoLength,
                              bool padInitial) noexcept;
    NTSTATUS SendAck(QuicPacketNumberSpace space) noexcept;
    NTSTATUS SendFramePacket(QuicPacketType type, QuicPacketNumberSpace space, const QuicPacketKeySet &key,
                             const QuicFrame &frame, const QuicAckRange *ackRanges, SIZE_T ackRangeCount,
                             bool padInitial, bool ackEliciting) noexcept;
    NTSTATUS HandleTlsProgress() noexcept;
    QuicStream *FindStream(ULONGLONG streamId) noexcept;
    NTSTATUS CreateStream(ULONGLONG streamId, QuicStream **stream) noexcept;
    void ClearStreams() noexcept;
    NTSTATUS SendStreamFrame(QuicStream &stream, const UCHAR *data, SIZE_T length, bool fin) noexcept;
    NTSTATUS HandleNewConnectionId(const QuicFrame &frame) noexcept;
    NTSTATUS HandleRetireConnectionId(const QuicFrame &frame) noexcept;
    NTSTATUS IssueConnectionId() noexcept;
    bool IsLocalConnectionId(QuicBufferView connectionId) const noexcept;
    bool MatchesStatelessReset(const UCHAR *packet, SIZE_T packetLength) const noexcept;
    NTSTATUS InstallApplicationKeys() noexcept;
    NTSTATUS InitiateKeyUpdate() noexcept;
    void ConfirmSendKeyUpdate(const QuicAckRange *ranges, SIZE_T rangeCount) noexcept;
    void DiscardExpiredReadKey(ULONGLONG now100ns) noexcept;
    ULONGLONG NextDeadline100ns() const noexcept;
    NTSTATUS ProcessDeadlines() noexcept;
    NTSTATUS SendProbe(QuicPacketNumberSpace space) noexcept;
    void WakeWorker() noexcept;
    void TransitionToClosed() noexcept;
    NTSTATUS EnterClosing(ULONGLONG errorCode, bool sendCloseFrame, bool applicationError = false) noexcept;
    void EnterDraining() noexcept;
    void FailConnection(NTSTATUS status, ULONGLONG transportError) noexcept;
    static void ReceiveNotification(void *context) noexcept;
#if defined(WKNET_USER_MODE_TEST)
    static void WorkerEntry(QuicConnection *connection) noexcept;
    mutable std::mutex lock_;
    std::condition_variable wake_;
    std::thread worker_;
#else
    static void WorkerEntry(void *context);
    mutable KSPIN_LOCK lock_ = {};
    KEVENT wake_ = {};
    PETHREAD worker_ = nullptr;
#endif
    HeapArray<QuicCommand *> queue_;
    QuicCommand *deferredCommand_ = nullptr;
    HeapArray<QuicStream *> streams_;
    HeapArray<QuicConnectionIdEntry> localConnectionIds_;
    HeapArray<QuicConnectionIdEntry> peerConnectionIds_;
    SIZE_T streamCount_ = 0;
    SIZE_T localConnectionIdCount_ = 0;
    SIZE_T peerConnectionIdCount_ = 0;
    SIZE_T head_ = 0;
    SIZE_T count_ = 0;
    QuicConnectionState state_ = QuicConnectionState::Idle;
    ULONGLONG nextBidiStreamId_ = 0;
    ULONGLONG nextUniStreamId_ = 2;
    ULONGLONG peerMaxStreamsBidi_ = 0;
    ULONGLONG peerMaxStreamsUni_ = 0;
    bool connectQueued_ = false;
    bool closeQueued_ = false;
    bool suspended_ = false;
    bool stop_ = false;
    bool workerActive_ = false;
    bool receiveReady_ = false;
    bool timerReady_ = false;
    bool receivePending_ = false;
    bool networkEnabled_ = false;
    net::WskClient *datagramClient_ = nullptr;
    net::WskDatagramSocket *datagramSocket_ = nullptr;
    SOCKADDR_STORAGE remoteAddress_ = {};
    ULONG remoteAddressLength_ = 0;
    HeapArray<char> serverName_;
    const tls::CertificateStore *certificateStore_ = nullptr;
    rtl::IScratchAllocator *certificateScratchAllocator_ = nullptr;
    const crypto::CngProviderCache *providerCache_ = nullptr;
    tls::Tls13SessionCache *sessionCache_ = nullptr;
    QuicTokenCache *tokenCache_ = nullptr;
    const crypto::TlsClientCredential *clientCredential_ = nullptr;
    QuicStreamApplicationEventSink applicationEventSink_ = {};
    bool verifyCertificate_ = true;
    bool requireRevocationCheck_ = false;
    UCHAR initialDestinationConnectionId_[QuicMaximumConnectionIdLength] = {};
    SIZE_T initialDestinationConnectionIdLength_ = 0;
    UCHAR sourceConnectionId_[QuicMaximumConnectionIdLength] = {};
    SIZE_T sourceConnectionIdLength_ = 0;
    UCHAR peerConnectionId_[QuicMaximumConnectionIdLength] = {};
    SIZE_T peerConnectionIdLength_ = 0;
    HeapArray<UCHAR> receiveBuffer_;
    HeapArray<UCHAR> packetBuffer_;
    HeapArray<UCHAR> decryptBuffer_;
    HeapArray<UCHAR> frameBuffer_;
    HeapArray<UCHAR> clientHelloBuffer_;
    HeapArray<QuicAckRange> ackRangeScratch_;
    QuicPacketKeySet initialWriteKey_ = {};
    QuicPacketKeySet initialReadKey_ = {};
    QuicPacketKeySet applicationWriteKey_ = {};
    QuicPacketKeySet previousApplicationWriteKey_ = {};
    QuicPacketKeySet applicationReadKey_ = {};
    QuicPacketKeySet nextApplicationReadKey_ = {};
    QuicPacketKeySet previousApplicationReadKey_ = {};
    QuicAttemptValidation attempt_;
    QuicTls tls_;
    QuicRecovery recovery_;
    QuicFlowController flowControl_;
    QuicAckTracker ackTrackers_[3];
    ULONGLONG nextPacketNumber_[3] = {};
    ULONGLONG expectedPacketNumber_[3] = {};
    SIZE_T clientHelloLength_ = 0;
    ULONGLONG initialCryptoSendOffset_ = 0;
    ULONGLONG handshakeCryptoSendOffset_ = 0;
    bool peerTransportParametersApplied_ = false;
    bool clientFinishedSent_ = false;
    bool peerConnectionIdAuthenticated_ = false;
    ULONGLONG currentPeerConnectionIdSequence_ = 0;
    ULONGLONG nextLocalConnectionIdSequence_ = 1;
    ULONGLONG sendKeyPhaseStartPacketNumber_ = 0;
    ULONGLONG oneRttPacketsInSendPhase_ = 0;
    ULONGLONG previousReadKeyDeadline100ns_ = 0;
    ULONGLONG lastActivityTime100ns_ = 0;
    ULONGLONG idleTimeout100ns_ = 300000000ULL;
    ULONGLONG closingDeadline100ns_ = 0;
    ULONGLONG drainingDeadline100ns_ = 0;
    bool applicationKeysInstalled_ = false;
    bool sendKeyPhase_ = false;
    bool receiveKeyPhase_ = false;
    bool previousReceiveKeyPhase_ = false;
    bool sendKeyUpdateAwaitingAck_ = false;
    bool previousReadKeyValid_ = false;
    ULONGLONG pendingTransportError_ = 0;
};
} // namespace wknet::quic
