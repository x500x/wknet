#pragma once
#include "net/WskDatagramSocket.h"
#include "quic/QuicTls.h"
#include "quic/QuicTypes.h"
#if defined(WKNET_USER_MODE_TEST)
#include "quic/QuicFrame.h"
#include "quic/QuicRecovery.h"
#endif
#if defined(WKNET_USER_MODE_TEST)
#include <condition_variable>
#include <mutex>
#endif
namespace wknet::quic
{
class QuicTokenCache;

enum class QuicConnectionState : UCHAR
{
    Idle,
    Connecting,
    Handshaking,
    Established,
    Closing,
    Draining,
    Closed,
    Failed
};
struct QuicOperation final
{
    NTSTATUS Status = STATUS_PENDING;
    ULONGLONG StreamId = 0;
    SIZE_T BytesTransferred = 0;
    bool Fin = false;
    volatile LONG CompletionState = 0;
#if defined(WKNET_USER_MODE_TEST)
    std::mutex Lock;
    std::condition_variable Event;
#else
    KEVENT Event = {};
#endif
};
struct QuicConnectionCreateOptions final
{
    SIZE_T CommandCapacity = WKNET_HARD_MAX_QUIC_COMMANDS;
    bool StartWorkerSuspended = false;
    net::WskClient *DatagramClient = nullptr;
    const SOCKADDR *RemoteAddress = nullptr;
    ULONG RemoteAddressLength = 0;
    const char *ServerName = nullptr;
    SIZE_T ServerNameLength = 0;
    QuicBufferView InitialDestinationConnectionId = {};
    QuicBufferView InitialSourceConnectionId = {};
    const tls::CertificateStore *CertificateStore = nullptr;
    rtl::IScratchAllocator *CertificateScratchAllocator = nullptr;
    const crypto::CngProviderCache *ProviderCache = nullptr;
    tls::Tls13SessionCache *SessionCache = nullptr;
    QuicTokenCache *TokenCache = nullptr;
    const crypto::TlsClientCredential *ClientCredential = nullptr;
    bool VerifyCertificate = true;
    bool RequireRevocationCheck = false;
};
class QuicConnection;
void QuicOperationInitialize(QuicOperation *operation) noexcept;
NTSTATUS QuicOperationWait(QuicOperation *operation, ULONG timeoutMilliseconds) noexcept;
NTSTATUS QuicConnectionCreate(const QuicConnectionCreateOptions &options, QuicConnection **connection) noexcept;
NTSTATUS QuicConnectionConnect(QuicConnection *connection, QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionOpenStream(QuicConnection *connection, QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionWriteStream(QuicConnection *connection, ULONGLONG streamId,
                                   _In_reads_bytes_opt_(dataLength) const UCHAR *data, SIZE_T dataLength, bool fin,
                                   QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionConsumeStream(QuicConnection *connection, ULONGLONG streamId,
                                     _Out_writes_bytes_opt_(capacity) UCHAR *output, SIZE_T capacity,
                                     QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionResetStream(QuicConnection *connection, ULONGLONG streamId, ULONGLONG errorCode,
                                   QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionStopSending(QuicConnection *connection, ULONGLONG streamId, ULONGLONG errorCode,
                                   QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionCloseAsync(QuicConnection *connection, QuicOperation *operation) noexcept;
QuicConnectionState QuicConnectionStateGet(const QuicConnection *connection) noexcept;
void QuicConnectionDestroy(QuicConnection *connection) noexcept;
#if defined(WKNET_USER_MODE_TEST)
void QuicConnectionTestSetWorkerStartFailure(bool fail) noexcept;
NTSTATUS QuicConnectionTestEnqueueNoop(QuicConnection *connection, QuicOperation *operation) noexcept;
void QuicConnectionTestResumeWorker(QuicConnection *connection) noexcept;
NTSTATUS QuicConnectionTestConfirmHandshake(QuicConnection *connection) noexcept;
NTSTATUS QuicConnectionTestCloseFromWorker(QuicConnection *connection) noexcept;
void QuicConnectionTestWakeTimer(QuicConnection *connection) noexcept;
NTSTATUS QuicConnectionTestProcessTimer(QuicConnection *connection) noexcept;
NTSTATUS QuicConnectionTestConfigureApplicationKeys(QuicConnection *connection, const QuicPacketKeySet &writeKey,
                                                    const QuicPacketKeySet &readKey) noexcept;
NTSTATUS QuicConnectionTestForceKeyUpdate(QuicConnection *connection) noexcept;
void QuicConnectionTestConfirmKeyUpdate(QuicConnection *connection, ULONGLONG packetNumber) noexcept;
bool QuicConnectionTestSendKeyPhase(const QuicConnection *connection) noexcept;
bool QuicConnectionTestSendKeyUpdatePending(const QuicConnection *connection) noexcept;
NTSTATUS QuicConnectionTestInjectFrame(QuicConnection *connection, QuicEncryptionLevel level,
                                       QuicPacketNumberSpace space, const QuicFrame &frame) noexcept;
#endif
} // namespace wknet::quic
