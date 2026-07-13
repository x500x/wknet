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
class QuicStream;
struct QuicStreamApplicationEventSink;

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
    const QuicStreamApplicationEventSink *ApplicationEventSink = nullptr;
    bool VerifyCertificate = true;
    bool RequireRevocationCheck = false;
};
class QuicConnection;
using QuicApplicationCommandCallback = NTSTATUS (*)(void *context, QuicConnection *connection) noexcept;
void QuicOperationInitialize(QuicOperation *operation) noexcept;
NTSTATUS QuicOperationWait(QuicOperation *operation, ULONG timeoutMilliseconds) noexcept;
NTSTATUS QuicConnectionCreate(const QuicConnectionCreateOptions &options, QuicConnection **connection) noexcept;
NTSTATUS QuicConnectionConnect(QuicConnection *connection, QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionWaitEstablishedAsync(QuicConnection *connection, QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionOpenStream(QuicConnection *connection, QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionOpenUnidirectionalStream(QuicConnection *connection, QuicOperation *operation) noexcept;
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
NTSTATUS QuicConnectionCloseApplicationAsync(QuicConnection *connection, ULONGLONG applicationError,
                                             QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionExecuteApplication(QuicConnection *connection, QuicApplicationCommandCallback callback,
                                          void *context, QuicOperation *operation) noexcept;
NTSTATUS QuicConnectionApplicationWriteStream(QuicConnection *connection, ULONGLONG streamId,
                                              _In_reads_bytes_opt_(dataLength) const UCHAR *data, SIZE_T dataLength,
                                              bool fin, _Out_ SIZE_T *bytesWritten) noexcept;
NTSTATUS QuicConnectionApplicationConsumeStream(QuicConnection *connection, ULONGLONG streamId,
                                                _Out_writes_bytes_opt_(capacity) UCHAR *output, SIZE_T capacity,
                                                _Out_ SIZE_T *bytesConsumed, _Out_ bool *fin) noexcept;
NTSTATUS QuicConnectionApplicationResetStream(QuicConnection *connection, ULONGLONG streamId,
                                              ULONGLONG applicationError) noexcept;
NTSTATUS QuicConnectionApplicationStopSending(QuicConnection *connection, ULONGLONG streamId,
                                              ULONGLONG applicationError) noexcept;
NTSTATUS QuicConnectionApplicationClose(QuicConnection *connection, ULONGLONG applicationError) noexcept;
NTSTATUS QuicConnectionWorkerOpenBidirectionalStream(QuicConnection *connection, _Out_ QuicStream **stream) noexcept;
NTSTATUS QuicConnectionWorkerOpenUnidirectionalStream(QuicConnection *connection, _Out_ QuicStream **stream) noexcept;
NTSTATUS QuicConnectionWorkerConsumeStream(QuicConnection *connection, QuicStream *stream,
                                           _Out_writes_bytes_opt_(capacity) UCHAR *output, SIZE_T capacity,
                                           _Out_ SIZE_T *bytesConsumed, _Out_ bool *fin) noexcept;
NTSTATUS QuicConnectionWorkerWriteStream(QuicConnection *connection, QuicStream *stream,
                                         _In_reads_bytes_opt_(length) const UCHAR *data, SIZE_T length, bool fin,
                                         _Out_opt_ SIZE_T *bytesWritten) noexcept;
NTSTATUS QuicConnectionWorkerResetStream(QuicConnection *connection, QuicStream *stream,
                                         ULONGLONG applicationError) noexcept;
NTSTATUS QuicConnectionWorkerStopSending(QuicConnection *connection, QuicStream *stream,
                                         ULONGLONG applicationError) noexcept;
NTSTATUS QuicConnectionWorkerCloseApplication(QuicConnection *connection, ULONGLONG applicationError) noexcept;
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
