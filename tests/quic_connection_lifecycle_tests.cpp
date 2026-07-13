#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif
#include "net/WskDatagramSocketTest.h"
#include "quic/QuicClock.h"
#include "quic/QuicConnection.h"
#include "quic/QuicStream.h"
#include "quic/QuicTokenCache.h"
#include <stdio.h>
#include <string.h>
namespace
{
bool f = false;

struct StreamEventState final
{
    SIZE_T OpenedCount = 0;
    ULONGLONG LastOpenedStreamId = 0;
};

struct ApplicationCommandState final
{
    bool Invoked = false;
    ULONGLONG StreamId = 0;
};

NTSTATUS RunApplicationCommand(void *context, wknet::quic::QuicConnection *connection) noexcept
{
    auto *state = static_cast<ApplicationCommandState *>(context);
    if (state == nullptr || connection == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    wknet::quic::QuicStream *stream = nullptr;
    NTSTATUS status = wknet::quic::QuicConnectionWorkerOpenBidirectionalStream(connection, &stream);
    if (NT_SUCCESS(status))
    {
        state->Invoked = true;
        state->StreamId = stream->Id();
    }
    return status;
}

void OnStreamOpened(void *context, wknet::quic::QuicStream *stream) noexcept
{
    auto *state = static_cast<StreamEventState *>(context);
    if (state != nullptr && stream != nullptr)
    {
        ++state->OpenedCount;
        state->LastOpenedStreamId = stream->Id();
    }
}

void E(bool c, const char *m)
{
    if (!c)
    {
        f = true;
        printf("FAIL: %s\n", m);
    }
}
} // namespace
int main()
{
    wknet::quic::QuicTokenCache tokenCache;
    E(NT_SUCCESS(tokenCache.Initialize(2)), "NEW_TOKEN cache initializes");
    const UCHAR firstToken[] = {1, 2, 3};
    const UCHAR secondToken[] = {4, 5};
    const UCHAR thirdToken[] = {6};
    E(NT_SUCCESS(tokenCache.Store({firstToken, sizeof(firstToken)})) &&
          NT_SUCCESS(tokenCache.Store({secondToken, sizeof(secondToken)})),
      "NEW_TOKEN cache stores bounded opaque tokens");
    E(NT_SUCCESS(tokenCache.Store({thirdToken, sizeof(thirdToken)})) && tokenCache.Count() == 2,
      "NEW_TOKEN cache evicts the oldest token at capacity");
    const wknet::quic::QuicBufferView latestToken = tokenCache.Latest();
    E(latestToken.Length == sizeof(thirdToken) && latestToken.Data[0] == thirdToken[0],
      "NEW_TOKEN cache returns the newest token");

    wknet::quic::QuicConnectionTestSetWorkerStartFailure(true);
    wknet::quic::QuicConnection *c = nullptr;
    wknet::quic::QuicConnectionCreateOptions o = {};
    E(wknet::quic::QuicConnectionCreate(o, &c) == STATUS_INSUFFICIENT_RESOURCES && c == nullptr,
      "worker start failure propagates");
    wknet::quic::QuicConnectionTestSetWorkerStartFailure(false);
    StreamEventState streamEvents = {};
    wknet::quic::QuicStreamApplicationEventSink streamSink = {};
    streamSink.Context = &streamEvents;
    streamSink.Opened = OnStreamOpened;
    o.ApplicationEventSink = &streamSink;
    o.CommandCapacity = 2;
    o.StartWorkerSuspended = true;
    E(NT_SUCCESS(wknet::quic::QuicConnectionCreate(o, &c)), "connection and suspended worker create");
    wknet::quic::QuicOperation a = {}, duplicateConnect = {}, b = {}, overflow = {};
    wknet::quic::QuicOperationInitialize(&a);
    wknet::quic::QuicOperationInitialize(&duplicateConnect);
    wknet::quic::QuicOperationInitialize(&b);
    wknet::quic::QuicOperationInitialize(&overflow);
    E(NT_SUCCESS(wknet::quic::QuicConnectionConnect(c, &a)), "Connect command enqueues");
    E(wknet::quic::QuicConnectionConnect(c, &duplicateConnect) == STATUS_INVALID_DEVICE_STATE,
      "queued Connect reserves the Idle transition");
    E(NT_SUCCESS(wknet::quic::QuicConnectionTestEnqueueNoop(c, &b)), "second command fills queue");
    E(wknet::quic::QuicConnectionTestEnqueueNoop(c, &b) == STATUS_INVALID_DEVICE_STATE,
      "one operation record cannot be queued twice");
    E(wknet::quic::QuicConnectionTestEnqueueNoop(c, &overflow) == STATUS_INSUFFICIENT_RESOURCES,
      "queue cap fails closed");
    wknet::quic::QuicConnectionTestResumeWorker(c);
    E(NT_SUCCESS(wknet::quic::QuicOperationWait(&a, 1000)), "Connect operation completes");
    E(wknet::quic::QuicConnectionStateGet(c) == wknet::quic::QuicConnectionState::Handshaking,
      "first Initial transitions to Handshaking");
    wknet::quic::QuicOperation established = {};
    wknet::quic::QuicOperationInitialize(&established);
    E(NT_SUCCESS(wknet::quic::QuicConnectionWaitEstablishedAsync(c, &established)),
      "established wait registers while handshaking");
    E(wknet::quic::QuicOperationWait(&established, 1) == STATUS_IO_TIMEOUT,
      "established wait remains pending before handshake confirmation");
    E(wknet::quic::QuicConnectionConnect(c, &overflow) == STATUS_INVALID_DEVICE_STATE, "repeat Connect rejected");
    E(NT_SUCCESS(wknet::quic::QuicConnectionTestConfirmHandshake(c)), "handshake confirmation injected");
    E(NT_SUCCESS(wknet::quic::QuicOperationWait(&established, 1000)),
      "established wait completes after handshake confirmation");
    E(wknet::quic::QuicConnectionStateGet(c) == wknet::quic::QuicConnectionState::Established,
      "confirmed handshake establishes connection");
    UCHAR applicationSecret[32] = {};
    for (SIZE_T index = 0; index < sizeof(applicationSecret); ++index)
    {
        applicationSecret[index] = static_cast<UCHAR>(index + 1);
    }
    wknet::quic::QuicPacketKeySet applicationKey = {};
    E(NT_SUCCESS(wknet::quic::QuicDerivePacketKeySet(wknet::quic::QuicCipherSuite::Aes128GcmSha256, applicationSecret,
                                                     sizeof(applicationSecret), &applicationKey)) &&
          NT_SUCCESS(wknet::quic::QuicConnectionTestConfigureApplicationKeys(c, applicationKey, applicationKey)),
      "application packet keys install for deterministic Key Phase testing");
    E(NT_SUCCESS(wknet::quic::QuicConnectionTestForceKeyUpdate(c)) && wknet::quic::QuicConnectionTestSendKeyPhase(c) &&
          wknet::quic::QuicConnectionTestSendKeyUpdatePending(c),
      "local Key Phase update derives next keys and waits for ACK confirmation");
    E(wknet::quic::QuicConnectionTestForceKeyUpdate(c) == STATUS_INVALID_DEVICE_STATE,
      "a second local Key Phase update is blocked before confirmation");
    wknet::quic::QuicConnectionTestConfirmKeyUpdate(c, 0);
    E(!wknet::quic::QuicConnectionTestSendKeyUpdatePending(c) &&
          NT_SUCCESS(wknet::quic::QuicConnectionTestForceKeyUpdate(c)) &&
          !wknet::quic::QuicConnectionTestSendKeyPhase(c),
      "ACK confirmation releases the previous send key and permits the next phase");
    wknet::quic::QuicClearPacketKeySet(&applicationKey);
    wknet::quic::QuicOperation open = {};
    wknet::quic::QuicOperationInitialize(&open);
    E(NT_SUCCESS(wknet::quic::QuicConnectionOpenStream(c, &open)), "OpenStream enqueues");
    E(NT_SUCCESS(wknet::quic::QuicOperationWait(&open, 1000)) && open.StreamId == 0,
      "first client bidi stream is zero");
    E(streamEvents.OpenedCount == 1 && streamEvents.LastOpenedStreamId == 0,
      "connection registers the application sink on a local bidirectional stream");
    wknet::quic::QuicOperation openUni = {};
    wknet::quic::QuicOperationInitialize(&openUni);
    E(NT_SUCCESS(wknet::quic::QuicConnectionOpenUnidirectionalStream(c, &openUni)),
      "OpenUnidirectionalStream enqueues");
    E(NT_SUCCESS(wknet::quic::QuicOperationWait(&openUni, 1000)) && openUni.StreamId == 2,
      "first client unidirectional stream is two");
    E(streamEvents.OpenedCount == 2 && streamEvents.LastOpenedStreamId == 2,
      "connection registers the application sink on a local unidirectional stream");
    ApplicationCommandState applicationState = {};
    wknet::quic::QuicOperation application = {};
    wknet::quic::QuicOperationInitialize(&application);
    E(NT_SUCCESS(
          wknet::quic::QuicConnectionExecuteApplication(c, RunApplicationCommand, &applicationState, &application)),
      "application command enqueues on the QUIC worker");
    E(NT_SUCCESS(wknet::quic::QuicOperationWait(&application, 1000)) && applicationState.Invoked &&
          applicationState.StreamId == 4,
      "application command executes worker-only stream services with a terminal fence");
    const UCHAR requestBytes[] = {1, 2, 3};
    wknet::quic::QuicOperation write = {};
    wknet::quic::QuicOperationInitialize(&write);
    E(NT_SUCCESS(wknet::quic::QuicConnectionWriteStream(c, open.StreamId, requestBytes, sizeof(requestBytes), false,
                                                        &write)) &&
          NT_SUCCESS(wknet::quic::QuicOperationWait(&write, 1000)) && write.BytesTransferred == sizeof(requestBytes),
      "stream write command copies input and advances flow-control state");
    UCHAR consumedBytes[8] = {};
    wknet::quic::QuicOperation consume = {};
    wknet::quic::QuicOperationInitialize(&consume);
    E(NT_SUCCESS(
          wknet::quic::QuicConnectionConsumeStream(c, open.StreamId, consumedBytes, sizeof(consumedBytes), &consume)) &&
          NT_SUCCESS(wknet::quic::QuicOperationWait(&consume, 1000)) && consume.BytesTransferred == 0,
      "stream consume command completes without inventing receive data");
    const UCHAR peerStreamBytes[] = {9, 8, 7};
    wknet::quic::QuicFrame peerStreamFrame = {};
    peerStreamFrame.Kind = wknet::quic::QuicFrameKind::Stream;
    peerStreamFrame.StreamId = 3;
    peerStreamFrame.Data = {peerStreamBytes, sizeof(peerStreamBytes)};
    peerStreamFrame.Fin = true;
    E(NT_SUCCESS(wknet::quic::QuicConnectionTestInjectFrame(c, wknet::quic::QuicEncryptionLevel::Application,
                                                            wknet::quic::QuicPacketNumberSpace::Application,
                                                            peerStreamFrame)),
      "worker dispatch creates a peer unidirectional stream from STREAM");
    wknet::quic::QuicOperation consumePeer = {};
    wknet::quic::QuicOperationInitialize(&consumePeer);
    E(NT_SUCCESS(wknet::quic::QuicConnectionConsumeStream(c, 3, consumedBytes, sizeof(consumedBytes), &consumePeer)) &&
          NT_SUCCESS(wknet::quic::QuicOperationWait(&consumePeer, 1000)) &&
          consumePeer.BytesTransferred == sizeof(peerStreamBytes) && consumePeer.Fin &&
          memcmp(consumedBytes, peerStreamBytes, sizeof(peerStreamBytes)) == 0,
      "peer STREAM data is reassembled and consumed through the command queue");
    const UCHAR peerConnectionId[] = {20, 21, 22, 23};
    const UCHAR peerResetToken[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    wknet::quic::QuicFrame newConnectionId = {};
    newConnectionId.Kind = wknet::quic::QuicFrameKind::NewConnectionId;
    newConnectionId.Sequence = 1;
    newConnectionId.ConnectionId = {peerConnectionId, sizeof(peerConnectionId)};
    newConnectionId.StatelessResetToken = {peerResetToken, sizeof(peerResetToken)};
    E(NT_SUCCESS(wknet::quic::QuicConnectionTestInjectFrame(c, wknet::quic::QuicEncryptionLevel::Application,
                                                            wknet::quic::QuicPacketNumberSpace::Application,
                                                            newConnectionId)),
      "NEW_CONNECTION_ID installs a bounded peer CID and stateless reset token");
    UCHAR conflictingResetToken[16] = {};
    memcpy(conflictingResetToken, peerResetToken, sizeof(conflictingResetToken));
    conflictingResetToken[0] ^= 0xff;
    newConnectionId.StatelessResetToken = {conflictingResetToken, sizeof(conflictingResetToken)};
    E(wknet::quic::QuicConnectionTestInjectFrame(c, wknet::quic::QuicEncryptionLevel::Application,
                                                 wknet::quic::QuicPacketNumberSpace::Application,
                                                 newConnectionId) == STATUS_INVALID_NETWORK_RESPONSE,
      "duplicate CID sequence with a different reset token is rejected");
    wknet::quic::QuicOperation stopSending = {};
    wknet::quic::QuicOperationInitialize(&stopSending);
    E(NT_SUCCESS(wknet::quic::QuicConnectionStopSending(c, open.StreamId, 10, &stopSending)) &&
          NT_SUCCESS(wknet::quic::QuicOperationWait(&stopSending, 1000)),
      "stream STOP_SENDING command completes on the worker");
    wknet::quic::QuicOperation reset = {};
    wknet::quic::QuicOperationInitialize(&reset);
    E(NT_SUCCESS(wknet::quic::QuicConnectionResetStream(c, open.StreamId, 11, &reset)) &&
          NT_SUCCESS(wknet::quic::QuicOperationWait(&reset, 1000)),
      "stream RESET_STREAM command uses the committed final size");
    E(wknet::quic::QuicConnectionTestCloseFromWorker(c) == STATUS_INVALID_DEVICE_STATE,
      "worker self-wait close rejected");
    wknet::quic::QuicOperation close = {};
    wknet::quic::QuicOperationInitialize(&close);
    E(NT_SUCCESS(wknet::quic::QuicConnectionCloseAsync(c, &close)), "Close enqueues");
    E(NT_SUCCESS(wknet::quic::QuicOperationWait(&close, 1000)), "Close operation completes");
    E(wknet::quic::QuicConnectionStateGet(c) == wknet::quic::QuicConnectionState::Closed, "local close reaches Closed");
    E(wknet::quic::QuicConnectionOpenStream(c, &overflow) == STATUS_DEVICE_NOT_READY, "Closed rejects new stream");
    E(wknet::quic::QuicConnectionOpenUnidirectionalStream(c, &overflow) == STATUS_DEVICE_NOT_READY,
      "Closed rejects new unidirectional stream");
    wknet::quic::QuicConnectionDestroy(c);

    wknet::quic::QuicConnection *pendingConnection = nullptr;
    o.CommandCapacity = 1;
    o.StartWorkerSuspended = true;
    E(NT_SUCCESS(wknet::quic::QuicConnectionCreate(o, &pendingConnection)), "pending-command drain connection creates");
    wknet::quic::QuicOperation pending = {};
    wknet::quic::QuicOperationInitialize(&pending);
    E(NT_SUCCESS(wknet::quic::QuicConnectionConnect(pendingConnection, &pending)),
      "pending command enqueues before destroy");
    wknet::quic::QuicConnectionDestroy(pendingConnection);
    E(wknet::quic::QuicOperationWait(&pending, 1000) == STATUS_CANCELLED,
      "destroy drains queued operation with one terminal cancellation");

    wknet::net::test::ResetProvider();
    wknet::net::test::SetCancelCompletesImmediately(true);
    wknet::net::WskClient *datagramClient = nullptr;
    E(NT_SUCCESS(wknet::net::WskClientCreate(&datagramClient)) &&
          NT_SUCCESS(wknet::net::WskClientInitialize(datagramClient)),
      "network connection WSK client initializes");
    SOCKADDR_STORAGE remote = {};
    SOCKADDR_IN *remoteIpv4 = reinterpret_cast<SOCKADDR_IN *>(&remote);
    remoteIpv4->sin_family = AF_INET;
    remoteIpv4->sin_port = 443;
    remoteIpv4->sin_addr = 0x0100007fUL;
    const UCHAR destinationConnectionId[] = {1, 2, 3, 4, 5, 6, 7, 8};
    const UCHAR sourceConnectionId[] = {9, 10, 11, 12, 13, 14, 15, 16};
    wknet::quic::QuicConnectionCreateOptions networkOptions = {};
    networkOptions.DatagramClient = datagramClient;
    networkOptions.RemoteAddress = reinterpret_cast<const SOCKADDR *>(&remote);
    networkOptions.RemoteAddressLength = sizeof(SOCKADDR_IN);
    networkOptions.ServerName = "example.com";
    networkOptions.ServerNameLength = 11;
    networkOptions.InitialDestinationConnectionId = {destinationConnectionId, sizeof(destinationConnectionId)};
    networkOptions.InitialSourceConnectionId = {sourceConnectionId, sizeof(sourceConnectionId)};
    networkOptions.VerifyCertificate = false;
    wknet::quic::QuicConnection *networkConnection = nullptr;
    E(NT_SUCCESS(wknet::quic::QuicConnectionCreate(networkOptions, &networkConnection)),
      "network QUIC connection creates");
    wknet::quic::QuicOperation networkConnect = {};
    wknet::quic::QuicOperationInitialize(&networkConnect);
    E(NT_SUCCESS(wknet::quic::QuicConnectionConnect(networkConnection, &networkConnect)) &&
          NT_SUCCESS(wknet::quic::QuicOperationWait(&networkConnect, 5000)),
      "network Connect sends the client Initial");
    const wknet::net::test::WskDatagramProviderStatistics networkStatistics = wknet::net::test::GetProviderStatistics();
    E(networkStatistics.SendCalls == 1 && networkStatistics.ReceiveCalls == 1 &&
          networkStatistics.OutstandingReceives == 1,
      "network Connect sends one Initial and arms one receive");
    wknet::quic::QuicPacketKeySet networkApplicationKey = {};
    E(NT_SUCCESS(wknet::quic::QuicDerivePacketKeySet(wknet::quic::QuicCipherSuite::Aes128GcmSha256, applicationSecret,
                                                     sizeof(applicationSecret), &networkApplicationKey)) &&
          NT_SUCCESS(wknet::quic::QuicConnectionTestConfigureApplicationKeys(networkConnection, networkApplicationKey,
                                                                             networkApplicationKey)),
      "network application keys install for PATH response testing");
    const UCHAR pathChallengeData[8] = {1, 3, 5, 7, 9, 11, 13, 15};
    wknet::quic::QuicFrame pathChallenge = {};
    pathChallenge.Kind = wknet::quic::QuicFrameKind::PathChallenge;
    pathChallenge.Data = {pathChallengeData, sizeof(pathChallengeData)};
    E(NT_SUCCESS(
          wknet::quic::QuicConnectionTestInjectFrame(networkConnection, wknet::quic::QuicEncryptionLevel::Application,
                                                     wknet::quic::QuicPacketNumberSpace::Application, pathChallenge)) &&
          wknet::net::test::GetProviderStatistics().SendCalls == 2,
      "PATH_CHALLENGE on the fixed peer path sends one PATH_RESPONSE");
    wknet::quic::QuicClearPacketKeySet(&networkApplicationKey);
    wknet::quic::QuicOperation networkClose = {};
    wknet::quic::QuicOperationInitialize(&networkClose);
    E(NT_SUCCESS(wknet::quic::QuicConnectionCloseAsync(networkConnection, &networkClose)) &&
          NT_SUCCESS(wknet::quic::QuicOperationWait(&networkClose, 5000)) &&
          wknet::quic::QuicConnectionStateGet(networkConnection) == wknet::quic::QuicConnectionState::Closing,
      "network close enters Closing until the three-PTO deadline");
    wknet::quic::QuicTestClockAdvance(400000000ULL);
    E(NT_SUCCESS(wknet::quic::QuicConnectionTestProcessTimer(networkConnection)) &&
          wknet::quic::QuicConnectionStateGet(networkConnection) == wknet::quic::QuicConnectionState::Closed,
      "Closing deadline drains receive and closes the network connection");
    wknet::quic::QuicConnectionDestroy(networkConnection);
    wknet::net::WskClientClose(datagramClient);
    if (f)
    {
        printf("QUIC CONNECTION LIFECYCLE TESTS FAILED\n");
        return 1;
    }
    printf("QUIC CONNECTION LIFECYCLE TESTS PASSED\n");
    return 0;
}
