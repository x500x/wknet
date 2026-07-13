#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif
#include "quic/QuicFlowControl.h"
#include "quic/QuicStream.h"
#include <stdio.h>
#include <string.h>
namespace
{
bool f = false;

struct StreamEventCapture final
{
    ULONG Opened = 0;
    ULONG Readable = 0;
    ULONG Writable = 0;
    ULONG Reset = 0;
    ULONG Closed = 0;
    ULONGLONG LastStreamId = 0;
    ULONGLONG LastResetError = 0;
    bool LastResetPeerInitiated = false;
};

void OnStreamOpened(void *context, wknet::quic::QuicStream *stream) noexcept
{
    StreamEventCapture *capture = static_cast<StreamEventCapture *>(context);
    ++capture->Opened;
    capture->LastStreamId = stream->Id();
}

void OnStreamReadable(void *context, wknet::quic::QuicStream *stream) noexcept
{
    StreamEventCapture *capture = static_cast<StreamEventCapture *>(context);
    ++capture->Readable;
    capture->LastStreamId = stream->Id();
}

void OnStreamWritable(void *context, wknet::quic::QuicStream *stream) noexcept
{
    StreamEventCapture *capture = static_cast<StreamEventCapture *>(context);
    ++capture->Writable;
    capture->LastStreamId = stream->Id();
}

void OnStreamReset(void *context, wknet::quic::QuicStream *stream, ULONGLONG errorCode, bool peerInitiated) noexcept
{
    StreamEventCapture *capture = static_cast<StreamEventCapture *>(context);
    ++capture->Reset;
    capture->LastStreamId = stream->Id();
    capture->LastResetError = errorCode;
    capture->LastResetPeerInitiated = peerInitiated;
}

void OnStreamClosed(void *context, wknet::quic::QuicStream *stream) noexcept
{
    StreamEventCapture *capture = static_cast<StreamEventCapture *>(context);
    ++capture->Closed;
    capture->LastStreamId = stream->Id();
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
    E(wknet::quic::QuicStreamIsClientInitiated(0) && wknet::quic::QuicStreamIsBidirectional(0),
      "stream 0 is client bidi");
    E(!wknet::quic::QuicStreamIsClientInitiated(1) && wknet::quic::QuicStreamIsBidirectional(1),
      "stream 1 is server bidi");
    E(!wknet::quic::QuicStreamIsBidirectional(2), "stream 2 is client uni");
    wknet::quic::QuicStream s;
    E(NT_SUCCESS(s.Initialize(0, 64, 4)), "stream initializes");
    const UCHAR tail[] = {4, 5, 6};
    const UCHAR head[] = {1, 2, 3, 4};
    E(NT_SUCCESS(s.Receive(3, tail, sizeof(tail), true)), "out-of-order tail accepted");
    E(s.ReceiveFlowControlBytes() == 6, "flow control tracks the highest accepted offset");
    E(NT_SUCCESS(s.Receive(0, head, sizeof(head), false)), "overlapping consistent head merges");
    E(s.ReceivedUniqueBytes() == 6, "overlap is counted once");
    const UCHAR conflict[] = {9};
    E(s.Receive(3, conflict, sizeof(conflict), false) == STATUS_INVALID_NETWORK_RESPONSE,
      "inconsistent overlap rejected");
    UCHAR out[16] = {};
    SIZE_T consumed = 0;
    bool fin = false;
    E(NT_SUCCESS(s.Consume(out, 2, &consumed, &fin)), "contiguous bytes partially consume");
    E(consumed == 2 && !fin && s.BufferedBytes() == 4 && memcmp(out, "\x01\x02", 2) == 0,
      "partial consume advances without copying the remaining chunk");
    E(NT_SUCCESS(s.Consume(out + 2, sizeof(out) - 2, &consumed, &fin)), "remaining bytes consume");
    E(consumed == 4 && fin && s.BufferedBytes() == 0 && memcmp(out, "\x01\x02\x03\x04\x05\x06", 6) == 0,
      "reassembly preserves bytes and FIN");
    E(NT_SUCCESS(s.SetSendLimit(5)), "send limit set");
    SIZE_T accepted = 0;
    E(NT_SUCCESS(s.Write(reinterpret_cast<const UCHAR *>("abc"), 3, false, &accepted)) && accepted == 3,
      "send data accepted");
    E(s.Write(reinterpret_cast<const UCHAR *>("def"), 3, false, &accepted) == STATUS_DEVICE_BUSY,
      "stream flow control blocks excess");
    E(NT_SUCCESS(s.OnMaxStreamData(8)), "MAX_STREAM_DATA raises limit");
    E(NT_SUCCESS(s.Write(reinterpret_cast<const UCHAR *>("def"), 3, true, &accepted)) && accepted == 3,
      "send resumes and FIN closes send side");
    E(s.Write(reinterpret_cast<const UCHAR *>("x"), 1, false, &accepted) == STATUS_INVALID_DEVICE_STATE,
      "write after FIN rejected");

    const UCHAR five[] = {1, 2, 3, 4, 5};
    wknet::quic::QuicStream blocked;
    E(NT_SUCCESS(blocked.Initialize(4)), "blocked stream initializes");
    E(NT_SUCCESS(blocked.SetSendLimit(2)), "blocked stream send limit sets");
    E(blocked.Write(five, 3, false, &accepted) == STATUS_DEVICE_BUSY, "stream send limit blocks data");
    ULONGLONG blockedLimit = 0;
    E(blocked.TakeStreamDataBlocked(&blockedLimit) && blockedLimit == 2,
      "STREAM_DATA_BLOCKED is emitted once for the active limit");
    E(!blocked.TakeStreamDataBlocked(&blockedLimit), "STREAM_DATA_BLOCKED is not duplicated without a new block");
    wknet::quic::QuicStream limited;
    E(NT_SUCCESS(limited.Initialize(4, 4, 1)), "limited stream");
    E(limited.Receive(0, five, sizeof(five), false) == STATUS_INSUFFICIENT_RESOURCES, "reassembly byte cap enforced");
    E(NT_SUCCESS(limited.Receive(2, five, 1, false)), "first gap");
    E(limited.Receive(0, five, 1, false) == STATUS_INSUFFICIENT_RESOURCES, "gap cap enforced");

    wknet::quic::QuicStream rolling;
    E(NT_SUCCESS(rolling.Initialize(8, 4, 2)), "rolling buffer stream initializes");
    E(NT_SUCCESS(rolling.Receive(0, five, 4, false)), "rolling buffer first window receives");
    E(NT_SUCCESS(rolling.Consume(out, 4, &consumed, &fin)) && consumed == 4, "rolling buffer first window consumes");
    E(NT_SUCCESS(rolling.Receive(4, five, 4, false)), "consumed bytes release reassembly capacity");

    wknet::quic::QuicStream clientUni;
    E(NT_SUCCESS(clientUni.Initialize(2)), "client unidirectional stream initializes");
    E(clientUni.Receive(0, five, 1, false) == STATUS_INVALID_DEVICE_STATE,
      "client unidirectional stream rejects receive data");
    wknet::quic::QuicStream serverUni;
    E(NT_SUCCESS(serverUni.Initialize(3)), "server unidirectional stream initializes");
    E(NT_SUCCESS(serverUni.SetSendLimit(4)), "server unidirectional send limit sets");
    E(serverUni.Write(five, 1, false, &accepted) == STATUS_INVALID_DEVICE_STATE,
      "server unidirectional stream rejects writes");

    wknet::quic::QuicStream receiveLimited;
    E(NT_SUCCESS(receiveLimited.Initialize(1)), "receive-limited stream initializes");
    E(NT_SUCCESS(receiveLimited.SetReceiveLimit(5)), "receive limit sets");
    E(receiveLimited.Receive(4, five, 2, false) == STATUS_INVALID_NETWORK_RESPONSE,
      "stream receive flow control rejects excess offset");
    E(NT_SUCCESS(receiveLimited.Receive(3, five, 1, false)), "receive-limited data accepts");
    E(receiveLimited.OnResetReceived(9, 3) == STATUS_INVALID_NETWORK_RESPONSE,
      "RESET_STREAM final size cannot shrink below received data");
    E(NT_SUCCESS(receiveLimited.OnResetReceived(9, 4)) && receiveLimited.ReceiveReset(),
      "consistent RESET_STREAM final size records receive reset");

    wknet::quic::QuicFlowController flow;
    E(NT_SUCCESS(flow.Initialize(5, 8)), "connection flow controller initializes");
    E(NT_SUCCESS(flow.ReserveSend(4)), "connection send credit reserves");
    E(flow.ReserveSend(2) == STATUS_DEVICE_BUSY, "connection MAX_DATA blocks excess send bytes");
    E(flow.TakeDataBlocked(&blockedLimit) && blockedLimit == 5, "DATA_BLOCKED records the active connection limit");
    E(NT_SUCCESS(flow.OnMaxData(9)) && NT_SUCCESS(flow.ReserveSend(2)), "MAX_DATA resumes connection sends");
    E(NT_SUCCESS(flow.OnStreamReceiveProgress(0, 5)), "first stream receive offset contributes to MAX_DATA");
    E(NT_SUCCESS(flow.OnStreamReceiveProgress(5, 7)), "only new stream offset contributes to MAX_DATA");
    E(flow.OnStreamReceiveProgress(0, 2) == STATUS_INVALID_NETWORK_RESPONSE,
      "connection receive limit rejects aggregate excess");
    E(NT_SUCCESS(flow.OnStreamConsumed(4)) && flow.ConsumedBytes() == 4,
      "connection consumption ledger advances independently");
    E(NT_SUCCESS(s.StopSending(42)), "STOP_SENDING recorded");
    E(NT_SUCCESS(s.Reset(7, 6)), "RESET_STREAM recorded");

    StreamEventCapture eventCapture = {};
    const wknet::quic::QuicStreamApplicationEventSink eventSink = {
        &eventCapture, OnStreamOpened, OnStreamReadable, OnStreamWritable, OnStreamReset, OnStreamClosed,
    };
    wknet::quic::QuicStream eventStream;
    E(NT_SUCCESS(eventStream.Initialize(1)), "event stream initializes");
    eventStream.SetApplicationEventSink(&eventSink);
    E(eventCapture.Opened == 1 && eventCapture.LastStreamId == 1,
      "registering a sink on an initialized stream reports opened once");
    E(NT_SUCCESS(eventStream.Receive(1, five, 1, false)) && eventCapture.Readable == 0,
      "out-of-order data does not report readable");
    E(NT_SUCCESS(eventStream.Receive(0, five, 1, false)) && eventCapture.Readable == 1,
      "new contiguous data reports readable");
    E(NT_SUCCESS(eventStream.Receive(0, five, 1, false)) && eventCapture.Readable == 1,
      "readable remains edge-triggered while data is pending");
    E(NT_SUCCESS(eventStream.Consume(out, sizeof(out), &consumed, &fin)) && consumed == 2 && !fin,
      "event stream consumes the readable edge");
    E(NT_SUCCESS(eventStream.Receive(2, nullptr, 0, true)) && eventCapture.Readable == 2,
      "FIN-only receive reports a new readable edge");
    E(NT_SUCCESS(eventStream.Consume(out, sizeof(out), &consumed, &fin)) && consumed == 0 && fin,
      "FIN-only readable edge can be consumed");
    E(NT_SUCCESS(eventStream.SetSendLimit(1)), "event stream send limit sets");
    E(NT_SUCCESS(eventStream.Write(five, 1, false, &accepted)), "event stream consumes send credit");
    E(eventStream.Write(five, 1, false, &accepted) == STATUS_DEVICE_BUSY, "event stream records a blocked write");
    E(eventStream.TakeStreamDataBlocked(&blockedLimit) && blockedLimit == 1,
      "wire STREAM_DATA_BLOCKED state is consumed independently");
    E(NT_SUCCESS(eventStream.OnMaxStreamData(2)) && eventCapture.Writable == 1,
      "MAX_STREAM_DATA reports writable after wire blocked state is consumed");
    E(NT_SUCCESS(eventStream.OnMaxStreamData(3)) && eventCapture.Writable == 1,
      "writable is not duplicated without another blocked write");

    StreamEventCapture resetCapture = {};
    const wknet::quic::QuicStreamApplicationEventSink resetSink = {
        &resetCapture, OnStreamOpened, OnStreamReadable, OnStreamWritable, OnStreamReset, OnStreamClosed,
    };
    wknet::quic::QuicStream resetStream;
    E(NT_SUCCESS(resetStream.Initialize(0)), "reset event stream initializes");
    resetStream.SetApplicationEventSink(&resetSink);
    E(NT_SUCCESS(resetStream.Reset(11, 0)) && resetCapture.Reset == 1 && resetCapture.LastResetError == 11 &&
          !resetCapture.LastResetPeerInitiated,
      "local reset reports reset metadata once");
    E(NT_SUCCESS(resetStream.Reset(11, 0)) && resetCapture.Reset == 1,
      "duplicate local reset does not duplicate the event");
    E(NT_SUCCESS(resetStream.OnResetReceived(12, 0)) && resetCapture.Reset == 2 && resetCapture.LastResetError == 12 &&
          resetCapture.LastResetPeerInitiated && resetCapture.Closed == 1,
      "peer reset reports metadata and closes a bidirectional stream");
    E(NT_SUCCESS(resetStream.OnResetReceived(12, 0)) && resetCapture.Reset == 2 && resetCapture.Closed == 1,
      "duplicate peer reset does not duplicate reset or closed events");
    resetStream.Clear();
    E(resetCapture.Closed == 1, "clear does not duplicate an already closed event");

    StreamEventCapture detachedCapture = {};
    const wknet::quic::QuicStreamApplicationEventSink detachedSink = {
        &detachedCapture, OnStreamOpened, OnStreamReadable, OnStreamWritable, OnStreamReset, OnStreamClosed,
    };
    wknet::quic::QuicStream detachedStream;
    E(NT_SUCCESS(detachedStream.Initialize(1)), "detached event stream initializes");
    detachedStream.SetApplicationEventSink(&detachedSink);
    detachedStream.SetApplicationEventSink(nullptr);
    E(NT_SUCCESS(detachedStream.Receive(0, five, 1, true)) && detachedCapture.Opened == 1 &&
          detachedCapture.Readable == 0 && detachedCapture.Closed == 0,
      "detached sink receives no later stream events");
    if (f)
    {
        printf("QUIC STREAM TESTS FAILED\n");
        return 1;
    }
    printf("QUIC STREAM TESTS PASSED\n");
    return 0;
}
