#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif
#include "quic/QuicFrame.h"
#include <stdio.h>

namespace
{
bool failed = false;
void E(bool c, const char *m)
{
    if (!c)
    {
        failed = true;
        printf("FAIL: %s\n", m);
    }
}
void P(const UCHAR *d, SIZE_T n, wknet::quic::QuicFrameKind k, const char *m)
{
    wknet::quic::QuicFrame f = {};
    SIZE_T c = 0;
    E(NT_SUCCESS(wknet::quic::QuicParseFrame(d, n, &f, &c)) && f.Kind == k && c == n, m);
}
} // namespace
int main()
{
    const UCHAR padding[] = {0x00}, ping[] = {0x01}, ack[] = {0x02, 1, 0, 0, 0}, reset[] = {0x04, 1, 2, 3},
                stop[] = {0x05, 1, 2};
    const UCHAR crypto[] = {0x06, 0, 3, 1, 2, 3}, token[] = {0x07, 2, 1, 2}, stream[] = {0x0f, 1, 0, 2, 9, 8};
    const UCHAR maxData[] = {0x10, 0x40, 0x40}, maxStream[] = {0x11, 1, 10}, maxStreams[] = {0x12, 2},
                blocked[] = {0x14, 10}, streamBlocked[] = {0x15, 1, 10}, streamsBlocked[] = {0x16, 2};
    UCHAR newCid[21] = {0x18, 1, 0, 1, 7};
    for (SIZE_T i = 5; i < 21; ++i)
        newCid[i] = static_cast<UCHAR>(i);
    const UCHAR retire[] = {0x19, 1}, challenge[] = {0x1a, 1, 2, 3, 4, 5, 6, 7, 8},
                response[] = {0x1b, 1, 2, 3, 4, 5, 6, 7, 8};
    const UCHAR closeT[] = {0x1c, 1, 6, 0}, closeA[] = {0x1d, 1, 0}, done[] = {0x1e};
    P(padding, sizeof(padding), wknet::quic::QuicFrameKind::Padding, "PADDING");
    P(ping, sizeof(ping), wknet::quic::QuicFrameKind::Ping, "PING");
    P(ack, sizeof(ack), wknet::quic::QuicFrameKind::Ack, "ACK");
    P(reset, sizeof(reset), wknet::quic::QuicFrameKind::ResetStream, "RESET_STREAM");
    P(stop, sizeof(stop), wknet::quic::QuicFrameKind::StopSending, "STOP_SENDING");
    P(crypto, sizeof(crypto), wknet::quic::QuicFrameKind::Crypto, "CRYPTO");
    P(token, sizeof(token), wknet::quic::QuicFrameKind::NewToken, "NEW_TOKEN");
    P(stream, sizeof(stream), wknet::quic::QuicFrameKind::Stream, "STREAM");
    P(maxData, sizeof(maxData), wknet::quic::QuicFrameKind::MaxData, "MAX_DATA");
    P(maxStream, sizeof(maxStream), wknet::quic::QuicFrameKind::MaxStreamData, "MAX_STREAM_DATA");
    P(maxStreams, sizeof(maxStreams), wknet::quic::QuicFrameKind::MaxStreams, "MAX_STREAMS");
    P(blocked, sizeof(blocked), wknet::quic::QuicFrameKind::DataBlocked, "DATA_BLOCKED");
    P(streamBlocked, sizeof(streamBlocked), wknet::quic::QuicFrameKind::StreamDataBlocked, "STREAM_DATA_BLOCKED");
    P(streamsBlocked, sizeof(streamsBlocked), wknet::quic::QuicFrameKind::StreamsBlocked, "STREAMS_BLOCKED");
    P(newCid, sizeof(newCid), wknet::quic::QuicFrameKind::NewConnectionId, "NEW_CONNECTION_ID");
    P(retire, sizeof(retire), wknet::quic::QuicFrameKind::RetireConnectionId, "RETIRE_CONNECTION_ID");
    P(challenge, sizeof(challenge), wknet::quic::QuicFrameKind::PathChallenge, "PATH_CHALLENGE");
    P(response, sizeof(response), wknet::quic::QuicFrameKind::PathResponse, "PATH_RESPONSE");
    P(closeT, sizeof(closeT), wknet::quic::QuicFrameKind::ConnectionClose, "transport close");
    P(closeA, sizeof(closeA), wknet::quic::QuicFrameKind::ConnectionClose, "application close");
    P(done, sizeof(done), wknet::quic::QuicFrameKind::HandshakeDone, "HANDSHAKE_DONE");
    const UCHAR badCrypto[] = {0x06, 0, 4, 1};
    wknet::quic::QuicFrame f = {};
    E(wknet::quic::QuicParseFrame(badCrypto, sizeof(badCrypto), &f, nullptr) == STATUS_INVALID_NETWORK_RESPONSE,
      "truncated data rejected");
    UCHAR tooManyAck[] = {0x02, 0, 0, 0x41, 0x01, 0};
    E(wknet::quic::QuicParseFrame(tooManyAck, sizeof(tooManyAck), &f, nullptr) == STATUS_INVALID_NETWORK_RESPONSE,
      "ACK range cap enforced");

    const wknet::quic::QuicAckRange ackRanges[] = {{90, 100}, {70, 80}, {60, 65}};
    wknet::quic::QuicFrame ackFrame = {};
    ackFrame.Kind = wknet::quic::QuicFrameKind::Ack;
    ackFrame.AckDelay = 7;
    UCHAR encoded[128] = {};
    SIZE_T encodedLength = 0;
    E(NT_SUCCESS(wknet::quic::QuicEncodeFrame(ackFrame, ackRanges, 3, encoded, sizeof(encoded), &encodedLength)),
      "ACK ranges encode");
    E(NT_SUCCESS(wknet::quic::QuicParseFrame(encoded, encodedLength, &f, nullptr)), "encoded ACK parses");
    wknet::quic::QuicAckRange decodedRanges[3] = {};
    SIZE_T decodedRangeCount = 0;
    E(NT_SUCCESS(wknet::quic::QuicDecodeAckRanges(f, decodedRanges, 3, &decodedRangeCount)) && decodedRangeCount == 3 &&
          decodedRanges[0].Smallest == 90 && decodedRanges[1].Largest == 80 && decodedRanges[2].Smallest == 60,
      "ACK range gaps round trip");

    const UCHAR streamData[] = {9, 8, 7};
    wknet::quic::QuicFrame streamFrame = {};
    streamFrame.Kind = wknet::quic::QuicFrameKind::Stream;
    streamFrame.StreamId = 4;
    streamFrame.Offset = 12;
    streamFrame.Fin = true;
    streamFrame.Data = {streamData, sizeof(streamData)};
    E(NT_SUCCESS(wknet::quic::QuicEncodeFrame(streamFrame, nullptr, 0, encoded, sizeof(encoded), &encodedLength)),
      "STREAM frame encodes");
    E(NT_SUCCESS(wknet::quic::QuicParseFrame(encoded, encodedLength, &f, nullptr)) && f.StreamId == 4 &&
          f.Offset == 12 && f.Fin && f.Data.Length == sizeof(streamData),
      "STREAM frame round trips");
    if (failed)
    {
        printf("QUIC FRAME TESTS FAILED\n");
        return 1;
    }
    printf("QUIC FRAME TESTS PASSED\n");
    return 0;
}
