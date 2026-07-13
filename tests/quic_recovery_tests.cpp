#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif
#include "quic/QuicAckTracker.h"
#include "quic/QuicClock.h"
#include "quic/QuicRecovery.h"
#include <stdio.h>
namespace
{
bool f = false;
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
    wknet::quic::QuicTestClockSet(1000000);
    wknet::quic::QuicRecovery r;
    E(NT_SUCCESS(r.Initialize()), "recovery initializes");
    E(r.Congestion().CongestionWindow() == 12000, "NewReno initial cwnd is ten 1200-byte datagrams");
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 1, 1200, true)), "packet 1 tracked");
    wknet::quic::QuicTestClockAdvance(100000);
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 2, 1200, true)), "packet 2 tracked");
    wknet::quic::QuicTestClockAdvance(100000);
    E(NT_SUCCESS(r.OnAckReceived(wknet::quic::QuicPacketNumberSpace::Application, 2, 0)), "ACK processes");
    E(r.Congestion().BytesInFlight() == 1200, "acked bytes leave flight");
    E(r.SmoothedRtt100ns() != 0, "RTT sample updates estimator");
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 3, 1200, true)), "packet 3");
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 4, 1200, true)), "packet 4");
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 5, 1200, true)), "packet 5");
    E(NT_SUCCESS(r.OnAckReceived(wknet::quic::QuicPacketNumberSpace::Application, 5, 0)),
      "largest ACK detects packet threshold loss");
    E(r.LostPacketCount() >= 1, "packet threshold loss recorded");
    E(r.Congestion().CongestionWindow() <= 7200, "loss enters NewReno recovery");
    const wknet::quic::QuicAckRange ranges[] = {{8, 8}, {3, 4}};
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 6, 1200, true)), "packet 6");
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 7, 1200, true)), "packet 7");
    E(NT_SUCCESS(r.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Application, 8, 1200, true)), "packet 8");
    E(NT_SUCCESS(r.OnAckRangesReceived(wknet::quic::QuicPacketNumberSpace::Application, ranges, 2, 0)),
      "discontiguous ACK ranges process");
    E(r.OutstandingPacketCount() == 2, "terminal packet metadata compacts while gaps remain outstanding");
    const wknet::quic::QuicAckRange malformedRanges[] = {{6, 7}, {7, 7}};
    E(r.OnAckRangesReceived(wknet::quic::QuicPacketNumberSpace::Application, malformedRanges, 2, 0) ==
          STATUS_INVALID_NETWORK_RESPONSE,
      "overlapping ACK ranges are rejected");
    const ULONGLONG firstPto = r.PtoDeadline100ns(wknet::quic::QuicPacketNumberSpace::Application, 25);
    r.OnPtoFired();
    const ULONGLONG secondPto = r.PtoDeadline100ns(wknet::quic::QuicPacketNumberSpace::Application, 25);
    E(secondPto > firstPto, "PTO backoff increases deadline");
    E(!r.Congestion().CanSend(1200, wknet::quic::QuicClockNow100ns()), "pacing blocks an immediate full datagram");
    wknet::quic::QuicTestClockAdvance(10000000);
    E(r.Congestion().CanSend(1200, wknet::quic::QuicClockNow100ns()), "pacing deadline eventually permits send");

    wknet::quic::QuicTestClockSet(10000000);
    wknet::quic::QuicRecovery timed;
    E(NT_SUCCESS(timed.Initialize()), "time-threshold recovery initializes");
    E(NT_SUCCESS(timed.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Handshake, 1, 1200, true)), "timed packet one");
    wknet::quic::QuicTestClockAdvance(100000);
    E(NT_SUCCESS(timed.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Handshake, 2, 1200, true)), "timed packet two");
    wknet::quic::QuicTestClockAdvance(100000);
    E(NT_SUCCESS(timed.OnAckReceived(wknet::quic::QuicPacketNumberSpace::Handshake, 2, 0)),
      "timed RTT sample establishes threshold");
    wknet::quic::QuicTestClockAdvance(200000);
    E(NT_SUCCESS(timed.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Handshake, 3, 1200, true)),
      "timed packet three");
    E(NT_SUCCESS(timed.OnAckReceived(wknet::quic::QuicPacketNumberSpace::Handshake, 3, 0)),
      "time-threshold ACK processes");
    E(timed.LostPacketCount() == 1, "time threshold marks the old packet lost");

    wknet::quic::QuicTestClockSet(15000000);
    wknet::quic::QuicRecovery lossTimer;
    E(NT_SUCCESS(lossTimer.Initialize()), "loss timer recovery initializes");
    E(NT_SUCCESS(lossTimer.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Handshake, 1, 1200, true)),
      "loss timer packet one");
    wknet::quic::QuicTestClockAdvance(100000);
    E(NT_SUCCESS(lossTimer.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Handshake, 2, 1200, true)),
      "loss timer packet two");
    E(NT_SUCCESS(lossTimer.OnAckReceived(wknet::quic::QuicPacketNumberSpace::Handshake, 2, 0)),
      "loss timer establishes an acknowledged packet");
    const ULONGLONG timerDeadline = lossTimer.LossDeadline100ns(wknet::quic::QuicPacketNumberSpace::Handshake);
    E(timerDeadline != 0, "loss timer exposes the earliest time-threshold deadline");
    wknet::quic::QuicTestClockSet(timerDeadline);
    E(NT_SUCCESS(lossTimer.OnLossTimerExpired(wknet::quic::QuicPacketNumberSpace::Handshake)) &&
          lossTimer.LostPacketCount() == 1,
      "loss timer marks overdue packets without waiting for another ACK");

    wknet::quic::QuicTestClockSet(20000000);
    wknet::quic::QuicRecovery persistent;
    E(NT_SUCCESS(persistent.Initialize()), "persistent-congestion recovery initializes");
    E(NT_SUCCESS(persistent.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 0, 1200, true)),
      "persistent RTT packet");
    wknet::quic::QuicTestClockAdvance(100000);
    E(NT_SUCCESS(persistent.OnAckReceived(wknet::quic::QuicPacketNumberSpace::Initial, 0, 0)), "persistent RTT sample");
    E(NT_SUCCESS(persistent.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 1, 1200, true)),
      "persistent packet one");
    wknet::quic::QuicTestClockAdvance(500000);
    E(NT_SUCCESS(persistent.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 2, 1200, true)),
      "persistent packet two");
    wknet::quic::QuicTestClockAdvance(500000);
    E(NT_SUCCESS(persistent.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 3, 1200, true)),
      "persistent packet three");
    wknet::quic::QuicTestClockAdvance(500000);
    E(NT_SUCCESS(persistent.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 4, 1200, true)),
      "persistent packet four");
    E(NT_SUCCESS(persistent.OnAckReceived(wknet::quic::QuicPacketNumberSpace::Initial, 4, 0)),
      "persistent loss interval processes");
    E(persistent.Congestion().CongestionWindow() == 2400, "persistent congestion reduces cwnd to two datagrams");

    wknet::quic::QuicAckTracker ackTracker;
    E(NT_SUCCESS(ackTracker.Initialize()), "ACK tracker initializes");
    bool duplicate = false;
    E(NT_SUCCESS(ackTracker.OnPacketReceived(10, true, false, 30000000, &duplicate)) && !duplicate,
      "first received packet creates an ACK range");
    E(NT_SUCCESS(ackTracker.OnPacketReceived(8, true, false, 30001000, &duplicate)) && !duplicate,
      "out-of-order packet creates a second ACK range");
    E(NT_SUCCESS(ackTracker.OnPacketReceived(9, false, false, 30002000, &duplicate)) && !duplicate,
      "bridging packet merges ACK ranges");
    wknet::quic::QuicAckRange receivedRanges[4] = {};
    SIZE_T receivedRangeCount = 0;
    E(NT_SUCCESS(ackTracker.CopyRanges(receivedRanges, 4, &receivedRangeCount)) && receivedRangeCount == 1 &&
          receivedRanges[0].Smallest == 8 && receivedRanges[0].Largest == 10,
      "ACK tracker merges adjacent packet numbers");
    E(ackTracker.AckDeadline100ns(25) == 30000000, "two ack-eliciting packets request an immediate ACK");
    E(NT_SUCCESS(ackTracker.OnPacketReceived(9, true, false, 30003000, &duplicate)) && duplicate,
      "duplicate packet number is reported without changing ranges");
    ackTracker.OnAckSent();
    E(!ackTracker.AckPending(), "ACK send clears delayed ACK state without discarding ranges");

    wknet::quic::QuicRecovery capped;
    E(NT_SUCCESS(capped.Initialize(2)), "small metadata table initializes");
    E(NT_SUCCESS(capped.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 1, 1200, true)), "cap packet one");
    E(NT_SUCCESS(capped.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 2, 1200, true)), "cap packet two");
    E(capped.OnPacketSent(wknet::quic::QuicPacketNumberSpace::Initial, 3, 1200, true) == STATUS_INSUFFICIENT_RESOURCES,
      "metadata cap fails closed");
    if (f)
    {
        printf("QUIC RECOVERY TESTS FAILED\n");
        return 1;
    }
    printf("QUIC RECOVERY TESTS PASSED\n");
    return 0;
}
