#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "net/WskDatagramSocket.h"
#include "net/WskDatagramSocketTest.h"

#include <wknet/Trace.h>

#include <atomic>
#include <chrono>
#include <stdio.h>
#include <string.h>
#include <thread>

namespace
{
    bool g_failed = false;
    char g_trace[4096] = {};
    SIZE_T g_traceLength = 0;
    bool g_sensitiveTrace = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void CaptureTrace(
        void*,
        wknet::TraceLevel,
        ULONG,
        const char* message) noexcept
    {
        if (message == nullptr) {
            return;
        }

        const SIZE_T length = strlen(message);
        const SIZE_T remaining = sizeof(g_trace) - g_traceLength;
        if (remaining > 1) {
            const SIZE_T copy = length < (remaining - 1) ? length : (remaining - 1);
            RtlCopyMemory(g_trace + g_traceLength, message, copy);
            g_traceLength += copy;
            g_trace[g_traceLength] = '\0';
        }

        if (strstr(message, "payload-secret") != nullptr ||
            strstr(message, "token-secret") != nullptr ||
            strstr(message, "0x12345678") != nullptr) {
            g_sensitiveTrace = true;
        }
    }

    SOCKADDR_STORAGE MakeIpv4(USHORT port, ULONG address) noexcept
    {
        SOCKADDR_STORAGE storage = {};
        auto* ipv4 = reinterpret_cast<SOCKADDR_IN*>(&storage);
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = port;
        ipv4->sin_addr = address;
        return storage;
    }

    SOCKADDR_STORAGE MakeIpv6(USHORT port, UCHAR suffix) noexcept
    {
        SOCKADDR_STORAGE storage = {};
        auto* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(&storage);
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = port;
        ipv6->sin6_addr[15] = suffix;
        return storage;
    }

    bool AddressEquals(const SOCKADDR_STORAGE& left, const SOCKADDR_STORAGE& right) noexcept
    {
        const SIZE_T length = left.ss_family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6);
        return left.ss_family == right.ss_family &&
            RtlCompareMemory(&left, &right, length) == length;
    }

    struct Fixture final
    {
        wknet::net::WskClient* Client = nullptr;
        wknet::net::WskDatagramSocket* Socket = nullptr;

        bool Initialize(USHORT family) noexcept
        {
            wknet::net::test::ResetProvider();
            NTSTATUS status = wknet::net::WskClientCreate(&Client);
            if (!NT_SUCCESS(status)) {
                return false;
            }
            status = wknet::net::WskClientInitialize(Client);
            if (!NT_SUCCESS(status)) {
                return false;
            }
            status = wknet::net::WskDatagramSocketCreate(Client, family, &Socket);
            return NT_SUCCESS(status);
        }

        void Cleanup() noexcept
        {
            if (Socket != nullptr) {
                (void)wknet::net::WskDatagramSocketClose(Socket);
                wknet::net::WskDatagramSocketDestroy(Socket);
                Socket = nullptr;
            }
            wknet::net::WskClientClose(Client);
            Client = nullptr;
        }

        ~Fixture() noexcept
        {
            Cleanup();
        }
    };

    void TestLifecycleAndSynchronousReceive() noexcept
    {
        Fixture fixture = {};
        Expect(fixture.Initialize(AF_INET), "IPv4 datagram socket is created");
        if (fixture.Socket == nullptr) {
            return;
        }

        wknet::net::WskDatagramSocketSetConnectionId(fixture.Socket, 7001);
        Expect(wknet::net::WskDatagramSocketConnectionId(fixture.Socket) == 7001,
            "connection correlation id round-trips");

        const char payload[] = "payload-secret";
        SIZE_T sent = 99;
        Expect(wknet::net::WskDatagramSocketSend(
            fixture.Socket, payload, sizeof(payload) - 1, &sent) == STATUS_INVALID_DEVICE_STATE,
            "Send requires Connected state");
        Expect(sent == 0, "failed Send clears byte count");

        const SOCKADDR_STORAGE local = MakeIpv4(4433, 0x0100007fUL);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketBind(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&local))),
            "IPv4 socket binds");
        Expect(wknet::net::WskDatagramSocketBind(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&local)) == STATUS_INVALID_DEVICE_STATE,
            "Bind is only valid from Created");

        SOCKADDR_STORAGE queried = {};
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketGetLocalAddress(fixture.Socket, &queried)),
            "bound local address is queryable");
        Expect(AddressEquals(local, queried), "queried local address matches bind address");

        const SOCKADDR_STORAGE source = MakeIpv4(8443, 0x0200007fUL);
        const UCHAR packet[] = { 0x41, 0x42, 0x43, 0x44 };
        wknet::net::test::WskDatagramTestReceiveCompletion completion = {};
        completion.Status = STATUS_SUCCESS;
        completion.Data = packet;
        completion.DataLength = sizeof(packet);
        completion.RemoteAddress = source;
        completion.RemoteAddressLength = sizeof(SOCKADDR_IN);
        completion.CompleteSynchronously = true;
        wknet::net::test::QueueReceiveCompletion(completion);

        UCHAR receiveBuffer[32] = {};
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer))),
            "synchronous provider completion is accepted");
        Expect(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer)) == STATUS_DEVICE_BUSY,
            "receive remains owned until CompleteReceive consumes it");

        wknet::net::WskDatagramReceiveResult result = {};
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketCompleteReceive(
            fixture.Socket, 1000, &result)),
            "synchronous completion is consumed at PASSIVE");
        Expect(result.Status == STATUS_SUCCESS && result.BytesReceived == sizeof(packet),
            "receive result reports terminal status and length");
        Expect(memcmp(receiveBuffer, packet, sizeof(packet)) == 0,
            "provider writes caller NonPaged receive buffer");
        Expect(AddressEquals(result.RemoteAddress, source), "receive result snapshots source address");

        const SOCKADDR_STORAGE peer = MakeIpv4(9443, 0x0300007fUL);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketConnectPeer(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&peer))),
            "bound IPv4 socket records peer");
        queried = {};
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketGetRemoteAddress(fixture.Socket, &queried)),
            "connected peer is queryable");
        Expect(AddressEquals(peer, queried), "queried peer matches connected address");

        wknet::net::test::SetNextSendResult(STATUS_SUCCESS, sizeof(payload) - 1);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketSend(
            fixture.Socket, payload, sizeof(payload) - 1, &sent)),
            "connected Send succeeds");
        Expect(sent == sizeof(payload) - 1, "connected Send reports bytes");

        const SOCKADDR_STORAGE alternate = MakeIpv4(10443, 0x0400007fUL);
        wknet::net::test::SetNextSendResult(STATUS_SUCCESS, sizeof(payload) - 1);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketSendTo(
            fixture.Socket,
            payload,
            sizeof(payload) - 1,
            reinterpret_cast<const SOCKADDR*>(&alternate),
            &sent)),
            "SendTo remains valid after ConnectPeer");
    }

    void TestIpv6AndFamilyValidation() noexcept
    {
        Fixture fixture = {};
        Expect(fixture.Initialize(AF_INET6), "IPv6 datagram socket is created");
        if (fixture.Socket == nullptr) {
            return;
        }

        const SOCKADDR_STORAGE ipv4 = MakeIpv4(443, 0x0100007fUL);
        Expect(wknet::net::WskDatagramSocketBind(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&ipv4)) == STATUS_INVALID_PARAMETER,
            "IPv6 endpoint rejects IPv4 bind address");

        const SOCKADDR_STORAGE local = MakeIpv6(4433, 1);
        const SOCKADDR_STORAGE peer = MakeIpv6(4434, 2);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketConnectPeer(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&peer))),
            "ConnectPeer from Created performs an implicit wildcard bind");

        SOCKADDR_STORAGE queried = {};
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketGetLocalAddress(fixture.Socket, &queried)),
            "implicit IPv6 bind produces a local address");
        Expect(queried.ss_family == AF_INET6, "implicit bind preserves IPv6 family");
        UNREFERENCED_PARAMETER(local);
    }

    void TestDispatchCompletionToPassiveConsumer() noexcept
    {
        Fixture fixture = {};
        Expect(fixture.Initialize(AF_INET), "async fixture initializes");
        if (fixture.Socket == nullptr) {
            return;
        }
        const SOCKADDR_STORAGE local = MakeIpv4(5000, 0);
        (void)wknet::net::WskDatagramSocketBind(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&local));

        const UCHAR packet[] = { 1, 2, 3, 4, 5, 6 };
        wknet::net::test::WskDatagramTestReceiveCompletion completion = {};
        completion.Status = STATUS_SUCCESS;
        completion.Data = packet;
        completion.DataLength = sizeof(packet);
        completion.RemoteAddress = MakeIpv4(5001, 0x0100007fUL);
        completion.RemoteAddressLength = sizeof(SOCKADDR_IN);
        completion.CompleteSynchronously = false;
        wknet::net::test::QueueReceiveCompletion(completion);

        UCHAR receiveBuffer[32] = {};
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer))),
            "pending receive starts");

        std::atomic<bool> consumerStarted = false;
        NTSTATUS consumerStatus = STATUS_UNSUCCESSFUL;
        wknet::net::WskDatagramReceiveResult result = {};
        std::thread consumer([&]() noexcept {
            consumerStarted.store(true, std::memory_order_release);
            consumerStatus = wknet::net::WskDatagramSocketCompleteReceive(
                fixture.Socket, 5000, &result);
        });
        while (!consumerStarted.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }

        Expect(wknet::net::test::CompletePendingReceive(),
            "provider completes pending receive at simulated DISPATCH");
        consumer.join();
        Expect(NT_SUCCESS(consumerStatus), "PASSIVE consumer wakes after completion event");
        Expect(result.BytesReceived == sizeof(packet), "PASSIVE consumer observes completion length");

        const wknet::net::test::WskDatagramProviderStatistics stats =
            wknet::net::test::GetProviderStatistics();
        Expect(stats.CompletionCallbacks == 1, "exactly one completion callback runs");
        Expect(stats.DispatchCompletions == 1, "provider records simulated DISPATCH completion");
        Expect(stats.PassiveConsumers == 1, "CompleteReceive records PASSIVE consumption");
        Expect(stats.CompletionThreadToken != 0 && stats.PassiveConsumerThreadToken != 0,
            "provider records completion and consumer threads");
        Expect(stats.CompletionThreadToken != stats.PassiveConsumerThreadToken,
            "DISPATCH completion and PASSIVE consumption run on different threads");
        Expect(stats.AllocationAttempts >= 1, "provider records receive allocation attempts");
        Expect(stats.PayloadParseCalls == 0, "completion path does not parse payload");
        Expect(stats.UpperCallbackCalls == 0, "completion path does not call upper layers");
        Expect(stats.BufferReferences == 0, "buffer ownership releases after consumption");
    }

    void TestCancelTimeoutAndLateCloseCompletion() noexcept
    {
        Fixture fixture = {};
        Expect(fixture.Initialize(AF_INET), "cancel fixture initializes");
        if (fixture.Socket == nullptr) {
            return;
        }
        const SOCKADDR_STORAGE local = MakeIpv4(6000, 0);
        (void)wknet::net::WskDatagramSocketBind(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&local));

        wknet::net::test::WskDatagramTestReceiveCompletion completion = {};
        completion.Status = STATUS_SUCCESS;
        completion.RemoteAddress = MakeIpv4(6001, 0x0100007fUL);
        completion.RemoteAddressLength = sizeof(SOCKADDR_IN);
        wknet::net::test::QueueReceiveCompletion(completion);

        UCHAR receiveBuffer[16] = {};
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer))),
            "timeout receive starts");
        wknet::net::test::SetCancelCompletesImmediately(true);
        wknet::net::WskDatagramReceiveResult result = {};
        Expect(wknet::net::WskDatagramSocketCompleteReceive(
            fixture.Socket, 1, &result) == STATUS_IO_TIMEOUT,
            "timeout cancels and drains through the common completion path");
        Expect(result.Status == STATUS_IO_TIMEOUT, "timeout result is mapped to STATUS_IO_TIMEOUT");

        wknet::net::test::QueueReceiveCompletion(completion);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer))),
            "explicit cancel receive starts");
        wknet::net::test::SetCancelCompletesImmediately(false);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketCancelReceive(fixture.Socket)),
            "CancelReceive transitions Pending to CancelPending");
        Expect(wknet::net::WskDatagramSocketCancelReceive(fixture.Socket) == STATUS_INVALID_DEVICE_STATE,
            "repeated CancelReceive is rejected");
        Expect(wknet::net::test::CompleteCancelledReceiveLate(),
            "cancelled provider request can complete late");
        Expect(wknet::net::WskDatagramSocketCompleteReceive(
            fixture.Socket, 1000, &result) == STATUS_CANCELLED,
            "explicit cancellation reports STATUS_CANCELLED");
        Expect(wknet::net::WskDatagramSocketCancelReceive(fixture.Socket) == STATUS_NOT_FOUND,
            "CancelReceive on Idle reports not found");

        wknet::net::test::QueueReceiveCompletion(completion);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer))),
            "close race receive starts");

        std::atomic<bool> closeReturned = false;
        NTSTATUS closeStatus = STATUS_UNSUCCESSFUL;
        std::thread closer([&]() noexcept {
            closeStatus = wknet::net::WskDatagramSocketClose(fixture.Socket);
            closeReturned.store(true, std::memory_order_release);
        });

        for (ULONG spin = 0; spin < 10000; ++spin) {
            const auto stats = wknet::net::test::GetProviderStatistics();
            if (stats.CancelCalls >= 3) {
                break;
            }
            std::this_thread::yield();
        }
        Expect(!closeReturned.load(std::memory_order_acquire),
            "Close waits for cancelled receive completion and rundown");
        Expect(wknet::net::test::CompleteCancelledReceiveLate(),
            "Close path accepts delayed cancellation completion");
        closer.join();
        Expect(NT_SUCCESS(closeStatus), "Close completes after late completion drains");

        const auto stats = wknet::net::test::GetProviderStatistics();
        Expect(stats.OutstandingReceives == 0, "Close returns with no outstanding provider receive");
        Expect(stats.BufferReferences == 0, "Close returns after releasing caller buffer ownership");
        Expect(stats.OpenSockets == 0, "Close returns after native socket close");
        Expect(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer)) == STATUS_DEVICE_NOT_READY,
            "closed endpoint rejects new I/O");
    }

    void TestFailureInjectionAndReceiveValidation() noexcept
    {
        wknet::net::test::ResetProvider();
        wknet::net::WskClient* client = nullptr;
        (void)wknet::net::WskClientCreate(&client);
        (void)wknet::net::WskClientInitialize(client);

        wknet::net::test::SetNextOpenResult(STATUS_INSUFFICIENT_RESOURCES);
        wknet::net::WskDatagramSocket* failedSocket = nullptr;
        Expect(wknet::net::WskDatagramSocketCreate(client, AF_INET, &failedSocket) ==
            STATUS_INSUFFICIENT_RESOURCES,
            "provider open failure is propagated");
        Expect(failedSocket == nullptr, "failed Create does not publish an object");

        wknet::net::test::FailNextAllocation();
        Expect(wknet::net::WskDatagramSocketCreate(client, AF_INET, &failedSocket) ==
            STATUS_INSUFFICIENT_RESOURCES,
            "object allocation failure is propagated");

        wknet::net::WskClientClose(client);

        Fixture fixture = {};
        Expect(fixture.Initialize(AF_INET), "failure fixture initializes");
        if (fixture.Socket == nullptr) {
            return;
        }
        const SOCKADDR_STORAGE local = MakeIpv4(7000, 0);
        (void)wknet::net::WskDatagramSocketBind(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&local));

        wknet::net::test::SetNextReceiveStartResult(STATUS_INSUFFICIENT_RESOURCES);
        UCHAR receiveBuffer[8] = {};
        Expect(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer)) == STATUS_INSUFFICIENT_RESOURCES,
            "IRP/MDL construction failure is propagated");
        Expect(wknet::net::test::GetProviderStatistics().BufferReferences == 0,
            "failed receive submission does not retain caller buffer");

        wknet::net::test::WskDatagramTestReceiveCompletion invalidSource = {};
        invalidSource.Status = STATUS_SUCCESS;
        invalidSource.RemoteAddress = MakeIpv4(7001, 0);
        invalidSource.RemoteAddressLength = sizeof(SOCKADDR_STORAGE) + 1;
        invalidSource.CompleteSynchronously = true;
        wknet::net::test::QueueReceiveCompletion(invalidSource);
        Expect(NT_SUCCESS(wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer))),
            "invalid-source completion is submitted");
        wknet::net::WskDatagramReceiveResult result = {};
        Expect(wknet::net::WskDatagramSocketCompleteReceive(
            fixture.Socket, 1000, &result) == STATUS_INVALID_NETWORK_RESPONSE,
            "oversized source address is rejected during PASSIVE consumption");

        wknet::net::test::SetNextSendResult(STATUS_CONNECTION_RESET, 0);
        const char payload[] = "token-secret";
        SIZE_T sent = 0;
        Expect(wknet::net::WskDatagramSocketSendTo(
            fixture.Socket,
            payload,
            sizeof(payload) - 1,
            reinterpret_cast<const SOCKADDR*>(&local),
            &sent) == STATUS_CONNECTION_RESET,
            "send provider failure is propagated");
    }

    void TestTraceContract() noexcept
    {
        g_traceLength = 0;
        g_trace[0] = '\0';
        g_sensitiveTrace = false;
        wknet::TraceSetSink(CaptureTrace, reinterpret_cast<void*>(0x12345678));
        wknet::TraceSetComponents(wknet::ComponentNet);
        wknet::TraceSetLevel(wknet::TraceLevel::Max);

        Fixture fixture = {};
        Expect(fixture.Initialize(AF_INET), "trace fixture initializes");
        if (fixture.Socket == nullptr) {
            return;
        }
        wknet::net::WskDatagramSocketSetConnectionId(fixture.Socket, 8128);
        const SOCKADDR_STORAGE local = MakeIpv4(8128, 0);
        (void)wknet::net::WskDatagramSocketBind(
            fixture.Socket, reinterpret_cast<const SOCKADDR*>(&local));

        wknet::net::test::SetNextSendResult(STATUS_CONNECTION_RESET, 0);
        const char payload[] = "payload-secret";
        SIZE_T sent = 0;
        (void)wknet::net::WskDatagramSocketSendTo(
            fixture.Socket,
            payload,
            sizeof(payload) - 1,
            reinterpret_cast<const SOCKADDR*>(&local),
            &sent);

        wknet::net::test::WskDatagramTestReceiveCompletion failed = {};
        failed.Status = STATUS_CONNECTION_RESET;
        failed.RemoteAddress = local;
        failed.RemoteAddressLength = sizeof(SOCKADDR_IN);
        failed.CompleteSynchronously = true;
        wknet::net::test::QueueReceiveCompletion(failed);
        UCHAR receiveBuffer[8] = {};
        (void)wknet::net::WskDatagramSocketStartReceive(
            fixture.Socket, receiveBuffer, sizeof(receiveBuffer));
        wknet::net::WskDatagramReceiveResult result = {};
        (void)wknet::net::WskDatagramSocketCompleteReceive(fixture.Socket, 1000, &result);
        fixture.Cleanup();

        Expect(strstr(g_trace, "net.datagram.opened") != nullptr,
            "opened lifecycle event is emitted");
        Expect(strstr(g_trace, "net.datagram.close_started") != nullptr,
            "close-started lifecycle event is emitted");
        Expect(strstr(g_trace, "net.datagram.close_completed") != nullptr,
            "close-completed lifecycle event is emitted");
        Expect(strstr(g_trace, "net.datagram.send.failed") != nullptr,
            "send failure event is emitted");
        Expect(strstr(g_trace, "net.datagram.receive.failed") != nullptr,
            "receive failure event is emitted");
        Expect(strstr(g_trace, "[conn=8128]") != nullptr,
            "datagram events carry ConnectionId correlation");
        Expect(!g_sensitiveTrace, "datagram logs do not expose payload, token, or address pointer");

        wknet::TraceSetSink(nullptr, nullptr);
    }
}

int main()
{
    TestLifecycleAndSynchronousReceive();
    TestIpv6AndFamilyValidation();
    TestDispatchCompletionToPassiveConsumer();
    TestCancelTimeoutAndLateCloseCompletion();
    TestFailureInjectionAndReceiveValidation();
    TestTraceContract();

    if (g_failed) {
        printf("DATAGRAM SOCKET TESTS FAILED\n");
        return 1;
    }

    printf("DATAGRAM SOCKET TESTS PASSED\n");
    return 0;
}
