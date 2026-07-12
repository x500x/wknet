#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/Trace.h>
#include "rtl/TraceInternal.h"

#include <atomic>
#include <stdio.h>
#include <string.h>
#include <thread>

namespace
{
    bool g_failed = false;
    ULONG g_sinkCalls = 0;
    wknet::TraceLevel g_lastLevel = wknet::TraceLevel::Off;
    ULONG g_lastComponent = wknet::ComponentNone;
    char g_lastMessage[8192] = {};
    ULONG g_recursiveDepth = 0;
    constexpr ULONG SinkContextMagicA = 0x54524341;
    constexpr ULONG SinkContextMagicB = 0x54524342;

    struct SinkContext final
    {
        ULONG Magic = 0;
        std::atomic<ULONG> Calls = 0;
    };

    SinkContext g_contextA = { SinkContextMagicA };
    SinkContext g_contextB = { SinkContextMagicB };
    std::atomic<bool> g_badSinkContext = false;
    std::atomic<bool> g_startConcurrentWriter = false;
    char g_longMessage[8192] = {};

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void ResetCapture() noexcept
    {
        g_sinkCalls = 0;
        g_lastLevel = wknet::TraceLevel::Off;
        g_lastComponent = wknet::ComponentNone;
        g_lastMessage[0] = '\0';
    }

    void CaptureTrace(
        _In_opt_ void* context,
        wknet::TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        ++g_sinkCalls;
        g_lastLevel = level;
        g_lastComponent = component;
        (void)strncpy_s(g_lastMessage, message, _TRUNCATE);
    }

    void RecursiveTraceSink(
        _In_opt_ void* context,
        wknet::TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(component);
        UNREFERENCED_PARAMETER(message);

        ++g_recursiveDepth;
        if (g_recursiveDepth < 40) {
            WKNET_TRACE(
                wknet::ComponentRtl,
                wknet::TraceLevel::Max,
                "trace.recursive depth=%u",
                g_recursiveDepth);
        }
        --g_recursiveDepth;
    }

    void ContextCheckingSink(
        _In_opt_ void* context,
        wknet::TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept
    {
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(component);
        UNREFERENCED_PARAMETER(message);

        auto* sinkContext = static_cast<SinkContext*>(context);
        if (sinkContext == nullptr ||
            (sinkContext->Magic != SinkContextMagicA && sinkContext->Magic != SinkContextMagicB)) {
            g_badSinkContext.store(true, std::memory_order_release);
            return;
        }
        (void)sinkContext->Calls.fetch_add(1, std::memory_order_acq_rel);
    }

    void ConcurrentTraceWriter() noexcept
    {
        while (!g_startConcurrentWriter.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }

        for (ULONG index = 0; index < 20000; ++index) {
            WKNET_TRACE(
                wknet::ComponentRtl,
                wknet::TraceLevel::Max,
                "trace.concurrent index=%u",
                index);
        }
    }

    void TestLevelThresholds() noexcept
    {
        const wknet::TraceLevel configuredLevels[] = {
            wknet::TraceLevel::Off,
            wknet::TraceLevel::Error,
            wknet::TraceLevel::Warning,
            wknet::TraceLevel::Info,
            wknet::TraceLevel::Verbose,
            wknet::TraceLevel::Max
        };
        const wknet::TraceLevel eventLevels[] = {
            wknet::TraceLevel::Error,
            wknet::TraceLevel::Warning,
            wknet::TraceLevel::Info,
            wknet::TraceLevel::Verbose,
            wknet::TraceLevel::Max
        };

        for (SIZE_T configured = 0; configured < sizeof(configuredLevels) / sizeof(configuredLevels[0]); ++configured) {
            ResetCapture();
            wknet::TraceSetLevel(configuredLevels[configured]);
            for (SIZE_T event = 0; event < sizeof(eventLevels) / sizeof(eventLevels[0]); ++event) {
                WKNET_TRACE(
                    wknet::ComponentTls,
                    eventLevels[event],
                    "trace.level configured=%Iu event=%Iu",
                    configured,
                    event);
            }
            Expect(g_sinkCalls == configured, "configured level includes every more severe level");
        }
    }
}

int main()
{
    wknet::TraceSetSink(CaptureTrace, nullptr);
    wknet::TraceSetComponents(wknet::ComponentTls);
    wknet::TraceSetLevel(wknet::TraceLevel::Off);
    wknet::TraceResetStatistics();

    int formattingSideEffect = 0;
    WKNET_TRACE(
        wknet::ComponentTls,
        wknet::TraceLevel::Error,
        "trace.off side_effect=%d",
        ++formattingSideEffect);
    Expect(g_sinkCalls == 0, "Off level suppresses sink delivery");
    Expect(formattingSideEffect == 0, "Off level suppresses argument evaluation");

    TestLevelThresholds();

    ResetCapture();
    wknet::TraceSetLevel(wknet::TraceLevel::Max);
    wknet::TraceSetComponents(wknet::ComponentTls);
    WKNET_TRACE(wknet::ComponentHttp1, wknet::TraceLevel::Error, "trace.filtered");
    Expect(g_sinkCalls == 0, "component mask suppresses disabled components");

    WKNET_TRACE(wknet::ComponentTls, wknet::TraceLevel::Info, "tls.negotiated version=%u", 13u);
    Expect(g_sinkCalls == 1, "enabled trace reaches the registered sink");
    Expect(g_lastLevel == wknet::TraceLevel::Info, "sink receives the trace level");
    Expect(g_lastComponent == wknet::ComponentTls, "sink receives the trace component");
    Expect(strstr(g_lastMessage, "[TLS][INF]") != nullptr, "formatted trace identifies component and level");
    Expect(strstr(g_lastMessage, "[seq=") != nullptr, "formatted trace contains the event sequence");
    Expect(strstr(g_lastMessage, "tls.negotiated version=13") != nullptr, "formatted trace contains the event payload");
    const SIZE_T messageLength = strlen(g_lastMessage);
    Expect(messageLength >= 2 && g_lastMessage[messageLength - 2] == '\r' && g_lastMessage[messageLength - 1] == '\n',
        "trace runtime owns the CRLF line ending");

    ResetCapture();
    wknet::TraceCorrelation correlation = {};
    correlation.OperationId = 101;
    correlation.ConnectionId = 202;
    correlation.StreamId = 3;
    WKNET_TRACE_CORRELATED(
        wknet::ComponentTransport,
        wknet::TraceLevel::Verbose,
        &correlation,
        "transport.send bytes=%u",
        512u);
    Expect(g_sinkCalls == 0, "correlated trace still honors the component mask");
    wknet::TraceSetComponents(wknet::ComponentTransport);
    WKNET_TRACE_CORRELATED(
        wknet::ComponentTransport,
        wknet::TraceLevel::Verbose,
        &correlation,
        "transport.send bytes=%u",
        512u);
    Expect(g_sinkCalls == 1, "correlated trace reaches the sink");
    Expect(strstr(g_lastMessage, "[TRANSPORT][VRB]") != nullptr, "transport component has a stable name");
    Expect(strstr(g_lastMessage, "[op=101][conn=202][stream=3]") != nullptr, "all correlation identifiers are formatted");

    Expect(wknet::rtl::TraceTestSlotSize() == wknet::rtl::TracePageBytes, "each trace slot occupies one page");
    Expect(wknet::rtl::TraceTestSlotAlignment() == wknet::rtl::TracePageBytes, "each trace slot is page aligned");

    for (SIZE_T index = 0; index + 1 < sizeof(g_longMessage); ++index) {
        g_longMessage[index] = 'X';
    }
    g_longMessage[sizeof(g_longMessage) - 1] = '\0';
    ResetCapture();
    wknet::TraceResetStatistics();
    WKNET_TRACE(wknet::ComponentTransport, wknet::TraceLevel::Max, "trace.long value=%s", g_longMessage);
    wknet::TraceStatistics statistics = {};
    wknet::TraceGetStatistics(&statistics);
    Expect(g_sinkCalls == 1, "truncated trace is still emitted");
    Expect(strstr(g_lastMessage, "[truncated]\r\n") != nullptr, "truncated trace is explicitly marked");
    Expect(statistics.Truncated == 1, "truncation is counted");
    Expect(statistics.Emitted == 1, "emitted trace is counted");

    wknet::TraceSetComponents(wknet::ComponentRtl);
    wknet::TraceSetSink(RecursiveTraceSink, nullptr);
    wknet::TraceResetStatistics();
    WKNET_TRACE(wknet::ComponentRtl, wknet::TraceLevel::Max, "trace.recursive depth=0");
    wknet::TraceGetStatistics(&statistics);
    Expect(statistics.DroppedBusy > 0, "recursive sink exhaustion drops instead of blocking");
    Expect(g_recursiveDepth == 0, "recursive sink unwinds cleanly");

    g_contextA.Calls.store(0, std::memory_order_release);
    g_contextB.Calls.store(0, std::memory_order_release);
    g_badSinkContext.store(false, std::memory_order_release);
    g_startConcurrentWriter.store(false, std::memory_order_release);
    wknet::TraceSetSink(ContextCheckingSink, &g_contextA);
    std::thread writerA(ConcurrentTraceWriter);
    std::thread writerB(ConcurrentTraceWriter);
    g_startConcurrentWriter.store(true, std::memory_order_release);
    for (ULONG index = 0; index < 2000; ++index) {
        wknet::TraceSetSink(ContextCheckingSink, (index & 1) == 0 ?
            static_cast<void*>(&g_contextA) : static_cast<void*>(&g_contextB));
    }
    writerA.join();
    writerB.join();
    Expect(!g_badSinkContext.load(std::memory_order_acquire), "concurrent sink replacement never exposes a mismatched context");
    Expect(g_contextA.Calls.load(std::memory_order_acquire) + g_contextB.Calls.load(std::memory_order_acquire) > 0,
        "concurrent writers reach installed sinks");

    Expect(wknet::TraceGetLevel() == wknet::TraceLevel::Max, "trace level getter reports Max");
    Expect(wknet::TraceGetComponents() == wknet::ComponentRtl, "component getter reports the active mask");

    wknet::TraceSetSink(nullptr, nullptr);
    wknet::TraceSetComponents(wknet::ComponentAll);
    wknet::TraceSetLevel(wknet::TraceLevel::Max);

    if (g_failed) {
        printf("TRACE TESTS FAILED\n");
        return 1;
    }

    printf("TRACE TESTS PASSED\n");
    return 0;
}
