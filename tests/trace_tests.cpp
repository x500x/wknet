#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/Trace.h>

#include <stdio.h>
#include <string.h>

namespace
{
    bool g_failed = false;
    ULONG g_sinkCalls = 0;
    wknet::TraceLevel g_lastLevel = wknet::TraceLevel::Off;
    ULONG g_lastComponent = wknet::ComponentNone;
    char g_lastMessage[256] = {};

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
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
}

int main()
{
    wknet::TraceSetSink(CaptureTrace, nullptr);
    wknet::TraceSetComponents(wknet::ComponentTls);
    wknet::TraceSetLevel(wknet::TraceLevel::Off);

    WKNET_TRACE(wknet::ComponentTls, wknet::TraceLevel::Error, "off path");
    Expect(g_sinkCalls == 0, "Off level suppresses formatting and sink delivery");

    wknet::TraceSetLevel(wknet::TraceLevel::Max);
    WKNET_TRACE(wknet::ComponentHttp1, wknet::TraceLevel::Error, "filtered component");
    Expect(g_sinkCalls == 0, "component mask suppresses disabled components");

    WKNET_TRACE(wknet::ComponentTls, wknet::TraceLevel::Info, "negotiated version=%u", 13u);
    Expect(g_sinkCalls == 1, "enabled trace reaches the registered sink");
    Expect(g_lastLevel == wknet::TraceLevel::Info, "sink receives the trace level");
    Expect(g_lastComponent == wknet::ComponentTls, "sink receives the trace component");
    Expect(strstr(g_lastMessage, "[TLS][INF]") != nullptr, "formatted trace identifies component and level");
    Expect(strstr(g_lastMessage, "negotiated version=13") != nullptr, "formatted trace contains the payload");
    Expect(wknet::TraceGetLevel() == wknet::TraceLevel::Max, "trace level getter reports Max");
    Expect(wknet::TraceGetComponents() == wknet::ComponentTls, "component getter reports the active mask");

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
