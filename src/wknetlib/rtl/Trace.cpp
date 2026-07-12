#include <wknet/Trace.h>

#if defined(WKNET_USER_MODE_TEST)
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#else
#include <ntstrsafe.h>
#include <stdarg.h>
#endif

namespace wknet
{
namespace
{
    volatile LONG g_traceLevel = static_cast<LONG>(TraceLevel::Off);
    volatile LONG g_traceComponents = static_cast<LONG>(ComponentAll);
    TraceSink g_traceSink = nullptr;
    void* g_traceSinkContext = nullptr;

    constexpr SIZE_T TraceFormatBufferBytes = 1024;

    const char* LevelName(TraceLevel level) noexcept
    {
        switch (level) {
        case TraceLevel::Error: return "ERR";
        case TraceLevel::Warning: return "WRN";
        case TraceLevel::Info: return "INF";
        case TraceLevel::Verbose: return "VRB";
        case TraceLevel::Max: return "MAX";
        case TraceLevel::Off:
        default: return "OFF";
        }
    }

    const char* ComponentName(ULONG component) noexcept
    {
        switch (component) {
        case ComponentRtl: return "RTL";
        case ComponentNet: return "NET";
        case ComponentTls: return "TLS";
        case ComponentHttp1: return "HTTP1";
        case ComponentHttp2: return "HTTP2";
        case ComponentWs: return "WS";
        case ComponentSession: return "SESSION";
        case ComponentCodec: return "CODEC";
        case ComponentCrypto: return "CRYPTO";
        case ComponentNone: return "NONE";
        default: return "MULTI";
        }
    }

    void DefaultEmit(_In_z_ const char* message) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        (void)fputs(message, stdout);
#else
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "%s", message);
#endif
    }
}

void TraceSetLevel(TraceLevel level) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    g_traceLevel = static_cast<LONG>(level);
#else
    InterlockedExchange(&g_traceLevel, static_cast<LONG>(level));
#endif
}

void TraceSetComponents(ULONG mask) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    g_traceComponents = static_cast<LONG>(mask);
#else
    InterlockedExchange(&g_traceComponents, static_cast<LONG>(mask));
#endif
}

TraceLevel TraceGetLevel() noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return static_cast<TraceLevel>(g_traceLevel);
#else
    return static_cast<TraceLevel>(InterlockedCompareExchange(&g_traceLevel, 0, 0));
#endif
}

ULONG TraceGetComponents() noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return static_cast<ULONG>(g_traceComponents);
#else
    return static_cast<ULONG>(InterlockedCompareExchange(&g_traceComponents, 0, 0));
#endif
}

void TraceSetSink(_In_opt_ TraceSink sink, _In_opt_ void* context) noexcept
{
    g_traceSink = sink;
    g_traceSinkContext = context;
}

_Must_inspect_result_
bool TraceIsEnabled(TraceLevel level, ULONG component) noexcept
{
    if (level == TraceLevel::Off) {
        return false;
    }

    const TraceLevel current = TraceGetLevel();
    if (current == TraceLevel::Off || level > current) {
        return false;
    }

    const ULONG mask = TraceGetComponents();
    return (mask & component) != 0;
}

void TraceWrite(
    ULONG component,
    TraceLevel level,
    _In_z_ _Printf_format_string_ const char* format,
    ...) noexcept
{
    if (!TraceIsEnabled(level, component) || format == nullptr) {
        return;
    }

    char* buffer = static_cast<char*>(AllocateNonPagedPoolBytes(TraceFormatBufferBytes));
    if (buffer == nullptr) {
        return;
    }
    buffer[0] = '\0';

    // Prefix: "wknet : [COMPONENT][LVL] "
    SIZE_T used = 0;
#if defined(WKNET_USER_MODE_TEST)
    {
        const int prefix = _snprintf_s(
            buffer,
            TraceFormatBufferBytes,
            _TRUNCATE,
            "%s : [%s][%s] ",
            WKNET_DRIVER_NAME,
            ComponentName(component),
            LevelName(level));
        if (prefix > 0) {
            used = static_cast<SIZE_T>(prefix);
        }
    }
#else
    {
        const NTSTATUS prefixStatus = RtlStringCbPrintfA(
            buffer,
            TraceFormatBufferBytes,
            "%s : [%s][%s] ",
            WKNET_DRIVER_NAME,
            ComponentName(component),
            LevelName(level));
        if (NT_SUCCESS(prefixStatus)) {
            SIZE_T length = 0;
            if (NT_SUCCESS(RtlStringCbLengthA(buffer, TraceFormatBufferBytes, &length))) {
                used = length;
            }
        }
    }
#endif

    if (used >= TraceFormatBufferBytes - 1) {
        FreeNonPagedPoolBytes(buffer);
        return;
    }

    va_list args = {};
    va_start(args, format);
#if defined(WKNET_USER_MODE_TEST)
    (void)_vsnprintf_s(
        buffer + used,
        TraceFormatBufferBytes - used,
        _TRUNCATE,
        format,
        args);
#else
    (void)RtlStringCbVPrintfA(
        buffer + used,
        TraceFormatBufferBytes - used,
        format,
        args);
#endif
    va_end(args);

#if defined(WKNET_USER_MODE_TEST)
    {
        const size_t len = strnlen(buffer, TraceFormatBufferBytes);
        if (len + 1 < TraceFormatBufferBytes && (len == 0 || buffer[len - 1] != '\n')) {
            buffer[len] = '\n';
            buffer[len + 1] = '\0';
        }
    }
#endif

    if (g_traceSink != nullptr) {
        g_traceSink(g_traceSinkContext, level, component, buffer);
    }
    else {
        DefaultEmit(buffer);
    }

    FreeNonPagedPoolBytes(buffer);
}
}


#if defined(WKNET_USER_MODE_TEST)
namespace
{
    // User-mode protocol tests run at full verbosity by default.
    // Product kernel default remains Off (g_traceLevel static init).
    struct TraceUserModeTestBootstrap final
    {
        TraceUserModeTestBootstrap() noexcept
        {
            ::wknet::TraceSetLevel(::wknet::TraceLevel::Max);
            ::wknet::TraceSetComponents(::wknet::ComponentAll);
        }
    };

    TraceUserModeTestBootstrap g_traceUserModeTestBootstrap;
}
#endif
