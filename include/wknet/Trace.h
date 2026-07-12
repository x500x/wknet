#pragma once

#include <wknet/WknetConfig.h>

namespace wknet
{
    enum class TraceLevel : ULONG
    {
        Off = 0,
        Error = 1,
        Warning = 2,
        Info = 3,
        Verbose = 4,
        Max = 5
    };

    enum TraceComponent : ULONG
    {
        ComponentNone     = 0,
        ComponentRtl      = 1u << 0,
        ComponentNet      = 1u << 1,
        ComponentTls      = 1u << 2,
        ComponentHttp1    = 1u << 3,
        ComponentHttp2    = 1u << 4,
        ComponentWs       = 1u << 5,
        ComponentSession  = 1u << 6,
        ComponentCodec    = 1u << 7,
        ComponentCrypto   = 1u << 8,
        ComponentTransport = 1u << 9,
        ComponentAll      = 0xFFFFFFFFu
    };

    struct TraceCorrelation final
    {
        ULONGLONG OperationId = 0;
        ULONGLONG ConnectionId = 0;
        ULONG StreamId = 0;
    };

    struct TraceStatistics final
    {
        ULONGLONG Emitted = 0;
        ULONGLONG DroppedBusy = 0;
        ULONGLONG FormatFailures = 0;
        ULONGLONG Truncated = 0;
    };

    typedef void (*TraceSink)(
        _In_opt_ void* context,
        TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept;

    void TraceSetLevel(TraceLevel level) noexcept;
    void TraceSetComponents(ULONG mask) noexcept;
    TraceLevel TraceGetLevel() noexcept;
    ULONG TraceGetComponents() noexcept;
    void TraceSetSink(_In_opt_ TraceSink sink, _In_opt_ void* context) noexcept;
    void TraceGetStatistics(_Out_ TraceStatistics* statistics) noexcept;
    void TraceResetStatistics() noexcept;

    _Must_inspect_result_
    bool TraceIsEnabled(TraceLevel level, ULONG component) noexcept;

    void TraceWrite(
        ULONG component,
        TraceLevel level,
        _In_z_ _Printf_format_string_ const char* format,
        ...) noexcept;

    void TraceWriteCorrelated(
        ULONG component,
        TraceLevel level,
        _In_opt_ const TraceCorrelation* correlation,
        _In_z_ _Printf_format_string_ const char* format,
        ...) noexcept;
}

// Internal/src macro. Component is a TraceComponent bit; level is TraceLevel.
#define WKNET_TRACE(component, level, ...) \
    do { \
        if (::wknet::TraceIsEnabled((level), static_cast<ULONG>(component))) { \
            ::wknet::TraceWrite(static_cast<ULONG>(component), (level), __VA_ARGS__); \
        } \
    } while (0)

#define WKNET_TRACE_CORRELATED(component, level, correlation, ...) \
    do { \
        if (::wknet::TraceIsEnabled((level), static_cast<ULONG>(component))) { \
            ::wknet::TraceWriteCorrelated( \
                static_cast<ULONG>(component), (level), (correlation), __VA_ARGS__); \
        } \
    } while (0)
