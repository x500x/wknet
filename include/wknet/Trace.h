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
        ComponentAll      = 0xFFFFFFFFu
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

    _Must_inspect_result_
    bool TraceIsEnabled(TraceLevel level, ULONG component) noexcept;

    void TraceWrite(
        ULONG component,
        TraceLevel level,
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

// Transitional alias for existing call sites (Verbose + all components).
// Prefer WKNET_TRACE with an explicit component/level for new code.
#undef WKNET_DBG_PRINT
#define WKNET_DBG_PRINT(...) \
    WKNET_TRACE(::wknet::ComponentAll, ::wknet::TraceLevel::Verbose, __VA_ARGS__)
