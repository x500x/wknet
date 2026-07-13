#include <wknet/Trace.h>
#include "rtl/TraceInternal.h"

#include <stdarg.h>

#if defined(WKNET_USER_MODE_TEST)
#include <atomic>
#include <stdio.h>
#include <string.h>
#include <thread>
#else
#include <ntstrsafe.h>
#endif

namespace wknet
{
namespace
{
    constexpr ULONG KnownTraceComponents =
        ComponentRtl |
        ComponentNet |
        ComponentTls |
        ComponentHttp1 |
        ComponentHttp2 |
        ComponentWs |
        ComponentSession |
        ComponentCodec |
        ComponentCrypto |
        ComponentTransport |
        ComponentQuic |
        ComponentHttp3;

    constexpr char TruncatedSuffix[] = " [truncated]";
    constexpr SIZE_T LineEndingBytes = 2;

#if defined(WKNET_USER_MODE_TEST)
    using AtomicLong = std::atomic<LONG>;
    using AtomicUnsigned64 = std::atomic<ULONGLONG>;
    using AtomicSink = std::atomic<TraceSink>;
    using AtomicPointer = std::atomic<void*>;
#else
    using AtomicLong = volatile LONG;
    using AtomicUnsigned64 = volatile LONGLONG;
    using AtomicSink = TraceSink;
    using AtomicPointer = void*;
#endif

    struct alignas(rtl::TracePageBytes) TraceSlot final
    {
        AtomicLong Busy = 0;
        char Buffer[rtl::TracePageBytes - sizeof(AtomicLong)] = {};
    };

    static_assert(sizeof(AtomicLong) == sizeof(LONG), "trace slot state must remain one LONG");
    static_assert(sizeof(TraceSlot) == rtl::TracePageBytes, "each trace slot must occupy one page");
    static_assert(alignof(TraceSlot) == rtl::TracePageBytes, "trace slots must be page aligned");

    alignas(rtl::TracePageBytes) TraceSlot g_traceSlots[rtl::TraceSlotCount] = {};
    AtomicLong g_traceLevel = static_cast<LONG>(TraceLevel::Off);
    AtomicLong g_traceComponents = static_cast<LONG>(ComponentAll);
    AtomicLong g_traceSlotCursor = 0;
    AtomicUnsigned64 g_traceSequence = 0;
    AtomicUnsigned64 g_traceCorrelationId = 0;
    AtomicUnsigned64 g_traceEmitted = 0;
    AtomicUnsigned64 g_traceDroppedBusy = 0;
    AtomicUnsigned64 g_traceFormatFailures = 0;
    AtomicUnsigned64 g_traceTruncated = 0;

    AtomicSink g_traceSink = nullptr;
    AtomicPointer g_traceSinkContext = nullptr;
    AtomicLong g_traceSinkSequence = 0;
    AtomicLong g_traceSinkActive = 0;
    AtomicLong g_traceSinkWriter = 0;

    LONG LoadLong(const AtomicLong& value) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return value.load(std::memory_order_acquire);
#else
        return InterlockedCompareExchange(const_cast<volatile LONG*>(&value), 0, 0);
#endif
    }

    void StoreLong(AtomicLong& target, LONG value) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        target.store(value, std::memory_order_release);
#else
        (void)InterlockedExchange(&target, value);
#endif
    }

    bool CompareExchangeLong(AtomicLong& target, LONG expected, LONG desired) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return target.compare_exchange_strong(
            expected,
            desired,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
#else
        return InterlockedCompareExchange(&target, desired, expected) == expected;
#endif
    }

    LONG IncrementLong(AtomicLong& target) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return target.fetch_add(1, std::memory_order_acq_rel) + 1;
#else
        return InterlockedIncrement(&target);
#endif
    }

    LONG DecrementLong(AtomicLong& target) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return target.fetch_sub(1, std::memory_order_acq_rel) - 1;
#else
        return InterlockedDecrement(&target);
#endif
    }

    ULONGLONG LoadUnsigned64(const AtomicUnsigned64& value) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return value.load(std::memory_order_acquire);
#else
        return static_cast<ULONGLONG>(InterlockedCompareExchange64(
            const_cast<volatile LONGLONG*>(&value), 0, 0));
#endif
    }

    ULONGLONG IncrementUnsigned64(AtomicUnsigned64& target) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return target.fetch_add(1, std::memory_order_acq_rel) + 1;
#else
        return static_cast<ULONGLONG>(InterlockedIncrement64(&target));
#endif
    }

    void ResetUnsigned64(AtomicUnsigned64& target) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        target.store(0, std::memory_order_release);
#else
        (void)InterlockedExchange64(&target, 0);
#endif
    }

    TraceSink LoadSink() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return g_traceSink.load(std::memory_order_acquire);
#else
        return reinterpret_cast<TraceSink>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_traceSink), nullptr, nullptr));
#endif
    }

    void StoreSink(TraceSink sink) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        g_traceSink.store(sink, std::memory_order_release);
#else
        (void)InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_traceSink),
            reinterpret_cast<PVOID>(sink));
#endif
    }

    void* LoadSinkContext() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return g_traceSinkContext.load(std::memory_order_acquire);
#else
        return InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_traceSinkContext), nullptr, nullptr);
#endif
    }

    void StoreSinkContext(void* context) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        g_traceSinkContext.store(context, std::memory_order_release);
#else
        (void)InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_traceSinkContext), context);
#endif
    }

    void YieldTraceWriter() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        std::this_thread::yield();
#else
        YieldProcessor();
#endif
    }

    bool IsValidLevel(TraceLevel level) noexcept
    {
        return level >= TraceLevel::Error && level <= TraceLevel::Max;
    }

    bool IsSingleKnownComponent(ULONG component) noexcept
    {
        return component != 0 &&
            (component & (component - 1)) == 0 &&
            (component & KnownTraceComponents) != 0;
    }

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
        case ComponentTransport: return "TRANSPORT";
        case ComponentQuic: return "QUIC";
        case ComponentHttp3: return "HTTP3";
        case ComponentNone:
        default: return "NONE";
        }
    }

    TraceSlot* ClaimTraceSlot() noexcept
    {
        const ULONG start = static_cast<ULONG>(IncrementLong(g_traceSlotCursor));
        for (SIZE_T attempt = 0; attempt < rtl::TraceSlotCount; ++attempt) {
            TraceSlot& slot = g_traceSlots[(start + attempt) % rtl::TraceSlotCount];
            if (CompareExchangeLong(slot.Busy, 0, 1)) {
                slot.Buffer[0] = '\0';
                return &slot;
            }
        }

        (void)IncrementUnsigned64(g_traceDroppedBusy);
        return nullptr;
    }

    void ReleaseTraceSlot(TraceSlot* slot) noexcept
    {
        if (slot == nullptr) {
            return;
        }

        slot->Buffer[0] = '\0';
        StoreLong(slot->Busy, 0);
    }

    SIZE_T BoundedLength(const char* text, SIZE_T capacity) noexcept
    {
        if (text == nullptr || capacity == 0) {
            return 0;
        }

        SIZE_T length = 0;
        while (length < capacity && text[length] != '\0') {
            ++length;
        }
        return length;
    }

    bool AppendLiteral(char* buffer, SIZE_T capacity, SIZE_T* used, const char* literal) noexcept
    {
        if (buffer == nullptr || used == nullptr || literal == nullptr || *used >= capacity) {
            return false;
        }

        const SIZE_T length = BoundedLength(literal, capacity);
        if (length >= capacity - *used) {
            return false;
        }

        RtlCopyMemory(buffer + *used, literal, length);
        *used += length;
        buffer[*used] = '\0';
        return true;
    }

    bool AppendUnsigned64Field(
        char* buffer,
        SIZE_T capacity,
        SIZE_T* used,
        const char* name,
        ULONGLONG value) noexcept
    {
        if (value == 0) {
            return true;
        }

#if defined(WKNET_USER_MODE_TEST)
        const int written = _snprintf_s(
            buffer + *used,
            capacity - *used,
            _TRUNCATE,
            "[%s=%llu]",
            name,
            static_cast<unsigned long long>(value));
        if (written < 0) {
            return false;
        }
        *used += static_cast<SIZE_T>(written);
        return true;
#else
        const NTSTATUS status = RtlStringCbPrintfA(
            buffer + *used,
            capacity - *used,
            "[%s=%llu]",
            name,
            value);
        if (!NT_SUCCESS(status)) {
            return false;
        }
        SIZE_T length = 0;
        if (!NT_SUCCESS(RtlStringCbLengthA(buffer + *used, capacity - *used, &length))) {
            return false;
        }
        *used += length;
        return true;
#endif
    }

    bool FormatPrefix(
        char* buffer,
        SIZE_T capacity,
        ULONG component,
        TraceLevel level,
        ULONGLONG sequence,
        const TraceCorrelation* correlation,
        SIZE_T* used) noexcept
    {
        if (buffer == nullptr || used == nullptr || capacity == 0) {
            return false;
        }

#if defined(WKNET_USER_MODE_TEST)
        const int prefix = _snprintf_s(
            buffer,
            capacity,
            _TRUNCATE,
            "%s : [%s][%s]",
            WKNET_DRIVER_NAME,
            ComponentName(component),
            LevelName(level));
        if (prefix < 0) {
            return false;
        }
        *used = static_cast<SIZE_T>(prefix);
#else
        const NTSTATUS status = RtlStringCbPrintfA(
            buffer,
            capacity,
            "%s : [%s][%s]",
            WKNET_DRIVER_NAME,
            ComponentName(component),
            LevelName(level));
        if (!NT_SUCCESS(status) ||
            !NT_SUCCESS(RtlStringCbLengthA(buffer, capacity, used))) {
            return false;
        }
#endif

        if (!AppendUnsigned64Field(buffer, capacity, used, "seq", sequence)) {
            return false;
        }
        if (correlation != nullptr) {
            if (!AppendUnsigned64Field(buffer, capacity, used, "op", correlation->OperationId) ||
                !AppendUnsigned64Field(buffer, capacity, used, "conn", correlation->ConnectionId) ||
                !AppendUnsigned64Field(buffer, capacity, used, "stream", correlation->StreamId)) {
                return false;
            }
        }

        return AppendLiteral(buffer, capacity, used, " ");
    }

    bool FormatMessage(
        char* buffer,
        SIZE_T capacity,
        SIZE_T used,
        const char* format,
        va_list args,
        bool* truncated) noexcept
    {
        if (buffer == nullptr || format == nullptr || truncated == nullptr || used >= capacity) {
            return false;
        }

        *truncated = false;
#if defined(WKNET_USER_MODE_TEST)
        const int result = _vsnprintf_s(
            buffer + used,
            capacity - used,
            _TRUNCATE,
            format,
            args);
        if (result < 0) {
            *truncated = true;
        }
#else
        const NTSTATUS status = RtlStringCbVPrintfA(
            buffer + used,
            capacity - used,
            format,
            args);
        if (status == STATUS_BUFFER_OVERFLOW) {
            *truncated = true;
        }
        else if (!NT_SUCCESS(status)) {
            return false;
        }
#endif
        return true;
    }

    bool FinalizeMessage(char* buffer, SIZE_T capacity, bool truncated) noexcept
    {
        if (buffer == nullptr || capacity <= LineEndingBytes + 1) {
            return false;
        }

        SIZE_T length = BoundedLength(buffer, capacity);
        if (length >= capacity) {
            length = capacity - 1;
            buffer[length] = '\0';
            truncated = true;
        }

        while (length > 0 && (buffer[length - 1] == '\r' || buffer[length - 1] == '\n')) {
            --length;
        }
        buffer[length] = '\0';

        if (truncated) {
            const SIZE_T suffixLength = sizeof(TruncatedSuffix) - 1;
            const SIZE_T maximumContent = capacity - suffixLength - LineEndingBytes - 1;
            if (length > maximumContent) {
                length = maximumContent;
            }
            buffer[length] = '\0';
            RtlCopyMemory(buffer + length, TruncatedSuffix, suffixLength);
            length += suffixLength;
            buffer[length] = '\0';
            (void)IncrementUnsigned64(g_traceTruncated);
        }

        if (length > capacity - LineEndingBytes - 1) {
            return false;
        }
        buffer[length++] = '\r';
        buffer[length++] = '\n';
        buffer[length] = '\0';
        return true;
    }

#if !defined(WKNET_USER_MODE_TEST)
    ULONG DbgPrintLevel(TraceLevel level) noexcept
    {
        switch (level) {
        case TraceLevel::Error: return DPFLTR_ERROR_LEVEL;
        case TraceLevel::Warning: return DPFLTR_WARNING_LEVEL;
        case TraceLevel::Verbose:
        case TraceLevel::Max: return DPFLTR_TRACE_LEVEL;
        case TraceLevel::Info:
        case TraceLevel::Off:
        default: return DPFLTR_INFO_LEVEL;
        }
    }
#endif

    void DefaultEmit(TraceLevel level, const char* message) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(level);
        const SIZE_T length = BoundedLength(message, rtl::TracePageBytes);
        if (length >= 2 && message[length - 2] == '\r' && message[length - 1] == '\n') {
            (void)fwrite(message, 1, length - 2, stdout);
            (void)fputc('\n', stdout);
        }
        else {
            (void)fputs(message, stdout);
        }
#else
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DbgPrintLevel(level), "%s", message);
#endif
    }

    bool EmitTrace(TraceLevel level, ULONG component, const char* message) noexcept
    {
        const LONG firstSequence = LoadLong(g_traceSinkSequence);
        if ((firstSequence & 1) == 0) {
            (void)IncrementLong(g_traceSinkActive);
            const LONG confirmedSequence = LoadLong(g_traceSinkSequence);
            if (confirmedSequence == firstSequence && (confirmedSequence & 1) == 0) {
                TraceSink sink = LoadSink();
                void* context = LoadSinkContext();
                if (sink != nullptr) {
                    sink(context, level, component, message);
                }
                else {
                    DefaultEmit(level, message);
                }
                (void)DecrementLong(g_traceSinkActive);
                return true;
            }
            (void)DecrementLong(g_traceSinkActive);
        }

        (void)IncrementUnsigned64(g_traceDroppedBusy);
        return false;
    }

    void TraceWriteV(
        ULONG component,
        TraceLevel level,
        const TraceCorrelation* correlation,
        const char* format,
        va_list args) noexcept
    {
        if (!TraceIsEnabled(level, component)) {
            return;
        }
        if (format == nullptr) {
            (void)IncrementUnsigned64(g_traceFormatFailures);
            return;
        }

        TraceSlot* slot = ClaimTraceSlot();
        if (slot == nullptr) {
            return;
        }

        SIZE_T used = 0;
        const ULONGLONG sequence = IncrementUnsigned64(g_traceSequence);
        if (!FormatPrefix(
                slot->Buffer,
                sizeof(slot->Buffer),
                component,
                level,
                sequence,
                correlation,
                &used)) {
            (void)IncrementUnsigned64(g_traceFormatFailures);
            ReleaseTraceSlot(slot);
            return;
        }

        bool truncated = false;
        if (!FormatMessage(slot->Buffer, sizeof(slot->Buffer), used, format, args, &truncated) ||
            !FinalizeMessage(slot->Buffer, sizeof(slot->Buffer), truncated)) {
            (void)IncrementUnsigned64(g_traceFormatFailures);
            ReleaseTraceSlot(slot);
            return;
        }

        if (EmitTrace(level, component, slot->Buffer)) {
            (void)IncrementUnsigned64(g_traceEmitted);
        }
        ReleaseTraceSlot(slot);
    }
}

void TraceSetLevel(TraceLevel level) noexcept
{
    StoreLong(g_traceLevel, IsValidLevel(level) || level == TraceLevel::Off ?
        static_cast<LONG>(level) : static_cast<LONG>(TraceLevel::Off));
}

void TraceSetComponents(ULONG mask) noexcept
{
    StoreLong(g_traceComponents, static_cast<LONG>(mask));
}

TraceLevel TraceGetLevel() noexcept
{
    return static_cast<TraceLevel>(LoadLong(g_traceLevel));
}

ULONG TraceGetComponents() noexcept
{
    return static_cast<ULONG>(LoadLong(g_traceComponents));
}

void TraceSetSink(TraceSink sink, void* context) noexcept
{
    while (!CompareExchangeLong(g_traceSinkWriter, 0, 1)) {
        YieldTraceWriter();
    }

    (void)IncrementLong(g_traceSinkSequence);
    while (LoadLong(g_traceSinkActive) != 0) {
        YieldTraceWriter();
    }

    StoreSinkContext(context);
    StoreSink(sink);
    (void)IncrementLong(g_traceSinkSequence);
    StoreLong(g_traceSinkWriter, 0);
}

void TraceGetStatistics(TraceStatistics* statistics) noexcept
{
    if (statistics == nullptr) {
        return;
    }

    statistics->Emitted = LoadUnsigned64(g_traceEmitted);
    statistics->DroppedBusy = LoadUnsigned64(g_traceDroppedBusy);
    statistics->FormatFailures = LoadUnsigned64(g_traceFormatFailures);
    statistics->Truncated = LoadUnsigned64(g_traceTruncated);
}

void TraceResetStatistics() noexcept
{
    ResetUnsigned64(g_traceEmitted);
    ResetUnsigned64(g_traceDroppedBusy);
    ResetUnsigned64(g_traceFormatFailures);
    ResetUnsigned64(g_traceTruncated);
}

bool TraceIsEnabled(TraceLevel level, ULONG component) noexcept
{
    if (!IsValidLevel(level) || !IsSingleKnownComponent(component)) {
        return false;
    }

    const TraceLevel current = TraceGetLevel();
    if (current == TraceLevel::Off || level > current) {
        return false;
    }

    return (TraceGetComponents() & component) != 0;
}

void TraceWrite(ULONG component, TraceLevel level, const char* format, ...) noexcept
{
    va_list args = {};
    va_start(args, format);
    TraceWriteV(component, level, nullptr, format, args);
    va_end(args);
}

void TraceWriteCorrelated(
    ULONG component,
    TraceLevel level,
    const TraceCorrelation* correlation,
    const char* format,
    ...) noexcept
{
    va_list args = {};
    va_start(args, format);
    TraceWriteV(component, level, correlation, format, args);
    va_end(args);
}

namespace rtl
{
ULONGLONG TraceAllocateCorrelationId() noexcept
{
    ULONGLONG id = IncrementUnsigned64(g_traceCorrelationId);
    if (id == 0) {
        id = IncrementUnsigned64(g_traceCorrelationId);
    }
    return id;
}

#if defined(WKNET_USER_MODE_TEST)
SIZE_T TraceTestSlotSize() noexcept
{
    return sizeof(TraceSlot);
}

SIZE_T TraceTestSlotAlignment() noexcept
{
    return alignof(TraceSlot);
}
#endif
}
}

#if defined(WKNET_USER_MODE_TEST)
namespace
{
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
