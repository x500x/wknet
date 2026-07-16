#include "session/SseClient.h"
#include "session/EngineUtils.h"
#include "session/HandleAlloc.h"
#include "session/HttpEngineInternal.hpp"
#include "session/Async.h"
#include "rtl/TraceInternal.h"

#if defined(WKNET_USER_MODE_TEST)
#include <atomic>
#include <chrono>
#include <stdlib.h>
#include <mutex>
#include <thread>
#else
#include <wdm.h>
#endif

namespace wknet
{
namespace session
{
namespace
{
    constexpr ULONG kSseClientMagic = 0x4B485353; // 'KHSS'
    constexpr SIZE_T kMaxQueuedEvents = 32;
    constexpr SIZE_T kMaxExtraHeaders = MaxHeadersPerRequest;
}

    struct SseQueuedEvent final
    {
        char Type[64] = {};
        SIZE_T TypeLength = 0;
        char* Data = nullptr;
        SIZE_T DataLength = 0;
        char Id[256] = {};
        SIZE_T IdLength = 0;
        bool Occupied = false;
    };

    struct SseClientObject final
    {
        ULONG Magic = kSseClientMagic;
        volatile LONG Closed = 0;
        SessionHandle Session = nullptr;
        SseClientState State = SseClientState::Idle;
        SseConnectOptions Options = {};
        char* UrlCopy = nullptr;
        SIZE_T UrlLength = 0;
        char* SeedLastEventId = nullptr;
        SIZE_T SeedLastEventIdLength = 0;
        StoredHeader ExtraHeaders[kMaxExtraHeaders] = {};
        SIZE_T ExtraHeaderCount = 0;
        ULONGLONG TraceOperationId = 0;

        sse::EventStreamParser Parser = {};
        SseQueuedEvent Queue[kMaxQueuedEvents] = {};
        SIZE_T QueueHead = 0;
        SIZE_T QueueTail = 0;
        SIZE_T QueueCount = 0;
        SseQueuedEvent LastDelivered = {};

        volatile LONG OpenReady = 0;
        volatile LONG OpenFailed = 0;
        NTSTATUS OpenStatus = STATUS_PENDING;
        USHORT ResponseStatusCode = 0;
        bool ContentTypeAccepted = false;
        bool ContentTypeSeen = false;
        bool StreamTerminal = false;
        NTSTATUS StreamStatus = STATUS_PENDING;
        ULONG ReconnectAttempt = 0;
        ULONG RecommendedRetryMs = 0;
        bool HasRecommendedRetry = false;
        http1::HttpAcceptEncodingPreference IdentityOnlyPreference = {};

        RequestHandle ActiveRequest = nullptr;
        AsyncOperationHandle ActiveOperation = nullptr;
        volatile LONG PumpRunning = 0;

#if defined(WKNET_USER_MODE_TEST)
        std::thread PumpThread = {};
        std::mutex QueueMutex = {};
        std::atomic<bool> OpenSignaled{false};
        std::atomic<bool> EventSignaled{false};
        std::atomic<bool> ClosedSignaled{false};
#else
        KEVENT OpenEvent = {};
        KEVENT EventAvailable = {};
        KEVENT ClosedEvent = {};
#endif
    };

namespace
{
    TraceCorrelation MakeSseCorrelation(_In_ const SseClientObject* client) noexcept
    {
        TraceCorrelation correlation = {};
        if (client != nullptr) {
            correlation.OperationId = client->TraceOperationId;
        }
        return correlation;
    }

    bool IsLiveClient(_In_opt_ const SseClientObject* client) noexcept
    {
        return client != nullptr && client->Magic == kSseClientMagic && client->Closed == 0;
    }

    void FreeQueuedEvent(_Inout_ SseQueuedEvent& event) noexcept
    {
        FreeApiMemory(event.Data);
        event = {};
    }

    void ClearEventQueue(_Inout_ SseClientObject* client) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        std::lock_guard<std::mutex> guard(client->QueueMutex);
#endif
        for (SIZE_T index = 0; index < kMaxQueuedEvents; ++index) {
            FreeQueuedEvent(client->Queue[index]);
        }
        client->QueueHead = 0;
        client->QueueTail = 0;
        client->QueueCount = 0;
        FreeQueuedEvent(client->LastDelivered);
    }

    void SignalOpen(_Inout_ SseClientObject* client, NTSTATUS status) noexcept
    {
        if (InterlockedCompareExchange(&client->OpenReady, 1, 0) != 0) {
            return;
        }
        client->OpenStatus = status;
        const TraceCorrelation correlation = MakeSseCorrelation(client);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&client->OpenFailed, 1);
            client->State = SseClientState::Failed;
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Error,
                &correlation,
                "sse.connect.failed status=0x%08X http_status=%u",
                static_cast<ULONG>(status),
                static_cast<ULONG>(client->ResponseStatusCode));
        }
        else {
            client->State = SseClientState::Open;
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Info,
                &correlation,
                "sse.connect.complete http_status=%u content_type_ok=%u",
                static_cast<ULONG>(client->ResponseStatusCode),
                client->ContentTypeAccepted ? 1u : 0u);
        }
#if defined(WKNET_USER_MODE_TEST)
        client->OpenSignaled.store(true);
#else
        KeSetEvent(&client->OpenEvent, IO_NO_INCREMENT, FALSE);
#endif
    }

    void SignalEventAvailable(_Inout_ SseClientObject* client) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        client->EventSignaled.store(true);
#else
        KeSetEvent(&client->EventAvailable, IO_NO_INCREMENT, FALSE);
#endif
    }

    void SignalClosed(_Inout_ SseClientObject* client) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        client->ClosedSignaled.store(true);
        client->OpenSignaled.store(true);
        client->EventSignaled.store(true);
#else
        KeSetEvent(&client->ClosedEvent, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&client->OpenEvent, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&client->EventAvailable, IO_NO_INCREMENT, FALSE);
#endif
    }

    _Must_inspect_result_
    NTSTATUS EnqueueEvent(
        _Inout_ SseClientObject* client,
        _In_ const sse::EventStreamEventView* view) noexcept
    {
        SseQueuedEvent slot = {};
        const char* type = view->Type;
        SIZE_T typeLength = view->TypeLength;
        if (type == nullptr || typeLength == 0) {
            type = "message";
            typeLength = 7;
        }
        if (typeLength >= sizeof(slot.Type)) {
            return STATUS_BUFFER_OVERFLOW;
        }
        RtlCopyMemory(slot.Type, type, typeLength);
        slot.Type[typeLength] = 0;
        // If source was a zero-filled buffer with a non-zero length, fall back to default.
        if (slot.Type[0] == 0) {
            RtlCopyMemory(slot.Type, "message", 7);
            slot.Type[7] = 0;
            typeLength = 7;
        }
        slot.TypeLength = typeLength;

        if (view->Data != nullptr && view->DataLength != 0) {
            slot.Data = AllocateTextCopy(view->Data, view->DataLength);
            if (slot.Data == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            slot.DataLength = view->DataLength;
        }

        if (view->HasId) {
            if (view->IdLength >= sizeof(slot.Id)) {
                FreeQueuedEvent(slot);
                return STATUS_BUFFER_OVERFLOW;
            }
            if (view->Id != nullptr && view->IdLength != 0) {
                RtlCopyMemory(slot.Id, view->Id, view->IdLength);
            }
            slot.Id[view->IdLength] = 0;
            slot.IdLength = view->IdLength;
        }
        slot.Occupied = true;

#if defined(WKNET_USER_MODE_TEST)
        {
            std::lock_guard<std::mutex> guard(client->QueueMutex);
            if (client->QueueCount >= kMaxQueuedEvents) {
                FreeQueuedEvent(slot);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            client->Queue[client->QueueTail] = slot;
            client->QueueTail = (client->QueueTail + 1) % kMaxQueuedEvents;
            ++client->QueueCount;
        }
#else
        if (client->QueueCount >= kMaxQueuedEvents) {
            FreeQueuedEvent(slot);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        client->Queue[client->QueueTail] = slot;
        client->QueueTail = (client->QueueTail + 1) % kMaxQueuedEvents;
        ++client->QueueCount;
#endif
        SignalEventAvailable(client);
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool DequeueEvent(_Inout_ SseClientObject* client, _Out_ SseEventView* out) noexcept
    {
        if (out != nullptr) {
            *out = {};
        }

#if defined(WKNET_USER_MODE_TEST)
        std::lock_guard<std::mutex> guard(client->QueueMutex);
#endif
        if (client->QueueCount == 0) {
            return false;
        }

        FreeQueuedEvent(client->LastDelivered);
        client->LastDelivered = client->Queue[client->QueueHead];
        client->Queue[client->QueueHead] = {};
        client->QueueHead = (client->QueueHead + 1) % kMaxQueuedEvents;
        --client->QueueCount;

        if (out != nullptr) {
            out->Type = client->LastDelivered.Type;
            out->TypeLength = client->LastDelivered.TypeLength;
            out->Data = client->LastDelivered.Data;
            out->DataLength = client->LastDelivered.DataLength;
            out->Id = client->LastDelivered.Id;
            out->IdLength = client->LastDelivered.IdLength;
        }
        return true;
    }

    _Must_inspect_result_
    NTSTATUS ParserEventCallback(
        _In_opt_ void* context,
        _In_ const sse::EventStreamEventView* event) noexcept
    {
        auto* client = static_cast<SseClientObject*>(context);
        if (!IsLiveClient(client) || event == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (event->HasRetry) {
            client->HasRecommendedRetry = true;
            client->RecommendedRetryMs = event->RetryMilliseconds;
        }

        NTSTATUS status = EnqueueEvent(client, event);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (client->Options.OnEvent != nullptr) {
            status = client->Options.OnEvent(
                client->Options.CallbackContext,
                event->Type,
                event->TypeLength,
                event->Data,
                event->DataLength,
                event->HasId ? event->Id : nullptr,
                event->HasId ? event->IdLength : 0);
        }
        return status;
    }

    bool ContentTypeIsEventStream(
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
    {
        // Accept media type prefix text/event-stream (optional parameters after ';').
        // Tolerate leading/trailing OWS and RFC 9110 optional whitespace around ';'.
        constexpr char kPrefix[] = "text/event-stream";
        constexpr SIZE_T kPrefixLength = sizeof(kPrefix) - 1;
        if (value == nullptr || valueLength == 0) {
            return false;
        }

        SIZE_T begin = 0;
        while (begin < valueLength &&
            (value[begin] == ' ' || value[begin] == '\t')) {
            ++begin;
        }
        SIZE_T end = valueLength;
        while (end > begin &&
            (value[end - 1] == ' ' || value[end - 1] == '\t' ||
                value[end - 1] == '\r' || value[end - 1] == '\n')) {
            --end;
        }
        if (end - begin < kPrefixLength) {
            return false;
        }
        if (!TextEqualsIgnoreCase(value + begin, kPrefixLength, kPrefix, kPrefixLength)) {
            return false;
        }
        if (end - begin == kPrefixLength) {
            return true;
        }
        const char next = value[begin + kPrefixLength];
        return next == ';' || next == ' ' || next == '\t';
    }

    _Must_inspect_result_
    NTSTATUS SseResponseStartCallback(void* context, USHORT statusCode) noexcept
    {
        auto* client = static_cast<SseClientObject*>(context);
        if (!IsLiveClient(client)) {
            return STATUS_CANCELLED;
        }

        client->ResponseStatusCode = statusCode;
        if (statusCode < 200 || statusCode > 299) {
            const NTSTATUS status = (statusCode >= 400 && statusCode <= 499) ?
                STATUS_ACCESS_DENIED :
                STATUS_UNSUCCESSFUL;
            SignalOpen(client, status);
            return status;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SseHeaderCallback(
        void* context,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength) noexcept
    {
        auto* client = static_cast<SseClientObject*>(context);
        if (!IsLiveClient(client)) {
            return STATUS_CANCELLED;
        }

        {
            const TraceCorrelation correlation = MakeSseCorrelation(client);
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Verbose,
                &correlation,
                "sse.header name_bytes=%Iu value_bytes=%Iu",
                nameLength,
                valueLength);
        }

        if (TextEqualsLiteralIgnoreCase(name, nameLength, "Content-Type")) {
            client->ContentTypeSeen = true;
            client->ContentTypeAccepted = ContentTypeIsEventStream(value, valueLength);
            const TraceCorrelation correlation = MakeSseCorrelation(client);
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Info,
                &correlation,
                "sse.content_type.seen accepted=%u value_bytes=%Iu",
                client->ContentTypeAccepted ? 1u : 0u,
                valueLength);
            if (client->Options.RequireEventStreamContentType && !client->ContentTypeAccepted) {
                WKNET_TRACE_CORRELATED(
                    ::wknet::ComponentSession,
                    ::wknet::TraceLevel::Error,
                    &correlation,
                    "sse.content_type.rejected value_bytes=%Iu",
                    valueLength);
                SignalOpen(client, STATUS_INVALID_NETWORK_RESPONSE);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        // Open as soon as status is 2xx and Content-Type is acceptable (or not required).
        // If Content-Type is required but not yet seen, wait for a later header/body chunk.
        if (client->ResponseStatusCode >= 200 &&
            client->ResponseStatusCode <= 299 &&
            (!client->Options.RequireEventStreamContentType || client->ContentTypeAccepted)) {
            SignalOpen(client, STATUS_SUCCESS);
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SseBodyCallback(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalChunk) noexcept
    {
        auto* client = static_cast<SseClientObject*>(context);
        if (!IsLiveClient(client)) {
            return STATUS_CANCELLED;
        }

        // Headers may arrive without Content-Type on some servers; open after first body if status ok.
        if (client->OpenReady == 0 &&
            client->ResponseStatusCode >= 200 &&
            client->ResponseStatusCode <= 299) {
            if (!client->Options.RequireEventStreamContentType ||
                client->ContentTypeAccepted ||
                !client->ContentTypeSeen) {
                if (!client->Options.RequireEventStreamContentType || client->ContentTypeAccepted) {
                    SignalOpen(client, STATUS_SUCCESS);
                }
                else if (!client->ContentTypeSeen && !client->Options.RequireEventStreamContentType) {
                    SignalOpen(client, STATUS_SUCCESS);
                }
            }
        }

        if (client->OpenFailed != 0) {
            return client->OpenStatus;
        }

        NTSTATUS status = STATUS_SUCCESS;
        if (dataLength != 0) {
            status = client->Parser.Feed(data, dataLength, ParserEventCallback, client);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (finalChunk) {
            status = client->Parser.Finish(ParserEventCallback, client);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            client->StreamTerminal = true;
            client->StreamStatus = STATUS_SUCCESS;
            SignalEventAvailable(client);
        }
        return STATUS_SUCCESS;
    }

    void ReleaseExtraHeaders(_Inout_ SseClientObject* client) noexcept
    {
        for (SIZE_T index = 0; index < client->ExtraHeaderCount; ++index) {
            FreeApiMemory(client->ExtraHeaders[index].Name);
            FreeApiMemory(client->ExtraHeaders[index].Value);
            client->ExtraHeaders[index] = {};
        }
        client->ExtraHeaderCount = 0;
    }

    void DestroyClient(_Inout_ SseClientObject* client) noexcept
    {
        if (client == nullptr) {
            return;
        }

        if (client->ActiveOperation != nullptr) {
            (void)AsyncOperationCancel(client->ActiveOperation);
            AsyncOperationRelease(client->ActiveOperation);
            client->ActiveOperation = nullptr;
        }
        if (client->ActiveRequest != nullptr) {
            HttpRequestRelease(client->ActiveRequest);
            client->ActiveRequest = nullptr;
        }

        ClearEventQueue(client);
        client->Parser.Reset();
        ReleaseExtraHeaders(client);
        FreeApiMemory(client->UrlCopy);
        FreeApiMemory(client->SeedLastEventId);
        client->UrlCopy = nullptr;
        client->SeedLastEventId = nullptr;

#if defined(WKNET_USER_MODE_TEST)
        if (client->PumpThread.joinable()) {
            client->PumpThread.join();
        }
        free(client);
#else
        FreeNonPagedObject(client);
#endif
    }

    _Must_inspect_result_
    NTSTATUS CopyConnectOptions(
        _In_ const SseConnectOptions& options,
        _Inout_ SseClientObject* client) noexcept
    {
        client->Options = options;
        client->Options.Url = nullptr;
        client->Options.LastEventId = nullptr;
        client->Options.Headers = nullptr;
        client->Options.HeaderCount = 0;

        client->UrlCopy = AllocateTextCopy(options.Url, options.UrlLength);
        if (client->UrlCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        client->UrlLength = options.UrlLength;
        client->Options.Url = client->UrlCopy;
        client->Options.UrlLength = options.UrlLength;

        if (options.LastEventId != nullptr && options.LastEventIdLength != 0) {
            client->SeedLastEventId = AllocateTextCopy(options.LastEventId, options.LastEventIdLength);
            if (client->SeedLastEventId == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            client->SeedLastEventIdLength = options.LastEventIdLength;
            client->Options.LastEventId = client->SeedLastEventId;
            client->Options.LastEventIdLength = options.LastEventIdLength;
        }

        if (options.Headers != nullptr && options.HeaderCount != 0) {
            if (options.HeaderCount > kMaxExtraHeaders) {
                return STATUS_INVALID_PARAMETER;
            }
            for (SIZE_T index = 0; index < options.HeaderCount; ++index) {
                const SseHeader& src = options.Headers[index];
                if (src.Name == nullptr || src.NameLength == 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                char* name = AllocateTextCopy(src.Name, src.NameLength);
                char* value = nullptr;
                if (src.ValueLength != 0) {
                    value = AllocateTextCopy(src.Value, src.ValueLength);
                    if (value == nullptr) {
                        FreeApiMemory(name);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
                if (name == nullptr) {
                    FreeApiMemory(value);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                client->ExtraHeaders[index].Name = name;
                client->ExtraHeaders[index].NameLength = src.NameLength;
                client->ExtraHeaders[index].Value = value;
                client->ExtraHeaders[index].ValueLength = src.ValueLength;
                ++client->ExtraHeaderCount;
            }
        }

        return STATUS_SUCCESS;
    }

    bool IsControlledSseHeaderName(
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength) noexcept
    {
        return TextEqualsLiteralIgnoreCase(name, nameLength, "Accept") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Last-Event-ID") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Cache-Control") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Accept-Encoding");
    }

    _Must_inspect_result_
    NTSTATUS BuildAndStartStream(_Inout_ SseClientObject* client) noexcept;

#if defined(WKNET_USER_MODE_TEST)
    void SseUmPumpThread(SseClientObject* client) noexcept
    {
        if (client == nullptr || client->ActiveOperation == nullptr) {
            return;
        }
        const NTSTATUS status = TestRunAsyncOperation(client->ActiveOperation);
        client->StreamStatus = status;
        client->StreamTerminal = true;
        if (client->OpenReady == 0) {
            if (client->Options.RequireEventStreamContentType && !client->ContentTypeAccepted) {
                SignalOpen(client, STATUS_INVALID_NETWORK_RESPONSE);
            }
            else {
                SignalOpen(client, !NT_SUCCESS(status) ? status : STATUS_UNSUCCESSFUL);
            }
        }
        SignalEventAvailable(client);
        InterlockedExchange(&client->PumpRunning, 0);
    }
#endif

    _Must_inspect_result_
    NTSTATUS WaitForOpen(_Inout_ SseClientObject* client, ULONG timeoutMs) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        const auto start = std::chrono::steady_clock::now();
        for (;;) {
            if (client->OpenSignaled.load() || client->Closed != 0) {
                break;
            }
            if (timeoutMs != 0) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= static_cast<long long>(timeoutMs)) {
                    return STATUS_IO_TIMEOUT;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
#else
        LARGE_INTEGER timeout = {};
        LARGE_INTEGER* timeoutPointer = nullptr;
        if (timeoutMs != 0xffffffffUL && timeoutMs != 0) {
            timeout.QuadPart = -static_cast<LONGLONG>(timeoutMs) * 10000LL;
            timeoutPointer = &timeout;
        }
        const NTSTATUS waitStatus = KeWaitForSingleObject(
            &client->OpenEvent,
            Executive,
            KernelMode,
            FALSE,
            timeoutPointer);
        if (waitStatus == STATUS_TIMEOUT) {
            return STATUS_IO_TIMEOUT;
        }
        if (!NT_SUCCESS(waitStatus)) {
            return waitStatus;
        }
#endif
        if (client->Closed != 0) {
            return STATUS_CANCELLED;
        }
        return client->OpenStatus;
    }

    _Must_inspect_result_
    NTSTATUS WaitForEventOrTerminal(
        _Inout_ SseClientObject* client,
        ULONG timeoutMs) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        const auto start = std::chrono::steady_clock::now();
        for (;;) {
            if (client->Closed != 0) {
                return STATUS_CANCELLED;
            }
            if (client->QueueCount != 0) {
                return STATUS_SUCCESS;
            }
            if (client->StreamTerminal && client->QueueCount == 0) {
                return NT_SUCCESS(client->StreamStatus) ?
                    STATUS_CONNECTION_DISCONNECTED :
                    client->StreamStatus;
            }
            if (timeoutMs != 0) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= static_cast<long long>(timeoutMs)) {
                    return STATUS_IO_TIMEOUT;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
#else
        for (;;) {
            if (client->Closed != 0) {
                return STATUS_CANCELLED;
            }
            if (client->QueueCount != 0) {
                return STATUS_SUCCESS;
            }
            if (client->StreamTerminal && client->QueueCount == 0) {
                return NT_SUCCESS(client->StreamStatus) ?
                    STATUS_CONNECTION_DISCONNECTED :
                    client->StreamStatus;
            }

            LARGE_INTEGER timeout = {};
            LARGE_INTEGER* timeoutPointer = nullptr;
            if (timeoutMs != 0xffffffffUL && timeoutMs != 0) {
                timeout.QuadPart = -static_cast<LONGLONG>(timeoutMs) * 10000LL;
                timeoutPointer = &timeout;
            }
            KeClearEvent(&client->EventAvailable);
            if (client->QueueCount != 0 || client->StreamTerminal || client->Closed != 0) {
                continue;
            }
            const NTSTATUS waitStatus = KeWaitForSingleObject(
                &client->EventAvailable,
                Executive,
                KernelMode,
                FALSE,
                timeoutPointer);
            if (waitStatus == STATUS_TIMEOUT) {
                return STATUS_IO_TIMEOUT;
            }
            if (!NT_SUCCESS(waitStatus)) {
                return waitStatus;
            }
        }
#endif
    }

    bool ShouldReconnect(_In_ const SseClientObject* client, NTSTATUS streamStatus) noexcept
    {
        if (!client->Options.AutoReconnect || client->Closed != 0) {
            return false;
        }
        if (client->OpenFailed != 0 &&
            client->ResponseStatusCode >= 400 &&
            client->ResponseStatusCode <= 499) {
            return false;
        }
        if (client->Options.MaxReconnectAttempts != 0 &&
            client->ReconnectAttempt >= client->Options.MaxReconnectAttempts) {
            return false;
        }
        // STATUS_ACCESS_DENIED used for 4xx open failures.
        if (streamStatus == STATUS_ACCESS_DENIED ||
            streamStatus == STATUS_INVALID_NETWORK_RESPONSE) {
            return false;
        }
        return true;
    }

    ULONG ComputeReconnectDelayMs(_In_ const SseClientObject* client) noexcept
    {
        ULONG delay = client->Options.InitialReconnectDelayMs;
        if (delay == 0) {
            delay = 1000;
        }
        if (client->HasRecommendedRetry) {
            delay = client->RecommendedRetryMs;
        }
        else {
            // Exponential backoff: Initial * 2^attempt (saturate).
            ULONG attempt = client->ReconnectAttempt;
            while (attempt > 0 && delay < client->Options.MaxReconnectDelayMs) {
                if (delay > (MAXULONG / 2)) {
                    delay = MAXULONG;
                    break;
                }
                delay *= 2;
                --attempt;
            }
        }
        if (client->Options.MaxReconnectDelayMs != 0 &&
            delay > client->Options.MaxReconnectDelayMs) {
            delay = client->Options.MaxReconnectDelayMs;
        }
        return delay;
    }

    _Must_inspect_result_
    NTSTATUS SleepInterruptible(_Inout_ SseClientObject* client, ULONG delayMs) noexcept
    {
        if (delayMs == 0) {
            return client->Closed != 0 ? STATUS_CANCELLED : STATUS_SUCCESS;
        }
#if defined(WKNET_USER_MODE_TEST)
        const auto start = std::chrono::steady_clock::now();
        while (client->Closed == 0 && !client->ClosedSignaled.load()) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= static_cast<long long>(delayMs)) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return client->Closed != 0 ? STATUS_CANCELLED : STATUS_SUCCESS;
#else
        LARGE_INTEGER timeout = {};
        timeout.QuadPart = -static_cast<LONGLONG>(delayMs) * 10000LL;
        const NTSTATUS status = KeWaitForSingleObject(
            &client->ClosedEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (status == STATUS_SUCCESS || client->Closed != 0) {
            return STATUS_CANCELLED;
        }
        return STATUS_SUCCESS;
#endif
    }

    void CleanupActiveStream(_Inout_ SseClientObject* client) noexcept
    {
        if (client->ActiveOperation != nullptr) {
            (void)AsyncOperationCancel(client->ActiveOperation);
#if defined(WKNET_USER_MODE_TEST)
            if (client->PumpThread.joinable()) {
                client->PumpThread.join();
            }
#endif
            AsyncOperationRelease(client->ActiveOperation);
            client->ActiveOperation = nullptr;
        }
        if (client->ActiveRequest != nullptr) {
            HttpRequestRelease(client->ActiveRequest);
            client->ActiveRequest = nullptr;
        }
        InterlockedExchange(&client->PumpRunning, 0);
    }

    _Must_inspect_result_
    NTSTATUS BuildAndStartStream(_Inout_ SseClientObject* client) noexcept
    {
        CleanupActiveStream(client);

        client->OpenReady = 0;
        client->OpenFailed = 0;
        client->OpenStatus = STATUS_PENDING;
        client->ResponseStatusCode = 0;
        client->ContentTypeAccepted = false;
        client->ContentTypeSeen = false;
        client->StreamTerminal = false;
        client->StreamStatus = STATUS_PENDING;
        client->State = SseClientState::Connecting;
#if defined(WKNET_USER_MODE_TEST)
        client->OpenSignaled.store(false);
        client->EventSignaled.store(false);
#else
        KeClearEvent(&client->OpenEvent);
        KeClearEvent(&client->EventAvailable);
#endif

        NTSTATUS status = client->Parser.Initialize(
            client->Options.MaxParserBufferBytes,
            client->Options.MaxEventBytes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        // Seed parser last-event-id via a synthetic empty path: store in options and header only.
        // Parser tracks ids from events; GetLastEventId prefers parser, else seed.

        const TraceCorrelation correlation = MakeSseCorrelation(client);
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentSession,
            ::wknet::TraceLevel::Verbose,
            &correlation,
            "sse.stream.start attempt=%lu auto_reconnect=%u",
            client->ReconnectAttempt,
            client->Options.AutoReconnect ? 1u : 0u);

        RequestHandle request = nullptr;
        status = HttpRequestCreate(client->Session, &request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = HttpRequestSetUrl(request, client->UrlCopy, client->UrlLength);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }
        status = HttpRequestSetMethod(request, HttpMethod::Get);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }
        status = HttpRequestSetConnectionPolicy(request, ConnectionPolicy::ForceNew);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }
        status = HttpRequestSetAddressFamily(request, client->Options.Family);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }
        status = HttpRequestSetTlsOptions(request, &client->Options.Tls);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }

        status = HttpRequestSetHeader(
            request,
            "Accept",
            sizeof("Accept") - 1,
            "text/event-stream",
            sizeof("text/event-stream") - 1);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }
        status = HttpRequestSetHeader(
            request,
            "Cache-Control",
            sizeof("Cache-Control") - 1,
            "no-cache",
            sizeof("no-cache") - 1);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }
        // Streaming body path supports identity only. Force that offer so servers
        // do not reply with gzip/br (which currently fail-close the stream).
        status = HttpRequestSetHeader(
            request,
            "Accept-Encoding",
            sizeof("Accept-Encoding") - 1,
            "identity",
            sizeof("identity") - 1);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }
        status = HttpRequestSetHeader(
            request,
            "User-Agent",
            sizeof("User-Agent") - 1,
            "wknet-sse/1.0",
            sizeof("wknet-sse/1.0") - 1);
        if (!NT_SUCCESS(status)) {
            HttpRequestRelease(request);
            return status;
        }

        const char* lastId = client->Parser.LastEventId();
        SIZE_T lastIdLength = client->Parser.LastEventIdLength();
        if (lastIdLength == 0 && client->SeedLastEventId != nullptr) {
            lastId = client->SeedLastEventId;
            lastIdLength = client->SeedLastEventIdLength;
        }
        if (lastId != nullptr && lastIdLength != 0) {
            status = HttpRequestSetHeader(
                request,
                "Last-Event-ID",
                sizeof("Last-Event-ID") - 1,
                lastId,
                lastIdLength);
            if (!NT_SUCCESS(status)) {
                HttpRequestRelease(request);
                return status;
            }
        }

        for (SIZE_T index = 0; index < client->ExtraHeaderCount; ++index) {
            const StoredHeader& header = client->ExtraHeaders[index];
            if (IsControlledSseHeaderName(header.Name, header.NameLength)) {
                HttpRequestRelease(request);
                return STATUS_INVALID_PARAMETER;
            }
            status = HttpRequestSetHeader(
                request,
                header.Name,
                header.NameLength,
                header.Value,
                header.ValueLength);
            if (!NT_SUCCESS(status)) {
                HttpRequestRelease(request);
                return status;
            }
        }

        // Keep preference on the client so async send outlives this stack frame.
        client->IdentityOnlyPreference.Coding = http1::HttpAcceptCoding::Identity;
        client->IdentityOnlyPreference.QValue = http1::HttpAcceptEncodingQValueMax;

        HttpSendOptions sendOptions = {};
        sendOptions.Flags = HttpSendFlagBypassCache | HttpSendFlagNoCacheStore;
        sendOptions.MaxRedirects = 0;
        sendOptions.Flags |= HttpSendFlagDisableAutoRedirect;
        sendOptions.ResponseHeaderTimeoutMilliseconds = client->Options.ConnectTimeoutMs;
        sendOptions.BodyReadTimeoutMilliseconds = client->Options.ReceiveTimeoutMs;
        sendOptions.BodyIdleTimeoutMilliseconds = client->Options.IdleTimeoutMs;
        sendOptions.AcceptEncodingPreferences = &client->IdentityOnlyPreference;
        sendOptions.AcceptEncodingPreferenceCount = 1;
        sendOptions.ResponseStartCallback = SseResponseStartCallback;
        sendOptions.HeaderCallback = SseHeaderCallback;
        sendOptions.BodyCallback = SseBodyCallback;
        sendOptions.CallbackContext = client;

        client->ActiveRequest = request;

#if defined(WKNET_USER_MODE_TEST)
        // Ensure the async HTTP body runs on a background pump thread so Connect
        // can return after headers while the stream continues.
        TestSetAsyncAutoRun(false);
#endif

        AsyncOperationHandle operation = nullptr;
        status = HttpSendAsync(client->Session, request, &sendOptions, &operation);

#if defined(WKNET_USER_MODE_TEST)
        TestSetAsyncAutoRun(true);
#endif
        if (!NT_SUCCESS(status)) {
            client->ActiveRequest = nullptr;
            HttpRequestRelease(request);
            return status;
        }

        client->ActiveOperation = operation;

InterlockedExchange(&client->PumpRunning, 1);
#if defined(WKNET_USER_MODE_TEST)
        client->PumpThread = std::thread(SseUmPumpThread, client);
#endif
        return STATUS_SUCCESS;
    }
}

    NTSTATUS SseClientConnectSync(
        SessionHandle session,
        const SseConnectOptions* options,
        SseClientObject** clientOut) noexcept
    {
        if (clientOut != nullptr) {
            *clientOut = nullptr;
        }
        if (!IsSessionHandle(session) || options == nullptr || clientOut == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (options->Url == nullptr || options->UrlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (options->Headers == nullptr && options->HeaderCount != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (options->LastEventId == nullptr && options->LastEventIdLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!IsValidAddressFamily(options->Family)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(WKNET_USER_MODE_TEST)
        auto* client = static_cast<SseClientObject*>(calloc(1, sizeof(SseClientObject)));
#else
        auto* client = AllocateNonPagedObject<SseClientObject>();
#endif
        if (client == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        client->Magic = kSseClientMagic;
        client->Session = session;
        client->State = SseClientState::Idle;
        client->TraceOperationId = rtl::TraceAllocateCorrelationId();
#if defined(WKNET_USER_MODE_TEST)
        client->OpenSignaled.store(false);
        client->EventSignaled.store(false);
        client->ClosedSignaled.store(false);
#else
        KeInitializeEvent(&client->OpenEvent, NotificationEvent, FALSE);
        KeInitializeEvent(&client->EventAvailable, SynchronizationEvent, FALSE);
        KeInitializeEvent(&client->ClosedEvent, NotificationEvent, FALSE);
#endif

        status = CopyConnectOptions(*options, client);
        if (!NT_SUCCESS(status)) {
            DestroyClient(client);
            return status;
        }

        {
            const TraceCorrelation correlation = MakeSseCorrelation(client);
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Info,
                &correlation,
                "sse.connect.start url_bytes=%Iu auto_reconnect=%u max_event_bytes=%Iu",
                client->UrlLength,
                client->Options.AutoReconnect ? 1u : 0u,
                client->Options.MaxEventBytes);
        }

        if (!SessionBeginOperation(session)) {
            DestroyClient(client);
            return STATUS_INVALID_PARAMETER;
        }

        status = BuildAndStartStream(client);
        if (!NT_SUCCESS(status)) {
            const TraceCorrelation correlation = MakeSseCorrelation(client);
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Error,
                &correlation,
                "sse.connect.failed status=0x%08X phase=stream_start",
                static_cast<ULONG>(status));
            SessionEndOperation(session);
            DestroyClient(client);
            return status;
        }

        status = WaitForOpen(
            client,
            client->Options.ConnectTimeoutMs == 0 ? 30000 : client->Options.ConnectTimeoutMs);
        if (!NT_SUCCESS(status)) {
            const TraceCorrelation correlation = MakeSseCorrelation(client);
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Error,
                &correlation,
                "sse.connect.failed status=0x%08X phase=wait_open",
                static_cast<ULONG>(status));
            client->Closed = 1;
            SignalClosed(client);
            CleanupActiveStream(client);
            SessionEndOperation(session);
            DestroyClient(client);
            return status;
        }

        *clientOut = client;
        return STATUS_SUCCESS;
    }

    NTSTATUS SseClientReceive(
        SseClientObject* client,
        SseEventView* event) noexcept
    {
        if (event != nullptr) {
            *event = {};
        }
        if (!IsLiveClient(client)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (;;) {
            if (client->Closed != 0) {
                return STATUS_CANCELLED;
            }

            if (DequeueEvent(client, event)) {
                return STATUS_SUCCESS;
            }

            status = WaitForEventOrTerminal(client, client->Options.ReceiveTimeoutMs);
            if (status == STATUS_SUCCESS) {
                if (DequeueEvent(client, event)) {
                    return STATUS_SUCCESS;
                }
                // Spurious or consumed by another path; continue.
                continue;
            }

            if (status != STATUS_CONNECTION_DISCONNECTED &&
                status != STATUS_CONNECTION_RESET &&
                !IsOrderlyConnectionCloseStatus(status) &&
                status != STATUS_SUCCESS) {
                // Timeout or hard failure.
                if (status == STATUS_IO_TIMEOUT) {
                    return STATUS_IO_TIMEOUT;
                }
            }

            // Stream ended (or reconnectable failure).
            NTSTATUS streamStatus = client->StreamStatus;
            if (streamStatus == STATUS_PENDING) {
                streamStatus = status;
            }

            if (!ShouldReconnect(client, streamStatus)) {
                client->State = SseClientState::Failed;
                return !NT_SUCCESS(streamStatus) ? streamStatus : STATUS_CONNECTION_DISCONNECTED;
            }

            // M5 reconnect path.
            client->State = SseClientState::Reconnecting;
            ++client->ReconnectAttempt;
            const ULONG delayMs = ComputeReconnectDelayMs(client);
            {
                const TraceCorrelation correlation = MakeSseCorrelation(client);
                WKNET_TRACE_CORRELATED(
                    ::wknet::ComponentSession,
                    ::wknet::TraceLevel::Warning,
                    &correlation,
                    "sse.reconnect.scheduled attempt=%lu delay_ms=%lu last_status=0x%08X last_event_id_bytes=%Iu",
                    client->ReconnectAttempt,
                    delayMs,
                    static_cast<ULONG>(streamStatus),
                    client->Parser.LastEventIdLength() != 0 ?
                        client->Parser.LastEventIdLength() :
                        client->SeedLastEventIdLength);
            }
            if (client->Options.OnReconnect != nullptr) {
                const char* lastId = client->Parser.LastEventId();
                SIZE_T lastIdLength = client->Parser.LastEventIdLength();
                if (lastIdLength == 0 && client->SeedLastEventId != nullptr) {
                    lastId = client->SeedLastEventId;
                    lastIdLength = client->SeedLastEventIdLength;
                }
                client->Options.OnReconnect(
                    client->Options.CallbackContext,
                    client->ReconnectAttempt,
                    delayMs,
                    streamStatus,
                    lastId,
                    lastIdLength);
            }

            status = SleepInterruptible(client, delayMs);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            // Preserve last-event-id across reconnect: seed from parser.
            const char* lastId = client->Parser.LastEventId();
            SIZE_T lastIdLength = client->Parser.LastEventIdLength();
            if (lastIdLength != 0) {
                char* copy = AllocateTextCopy(lastId, lastIdLength);
                if (copy != nullptr) {
                    FreeApiMemory(client->SeedLastEventId);
                    client->SeedLastEventId = copy;
                    client->SeedLastEventIdLength = lastIdLength;
                }
            }

            status = BuildAndStartStream(client);
            if (!NT_SUCCESS(status)) {
                client->State = SseClientState::Failed;
                return status;
            }

            status = WaitForOpen(
                client,
                client->Options.ConnectTimeoutMs == 0 ? 30000 : client->Options.ConnectTimeoutMs);
            if (!NT_SUCCESS(status)) {
                if (ShouldReconnect(client, status)) {
                    continue;
                }
                client->State = SseClientState::Failed;
                return status;
            }
            // Continue receive loop on the new stream.
        }
    }

    NTSTATUS SseClientGetLastEventId(
        SseClientObject* client,
        const char** id,
        SIZE_T* idLength) noexcept
    {
        if (id != nullptr) {
            *id = nullptr;
        }
        if (idLength != nullptr) {
            *idLength = 0;
        }
        if (!IsLiveClient(client) || id == nullptr || idLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const char* lastId = client->Parser.LastEventId();
        SIZE_T lastIdLength = client->Parser.LastEventIdLength();
        if (lastIdLength == 0 && client->SeedLastEventId != nullptr) {
            lastId = client->SeedLastEventId;
            lastIdLength = client->SeedLastEventIdLength;
        }
        *id = lastId;
        *idLength = lastIdLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS SseClientGetReconnectAttempt(
        SseClientObject* client,
        ULONG* attempt) noexcept
    {
        if (attempt != nullptr) {
            *attempt = 0;
        }
        if (!IsLiveClient(client) || attempt == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *attempt = client->ReconnectAttempt;
        return STATUS_SUCCESS;
    }

    NTSTATUS SseClientClose(SseClientObject* client) noexcept
    {
        if (client == nullptr) {
            return STATUS_SUCCESS;
        }
        if (client->Magic != kSseClientMagic) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (InterlockedCompareExchange(&client->Closed, 1, 0) != 0) {
            return STATUS_SUCCESS;
        }

        client->State = SseClientState::Closed;
        {
            const TraceCorrelation correlation = MakeSseCorrelation(client);
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Info,
                &correlation,
                "sse.close.start reconnect_attempt=%lu",
                client->ReconnectAttempt);
        }
        SignalClosed(client);
        CleanupActiveStream(client);

        SessionHandle session = client->Session;
        const TraceCorrelation correlation = MakeSseCorrelation(client);
        DestroyClient(client);
        if (session != nullptr) {
            SessionEndOperation(session);
        }
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentSession,
            ::wknet::TraceLevel::Info,
            &correlation,
            "sse.close.complete");
        return STATUS_SUCCESS;
    }
}
}
