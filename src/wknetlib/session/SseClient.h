#pragma once

#include "sse/EventStreamParser.h"
#include "session/Engine.h"
#include "session/Async.h"

namespace wknet
{
namespace session
{
    enum class SseClientState : ULONG
    {
        Idle = 0,
        Connecting = 1,
        Open = 2,
        Reconnecting = 3,
        Failed = 4,
        Closed = 5
    };

    struct SseHeader final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct SseConnectOptions final
    {
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const SseHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        const char* LastEventId = nullptr;
        SIZE_T LastEventIdLength = 0;
        bool AutoReconnect = true;
        ULONG MaxReconnectAttempts = 0; // 0 = unlimited until Close
        ULONG InitialReconnectDelayMs = 1000;
        ULONG MaxReconnectDelayMs = 30000;
        ULONG ConnectTimeoutMs = 30000;
        ULONG IdleTimeoutMs = 0;
        ULONG ReceiveTimeoutMs = 0;
        SIZE_T MaxEventBytes = 1 * 1024 * 1024;
        SIZE_T MaxParserBufferBytes = 256 * 1024;
        // 0 = library default (32). Queue grows on demand up to this cap.
        SIZE_T MaxQueuedEvents = 0;
        bool RequireEventStreamContentType = true;
        TlsOptions Tls = {};
        AddressFamily Family = AddressFamily::Any;
        void* CallbackContext = nullptr;
        NTSTATUS (*OnEvent)(
            void* context,
            const char* type,
            SIZE_T typeLength,
            const char* data,
            SIZE_T dataLength,
            const char* id,
            SIZE_T idLength) = nullptr;
        void (*OnReconnect)(
            void* context,
            ULONG attempt,
            ULONG delayMs,
            NTSTATUS lastError,
            const char* lastEventId,
            SIZE_T lastEventIdLength) = nullptr;
    };

    struct SseEventView final
    {
        const char* Type = nullptr;
        SIZE_T TypeLength = 0;
        const char* Data = nullptr;
        SIZE_T DataLength = 0;
        const char* Id = nullptr;
        SIZE_T IdLength = 0;
    };

    struct SseClientObject;

    _Must_inspect_result_
    NTSTATUS SseClientConnectSync(
        _In_ SessionHandle session,
        _In_ const SseConnectOptions* options,
        _Out_ SseClientObject** client) noexcept;

    _Must_inspect_result_
    NTSTATUS SseClientReceive(
        _In_ SseClientObject* client,
        _Out_opt_ SseEventView* event) noexcept;

    _Must_inspect_result_
    NTSTATUS SseClientGetLastEventId(
        _In_ SseClientObject* client,
        _Outptr_result_bytebuffer_(*idLength) const char** id,
        _Out_ SIZE_T* idLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SseClientGetReconnectAttempt(
        _In_ SseClientObject* client,
        _Out_ ULONG* attempt) noexcept;

    _Must_inspect_result_
    NTSTATUS SseClientClose(_In_opt_ SseClientObject* client) noexcept;
}
}
