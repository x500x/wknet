#pragma once

#include <wknet/http/Types.h>

namespace wknet::sse {
    struct SseClient;

    struct Event final
    {
        const char* Type = nullptr;
        SIZE_T TypeLength = 0;
        const char* Data = nullptr;
        SIZE_T DataLength = 0;
        const char* Id = nullptr;
        SIZE_T IdLength = 0;
    };

    // Caller-supplied opening header (e.g. Authorization). Library-managed
    // Accept / Last-Event-ID / Cache-Control may be injected or rejected if
    // they conflict with controlled SSE headers.
    struct Header final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
        const char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    typedef NTSTATUS (*EventCallback)(
        void* context,
        const Event* event);

    typedef void (*ReconnectCallback)(
        void* context,
        ULONG attempt,
        ULONG delayMs,
        NTSTATUS lastError,
        const char* lastEventId,
        SIZE_T lastEventIdLength);

    struct ConnectConfig final
    {
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const Header* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        wknet::http::TlsConfig Tls = {};
        wknet::http::AddressFamily Family = wknet::http::AddressFamily::Any;

        const char* LastEventId = nullptr;
        SIZE_T LastEventIdLength = 0;

        bool AutoReconnect = true;
        ULONG MaxReconnectAttempts = 0;
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

        EventCallback OnEvent = nullptr;
        ReconnectCallback OnReconnect = nullptr;
        void* CallbackContext = nullptr;
    };

    struct ReceiveOptions final
    {
        SIZE_T MaxEventBytes = 0;
        EventCallback OnEvent = nullptr;
        void* CallbackContext = nullptr;
    };

    ConnectConfig DefaultConnectConfig() noexcept;

    _Must_inspect_result_
    NTSTATUS Connect(
        _In_ wknet::http::Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ SseClient** client) noexcept;

    _Must_inspect_result_
    NTSTATUS Connect(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ SseClient** client) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectEx(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ SseClient** client) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectAsync(
        _In_ wknet::http::Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ wknet::http::AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectAsync(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ wknet::http::AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectAsyncEx(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ wknet::http::AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGetSseClient(
        _In_ wknet::http::AsyncOp* operation,
        _Out_ SseClient** client) noexcept;

    _Must_inspect_result_
    NTSTATUS Receive(
        _In_ SseClient* client,
        _Out_ Event* event) noexcept;

    _Must_inspect_result_
    NTSTATUS ReceiveEx(
        _In_ SseClient* client,
        _In_opt_ const ReceiveOptions* options,
        _Out_opt_ Event* event) noexcept;

    _Must_inspect_result_
    NTSTATUS GetLastEventId(
        _In_ SseClient* client,
        _Outptr_result_bytebuffer_(*idLength) const char** id,
        _Out_ SIZE_T* idLength) noexcept;

    _Must_inspect_result_
    NTSTATUS GetReconnectAttempt(
        _In_ SseClient* client,
        _Out_ ULONG* attempt) noexcept;

    _Must_inspect_result_
    NTSTATUS Close(_In_opt_ SseClient* client) noexcept;
}
