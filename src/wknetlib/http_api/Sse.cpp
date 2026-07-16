#include <wknet/sse/Sse.h>
#include "session/SseClient.h"
#include "session/detail/HttpHandles.h"
#include "session/EngineUtils.h"
#include "http1/HttpTypes.h"
#include <stdlib.h>

namespace wknet::sse {
namespace
{
    constexpr ULONG kPublicSseMagic = 0x50535345; // 'PSSE'

    struct PublicSseClient final
    {
        ULONG Magic = kPublicSseMagic;
        ::wknet::session::SseClientObject* Engine = nullptr;
        EventCallback OnEvent = nullptr;
        ReconnectCallback OnReconnect = nullptr;
        void* CallbackContext = nullptr;
    };

    NTSTATUS SessionOnEventThunk(
        void* context,
        const char* type,
        SIZE_T typeLength,
        const char* data,
        SIZE_T dataLength,
        const char* id,
        SIZE_T idLength) noexcept
    {
        auto* client = static_cast<PublicSseClient*>(context);
        if (client == nullptr || client->Magic != kPublicSseMagic || client->OnEvent == nullptr) {
            return STATUS_SUCCESS;
        }
        Event event = {};
        event.Type = type;
        event.TypeLength = typeLength;
        event.Data = data;
        event.DataLength = dataLength;
        event.Id = id;
        event.IdLength = idLength;
        return client->OnEvent(client->CallbackContext, &event);
    }

    void SessionOnReconnectThunk(
        void* context,
        ULONG attempt,
        ULONG delayMs,
        NTSTATUS lastError,
        const char* lastEventId,
        SIZE_T lastEventIdLength) noexcept
    {
        auto* client = static_cast<PublicSseClient*>(context);
        if (client == nullptr || client->Magic != kPublicSseMagic || client->OnReconnect == nullptr) {
            return;
        }
        client->OnReconnect(
            client->CallbackContext,
            attempt,
            delayMs,
            lastError,
            lastEventId,
            lastEventIdLength);
    }

    void FillSessionConnectOptions(
        const ConnectConfig& src,
        PublicSseClient* publicClient,
        ::wknet::session::SseHeader* headerBuffer,
        SIZE_T headerBufferCount,
        ::wknet::session::SseConnectOptions& dst) noexcept
    {
        dst.Url = src.Url;
        dst.UrlLength = src.UrlLength;
        dst.LastEventId = src.LastEventId;
        dst.LastEventIdLength = src.LastEventIdLength;
        dst.AutoReconnect = src.AutoReconnect;
        dst.MaxReconnectAttempts = src.MaxReconnectAttempts;
        dst.InitialReconnectDelayMs = src.InitialReconnectDelayMs;
        dst.MaxReconnectDelayMs = src.MaxReconnectDelayMs;
        dst.ConnectTimeoutMs = src.ConnectTimeoutMs;
        dst.IdleTimeoutMs = src.IdleTimeoutMs;
        dst.ReceiveTimeoutMs = src.ReceiveTimeoutMs;
        dst.MaxEventBytes = src.MaxEventBytes;
        dst.MaxParserBufferBytes = src.MaxParserBufferBytes;
        dst.MaxQueuedEvents = src.MaxQueuedEvents;
        dst.RequireEventStreamContentType = src.RequireEventStreamContentType;
        wknet::http::detail::FillApiTlsOptions(src.Tls, dst.Tls);
        dst.Family = wknet::http::detail::ToApiAddressFamily(src.Family);

        publicClient->OnEvent = src.OnEvent;
        publicClient->OnReconnect = src.OnReconnect;
        publicClient->CallbackContext = src.CallbackContext;
        dst.CallbackContext = publicClient;
        dst.OnEvent = src.OnEvent != nullptr ? SessionOnEventThunk : nullptr;
        dst.OnReconnect = src.OnReconnect != nullptr ? SessionOnReconnectThunk : nullptr;

        if (src.Headers != nullptr && src.HeaderCount != 0 &&
            headerBuffer != nullptr && src.HeaderCount <= headerBufferCount) {
            for (SIZE_T index = 0; index < src.HeaderCount; ++index) {
                headerBuffer[index].Name = src.Headers[index].Name;
                headerBuffer[index].NameLength = src.Headers[index].NameLength;
                headerBuffer[index].Value = src.Headers[index].Value;
                headerBuffer[index].ValueLength = src.Headers[index].ValueLength;
            }
            dst.Headers = headerBuffer;
            dst.HeaderCount = src.HeaderCount;
        }
    }

    PublicSseClient* AsPublic(_In_opt_ SseClient* client) noexcept
    {
        auto* publicClient = reinterpret_cast<PublicSseClient*>(client);
        if (publicClient == nullptr || publicClient->Magic != kPublicSseMagic) {
            return nullptr;
        }
        return publicClient;
    }
}

ConnectConfig DefaultConnectConfig() noexcept
{
    return ConnectConfig{};
}

NTSTATUS Connect(
    wknet::http::Session* session,
    const char* url,
    SIZE_T urlLength,
    SseClient** client) noexcept
{
    if (client != nullptr) {
        *client = nullptr;
    }
    if (session == nullptr || url == nullptr || urlLength == 0 || client == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    ConnectConfig config = DefaultConnectConfig();
    config.Url = url;
    config.UrlLength = urlLength;
    return ConnectEx(session, &config, client);
}

NTSTATUS Connect(
    wknet::http::Session* session,
    const ConnectConfig* config,
    SseClient** client) noexcept
{
    return ConnectEx(session, config, client);
}

NTSTATUS ConnectEx(
    wknet::http::Session* session,
    const ConnectConfig* config,
    SseClient** client) noexcept
{
    if (client != nullptr) {
        *client = nullptr;
    }
    if (session == nullptr || config == nullptr || client == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->Url == nullptr || config->UrlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!wknet::http::detail::IsValidSession(session)) {
        return STATUS_INVALID_PARAMETER;
    }

    const SIZE_T headerCount = config->HeaderCount;
    if (headerCount > ::wknet::session::MaxHeadersPerRequest) {
        return STATUS_INVALID_PARAMETER;
    }
    ::wknet::HeapArray<::wknet::session::SseHeader> headerBuffer(headerCount != 0 ? headerCount : 1);
    if (!headerBuffer.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

#if defined(WKNET_USER_MODE_TEST)
    auto* publicClient = static_cast<PublicSseClient*>(calloc(1, sizeof(PublicSseClient)));
#else
    auto* publicClient = ::wknet::AllocateNonPagedObject<PublicSseClient>();
#endif
    if (publicClient == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    publicClient->Magic = kPublicSseMagic;

    ::wknet::session::SseConnectOptions apiOptions = {};
    FillSessionConnectOptions(
        *config,
        publicClient,
        headerBuffer.Get(),
        headerCount,
        apiOptions);

    ::wknet::session::SseClientObject* engineClient = nullptr;
    NTSTATUS status = ::wknet::session::SseClientConnectSync(
        session->Engine,
        &apiOptions,
        &engineClient);
    if (!NT_SUCCESS(status)) {
#if defined(WKNET_USER_MODE_TEST)
        free(publicClient);
#else
        ::wknet::FreeNonPagedObject(publicClient);
#endif
        return status;
    }

    publicClient->Engine = engineClient;
    *client = reinterpret_cast<SseClient*>(publicClient);
    return STATUS_SUCCESS;
}

NTSTATUS ConnectAsync(
    wknet::http::Session* session,
    const char* url,
    SIZE_T urlLength,
    wknet::http::AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (session == nullptr || url == nullptr || urlLength == 0 || operation == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    ConnectConfig config = DefaultConnectConfig();
    config.Url = url;
    config.UrlLength = urlLength;
    return ConnectAsyncEx(session, &config, operation);
}

NTSTATUS ConnectAsync(
    wknet::http::Session* session,
    const ConnectConfig* config,
    wknet::http::AsyncOp** operation) noexcept
{
    return ConnectAsyncEx(session, config, operation);
}

NTSTATUS ConnectAsyncEx(
    wknet::http::Session* session,
    const ConnectConfig* config,
    wknet::http::AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (session == nullptr || config == nullptr || operation == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->Url == nullptr || config->UrlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    // Async connect lands with full async worker packaging; M4 ships sync Connect.
    UNREFERENCED_PARAMETER(session);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS AsyncGetSseClient(
    wknet::http::AsyncOp* operation,
    SseClient** client) noexcept
{
    if (client != nullptr) {
        *client = nullptr;
    }
    if (operation == nullptr || client == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS Receive(SseClient* client, Event* event) noexcept
{
    return ReceiveEx(client, nullptr, event);
}

NTSTATUS ReceiveEx(
    SseClient* client,
    const ReceiveOptions* options,
    Event* event) noexcept
{
    if (event != nullptr) {
        *event = {};
    }
    PublicSseClient* publicClient = AsPublic(client);
    if (publicClient == nullptr || publicClient->Engine == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    ::wknet::session::SseEventView view = {};
    NTSTATUS status = ::wknet::session::SseClientReceive(publicClient->Engine, &view);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Event delivered = {};
    delivered.Type = view.Type;
    delivered.TypeLength = view.TypeLength;
    delivered.Data = view.Data;
    delivered.DataLength = view.DataLength;
    delivered.Id = view.Id;
    delivered.IdLength = view.IdLength;

    if (options != nullptr && options->OnEvent != nullptr) {
        status = options->OnEvent(
            options->CallbackContext != nullptr ? options->CallbackContext : publicClient->CallbackContext,
            &delivered);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (event != nullptr) {
        *event = delivered;
    }
    return STATUS_SUCCESS;
}

NTSTATUS GetLastEventId(
    SseClient* client,
    const char** id,
    SIZE_T* idLength) noexcept
{
    if (id != nullptr) {
        *id = nullptr;
    }
    if (idLength != nullptr) {
        *idLength = 0;
    }
    PublicSseClient* publicClient = AsPublic(client);
    if (publicClient == nullptr || publicClient->Engine == nullptr || id == nullptr || idLength == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return ::wknet::session::SseClientGetLastEventId(publicClient->Engine, id, idLength);
}

NTSTATUS GetReconnectAttempt(SseClient* client, ULONG* attempt) noexcept
{
    if (attempt != nullptr) {
        *attempt = 0;
    }
    PublicSseClient* publicClient = AsPublic(client);
    if (publicClient == nullptr || publicClient->Engine == nullptr || attempt == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return ::wknet::session::SseClientGetReconnectAttempt(publicClient->Engine, attempt);
}

NTSTATUS Close(SseClient* client) noexcept
{
    if (client == nullptr) {
        return STATUS_SUCCESS;
    }
    PublicSseClient* publicClient = AsPublic(client);
    if (publicClient == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = ::wknet::session::SseClientClose(publicClient->Engine);
    publicClient->Engine = nullptr;
    publicClient->Magic = 0;
#if defined(WKNET_USER_MODE_TEST)
    free(publicClient);
#else
    ::wknet::FreeNonPagedObject(publicClient);
#endif
    return status;
}
}
