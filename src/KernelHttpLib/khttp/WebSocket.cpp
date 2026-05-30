#include <KernelHttp/khttp/WebSocket.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace KernelHttp
{
namespace khttp
{
namespace
{
    void FillApiWsConnectOptions(
        const WsConnectConfig& src,
        engine::KhWebSocketConnectOptions& dst) noexcept
    {
        dst.Url = src.Url;
        dst.UrlLength = src.UrlLength;
        dst.Subprotocol = src.Subprotocol;
        dst.SubprotocolLength = src.SubprotocolLength;
        detail::FillApiTlsOptions(src.Tls, dst.Tls);
        dst.AddressFamily = detail::ToApiAddressFamily(src.Family);
        dst.MaxMessageBytes = src.MaxMessageBytes;
        dst.AutoReplyPing = src.AutoReplyPing;
    }
}

NTSTATUS WsConnect(Session* session, const char* url, SIZE_T urlLength, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    if (url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    WsConnectConfig config = DefaultWsConnectConfig();
    config.Url = url;
    config.UrlLength = urlLength;
    return WsConnectEx(session, &config, websocket);
}

NTSTATUS WsConnectEx(Session* session, const WsConnectConfig* config, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    engine::KhWebSocketConnectOptions apiOptions = {};
    FillApiWsConnectOptions(*config, apiOptions);

    engine::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = engine::KhWebSocketConnectSync(
        detail::ToApiSession(session),
        &apiOptions,
        &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = detail::FromApiWebSocket(apiWs);
    }
    return status;
}

NTSTATUS WsConnect(Session* session, const WsConnectConfig* config, WebSocket** websocket) noexcept
{
    return WsConnectEx(session, config, websocket);
}

NTSTATUS WsConnectAsync(Session* session, const char* url, SIZE_T urlLength, AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    WsConnectConfig config = DefaultWsConnectConfig();
    config.Url = url;
    config.UrlLength = urlLength;
    return WsConnectAsyncEx(session, &config, operation);
}

NTSTATUS WsConnectAsyncEx(Session* session, const WsConnectConfig* config, AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    engine::KhWebSocketConnectOptions apiOptions = {};
    FillApiWsConnectOptions(*config, apiOptions);

    engine::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = engine::KhWebSocketConnectAsync(
        detail::ToApiSession(session),
        &apiOptions,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS WsConnectAsync(Session* session, const WsConnectConfig* config, AsyncOp** operation) noexcept
{
    return WsConnectAsyncEx(session, config, operation);
}

NTSTATUS WsSendText(WebSocket* websocket, const char* text, SIZE_T textLength) noexcept
{
    return engine::KhWebSocketSendTextSync(detail::ToApiWebSocket(websocket), text, textLength, nullptr);
}

NTSTATUS WsSendTextEx(
    WebSocket* websocket,
    const char* text,
    SIZE_T textLength,
    const WsSendOptions* options) noexcept
{
    engine::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return engine::KhWebSocketSendTextSync(
        detail::ToApiWebSocket(websocket),
        text,
        textLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS WsSendBinary(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return engine::KhWebSocketSendBinarySync(detail::ToApiWebSocket(websocket), data, dataLength, nullptr);
}

NTSTATUS WsSendBinaryEx(
    WebSocket* websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const WsSendOptions* options) noexcept
{
    engine::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return engine::KhWebSocketSendBinarySync(
        detail::ToApiWebSocket(websocket),
        data,
        dataLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS WsReceive(WebSocket* websocket, WsMessage* message) noexcept
{
    if (message != nullptr) {
        *message = {};
    }
    engine::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = engine::KhWebSocketReceiveSync(
        detail::ToApiWebSocket(websocket),
        nullptr,
        &apiMessage);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = detail::FromApiWsMsgType(apiMessage.Type);
        message->Data = apiMessage.Data;
        message->DataLength = apiMessage.DataLength;
        message->Final = apiMessage.FinalFragment;
        message->FinalFragment = apiMessage.FinalFragment;
    }
    return status;
}

NTSTATUS WsReceiveEx(
    WebSocket* websocket,
    const WsReceiveOptions* options,
    WsMessage* message) noexcept
{
    if (message != nullptr) {
        *message = {};
    }

    engine::KhWebSocketReceiveOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.MaxMessageBytes = options->MaxMessageBytes;
        apiOptions.AutoAllocate = options->AutoAllocate;
        apiOptions.MessageCallback = reinterpret_cast<engine::KhWebSocketMessageCallback>(options->OnMessage);
        apiOptions.CallbackContext = options->CallbackContext;
    }

    engine::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = engine::KhWebSocketReceiveSync(
        detail::ToApiWebSocket(websocket),
        options != nullptr ? &apiOptions : nullptr,
        message != nullptr ? &apiMessage : nullptr);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = detail::FromApiWsMsgType(apiMessage.Type);
        message->Data = apiMessage.Data;
        message->DataLength = apiMessage.DataLength;
        message->Final = apiMessage.FinalFragment;
        message->FinalFragment = apiMessage.FinalFragment;
    }
    return status;
}

NTSTATUS WsClose(WebSocket* websocket) noexcept
{
    return engine::KhWebSocketCloseSync(detail::ToApiWebSocket(websocket));
}
}
}
