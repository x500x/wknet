#include <wknet/websocket/WebSocket.h>
#include <wknet/http/Detail.h>
#include <wknet/engine/Engine.h>
#include <wknet/http1/HttpTypes.h>

namespace wknet::websocket {
namespace
{
    void FillApiConnectOptions(
        const ConnectConfig& src,
        ::wknet::session::KhWebSocketHeader* headerBuffer,
        SIZE_T headerBufferCount,
        ::wknet::session::KhWebSocketConnectOptions& dst) noexcept
    {
        dst.Url = src.Url;
        dst.UrlLength = src.UrlLength;
        dst.Subprotocol = src.Subprotocol;
        dst.SubprotocolLength = src.SubprotocolLength;
        wknet::http::detail::FillApiTlsOptions(src.Tls, dst.Tls);
        dst.AddressFamily = wknet::http::detail::ToApiAddressFamily(src.Family);
        dst.MaxMessageBytes = src.MaxMessageBytes;
        dst.AutoReplyPing = src.AutoReplyPing;
        dst.AllowWebSocketOverHttp2 = src.AllowWebSocketOverHttp2;
        dst.TransportMode = wknet::http::detail::ToApiWebSocketTransportMode(src.TransportMode);
        dst.PerMessageDeflate = src.PerMessageDeflate;
        dst.ChallengeCallback = src.ChallengeCallback;
        dst.ChallengeContext = src.ChallengeContext;
        dst.MaxHandshakeRetries = src.MaxHandshakeRetries;

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

    // Mirrors session::KhMaxHeadersPerRequest (the engine validates against the same cap).
    constexpr SIZE_T kMaxConnectHeaders = 16;
}

NTSTATUS Connect(wknet::http::Session* session, const char* url, SIZE_T urlLength, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    if (url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ConnectConfig config = DefaultConnectConfig();
    config.Url = url;
    config.UrlLength = urlLength;
    return ConnectEx(session, &config, websocket);
}

NTSTATUS ConnectEx(wknet::http::Session* session, const ConnectConfig* config, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    ::wknet::HeapArray<::wknet::session::KhWebSocketHeader> headerBuffer(kMaxConnectHeaders);
    if (!headerBuffer.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ::wknet::session::KhWebSocketConnectOptions apiOptions = {};
    FillApiConnectOptions(*config, headerBuffer.Get(), headerBuffer.Count(), apiOptions);

    ::wknet::session::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = ::wknet::session::KhWebSocketConnectSync(
        wknet::http::detail::ToApiSession(session),
        &apiOptions,
        &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = wknet::http::detail::FromApiWebSocket(apiWs);
    }
    return status;
}

NTSTATUS Connect(wknet::http::Session* session, const ConnectConfig* config, WebSocket** websocket) noexcept
{
    return ConnectEx(session, config, websocket);
}

NTSTATUS ConnectAsync(wknet::http::Session* session, const char* url, SIZE_T urlLength, wknet::http::AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ConnectConfig config = DefaultConnectConfig();
    config.Url = url;
    config.UrlLength = urlLength;
    return ConnectAsyncEx(session, &config, operation);
}

NTSTATUS ConnectAsyncEx(wknet::http::Session* session, const ConnectConfig* config, wknet::http::AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    ::wknet::HeapArray<::wknet::session::KhWebSocketHeader> headerBuffer(kMaxConnectHeaders);
    if (!headerBuffer.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ::wknet::session::KhWebSocketConnectOptions apiOptions = {};
    FillApiConnectOptions(*config, headerBuffer.Get(), headerBuffer.Count(), apiOptions);

    ::wknet::session::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = ::wknet::session::KhWebSocketConnectAsync(
        wknet::http::detail::ToApiSession(session),
        &apiOptions,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = wknet::http::detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS ConnectAsync(wknet::http::Session* session, const ConnectConfig* config, wknet::http::AsyncOp** operation) noexcept
{
    return ConnectAsyncEx(session, config, operation);
}

NTSTATUS SendText(WebSocket* websocket, const char* text, SIZE_T textLength) noexcept
{
    return ::wknet::session::KhWebSocketSendTextSync(wknet::http::detail::ToApiWebSocket(websocket), text, textLength, nullptr);
}

NTSTATUS SendTextEx(
    WebSocket* websocket,
    const char* text,
    SIZE_T textLength,
    const SendOptions* options) noexcept
{
    ::wknet::session::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return ::wknet::session::KhWebSocketSendTextSync(
        wknet::http::detail::ToApiWebSocket(websocket),
        text,
        textLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS SendBinary(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return ::wknet::session::KhWebSocketSendBinarySync(wknet::http::detail::ToApiWebSocket(websocket), data, dataLength, nullptr);
}

NTSTATUS SendBinaryEx(
    WebSocket* websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const SendOptions* options) noexcept
{
    ::wknet::session::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return ::wknet::session::KhWebSocketSendBinarySync(
        wknet::http::detail::ToApiWebSocket(websocket),
        data,
        dataLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS SendContinuation(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return ::wknet::session::KhWebSocketSendContinuationSync(wknet::http::detail::ToApiWebSocket(websocket), data, dataLength, nullptr);
}

NTSTATUS SendContinuationEx(
    WebSocket* websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const SendOptions* options) noexcept
{
    ::wknet::session::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return ::wknet::session::KhWebSocketSendContinuationSync(
        wknet::http::detail::ToApiWebSocket(websocket),
        data,
        dataLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS SendPing(WebSocket* websocket, const UCHAR* payload, SIZE_T payloadLength) noexcept
{
    return ::wknet::session::KhWebSocketSendPingSync(wknet::http::detail::ToApiWebSocket(websocket), payload, payloadLength);
}

NTSTATUS SendPong(WebSocket* websocket, const UCHAR* payload, SIZE_T payloadLength) noexcept
{
    return ::wknet::session::KhWebSocketSendPongSync(wknet::http::detail::ToApiWebSocket(websocket), payload, payloadLength);
}

NTSTATUS Receive(WebSocket* websocket, Message* message) noexcept
{
    if (message != nullptr) {
        *message = {};
    }
    ::wknet::session::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = ::wknet::session::KhWebSocketReceiveSync(
        wknet::http::detail::ToApiWebSocket(websocket),
        nullptr,
        &apiMessage);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = wknet::http::detail::FromApiWsMsgType(apiMessage.Type);
        message->Data = apiMessage.Data;
        message->DataLength = apiMessage.DataLength;
        message->Final = apiMessage.FinalFragment;
        message->FinalFragment = apiMessage.FinalFragment;
    }
    return status;
}

NTSTATUS ReceiveEx(
    WebSocket* websocket,
    const ReceiveOptions* options,
    Message* message) noexcept
{
    if (message != nullptr) {
        *message = {};
    }

    ::wknet::session::KhWebSocketReceiveOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.MaxMessageBytes = options->MaxMessageBytes;
        apiOptions.AutoAllocate = options->AutoAllocate;
        apiOptions.DeliverFragments = options->DeliverFragments;
        apiOptions.MessageCallback = reinterpret_cast<::wknet::session::KhWebSocketMessageCallback>(options->OnMessage);
        apiOptions.CallbackContext = options->CallbackContext;
    }

    ::wknet::session::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = ::wknet::session::KhWebSocketReceiveSync(
        wknet::http::detail::ToApiWebSocket(websocket),
        options != nullptr ? &apiOptions : nullptr,
        message != nullptr ? &apiMessage : nullptr);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = wknet::http::detail::FromApiWsMsgType(apiMessage.Type);
        message->Data = apiMessage.Data;
        message->DataLength = apiMessage.DataLength;
        message->Final = apiMessage.FinalFragment;
        message->FinalFragment = apiMessage.FinalFragment;
    }
    return status;
}

NTSTATUS Close(WebSocket* websocket) noexcept
{
    return ::wknet::session::KhWebSocketCloseSync(wknet::http::detail::ToApiWebSocket(websocket));
}

NTSTATUS CloseEx(
    WebSocket* websocket,
    USHORT statusCode,
    const UCHAR* reason,
    SIZE_T reasonLength) noexcept
{
    return ::wknet::session::KhWebSocketCloseExSync(
        wknet::http::detail::ToApiWebSocket(websocket),
        statusCode,
        reason,
        reasonLength);
}

NTSTATUS SelectedSubprotocol(
    WebSocket* websocket,
    const char** subprotocol,
    SIZE_T* subprotocolLength) noexcept
{
    return ::wknet::session::KhWebSocketSelectedSubprotocol(
        wknet::http::detail::ToApiWebSocket(websocket),
        subprotocol,
        subprotocolLength);
}

NTSTATUS AsyncGetWebSocket(wknet::http::AsyncOp* operation, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    ::wknet::session::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = ::wknet::session::KhAsyncGetWebSocket(wknet::http::detail::ToApiAsyncOp(operation), &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = wknet::http::detail::FromApiWebSocket(apiWs);
    }
    return status;
}
}
