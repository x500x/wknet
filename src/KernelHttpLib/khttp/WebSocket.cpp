#include <KernelHttp/kws/WebSocket.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>
#include <KernelHttp/http/HttpTypes.h>

namespace kws
{
namespace
{
    void FillApiConnectOptions(
        const ConnectConfig& src,
        ::KernelHttp::engine::KhWebSocketHeader* headerBuffer,
        SIZE_T headerBufferCount,
        ::KernelHttp::engine::KhWebSocketConnectOptions& dst) noexcept
    {
        dst.Url = src.Url;
        dst.UrlLength = src.UrlLength;
        dst.Subprotocol = src.Subprotocol;
        dst.SubprotocolLength = src.SubprotocolLength;
        khttp::detail::FillApiTlsOptions(src.Tls, dst.Tls);
        dst.AddressFamily = khttp::detail::ToApiAddressFamily(src.Family);
        dst.MaxMessageBytes = src.MaxMessageBytes;
        dst.AutoReplyPing = src.AutoReplyPing;
        dst.AllowWebSocketOverHttp2 = src.AllowWebSocketOverHttp2;

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

    // Mirrors engine::KhMaxHeadersPerRequest (the engine validates against the same cap).
    constexpr SIZE_T kMaxConnectHeaders = 16;
}

NTSTATUS Connect(khttp::Session* session, const char* url, SIZE_T urlLength, WebSocket** websocket) noexcept
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

NTSTATUS ConnectEx(khttp::Session* session, const ConnectConfig* config, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    ::KernelHttp::HeapArray<::KernelHttp::engine::KhWebSocketHeader> headerBuffer(kMaxConnectHeaders);
    if (!headerBuffer.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ::KernelHttp::engine::KhWebSocketConnectOptions apiOptions = {};
    FillApiConnectOptions(*config, headerBuffer.Get(), headerBuffer.Count(), apiOptions);

    ::KernelHttp::engine::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = ::KernelHttp::engine::KhWebSocketConnectSync(
        khttp::detail::ToApiSession(session),
        &apiOptions,
        &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = khttp::detail::FromApiWebSocket(apiWs);
    }
    return status;
}

NTSTATUS Connect(khttp::Session* session, const ConnectConfig* config, WebSocket** websocket) noexcept
{
    return ConnectEx(session, config, websocket);
}

NTSTATUS ConnectAsync(khttp::Session* session, const char* url, SIZE_T urlLength, khttp::AsyncOp** operation) noexcept
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

NTSTATUS ConnectAsyncEx(khttp::Session* session, const ConnectConfig* config, khttp::AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    ::KernelHttp::HeapArray<::KernelHttp::engine::KhWebSocketHeader> headerBuffer(kMaxConnectHeaders);
    if (!headerBuffer.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ::KernelHttp::engine::KhWebSocketConnectOptions apiOptions = {};
    FillApiConnectOptions(*config, headerBuffer.Get(), headerBuffer.Count(), apiOptions);

    ::KernelHttp::engine::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = ::KernelHttp::engine::KhWebSocketConnectAsync(
        khttp::detail::ToApiSession(session),
        &apiOptions,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = khttp::detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS ConnectAsync(khttp::Session* session, const ConnectConfig* config, khttp::AsyncOp** operation) noexcept
{
    return ConnectAsyncEx(session, config, operation);
}

NTSTATUS SendText(WebSocket* websocket, const char* text, SIZE_T textLength) noexcept
{
    return ::KernelHttp::engine::KhWebSocketSendTextSync(khttp::detail::ToApiWebSocket(websocket), text, textLength, nullptr);
}

NTSTATUS SendTextEx(
    WebSocket* websocket,
    const char* text,
    SIZE_T textLength,
    const SendOptions* options) noexcept
{
    ::KernelHttp::engine::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return ::KernelHttp::engine::KhWebSocketSendTextSync(
        khttp::detail::ToApiWebSocket(websocket),
        text,
        textLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS SendBinary(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return ::KernelHttp::engine::KhWebSocketSendBinarySync(khttp::detail::ToApiWebSocket(websocket), data, dataLength, nullptr);
}

NTSTATUS SendBinaryEx(
    WebSocket* websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const SendOptions* options) noexcept
{
    ::KernelHttp::engine::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return ::KernelHttp::engine::KhWebSocketSendBinarySync(
        khttp::detail::ToApiWebSocket(websocket),
        data,
        dataLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS SendContinuation(WebSocket* websocket, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return ::KernelHttp::engine::KhWebSocketSendContinuationSync(khttp::detail::ToApiWebSocket(websocket), data, dataLength, nullptr);
}

NTSTATUS SendContinuationEx(
    WebSocket* websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const SendOptions* options) noexcept
{
    ::KernelHttp::engine::KhWebSocketSendOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.FinalFragment = options->FinalFragment;
    }
    return ::KernelHttp::engine::KhWebSocketSendContinuationSync(
        khttp::detail::ToApiWebSocket(websocket),
        data,
        dataLength,
        options != nullptr ? &apiOptions : nullptr);
}

NTSTATUS SendPing(WebSocket* websocket, const UCHAR* payload, SIZE_T payloadLength) noexcept
{
    return ::KernelHttp::engine::KhWebSocketSendPingSync(khttp::detail::ToApiWebSocket(websocket), payload, payloadLength);
}

NTSTATUS SendPong(WebSocket* websocket, const UCHAR* payload, SIZE_T payloadLength) noexcept
{
    return ::KernelHttp::engine::KhWebSocketSendPongSync(khttp::detail::ToApiWebSocket(websocket), payload, payloadLength);
}

NTSTATUS Receive(WebSocket* websocket, Message* message) noexcept
{
    if (message != nullptr) {
        *message = {};
    }
    ::KernelHttp::engine::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = ::KernelHttp::engine::KhWebSocketReceiveSync(
        khttp::detail::ToApiWebSocket(websocket),
        nullptr,
        &apiMessage);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = khttp::detail::FromApiWsMsgType(apiMessage.Type);
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

    ::KernelHttp::engine::KhWebSocketReceiveOptions apiOptions = {};
    if (options != nullptr) {
        apiOptions.MaxMessageBytes = options->MaxMessageBytes;
        apiOptions.AutoAllocate = options->AutoAllocate;
        apiOptions.DeliverFragments = options->DeliverFragments;
        apiOptions.MessageCallback = reinterpret_cast<::KernelHttp::engine::KhWebSocketMessageCallback>(options->OnMessage);
        apiOptions.CallbackContext = options->CallbackContext;
    }

    ::KernelHttp::engine::KhWebSocketMessage apiMessage = {};
    NTSTATUS status = ::KernelHttp::engine::KhWebSocketReceiveSync(
        khttp::detail::ToApiWebSocket(websocket),
        options != nullptr ? &apiOptions : nullptr,
        message != nullptr ? &apiMessage : nullptr);
    if (NT_SUCCESS(status) && message != nullptr) {
        message->Type = khttp::detail::FromApiWsMsgType(apiMessage.Type);
        message->Data = apiMessage.Data;
        message->DataLength = apiMessage.DataLength;
        message->Final = apiMessage.FinalFragment;
        message->FinalFragment = apiMessage.FinalFragment;
    }
    return status;
}

NTSTATUS Close(WebSocket* websocket) noexcept
{
    return ::KernelHttp::engine::KhWebSocketCloseSync(khttp::detail::ToApiWebSocket(websocket));
}

NTSTATUS CloseEx(
    WebSocket* websocket,
    USHORT statusCode,
    const UCHAR* reason,
    SIZE_T reasonLength) noexcept
{
    return ::KernelHttp::engine::KhWebSocketCloseExSync(
        khttp::detail::ToApiWebSocket(websocket),
        statusCode,
        reason,
        reasonLength);
}

NTSTATUS SelectedSubprotocol(
    WebSocket* websocket,
    const char** subprotocol,
    SIZE_T* subprotocolLength) noexcept
{
    return ::KernelHttp::engine::KhWebSocketSelectedSubprotocol(
        khttp::detail::ToApiWebSocket(websocket),
        subprotocol,
        subprotocolLength);
}

NTSTATUS AsyncGetWebSocket(khttp::AsyncOp* operation, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    ::KernelHttp::engine::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = ::KernelHttp::engine::KhAsyncGetWebSocket(khttp::detail::ToApiAsyncOp(operation), &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = khttp::detail::FromApiWebSocket(apiWs);
    }
    return status;
}
}
