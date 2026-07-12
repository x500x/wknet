NTSTATUS WebSocketConnectSync(
    SessionHandle session,
    const WebSocketConnectOptions* options,
    WebSocketHandle* websocket) noexcept
{
    return WebSocketConnectSyncImpl(session, options, websocket);
}

NTSTATUS WebSocketConnectAsync(
    SessionHandle session,
    const WebSocketConnectOptions* options,
    AsyncOperationHandle* operation) noexcept
{
    return WebSocketConnectAsyncImpl(session, options, operation);
}

NTSTATUS WebSocketSendTextSync(
    WebSocketHandle websocket,
    const char* text,
    SIZE_T textLength,
    const WebSocketSendOptions* options) noexcept
{
    return WebSocketSendTextSyncImpl(websocket, text, textLength, options);
}

NTSTATUS WebSocketSendBinarySync(
    WebSocketHandle websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const WebSocketSendOptions* options) noexcept
{
    return WebSocketSendBinarySyncImpl(websocket, data, dataLength, options);
}

NTSTATUS WebSocketSendContinuationSync(
    WebSocketHandle websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const WebSocketSendOptions* options) noexcept
{
    return WebSocketSendContinuationSyncImpl(websocket, data, dataLength, options);
}

NTSTATUS WebSocketSendPingSync(
    WebSocketHandle websocket,
    const UCHAR* payload,
    SIZE_T payloadLength) noexcept
{
    return WebSocketSendPingSyncImpl(websocket, payload, payloadLength);
}

NTSTATUS WebSocketSendPongSync(
    WebSocketHandle websocket,
    const UCHAR* payload,
    SIZE_T payloadLength) noexcept
{
    return WebSocketSendPongSyncImpl(websocket, payload, payloadLength);
}

NTSTATUS WebSocketReceiveSync(
    WebSocketHandle websocket,
    const WebSocketReceiveOptions* options,
    WebSocketMessage* message) noexcept
{
    return WebSocketReceiveSyncImpl(websocket, options, message);
}

NTSTATUS WebSocketCloseSync(WebSocketHandle websocket) noexcept
{
    return WebSocketCloseSyncImpl(websocket);
}

NTSTATUS WebSocketCloseExSync(
    WebSocketHandle websocket,
    USHORT statusCode,
    const UCHAR* reason,
    SIZE_T reasonLength) noexcept
{
    return WebSocketCloseExSyncImpl(websocket, statusCode, reason, reasonLength);
}
