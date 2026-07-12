    NTSTATUS WebSocketSendControlSyncImpl(
        WebSocketHandle websocket,
        WebSocketMessageType type,
        const UCHAR* payload,
        SIZE_T payloadLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (type != WebSocketMessageType::Ping &&
            type != WebSocketMessageType::Pong) {
            return STATUS_INVALID_PARAMETER;
        }

        WebSocketOperationScope operation(websocket);
        if (!operation.IsActive() ||
            (payload == nullptr && payloadLength != 0) ||
            payloadLength > ws::WebSocketMaxControlPayloadLength) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            type,
            payload,
            payloadLength,
            true);
        if (!NT_SUCCESS(status)) {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        MutexScope sendLock(&websocket->SendLock);
        session::WsIoBuffers buffers = {};
        if (!TryUseWebSocketSendFrameScratch(*websocket, buffers)) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (type == WebSocketMessageType::Ping) {
            status = websocket->Client->SendPing(payload, payloadLength, buffers);
        }
        else {
            status = websocket->Client->SendPong(payload, payloadLength, buffers);
        }
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("WebSocketSendControlSync Client->SendControl failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

    NTSTATUS WebSocketSendPingSyncImpl(
        WebSocketHandle websocket,
        const UCHAR* payload,
        SIZE_T payloadLength) noexcept
    {
        return WebSocketSendControlSyncImpl(
            websocket,
            WebSocketMessageType::Ping,
            payload,
            payloadLength);
    }

    NTSTATUS WebSocketSendPongSyncImpl(
        WebSocketHandle websocket,
        const UCHAR* payload,
        SIZE_T payloadLength) noexcept
    {
        return WebSocketSendControlSyncImpl(
            websocket,
            WebSocketMessageType::Pong,
            payload,
            payloadLength);
    }

