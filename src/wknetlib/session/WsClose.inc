    NTSTATUS WebSocketCloseSyncImpl(WebSocketHandle websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket == nullptr) {
            return STATUS_SUCCESS;
        }

        if (!TryCloseActiveWebSocketHandle(websocket)) {
            return STATUS_INVALID_PARAMETER;
        }

        WaitForWebSocketDrain(websocket);

        const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
        UNREFERENCED_PARAMETER(closeStatus);
        ReleaseWebSocketStorage(*websocket);
        FreeHandle(websocket);
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketCloseExSyncImpl(
        WebSocketHandle websocket,
        USHORT statusCode,
        const UCHAR* reason,
        SIZE_T reasonLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsValidWebSocketCloseStatus(statusCode) ||
            (reason == nullptr && reasonLength != 0) ||
            reasonLength > ws::WebSocketMaxControlPayloadLength - 2 ||
            !IsValidWebSocketUtf8(reason, reasonLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (websocket == nullptr) {
            return STATUS_SUCCESS;
        }

        if (!TryCloseActiveWebSocketHandle(websocket)) {
            return STATUS_INVALID_PARAMETER;
        }

        WaitForWebSocketDrain(websocket);

        HeapArray<UCHAR> closePayload(2 + reasonLength);
        if (!closePayload.IsValid()) {
            ReleaseWebSocketStorage(*websocket);
            FreeHandle(websocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        closePayload[0] = static_cast<UCHAR>((statusCode >> 8) & 0xff);
        closePayload[1] = static_cast<UCHAR>(statusCode & 0xff);
        if (reasonLength != 0) {
            RtlCopyMemory(closePayload.Get() + 2, reason, reasonLength);
        }

        status = STATUS_SUCCESS;
#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketSend != nullptr && websocket->Connected) {
            status = g_testWebSocketSend(
                g_testWebSocketTransportContext,
                websocket,
                WebSocketMessageType::Close,
                closePayload.Get(),
                closePayload.Count(),
                true);
        }
        const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
        UNREFERENCED_PARAMETER(closeStatus);
#endif
#if !defined(WKNET_USER_MODE_TEST)
        if (websocket->Client != nullptr) {
            session::WsIoBuffers buffers = {};
            if (!TryUseWebSocketSendFrameScratch(*websocket, buffers)) {
                status = STATUS_INVALID_DEVICE_STATE;
            }
            else {
                status = websocket->Client->Close(statusCode, reason, reasonLength, buffers);
            }
        }
        const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
        if (NT_SUCCESS(status)) {
            status = closeStatus;
        }
#endif
        ReleaseWebSocketStorage(*websocket);
        FreeHandle(websocket);
        return status;
    }

    NTSTATUS WebSocketSelectedSubprotocol(
        WebSocketHandle websocket,
        const char** subprotocol,
        SIZE_T* subprotocolLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (subprotocol != nullptr) {
            *subprotocol = nullptr;
        }
        if (subprotocolLength != nullptr) {
            *subprotocolLength = 0;
        }

        WebSocketOperationScope operation(websocket);
        if (!operation.IsActive() ||
            subprotocol == nullptr ||
            subprotocolLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (websocket->Subprotocol == nullptr || websocket->SubprotocolLength == 0) {
            return STATUS_NOT_FOUND;
        }

        *subprotocol = websocket->Subprotocol;
        *subprotocolLength = websocket->SubprotocolLength;
        return STATUS_SUCCESS;
    }


