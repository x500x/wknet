    NTSTATUS WebSocketSendTextSyncImpl(
        WebSocketHandle websocket,
        const char* text,
        SIZE_T textLength,
        const WebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        WebSocketOperationScope operation(websocket);
        if (!operation.IsActive() || (text == nullptr && textLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        if (websocket->SendFragmentOpen) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (textLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG nextCodePoint = 0;
        UCHAR nextRemaining = 0;
        UCHAR nextExpected = 0;
        status = ValidateWebSocketOutgoingText(
            *websocket,
            WebSocketMessageType::Text,
            reinterpret_cast<const UCHAR*>(text),
            textLength,
            finalFragment,
            &nextCodePoint,
            &nextRemaining,
            &nextExpected);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            WebSocketMessageType::Text,
            reinterpret_cast<const UCHAR*>(text),
            textLength,
            finalFragment);
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                WebSocketMessageType::Text,
                textLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        MutexScope sendLock(&websocket->SendLock);
        client::WebSocketIoBuffers buffers = {};
        if (!TryUseWebSocketSendFrameScratch(*websocket, buffers)) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        status = websocket->Client->SendText(text, textLength, buffers, finalFragment);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("WebSocketSendTextSync Client->SendText failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                WebSocketMessageType::Text,
                textLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

    NTSTATUS WebSocketSendBinarySyncImpl(
        WebSocketHandle websocket,
        const UCHAR* data,
        SIZE_T dataLength,
        const WebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        WebSocketOperationScope operation(websocket);
        if (!operation.IsActive() || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        if (websocket->SendFragmentOpen) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (dataLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG nextCodePoint = 0;
        UCHAR nextRemaining = 0;
        UCHAR nextExpected = 0;
        status = ValidateWebSocketOutgoingText(
            *websocket,
            WebSocketMessageType::Binary,
            data,
            dataLength,
            finalFragment,
            &nextCodePoint,
            &nextRemaining,
            &nextExpected);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            WebSocketMessageType::Binary,
            data,
            dataLength,
            finalFragment);
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                WebSocketMessageType::Binary,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        MutexScope sendLock(&websocket->SendLock);
        client::WebSocketIoBuffers buffers = {};
        if (!TryUseWebSocketSendFrameScratch(*websocket, buffers)) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        status = websocket->Client->SendBinary(data, dataLength, buffers, finalFragment);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("WebSocketSendBinarySync Client->SendBinary failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                WebSocketMessageType::Binary,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

    NTSTATUS WebSocketSendContinuationSyncImpl(
        WebSocketHandle websocket,
        const UCHAR* data,
        SIZE_T dataLength,
        const WebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        WebSocketOperationScope operation(websocket);
        if (!operation.IsActive() || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        if (!websocket->SendFragmentOpen) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (websocket->SendFragmentLength > websocket->MaxMessageBytes ||
            dataLength > websocket->MaxMessageBytes - websocket->SendFragmentLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG nextCodePoint = 0;
        UCHAR nextRemaining = 0;
        UCHAR nextExpected = 0;
        status = ValidateWebSocketOutgoingText(
            *websocket,
            WebSocketMessageType::Continuation,
            data,
            dataLength,
            finalFragment,
            &nextCodePoint,
            &nextRemaining,
            &nextExpected);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            WebSocketMessageType::Continuation,
            data,
            dataLength,
            finalFragment);
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                WebSocketMessageType::Continuation,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        MutexScope sendLock(&websocket->SendLock);
        client::WebSocketIoBuffers buffers = {};
        if (!TryUseWebSocketSendFrameScratch(*websocket, buffers)) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        status = websocket->Client->SendContinuation(data, dataLength, buffers, finalFragment);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("WebSocketSendContinuationSync Client->SendContinuation failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                WebSocketMessageType::Continuation,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

