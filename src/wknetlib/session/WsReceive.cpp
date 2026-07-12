#include "session/WsEngineInternal.hpp"

namespace wknet
{
namespace session
{
    NTSTATUS WebSocketReceiveSyncImpl(
        WebSocketHandle websocket,
        const WebSocketReceiveOptions* options,
        WebSocketMessage* message) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (message != nullptr) {
            *message = {};
        }

        WebSocketOperationScope operation(websocket);
        if (!operation.IsActive()) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        WebSocketReceiveOptions effectiveOptions = {};
        effectiveOptions.AutoAllocate = true;
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidReceiveOptions(effectiveOptions)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (effectiveOptions.AutoAllocate && message == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketReceive == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        TestWebSocketMessage received = {};
        status = g_testWebSocketReceive(g_testWebSocketTransportContext, websocket, &received);
        if (!NT_SUCCESS(status)) {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
            return status;
        }

        if (received.Data == nullptr && received.DataLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T maxMessageBytes = websocket->MaxMessageBytes;
        if (effectiveOptions.MaxMessageBytes != 0 &&
            effectiveOptions.MaxMessageBytes < maxMessageBytes) {
            maxMessageBytes = effectiveOptions.MaxMessageBytes;
        }
        if (received.DataLength > maxMessageBytes) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (effectiveOptions.MessageCallback != nullptr) {
            status = effectiveOptions.MessageCallback(
                effectiveOptions.CallbackContext,
                received.Type,
                received.Data,
                received.DataLength,
                received.FinalFragment);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (effectiveOptions.AutoAllocate) {
            status = StoreWebSocketMessage(*websocket, received.Type, received.Data, received.DataLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message->Type = websocket->LastMessageType;
            message->Data = websocket->LastMessage;
            message->DataLength = websocket->LastMessageLength;
            message->FinalFragment = received.FinalFragment;
        }

        if (received.Type == WebSocketMessageType::Close) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        return STATUS_SUCCESS;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        SIZE_T maxMessageBytes = websocket->MaxMessageBytes;
        if (effectiveOptions.MaxMessageBytes != 0 &&
            effectiveOptions.MaxMessageBytes < maxMessageBytes) {
            maxMessageBytes = effectiveOptions.MaxMessageBytes;
        }
        if (websocket->Workspace == nullptr ||
            websocket->Workspace->WebSocketFrameScratch.Data == nullptr ||
            websocket->Workspace->WebSocketFrameScratch.Length < WorkspaceWebSocketFrameScratchBytes ||
            websocket->Workspace->WebSocketPayloadScratch.Data == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (websocket->Workspace->WebSocketPayloadScratch.Length < maxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        MutexScope receiveLock(&websocket->ReceiveLock);
        session::WsIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Workspace->WebSocketFrameScratch.Length;
        wknet::ws::WebSocketOpcode opcode = wknet::ws::WebSocketOpcode::Continuation;
        SIZE_T bytesReceived = 0;
        bool finalFragment = true;
        status = websocket->Client->ReceiveMessage(
            buffers,
            &opcode,
            websocket->Workspace->WebSocketPayloadScratch.Data,
            maxMessageBytes,
            &bytesReceived,
            websocket->AutoReplyPing,
            effectiveOptions.DeliverFragments,
            &finalFragment);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentWs, ::wknet::TraceLevel::Error, "ws.message.receive_failed status=0x%08X",
                static_cast<ULONG>(status));
            if (status == STATUS_BUFFER_TOO_SMALL || IsWebSocketTransportTerminalStatus(status)) {
                const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
                UNREFERENCED_PARAMETER(closeStatus);
            }
            return status;
        }

        WebSocketMessageType type = WebSocketMessageType::Binary;
        if (opcode == wknet::ws::WebSocketOpcode::Text) {
            type = WebSocketMessageType::Text;
        }
        else if (opcode == wknet::ws::WebSocketOpcode::Close) {
            type = WebSocketMessageType::Close;
        }
        else if (opcode == wknet::ws::WebSocketOpcode::Ping) {
            type = WebSocketMessageType::Ping;
        }
        else if (opcode == wknet::ws::WebSocketOpcode::Pong) {
            type = WebSocketMessageType::Pong;
        }
        else if (opcode == wknet::ws::WebSocketOpcode::Continuation) {
            type = WebSocketMessageType::Continuation;
        }

        const UCHAR* data = websocket->Workspace->WebSocketPayloadScratch.Data;
        if (effectiveOptions.MessageCallback != nullptr) {
            status = effectiveOptions.MessageCallback(
                effectiveOptions.CallbackContext,
                type,
                data,
                bytesReceived,
                finalFragment);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (effectiveOptions.AutoAllocate) {
            status = StoreWebSocketMessage(*websocket, type, data, bytesReceived);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message->Type = websocket->LastMessageType;
            message->Data = websocket->LastMessage;
            message->DataLength = websocket->LastMessageLength;
            message->FinalFragment = finalFragment;
        }

        if (type == WebSocketMessageType::Close) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        return STATUS_SUCCESS;
#endif
    }


}
}
