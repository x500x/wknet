#include "session/WsEngineInternal.hpp"

namespace wknet
{
namespace session
{
    NTSTATUS AsyncGetWebSocket(AsyncOperationHandle operation, WebSocketHandle* websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        if (!AsyncOperationIsValid(operation) ||
            websocket == nullptr ||
            AsyncOperationGetKind(operation) != AsyncOperationKind::WebSocketConnect) {
            return STATUS_INVALID_PARAMETER;
        }

        status = AsyncOperationStatus(operation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* context = static_cast<AsyncWebSocketConnectContext*>(AsyncOperationContext(operation));
        WebSocketHandle asyncWebSocket = TakeAsyncWebSocketConnectResult(context);
        if (asyncWebSocket == nullptr) {
            return STATUS_NOT_FOUND;
        }

        *websocket = asyncWebSocket;
        return STATUS_SUCCESS;
    }




}
}
