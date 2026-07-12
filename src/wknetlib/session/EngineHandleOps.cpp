#include "session/EnginePrivate.hpp"

namespace wknet
{
namespace session
{
    bool IsSessionHandle(SessionHandle session) noexcept
    {
        return IsActiveHandle(ToHandleHeader(session), HandleKind::Session);
    }

    bool IsRequestHandle(RequestHandle request) noexcept
    {
        return IsActiveHandle(ToHandleHeader(request), HandleKind::Request);
    }

    bool IsResponseHandle(ResponseHandle response) noexcept
    {
        return IsActiveHandle(ToHandleHeader(response), HandleKind::Response);
    }

    bool IsWebSocketHandle(WebSocketHandle websocket) noexcept
    {
        return IsActiveHandle(ToHandleHeader(websocket), HandleKind::WebSocket);
    }

    NTSTATUS RegisterActiveSessionHandle(SessionHandle session) noexcept
    {
        return RegisterActiveHandle(ToHandleHeader(session), HandleKind::Session);
    }

    NTSTATUS RegisterActiveRequestHandle(RequestHandle request) noexcept
    {
        return RegisterActiveHandle(ToHandleHeader(request), HandleKind::Request);
    }

    NTSTATUS RegisterActiveResponseHandle(ResponseHandle response) noexcept
    {
        return RegisterActiveHandle(ToHandleHeader(response), HandleKind::Response);
    }

    NTSTATUS RegisterActiveWebSocketHandle(WebSocketHandle websocket) noexcept
    {
        return RegisterActiveHandle(ToHandleHeader(websocket), HandleKind::WebSocket);
    }

    bool TryCloseActiveSessionHandle(SessionHandle session) noexcept
    {
        return TryCloseActiveHandle(ToHandleHeader(session), HandleKind::Session);
    }

    bool TryCloseActiveRequestHandle(RequestHandle request) noexcept
    {
        return TryCloseActiveHandle(ToHandleHeader(request), HandleKind::Request);
    }

    bool TryCloseActiveResponseHandle(ResponseHandle response) noexcept
    {
        return TryCloseActiveHandle(ToHandleHeader(response), HandleKind::Response);
    }

    bool TryCloseActiveWebSocketHandle(WebSocketHandle websocket) noexcept
    {
        return TryCloseActiveHandle(ToHandleHeader(websocket), HandleKind::WebSocket);
    }

    bool SessionBeginOperation(SessionHandle session) noexcept
    {
        return BeginHandleOperation(ToHandleHeader(session), HandleKind::Session);
    }

    void SessionEndOperation(SessionHandle session) noexcept
    {
        if (session == nullptr || session->Header.Kind != HandleKind::Session) {
            return;
        }

        EndHandleOperation(
            ToHandleHeader(session),
            HandleKind::Session,
            &session->InFlight
#if !defined(WKNET_USER_MODE_TEST)
            ,
            &session->DrainEvent
#endif
            );
    }

    bool RequestBeginOperation(RequestHandle request) noexcept
    {
        return BeginHandleOperation(ToHandleHeader(request), HandleKind::Request);
    }

    void RequestEndOperation(RequestHandle request) noexcept
    {
        if (request == nullptr || request->Header.Kind != HandleKind::Request) {
            return;
        }

        EndHandleOperation(
            ToHandleHeader(request),
            HandleKind::Request,
            &request->InFlight
#if !defined(WKNET_USER_MODE_TEST)
            ,
            &request->DrainEvent
#endif
            );
    }

    bool ResponseBeginOperation(ResponseHandle response) noexcept
    {
        return BeginHandleOperation(ToHandleHeader(response), HandleKind::Response);
    }

    void ResponseEndOperation(ResponseHandle response) noexcept
    {
        if (response == nullptr || response->Header.Kind != HandleKind::Response) {
            return;
        }

        EndHandleOperation(
            ToHandleHeader(response),
            HandleKind::Response,
            &response->InFlight
#if !defined(WKNET_USER_MODE_TEST)
            ,
            &response->DrainEvent
#endif
            );
    }

    bool WebSocketBeginOperation(WebSocketHandle websocket) noexcept
    {
        return BeginHandleOperation(ToHandleHeader(websocket), HandleKind::WebSocket);
    }

    void WaitForSessionDrain(SessionHandle session) noexcept
    {
        if (session == nullptr) {
            return;
        }

        WaitForHandleDrain(
            &session->InFlight
#if !defined(WKNET_USER_MODE_TEST)
            ,
            &session->DrainEvent
#endif
            );
    }

    void WaitForRequestDrain(RequestHandle request) noexcept
    {
        if (request == nullptr) {
            return;
        }

        WaitForHandleDrain(
            &request->InFlight
#if !defined(WKNET_USER_MODE_TEST)
            ,
            &request->DrainEvent
#endif
            );
    }

    void WaitForResponseDrain(ResponseHandle response) noexcept
    {
        if (response == nullptr) {
            return;
        }

        WaitForHandleDrain(
            &response->InFlight
#if !defined(WKNET_USER_MODE_TEST)
            ,
            &response->DrainEvent
#endif
            );
    }


}
}
