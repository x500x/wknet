#include "transport/TransportPrivate.hpp"

#include "net/WskSocket.h"

namespace wknet::transport {
namespace
{
    struct WskTransportContext final
    {
        net::WskSocket* Socket = nullptr;
        net::WskCancellationToken Cancellation = {};
    };

    const net::WskCancellationToken* CancellationOrNull(WskTransportContext* state) noexcept
    {
        return state != nullptr && state->Cancellation.IsCancellationRequested != nullptr
            ? &state->Cancellation
            : nullptr;
    }

    NTSTATUS Send(void* context, const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
    {
        auto* state = static_cast<WskTransportContext*>(context);
        return state == nullptr || state->Socket == nullptr
            ? STATUS_INVALID_DEVICE_STATE
            : net::WskSocketSend(
                state->Socket, data, length, bytesSent, WSK_FLAG_NODELAY, CancellationOrNull(state));
    }

    NTSTATUS Receive(void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
    {
        auto* state = static_cast<WskTransportContext*>(context);
        return state == nullptr || state->Socket == nullptr
            ? STATUS_INVALID_DEVICE_STATE
            : net::WskSocketReceive(state->Socket,
                buffer, length, bytesReceived, 0, WskOperationTimeoutMilliseconds, CancellationOrNull(state));
    }

    NTSTATUS ReceiveWithTimeout(
        void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived, ULONG timeoutMilliseconds) noexcept
    {
        auto* state = static_cast<WskTransportContext*>(context);
        return state == nullptr || state->Socket == nullptr
            ? STATUS_INVALID_DEVICE_STATE
            : net::WskSocketReceive(state->Socket,
                buffer, length, bytesReceived, 0, timeoutMilliseconds, CancellationOrNull(state));
    }

    void SetCancellation(void* context, const net::WskCancellationToken* cancellation) noexcept
    {
        auto* state = static_cast<WskTransportContext*>(context);
        if (state != nullptr) {
            state->Cancellation = cancellation != nullptr ? *cancellation : net::WskCancellationToken{};
        }
    }

    void CloseContext(void* context) noexcept
    {
        FreeNonPagedObject(static_cast<WskTransportContext*>(context));
    }

    const TransportOperations Operations = {
        { Send, Receive, ReceiveWithTimeout, SetCancellation },
        CloseContext
    };
}

NTSTATUS TransportCreateWsk(net::WskSocket* socket, Transport** transport) noexcept
{
    if (transport != nullptr) {
        *transport = nullptr;
    }
    if (socket == nullptr || transport == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* context = AllocateNonPagedObject<WskTransportContext>();
    auto* created = AllocateNonPagedObject<Transport>();
    if (context == nullptr || created == nullptr) {
        FreeNonPagedObject(created);
        FreeNonPagedObject(context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    context->Socket = socket;
    created->Operations = &Operations;
    created->Context = context;
    created->ConnectionId = net::WskSocketConnectionId(socket);
    created->OwnsOperations = false;
    *transport = created;
    const TraceCorrelation correlation = { 0, created->ConnectionId, 0 };
    WKNET_TRACE_CORRELATED(
        ::wknet::ComponentTransport,
        ::wknet::TraceLevel::Info,
        &correlation,
        "transport.wsk.created");
    return STATUS_SUCCESS;
}
}
