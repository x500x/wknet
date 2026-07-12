#include "transport/TransportPrivate.hpp"

#include "tls/TlsConnection.h"

namespace wknet::transport {
namespace
{
    struct TlsTransportContext final
    {
        Transport* RawTransport = nullptr;
        tls::TlsConnection* Tls = nullptr;
    };

    NTSTATUS TlsSend(void* context, const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
    {
        auto* state = static_cast<TlsTransportContext*>(context);
        return state == nullptr || state->RawTransport == nullptr || state->Tls == nullptr
            ? STATUS_INVALID_DEVICE_STATE
            : tls::TlsConnectionSend(state->Tls, state->RawTransport, data, length, bytesSent);
    }

    NTSTATUS TlsReceive(void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
    {
        auto* state = static_cast<TlsTransportContext*>(context);
        return state == nullptr || state->RawTransport == nullptr || state->Tls == nullptr
            ? STATUS_INVALID_DEVICE_STATE
            : tls::TlsConnectionReceive(
                state->Tls, state->RawTransport, buffer, length, bytesReceived);
    }

    NTSTATUS TlsReceiveWithTimeout(
        void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived, ULONG timeoutMilliseconds) noexcept
    {
        auto* state = static_cast<TlsTransportContext*>(context);
        return state == nullptr || state->RawTransport == nullptr || state->Tls == nullptr
            ? STATUS_INVALID_DEVICE_STATE
            : tls::TlsConnectionReceive(
                state->Tls, state->RawTransport, buffer, length, bytesReceived, timeoutMilliseconds);
    }

    void TlsSetCancellation(void* context, const net::WskCancellationToken* cancellation) noexcept
    {
        auto* state = static_cast<TlsTransportContext*>(context);
        if (state != nullptr) {
            TransportSetCancellation(state->RawTransport, cancellation);
        }
    }

    void CloseTlsContext(void* context) noexcept
    {
        FreeNonPagedObject(static_cast<TlsTransportContext*>(context));
    }

    const TransportOperations TlsOperations = {
        { TlsSend, TlsReceive, TlsReceiveWithTimeout, TlsSetCancellation },
        CloseTlsContext
    };
    NTSTATUS CreateTransport(
        const TransportOperations* operations,
        void* context,
        Transport** transport) noexcept
    {
        if (transport != nullptr) {
            *transport = nullptr;
        }
        if (operations == nullptr || transport == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        auto* created = AllocateNonPagedObject<Transport>();
        if (created == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        created->Operations = operations;
        created->Context = context;
        created->OwnsOperations = false;
        *transport = created;
        return STATUS_SUCCESS;
    }
}

NTSTATUS TransportCreateTls(
    Transport* rawTransport, tls::TlsConnection* tlsConnection, Transport** transport) noexcept
{
    if (rawTransport == nullptr || tlsConnection == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* context = AllocateNonPagedObject<TlsTransportContext>();
    if (context == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    context->RawTransport = rawTransport;
    context->Tls = tlsConnection;
    const NTSTATUS status = CreateTransport(&TlsOperations, context, transport);
    if (!NT_SUCCESS(status)) {
        FreeNonPagedObject(context);
    }
    return status;
}

NTSTATUS TransportCreateCallbacks(
    const TransportCallbacks* callbacks, void* context, Transport** transport) noexcept
{
    if (callbacks == nullptr || callbacks->Send == nullptr || callbacks->Receive == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* operations = AllocateNonPagedObject<TransportOperations>();
    if (operations == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    operations->Callbacks = *callbacks;
    operations->CloseContext = nullptr;
    const NTSTATUS status = CreateTransport(operations, context, transport);
    if (!NT_SUCCESS(status)) {
        FreeNonPagedObject(operations);
    }
    else {
        (*transport)->OwnsOperations = true;
    }
    return status;
}

void TransportClose(Transport* transport) noexcept
{
    if (transport == nullptr) {
        return;
    }
    const TransportOperations* operations = transport->Operations;
    if (operations != nullptr && operations->CloseContext != nullptr) {
        operations->CloseContext(transport->Context);
    }
    if (operations != nullptr && transport->OwnsOperations) {
        FreeNonPagedObject(const_cast<TransportOperations*>(operations));
    }
    FreeNonPagedObject(transport);
}

NTSTATUS TransportSend(Transport* transport, const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
{
    if (transport == nullptr || transport->Operations == nullptr || transport->Operations->Callbacks.Send == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return transport->Operations->Callbacks.Send(transport->Context, data, length, bytesSent);
}

NTSTATUS TransportReceive(Transport* transport, void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
{
    if (transport == nullptr || transport->Operations == nullptr || transport->Operations->Callbacks.Receive == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return transport->Operations->Callbacks.Receive(transport->Context, buffer, length, bytesReceived);
}

NTSTATUS TransportReceiveWithTimeout(
    Transport* transport, void* buffer, SIZE_T length, SIZE_T* bytesReceived, ULONG timeoutMilliseconds) noexcept
{
    if (transport == nullptr || transport->Operations == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    const auto callback = transport->Operations->Callbacks.ReceiveWithTimeout;
    return callback != nullptr
        ? callback(transport->Context, buffer, length, bytesReceived, timeoutMilliseconds)
        : TransportReceive(transport, buffer, length, bytesReceived);
}

void TransportSetCancellation(Transport* transport, const net::WskCancellationToken* cancellation) noexcept
{
    if (transport != nullptr && transport->Operations != nullptr &&
        transport->Operations->Callbacks.SetCancellation != nullptr) {
        transport->Operations->Callbacks.SetCancellation(transport->Context, cancellation);
    }
}
}
