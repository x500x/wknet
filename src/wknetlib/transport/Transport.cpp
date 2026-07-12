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
    else {
        (*transport)->ConnectionId = rawTransport->ConnectionId;
        const TraceCorrelation correlation = { 0, (*transport)->ConnectionId, 0 };
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentTransport,
            ::wknet::TraceLevel::Info,
            &correlation,
            "transport.tls.created");
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
    const TraceCorrelation correlation = { 0, transport->ConnectionId, 0 };
    WKNET_TRACE_CORRELATED(
        ::wknet::ComponentTransport,
        ::wknet::TraceLevel::Info,
        &correlation,
        "transport.closed");
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
    const NTSTATUS status = transport->Operations->Callbacks.Send(transport->Context, data, length, bytesSent);
    const TraceCorrelation correlation = { 0, transport->ConnectionId, 0 };
    if (NT_SUCCESS(status)) {
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentTransport,
            ::wknet::TraceLevel::Max,
            &correlation,
            "transport.send bytes=%Iu requested=%Iu",
            bytesSent != nullptr ? *bytesSent : length,
            length);
    }
    else {
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentTransport,
            ::wknet::TraceLevel::Error,
            &correlation,
            "transport.send.failed status=0x%08X requested=%Iu",
            static_cast<ULONG>(status),
            length);
    }
    return status;
}

NTSTATUS TransportReceive(Transport* transport, void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
{
    if (transport == nullptr || transport->Operations == nullptr || transport->Operations->Callbacks.Receive == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    const NTSTATUS status = transport->Operations->Callbacks.Receive(transport->Context, buffer, length, bytesReceived);
    const TraceCorrelation correlation = { 0, transport->ConnectionId, 0 };
    if (NT_SUCCESS(status)) {
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentTransport,
            ::wknet::TraceLevel::Max,
            &correlation,
            "transport.receive bytes=%Iu requested=%Iu",
            bytesReceived != nullptr ? *bytesReceived : static_cast<SIZE_T>(0),
            length);
    }
    else {
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentTransport,
            ::wknet::TraceLevel::Error,
            &correlation,
            "transport.receive.failed status=0x%08X requested=%Iu",
            static_cast<ULONG>(status),
            length);
    }
    return status;
}

NTSTATUS TransportReceiveWithTimeout(
    Transport* transport, void* buffer, SIZE_T length, SIZE_T* bytesReceived, ULONG timeoutMilliseconds) noexcept
{
    if (transport == nullptr || transport->Operations == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    const auto callback = transport->Operations->Callbacks.ReceiveWithTimeout;
    if (callback == nullptr) {
        return TransportReceive(transport, buffer, length, bytesReceived);
    }

    const NTSTATUS status = callback(
        transport->Context,
        buffer,
        length,
        bytesReceived,
        timeoutMilliseconds);
    const TraceCorrelation correlation = { 0, transport->ConnectionId, 0 };
    if (NT_SUCCESS(status)) {
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentTransport,
            ::wknet::TraceLevel::Max,
            &correlation,
            "transport.receive_timeout bytes=%Iu requested=%Iu timeout_ms=%u",
            bytesReceived != nullptr ? *bytesReceived : static_cast<SIZE_T>(0),
            length,
            timeoutMilliseconds);
    }
    else {
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentTransport,
            ::wknet::TraceLevel::Error,
            &correlation,
            "transport.receive_timeout.failed status=0x%08X requested=%Iu timeout_ms=%u",
            static_cast<ULONG>(status),
            length,
            timeoutMilliseconds);
    }
    return status;
}

void TransportSetCancellation(Transport* transport, const net::WskCancellationToken* cancellation) noexcept
{
    if (transport != nullptr && transport->Operations != nullptr &&
        transport->Operations->Callbacks.SetCancellation != nullptr) {
        transport->Operations->Callbacks.SetCancellation(transport->Context, cancellation);
    }
}

void TransportSetConnectionId(Transport* transport, ULONGLONG connectionId) noexcept
{
    if (transport != nullptr) {
        transport->ConnectionId = connectionId;
    }
}

ULONGLONG TransportConnectionId(const Transport* transport) noexcept
{
    return transport != nullptr ? transport->ConnectionId : 0;
}
}
