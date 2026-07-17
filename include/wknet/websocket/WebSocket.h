#pragma once

#include <wknet/http/Types.h>

namespace wknet::websocket {
    // IRQL: Connect/Send/Receive/Close entry points require PASSIVE_LEVEL in kernel builds.
    _Must_inspect_result_
    NTSTATUS Connect(
        _In_ wknet::http::Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ WebSocket** websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS Connect(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ WebSocket** websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectEx(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ WebSocket** websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectAsync(
        _In_ wknet::http::Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ wknet::http::AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectAsync(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ wknet::http::AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectAsyncEx(
        _In_ wknet::http::Session* session,
        _In_ const ConnectConfig* config,
        _Out_ wknet::http::AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS SendText(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendTextEx(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        _In_opt_ const SendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS SendBinary(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendBinaryEx(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const SendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS SendContinuation(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendContinuationEx(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const SendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS SendPing(
        _In_ WebSocket* websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendPong(
        _In_ WebSocket* websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS Receive(
        _In_ WebSocket* websocket,
        _Out_ Message* message) noexcept;

    _Must_inspect_result_
    NTSTATUS ReceiveEx(
        _In_ WebSocket* websocket,
        _In_opt_ const ReceiveOptions* options,
        _Out_opt_ Message* message) noexcept;

    _Must_inspect_result_
    NTSTATUS Close(_In_opt_ WebSocket* websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS CloseEx(
        _In_opt_ WebSocket* websocket,
        USHORT statusCode,
        _In_reads_bytes_opt_(reasonLength) const UCHAR* reason,
        SIZE_T reasonLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SelectedSubprotocol(
        _In_ WebSocket* websocket,
        _Outptr_result_bytebuffer_(*subprotocolLength) const char** subprotocol,
        _Out_ SIZE_T* subprotocolLength) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncGetWebSocket(
        _In_ wknet::http::AsyncOp* operation,
        _Out_ WebSocket** websocket) noexcept;
}
