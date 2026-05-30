#pragma once

#include <KernelHttp/khttp/Types.h>

namespace KernelHttp
{
namespace khttp
{
    _Must_inspect_result_
    NTSTATUS WsConnect(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ WebSocket** websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS WsConnect(
        _In_ Session* session,
        _In_ const WsConnectConfig* config,
        _Out_ WebSocket** websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS WsConnectEx(
        _In_ Session* session,
        _In_ const WsConnectConfig* config,
        _Out_ WebSocket** websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS WsConnectAsync(
        _In_ Session* session,
        _In_reads_bytes_(urlLength) const char* url,
        SIZE_T urlLength,
        _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS WsConnectAsync(
        _In_ Session* session,
        _In_ const WsConnectConfig* config,
        _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS WsConnectAsyncEx(
        _In_ Session* session,
        _In_ const WsConnectConfig* config,
        _Out_ AsyncOp** operation) noexcept;

    _Must_inspect_result_
    NTSTATUS WsSendText(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WsSendTextEx(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        _In_opt_ const WsSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WsSendBinary(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WsSendBinaryEx(
        _In_ WebSocket* websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const WsSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WsReceive(
        _In_ WebSocket* websocket,
        _Out_ WsMessage* message) noexcept;

    _Must_inspect_result_
    NTSTATUS WsReceiveEx(
        _In_ WebSocket* websocket,
        _In_opt_ const WsReceiveOptions* options,
        _Out_opt_ WsMessage* message) noexcept;

    _Must_inspect_result_
    NTSTATUS WsClose(_In_opt_ WebSocket* websocket) noexcept;
}
}
