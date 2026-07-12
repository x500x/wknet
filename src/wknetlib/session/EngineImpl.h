#pragma once

#include "session/EngineUtils.h"

namespace wknet
{
namespace session
{
    _Must_inspect_result_
    NTSTATUS HttpSendSyncImpl(
        _In_ SessionHandle session,
        _In_ RequestHandle request,
        _In_opt_ const HttpSendOptions* options,
        _Out_opt_ ResponseHandle* response,
        _In_opt_ AsyncOperationHandle cancellationOperation = nullptr) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpSendAsyncImpl(
        _In_ SessionHandle session,
        _In_ RequestHandle request,
        _In_opt_ const HttpSendOptions* options,
        _Out_ AsyncOperationHandle* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketConnectSyncImpl(
        _In_ SessionHandle session,
        _In_ const WebSocketConnectOptions* options,
        _Out_ WebSocketHandle* websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketConnectAsyncImpl(
        _In_ SessionHandle session,
        _In_ const WebSocketConnectOptions* options,
        _Out_ AsyncOperationHandle* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendTextSyncImpl(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        _In_opt_ const WebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendBinarySyncImpl(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const WebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendContinuationSyncImpl(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const WebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendPingSyncImpl(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketSendPongSyncImpl(
        _In_ WebSocketHandle websocket,
        _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
        SIZE_T payloadLength) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketReceiveSyncImpl(
        _In_ WebSocketHandle websocket,
        _In_opt_ const WebSocketReceiveOptions* options,
        _Out_opt_ WebSocketMessage* message) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketCloseSyncImpl(_In_opt_ WebSocketHandle websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS WebSocketCloseExSyncImpl(
        _In_opt_ WebSocketHandle websocket,
        USHORT statusCode,
        _In_reads_bytes_opt_(reasonLength) const UCHAR* reason,
        SIZE_T reasonLength) noexcept;
}
}
