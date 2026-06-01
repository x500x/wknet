#pragma once

#include <KernelHttp/engine/EngineUtils.h>

namespace KernelHttp
{
namespace engine
{
    _Must_inspect_result_
    NTSTATUS KhHttpSendSyncImpl(
        _In_ KH_SESSION session,
        _In_ KH_REQUEST request,
        _In_opt_ const KhHttpSendOptions* options,
        _Out_opt_ KH_RESPONSE* response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpSendAsyncImpl(
        _In_ KH_SESSION session,
        _In_ KH_REQUEST request,
        _In_opt_ const KhHttpSendOptions* options,
        _Out_ KH_ASYNC_OPERATION* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketConnectSyncImpl(
        _In_ KH_SESSION session,
        _In_ const KhWebSocketConnectOptions* options,
        _Out_ KH_WEBSOCKET* websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketConnectAsyncImpl(
        _In_ KH_SESSION session,
        _In_ const KhWebSocketConnectOptions* options,
        _Out_ KH_ASYNC_OPERATION* operation) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendTextSyncImpl(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        _In_opt_ const KhWebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketSendBinarySyncImpl(
        _In_ KH_WEBSOCKET websocket,
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _In_opt_ const KhWebSocketSendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketReceiveSyncImpl(
        _In_ KH_WEBSOCKET websocket,
        _In_opt_ const KhWebSocketReceiveOptions* options,
        _Out_opt_ KhWebSocketMessage* message) noexcept;

    _Must_inspect_result_
    NTSTATUS KhWebSocketCloseSyncImpl(_In_opt_ KH_WEBSOCKET websocket) noexcept;
}
}
