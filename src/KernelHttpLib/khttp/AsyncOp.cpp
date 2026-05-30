#include <KernelHttp/khttp/AsyncOp.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Async.h>
#include <KernelHttp/engine/Engine.h>

namespace KernelHttp
{
namespace khttp
{
NTSTATUS AsyncWait(AsyncOp* operation, ULONG timeoutMs) noexcept
{
    return engine::KhAsyncWait(detail::ToApiAsyncOp(operation), timeoutMs);
}

NTSTATUS AsyncCancel(AsyncOp* operation) noexcept
{
    return engine::KhAsyncCancel(detail::ToApiAsyncOp(operation));
}

NTSTATUS AsyncGetStatus(const AsyncOp* operation) noexcept
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    return engine::KhTestAsyncStatus(const_cast<engine::KH_ASYNC_OPERATION>(
        reinterpret_cast<const engine::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return reinterpret_cast<const engine::KhAsyncOperation*>(operation)->Status;
#endif
}

bool AsyncIsCompleted(const AsyncOp* operation) noexcept
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    return engine::KhTestAsyncIsCompleted(const_cast<engine::KH_ASYNC_OPERATION>(
        reinterpret_cast<const engine::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return reinterpret_cast<const engine::KhAsyncOperation*>(operation)->State == engine::KhAsyncState::Completed;
#endif
}

bool AsyncIsCanceled(const AsyncOp* operation) noexcept
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    return engine::KhTestAsyncIsCanceled(const_cast<engine::KH_ASYNC_OPERATION>(
        reinterpret_cast<const engine::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return reinterpret_cast<const engine::KhAsyncOperation*>(operation)->Canceled != 0;
#endif
}

NTSTATUS AsyncGetResponse(AsyncOp* operation, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    engine::KH_RESPONSE apiResp = nullptr;
    NTSTATUS status = engine::KhAsyncGetHttpResponse(detail::ToApiAsyncOp(operation), &apiResp);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    return status;
}

NTSTATUS AsyncGetWebSocket(AsyncOp* operation, WebSocket** websocket) noexcept
{
    if (websocket != nullptr) {
        *websocket = nullptr;
    }
    engine::KH_WEBSOCKET apiWs = nullptr;
    NTSTATUS status = engine::KhAsyncGetWebSocket(detail::ToApiAsyncOp(operation), &apiWs);
    if (NT_SUCCESS(status) && websocket != nullptr) {
        *websocket = detail::FromApiWebSocket(apiWs);
    }
    return status;
}

void AsyncRelease(AsyncOp* operation) noexcept
{
    engine::KhAsyncRelease(detail::ToApiAsyncOp(operation));
}
}
}
