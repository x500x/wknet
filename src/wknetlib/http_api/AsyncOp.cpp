#include <wknet/http/AsyncOp.h>
#include "Detail.h"
#include "session/Async.h"
#include "session/Engine.h"

namespace wknet::http {
NTSTATUS AsyncWait(AsyncOp* operation, ULONG timeoutMs) noexcept
{
    return ::wknet::session::KhAsyncWait(detail::ToApiAsyncOp(operation), timeoutMs);
}

NTSTATUS AsyncCancel(AsyncOp* operation) noexcept
{
    return ::wknet::session::KhAsyncCancel(detail::ToApiAsyncOp(operation));
}

NTSTATUS AsyncGetStatus(const AsyncOp* operation) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::KhTestAsyncStatus(const_cast<::wknet::session::KH_ASYNC_OPERATION>(
        reinterpret_cast<const ::wknet::session::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return reinterpret_cast<const ::wknet::session::KhAsyncOperation*>(operation)->Status;
#endif
}

bool AsyncIsCompleted(const AsyncOp* operation) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::KhTestAsyncIsCompleted(const_cast<::wknet::session::KH_ASYNC_OPERATION>(
        reinterpret_cast<const ::wknet::session::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return ::wknet::session::KhAsyncOperationState(detail::ToApiAsyncOp(const_cast<AsyncOp*>(operation))) ==
        ::wknet::session::KhAsyncState::Completed;
#endif
}

bool AsyncIsCanceled(const AsyncOp* operation) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::KhTestAsyncIsCanceled(const_cast<::wknet::session::KH_ASYNC_OPERATION>(
        reinterpret_cast<const ::wknet::session::KhAsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return reinterpret_cast<const ::wknet::session::KhAsyncOperation*>(operation)->Canceled != 0;
#endif
}

NTSTATUS AsyncGetResponse(AsyncOp* operation, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    ::wknet::session::KH_RESPONSE apiResp = nullptr;
    NTSTATUS status = ::wknet::session::KhAsyncGetHttpResponse(detail::ToApiAsyncOp(operation), &apiResp);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    return status;
}

void AsyncRelease(AsyncOp* operation) noexcept
{
    ::wknet::session::KhAsyncRelease(detail::ToApiAsyncOp(operation));
}
}
