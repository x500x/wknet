#include <wknet/http/AsyncOp.h>
#include "Detail.h"
#include "session/Async.h"
#include "session/Engine.h"

namespace wknet::http {
NTSTATUS AsyncWait(AsyncOp* operation, ULONG timeoutMs) noexcept
{
    return ::wknet::session::AsyncWait(detail::ToApiAsyncOp(operation), timeoutMs);
}

NTSTATUS AsyncCancel(AsyncOp* operation) noexcept
{
    return ::wknet::session::AsyncCancel(detail::ToApiAsyncOp(operation));
}

NTSTATUS AsyncGetStatus(const AsyncOp* operation) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::TestAsyncStatus(const_cast<::wknet::session::AsyncOperationHandle>(
        reinterpret_cast<const ::wknet::session::AsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return reinterpret_cast<const ::wknet::session::AsyncOperation*>(operation)->Status;
#endif
}

bool AsyncIsCompleted(const AsyncOp* operation) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::TestAsyncIsCompleted(const_cast<::wknet::session::AsyncOperationHandle>(
        reinterpret_cast<const ::wknet::session::AsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return ::wknet::session::AsyncOperationState(detail::ToApiAsyncOp(const_cast<AsyncOp*>(operation))) ==
        ::wknet::session::AsyncState::Completed;
#endif
}

bool AsyncIsCanceled(const AsyncOp* operation) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::TestAsyncIsCanceled(const_cast<::wknet::session::AsyncOperationHandle>(
        reinterpret_cast<const ::wknet::session::AsyncOperation*>(operation)));
#else
    if (operation == nullptr) {
        return false;
    }
    return reinterpret_cast<const ::wknet::session::AsyncOperation*>(operation)->Canceled != 0;
#endif
}

NTSTATUS AsyncGetResponse(AsyncOp* operation, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    ::wknet::session::ResponseHandle apiResp = nullptr;
    NTSTATUS status = ::wknet::session::AsyncGetHttpResponse(detail::ToApiAsyncOp(operation), &apiResp);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    return status;
}

void AsyncRelease(AsyncOp* operation) noexcept
{
    ::wknet::session::AsyncRelease(detail::ToApiAsyncOp(operation));
}
}
