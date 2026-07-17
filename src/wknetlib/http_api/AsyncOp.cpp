#include <wknet/http/AsyncOp.h>
#include "session/detail/HttpHandles.h"
#include "session/Async.h"
#include "session/Engine.h"
#include <wknet/http/Session.h>
#include "TransientSessionPool.h"

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
    if (operation == nullptr || operation->Magic != detail::HighAsyncOpMagic) {
        return STATUS_INVALID_PARAMETER;
    }
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::TestAsyncStatus(operation->Engine);
#else
    if (operation->Engine == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return operation->Engine->Status;
#endif
}

bool AsyncIsCompleted(const AsyncOp* operation) noexcept
{
    if (operation == nullptr || operation->Magic != detail::HighAsyncOpMagic) {
        return false;
    }
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::TestAsyncIsCompleted(operation->Engine);
#else
    return ::wknet::session::AsyncOperationState(operation->Engine) ==
        ::wknet::session::AsyncState::Completed;
#endif
}

bool AsyncIsCanceled(const AsyncOp* operation) noexcept
{
    if (operation == nullptr || operation->Magic != detail::HighAsyncOpMagic) {
        return false;
    }
#if defined(WKNET_USER_MODE_TEST)
    return ::wknet::session::TestAsyncIsCanceled(operation->Engine);
#else
    if (operation->Engine == nullptr) {
        return false;
    }
    return operation->Engine->Canceled != 0;
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
    if (operation == nullptr || operation->Magic != detail::HighAsyncOpMagic) {
        return;
    }

    ::wknet::session::AsyncOperation* engine = operation->Engine;
    Session* ownedSession = operation->OwnedSession;
    operation->Engine = nullptr;
    operation->OwnedSession = nullptr;
    operation->Magic = 0;

    // Engine cleanup (SessionEndOperation) must finish before closing owned Session.
    ::wknet::session::AsyncRelease(engine);
    if (ownedSession != nullptr) {
        detail::ReleaseTransientSession(ownedSession);
    }
    ::wknet::FreeNonPagedObject(operation);
}
}
