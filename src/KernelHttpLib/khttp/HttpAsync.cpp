#include <KernelHttp/khttp/HttpAsync.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace KernelHttp
{
namespace khttp
{
namespace
{
    void FillApiSendOptions(
        const SendOptions& src,
        engine::KhHttpSendOptions& dst) noexcept
    {
        dst.MaxResponseBytes = src.MaxResponseBytes;
        dst.Flags = src.Flags;
        dst.MaxRedirects = src.MaxRedirects;
        dst.HeaderCallback = reinterpret_cast<engine::KhHeaderCallback>(src.OnHeader);
        dst.BodyCallback = reinterpret_cast<engine::KhBodyCallback>(src.OnBody);
        dst.CallbackContext = src.CallbackContext;
        dst.CompletionCallback = reinterpret_cast<engine::KhAsyncCompletionCallback>(src.OnComplete);
        dst.CompletionContext = src.CompletionContext;
    }

    NTSTATUS DoSimpleSendAsync(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const UCHAR* body,
        SIZE_T bodyLength,
        AsyncOp** operation) noexcept
    {
        if (operation != nullptr) {
            *operation = nullptr;
        }
        if (session == nullptr || url == nullptr || urlLength == 0 || operation == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        engine::KH_REQUEST request = nullptr;
        NTSTATUS status = engine::KhHttpRequestCreate(detail::ToApiSession(session), &request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = engine::KhHttpRequestSetUrl(request, url, urlLength);
        if (NT_SUCCESS(status)) {
            status = engine::KhHttpRequestSetMethod(request, detail::ToApiMethod(method));
        }
        if (NT_SUCCESS(status) && body != nullptr && bodyLength != 0) {
            status = engine::KhHttpRequestSetBody(request, body, bodyLength);
        }

        engine::KH_ASYNC_OPERATION apiOp = nullptr;
        if (NT_SUCCESS(status)) {
            status = engine::KhHttpSendAsync(detail::ToApiSession(session), request, nullptr, &apiOp);
        }
        engine::KhHttpRequestRelease(request);

        if (NT_SUCCESS(status)) {
            *operation = detail::FromApiAsyncOp(apiOp);
        }
        return status;
    }
}

NTSTATUS GetAsync(Session* session, const char* url, SIZE_T urlLength, AsyncOp** operation) noexcept
{
    return DoSimpleSendAsync(session, Method::Get, url, urlLength, nullptr, 0, operation);
}

NTSTATUS PostAsync(
    Session* session,
    const char* url,
    SIZE_T urlLength,
    const UCHAR* body,
    SIZE_T bodyLength,
    AsyncOp** operation) noexcept
{
    return DoSimpleSendAsync(session, Method::Post, url, urlLength, body, bodyLength, operation);
}

NTSTATUS SendAsync(Session* session, Request* request, AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }
    engine::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = engine::KhHttpSendAsync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        nullptr,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS SendAsyncEx(
    Session* session,
    Request* request,
    const SendOptions* options,
    AsyncOp** operation) noexcept
{
    if (operation != nullptr) {
        *operation = nullptr;
    }

    engine::KhHttpSendOptions apiOptions = {};
    if (options != nullptr) {
        FillApiSendOptions(*options, apiOptions);
    }

    engine::KH_ASYNC_OPERATION apiOp = nullptr;
    NTSTATUS status = engine::KhHttpSendAsync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        options != nullptr ? &apiOptions : nullptr,
        &apiOp);
    if (NT_SUCCESS(status) && operation != nullptr) {
        *operation = detail::FromApiAsyncOp(apiOp);
    }
    return status;
}

NTSTATUS SendAsync(
    Session* session,
    Request* request,
    const SendOptions* options,
    AsyncOp** operation) noexcept
{
    return SendAsyncEx(session, request, options, operation);
}
}
}
