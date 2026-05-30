#include <KernelHttp/khttp/Http.h>
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
        dst.HeaderCallback = reinterpret_cast<engine::KhHeaderCallback>(src.OnHeader);
        dst.BodyCallback = reinterpret_cast<engine::KhBodyCallback>(src.OnBody);
        dst.CallbackContext = src.CallbackContext;
        dst.CompletionCallback = reinterpret_cast<engine::KhAsyncCompletionCallback>(src.OnComplete);
        dst.CompletionContext = src.CompletionContext;
    }

    NTSTATUS DoSimpleSend(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const UCHAR* body,
        SIZE_T bodyLength,
        Response** response) noexcept
    {
        if (response != nullptr) {
            *response = nullptr;
        }
        if (session == nullptr || url == nullptr || urlLength == 0 || response == nullptr) {
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

        engine::KH_RESPONSE apiResp = nullptr;
        if (NT_SUCCESS(status)) {
            status = engine::KhHttpSendSync(detail::ToApiSession(session), request, nullptr, &apiResp);
        }
        engine::KhHttpRequestRelease(request);

        if (NT_SUCCESS(status)) {
            *response = detail::FromApiResponse(apiResp);
        }
        else if (apiResp != nullptr) {
            engine::KhResponseRelease(apiResp);
        }
        return status;
    }
}

NTSTATUS Get(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Get, url, urlLength, nullptr, 0, response);
}

NTSTATUS Post(Session* session, const char* url, SIZE_T urlLength, const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Post, url, urlLength, body, bodyLength, response);
}

NTSTATUS Put(Session* session, const char* url, SIZE_T urlLength, const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Put, url, urlLength, body, bodyLength, response);
}

NTSTATUS Patch(Session* session, const char* url, SIZE_T urlLength, const UCHAR* body, SIZE_T bodyLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Patch, url, urlLength, body, bodyLength, response);
}

NTSTATUS Delete(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Delete, url, urlLength, nullptr, 0, response);
}

NTSTATUS Head(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Head, url, urlLength, nullptr, 0, response);
}

NTSTATUS Options(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept
{
    return DoSimpleSend(session, Method::Options, url, urlLength, nullptr, 0, response);
}

NTSTATUS Send(Session* session, Request* request, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    engine::KH_RESPONSE apiResp = nullptr;
    NTSTATUS status = engine::KhHttpSendSync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        nullptr,
        &apiResp);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    else if (apiResp != nullptr) {
        engine::KhResponseRelease(apiResp);
    }
    return status;
}

NTSTATUS SendEx(
    Session* session,
    Request* request,
    const SendOptions* options,
    Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }

    engine::KhHttpSendOptions apiOptions = {};
    if (options != nullptr) {
        FillApiSendOptions(*options, apiOptions);
    }

    engine::KH_RESPONSE apiResp = nullptr;
    NTSTATUS status = engine::KhHttpSendSync(
        detail::ToApiSession(session),
        detail::ToApiRequest(request),
        options != nullptr ? &apiOptions : nullptr,
        response != nullptr ? &apiResp : nullptr);
    if (NT_SUCCESS(status) && response != nullptr) {
        *response = detail::FromApiResponse(apiResp);
    }
    else if (apiResp != nullptr) {
        engine::KhResponseRelease(apiResp);
    }
    return status;
}

NTSTATUS Send(
    Session* session,
    Request* request,
    const SendOptions* options,
    Response** response) noexcept
{
    return SendEx(session, request, options, response);
}
}
}
