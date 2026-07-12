#include <wknet/http/HttpAsync.h>
#include "Detail.h"
#include "session/Engine.h"

namespace wknet::http {
namespace
{
    SIZE_T StringLength(const char* text) noexcept
    {
        if (text == nullptr) {
            return 0;
        }
        SIZE_T length = 0;
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    NTSTATUS AsyncSendCore(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const Headers* headers,
        const Body* body,
        const AsyncOptions* options,
        AsyncOp** operation) noexcept
    {
        if (operation != nullptr) {
            *operation = nullptr;
        }
        if (operation == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ::wknet::session::RequestHandle apiRequest = nullptr;
        NTSTATUS status = detail::PrepareHttpRequest(
            session,
            method,
            url,
            urlLength,
            headers,
            body,
            options != nullptr ? &options->Send : nullptr,
            &apiRequest);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ::wknet::session::HttpSendOptions apiOptions = {};
        const ::wknet::session::HttpSendOptions* apiOptionsPtr = nullptr;
        if (options != nullptr) {
            detail::FillApiSendOptions(options->Send, apiOptions);
            apiOptions.CompletionCallback =
                reinterpret_cast<::wknet::session::AsyncCompletionCallback>(options->OnComplete);
            apiOptions.CompletionContext = options->CompletionContext;
            apiOptionsPtr = &apiOptions;
        }

        ::wknet::session::AsyncOperationHandle apiOp = nullptr;
        status = ::wknet::session::HttpSendAsync(session->Engine, apiRequest, apiOptionsPtr, &apiOp);
        ::wknet::session::HttpRequestRelease(apiRequest);

        if (NT_SUCCESS(status)) {
            *operation = detail::FromApiAsyncOp(apiOp);
        }
        return status;
    }
}

NTSTATUS AsyncSend(Session* session, Method method, const char* url, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept
{
    return AsyncSendEx(session, method, url, StringLength(url), headers, body, options, operation);
}

NTSTATUS AsyncSendEx(Session* session, Method method, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept
{
    return AsyncSendCore(session, method, url, urlLength, headers, body, options, operation);
}

NTSTATUS AsyncSend(Request* request, Method method, const char* url, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept
{
    return AsyncSendEx(request, method, url, StringLength(url), headers, body, options, operation);
}

NTSTATUS AsyncSendEx(Request* request, Method method, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept
{
    return AsyncSendCore(detail::SessionFromSendHandle(request), method, url, urlLength, headers, body, options, operation);
}

NTSTATUS AsyncGet(Session* session, const char* url, AsyncOp** operation) noexcept { return AsyncGetEx(session, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncGetEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Get, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncPost(Session* session, const char* url, const Body* body, AsyncOp** operation) noexcept { return AsyncPostEx(session, url, StringLength(url), nullptr, body, nullptr, operation); }
NTSTATUS AsyncPostEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Post, url, urlLength, headers, body, options, operation); }
NTSTATUS AsyncPut(Session* session, const char* url, const Body* body, AsyncOp** operation) noexcept { return AsyncPutEx(session, url, StringLength(url), nullptr, body, nullptr, operation); }
NTSTATUS AsyncPutEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Put, url, urlLength, headers, body, options, operation); }
NTSTATUS AsyncPatch(Session* session, const char* url, const Body* body, AsyncOp** operation) noexcept { return AsyncPatchEx(session, url, StringLength(url), nullptr, body, nullptr, operation); }
NTSTATUS AsyncPatchEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Patch, url, urlLength, headers, body, options, operation); }
NTSTATUS AsyncDelete(Session* session, const char* url, AsyncOp** operation) noexcept { return AsyncDeleteEx(session, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncDeleteEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Delete, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncHead(Session* session, const char* url, AsyncOp** operation) noexcept { return AsyncHeadEx(session, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncHeadEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Head, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncOptionsRequest(Session* session, const char* url, AsyncOp** operation) noexcept { return AsyncOptionsRequestEx(session, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncOptionsRequestEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Options, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncTrace(Session* session, const char* url, AsyncOp** operation) noexcept { return AsyncTraceEx(session, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncTraceEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(session, Method::Trace, url, urlLength, headers, nullptr, options, operation); }

NTSTATUS AsyncGet(Request* request, const char* url, AsyncOp** operation) noexcept { return AsyncGetEx(request, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncGetEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Get, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncPost(Request* request, const char* url, const Body* body, AsyncOp** operation) noexcept { return AsyncPostEx(request, url, StringLength(url), nullptr, body, nullptr, operation); }
NTSTATUS AsyncPostEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Post, url, urlLength, headers, body, options, operation); }
NTSTATUS AsyncPut(Request* request, const char* url, const Body* body, AsyncOp** operation) noexcept { return AsyncPutEx(request, url, StringLength(url), nullptr, body, nullptr, operation); }
NTSTATUS AsyncPutEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Put, url, urlLength, headers, body, options, operation); }
NTSTATUS AsyncPatch(Request* request, const char* url, const Body* body, AsyncOp** operation) noexcept { return AsyncPatchEx(request, url, StringLength(url), nullptr, body, nullptr, operation); }
NTSTATUS AsyncPatchEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Patch, url, urlLength, headers, body, options, operation); }
NTSTATUS AsyncDelete(Request* request, const char* url, AsyncOp** operation) noexcept { return AsyncDeleteEx(request, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncDeleteEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Delete, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncHead(Request* request, const char* url, AsyncOp** operation) noexcept { return AsyncHeadEx(request, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncHeadEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Head, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncOptionsRequest(Request* request, const char* url, AsyncOp** operation) noexcept { return AsyncOptionsRequestEx(request, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncOptionsRequestEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Options, url, urlLength, headers, nullptr, options, operation); }
NTSTATUS AsyncTrace(Request* request, const char* url, AsyncOp** operation) noexcept { return AsyncTraceEx(request, url, StringLength(url), nullptr, nullptr, operation); }
NTSTATUS AsyncTraceEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const AsyncOptions* options, AsyncOp** operation) noexcept { return AsyncSendEx(request, Method::Trace, url, urlLength, headers, nullptr, options, operation); }

#if defined(WKNET_USER_MODE_TEST)
NTSTATUS GetAsync(Session* session, const char* url, SIZE_T urlLength, AsyncOp** operation) noexcept
{
    return AsyncGetEx(session, url, urlLength, nullptr, nullptr, operation);
}

NTSTATUS PostAsync(Session* session, const char* url, SIZE_T urlLength, const UCHAR* data, SIZE_T dataLength, AsyncOp** operation) noexcept
{
    Body* body = nullptr;
    NTSTATUS status = BodyCreateBytes(data, dataLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = AsyncPostEx(session, url, urlLength, nullptr, body, nullptr, operation);
    BodyRelease(body);
    return status;
}

NTSTATUS SendAsync(Session* session, Request* request, AsyncOp** operation) noexcept
{
    return SendAsyncEx(session, request, nullptr, operation);
}

NTSTATUS SendAsync(Session* session, Request* request, const SendOptions* options, AsyncOp** operation) noexcept
{
    return SendAsyncEx(session, request, options, operation);
}

NTSTATUS SendAsyncEx(Session* session, Request* request, const SendOptions* options, AsyncOp** operation) noexcept
{
    UNREFERENCED_PARAMETER(session);
    if (request == nullptr || request->Magic != detail::HighRequestMagic ||
        request->BuilderUrl == nullptr || request->BuilderUrlLength == 0) {
        if (operation != nullptr) {
            *operation = nullptr;
        }
        return STATUS_INVALID_PARAMETER;
    }

    AsyncOptions* asyncOptions = nullptr;
    const AsyncOptions* effectiveOptions = nullptr;
    if (options != nullptr || request->BuilderOptions != nullptr) {
        NTSTATUS status = AsyncOptionsCreate(&asyncOptions);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        asyncOptions->Send = options != nullptr ? *options : DefaultSendOptions();
        if (request->BuilderOptions != nullptr) {
            if (request->BuilderOptions->HasTlsOverride) {
                asyncOptions->Send.Tls = request->BuilderOptions->Tls;
                asyncOptions->Send.HasTlsOverride = true;
            }
            asyncOptions->Send.ConnectionPolicy = request->BuilderOptions->ConnectionPolicy;
            asyncOptions->Send.Family = request->BuilderOptions->Family;
            asyncOptions->Send.AcceptEncodingPreferences = request->BuilderOptions->AcceptEncodingPreferences;
            asyncOptions->Send.AcceptEncodingPreferenceCount = request->BuilderOptions->AcceptEncodingPreferenceCount;
        }
        const SendOptions* completionOptions = options != nullptr ? options : request->BuilderOptions;
        asyncOptions->OnComplete = completionOptions->OnComplete;
        asyncOptions->CompletionContext = completionOptions->CompletionContext;
        effectiveOptions = asyncOptions;
    }

    NTSTATUS status = AsyncSendEx(
        request,
        request->BuilderMethod,
        request->BuilderUrl,
        request->BuilderUrlLength,
        request->BuilderHeaders,
        request->BuilderBody,
        effectiveOptions,
        operation);
    AsyncOptionsRelease(asyncOptions);
    return status;
}
#endif
}
