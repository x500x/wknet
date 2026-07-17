#include <wknet/http/Http.h>
#include <wknet/http/Session.h>
#include "TransientSessionPool.h"
#include "session/detail/HttpHandles.h"
#include "session/Engine.h"
#include "session/CookieJar.h"
#include "session/EngineUtils.h"

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

    bool TextEqualsLiteralIgnoreCase(const char* left, SIZE_T leftLength, const char* literal) noexcept
    {
        const SIZE_T rightLength = StringLength(literal);
        if (left == nullptr || leftLength != rightLength) {
            return false;
        }
        for (SIZE_T index = 0; index < leftLength; ++index) {
            char a = left[index];
            char b = literal[index];
            if (a >= 'A' && a <= 'Z') {
                a = static_cast<char>(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = static_cast<char>(b - 'A' + 'a');
            }
            if (a != b) {
                return false;
            }
        }
        return true;
    }

    bool IsValidMethod(Method method) noexcept
    {
        switch (method) {
        case Method::Get:
        case Method::Post:
        case Method::Put:
        case Method::Patch:
        case Method::Delete:
        case Method::Head:
        case Method::Options:
        case Method::Connect:
        case Method::Trace:
            return true;
        default:
            return false;
        }
    }

    bool FindHeader(
        const Headers* headers,
        const char* name,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }
        if (headers == nullptr || headers->Magic != detail::HighHeadersMagic) {
            return false;
        }
        for (SIZE_T index = 0; index < headers->Count; ++index) {
            const detail::StoredHeader& header = headers->Items[index];
            if (TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, name)) {
                if (value != nullptr) {
                    *value = header.Value;
                }
                if (valueLength != nullptr) {
                    *valueLength = header.ValueLength;
                }
                return true;
            }
        }
        return false;
    }

    void FillEngineSendOptions(
        const SendOptions& src,
        ::wknet::session::HttpSendOptions& dst) noexcept
    {
        dst.MaxResponseBytes = src.MaxResponseBytes;
        dst.Flags = src.Flags;
        dst.MaxRedirects = src.MaxRedirects;
        dst.ExpectContinueTimeoutMilliseconds = src.ExpectContinueTimeoutMs;
        dst.ResponseHeaderTimeoutMilliseconds = src.ResponseHeaderTimeoutMs;
        dst.BodyReadTimeoutMilliseconds = src.BodyReadTimeoutMs;
        dst.BodyIdleTimeoutMilliseconds = src.BodyIdleTimeoutMs;
        dst.HeaderCallback = reinterpret_cast<::wknet::session::HeaderCallback>(src.OnHeader);
        dst.BodyCallback = reinterpret_cast<::wknet::session::BodyCallback>(src.OnBody);
        dst.CallbackContext = src.CallbackContext;
        dst.Http2CleartextMode = detail::ToApiHttp2CleartextMode(src.Http2CleartextMode);
        dst.AcceptEncodingPreferences = detail::ToApiAcceptEncodingPreferences(src.AcceptEncodingPreferences);
        dst.AcceptEncodingPreferenceCount = src.AcceptEncodingPreferenceCount;
        dst.ContentCodingMaterials = detail::ToApiCodingMaterials(src.ContentCodingMaterials);
        dst.Http2Priority = detail::ToApiHttp2Priority(src.Http2Priority);
        dst.Cache = detail::ToApiCache(src.Cache);
    }

    NTSTATUS ApplyOptionsToRequest(
        ::wknet::session::RequestHandle request,
        const SendOptions* options) noexcept
    {
        if (options == nullptr) {
            return STATUS_SUCCESS;
        }
        NTSTATUS status = STATUS_SUCCESS;
        if (options->HasTlsOverride) {
            ::wknet::session::TlsOptions tls = {};
            detail::FillApiTlsOptions(options->Tls, tls);
            status = ::wknet::session::HttpRequestSetTlsOptions(request, &tls);
        }
        if (NT_SUCCESS(status)) {
            status = ::wknet::session::HttpRequestSetConnectionPolicy(
                request,
                detail::ToApiConnPolicy(options->ConnectionPolicy));
        }
        if (NT_SUCCESS(status)) {
            status = ::wknet::session::HttpRequestSetAddressFamily(
                request,
                detail::ToApiAddressFamily(options->Family));
        }
        return status;
    }

    NTSTATUS ApplyHeadersToRequest(
        ::wknet::session::RequestHandle request,
        const Headers* headers,
        bool skipContentType) noexcept
    {
        if (headers == nullptr) {
            return STATUS_SUCCESS;
        }
        if (headers->Magic != detail::HighHeadersMagic) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T index = 0; index < headers->Count; ++index) {
            const detail::StoredHeader& header = headers->Items[index];
            if (skipContentType && TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, "Content-Type")) {
                continue;
            }
            NTSTATUS status = ::wknet::session::HttpRequestSetHeader(
                request,
                header.Name,
                header.NameLength,
                header.Value,
                header.ValueLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS ApplyBodyToRequest(
        ::wknet::session::RequestHandle request,
        const Body* body,
        const Headers* headers) noexcept
    {
        if (body == nullptr) {
            return STATUS_SUCCESS;
        }
        if (body->Magic != detail::HighBodyMagic) {
            return STATUS_INVALID_PARAMETER;
        }

        const char* contentType = body->ContentType;
        SIZE_T contentTypeLength = body->ContentTypeLength;
        const char* overrideContentType = nullptr;
        SIZE_T overrideContentTypeLength = 0;
        if (FindHeader(headers, "Content-Type", &overrideContentType, &overrideContentTypeLength)) {
            contentType = overrideContentType;
            contentTypeLength = overrideContentTypeLength;
        }

        NTSTATUS status = STATUS_SUCCESS;
        switch (body->Kind) {
        case detail::BodyStorageKind::Text:
            status = ::wknet::session::HttpRequestSetTextBody(
                request,
                reinterpret_cast<const char*>(body->Data),
                body->DataLength,
                contentType,
                contentTypeLength);
            break;
        case detail::BodyStorageKind::Json:
        case detail::BodyStorageKind::Bytes:
            if (contentType != nullptr) {
                status = ::wknet::session::HttpRequestSetRawBody(
                    request,
                    body->Data,
                    body->DataLength,
                    contentType,
                    contentTypeLength);
            }
            else {
                status = ::wknet::session::HttpRequestSetBody(request, body->Data, body->DataLength);
            }
            break;
        case detail::BodyStorageKind::Form:
        {
            ::wknet::HeapArray<::wknet::session::NameValuePair> pairs(body->FormPairCount);
            if (!pairs.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            for (SIZE_T index = 0; index < body->FormPairCount; ++index) {
                pairs[index].Name = body->FormPairs[index].Name;
                pairs[index].NameLength = body->FormPairs[index].NameLength;
                pairs[index].Value = body->FormPairs[index].Value;
                pairs[index].ValueLength = body->FormPairs[index].ValueLength;
            }
            status = ::wknet::session::HttpRequestSetUrlEncodedBody(request, pairs.Get(), body->FormPairCount);
            break;
        }
        case detail::BodyStorageKind::Multipart:
        {
            ::wknet::HeapArray<::wknet::session::MultipartFormDataPart> parts(body->MultipartPartCount);
            if (!parts.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            for (SIZE_T index = 0; index < body->MultipartPartCount; ++index) {
                const MultipartPart& source = body->MultipartParts[index];
                parts[index].Kind = detail::ToApiBodyPartKind(source.Kind);
                parts[index].Name = source.Name;
                parts[index].NameLength = source.NameLength;
                parts[index].Value = source.Value;
                parts[index].ValueLength = source.ValueLength;
                parts[index].Data = source.Data;
                parts[index].DataLength = source.DataLength;
                parts[index].FilePath = source.FilePath;
                parts[index].FilePathLength = source.FilePathLength;
                parts[index].FileName = source.FileName;
                parts[index].FileNameLength = source.FileNameLength;
                parts[index].ContentType = source.ContentType;
                parts[index].ContentTypeLength = source.ContentTypeLength;
            }
            status = ::wknet::session::HttpRequestSetMultipartFormDataBody(
                request,
                parts.Get(),
                body->MultipartPartCount);
            break;
        }
        case detail::BodyStorageKind::File:
            status = ::wknet::session::HttpRequestSetFileBody(
                request,
                body->FilePath,
                body->FilePathLength,
                contentType,
                contentTypeLength);
            break;
        case detail::BodyStorageKind::Stream:
            status = ::wknet::session::HttpRequestSetBodySource(
                request,
                reinterpret_cast<::wknet::session::RequestBodyReadCallback>(body->StreamCallback),
                body->StreamContext,
                body->StreamContentLength,
                body->StreamContentLengthKnown);
            if (NT_SUCCESS(status) && contentType != nullptr) {
                status = ::wknet::session::HttpRequestSetHeader(
                    request,
                    "Content-Type",
                    sizeof("Content-Type") - 1,
                    contentType,
                    contentTypeLength);
            }
            break;
        case detail::BodyStorageKind::Empty:
        default:
            status = ::wknet::session::HttpRequestSetBody(request, nullptr, 0);
            break;
        }

        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ::wknet::session::HttpRequestSetBodyMode(request, detail::ToApiRequestBodyMode(body->Mode));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < body->TrailerCount; ++index) {
            const detail::StoredHeader& trailer = body->Trailers[index];
            status = ::wknet::session::HttpRequestAddTrailer(
                request,
                trailer.Name,
                trailer.NameLength,
                trailer.Value,
                trailer.ValueLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS PrepareRequest(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const Headers* headers,
        const Body* body,
        const SendOptions* options,
        ::wknet::session::RequestHandle* request) noexcept
    {
        if (request != nullptr) {
            *request = nullptr;
        }
        if (!detail::IsValidSession(session) || !IsValidMethod(method) ||
            url == nullptr || urlLength == 0 || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ::wknet::session::RequestHandle apiRequest = nullptr;
        NTSTATUS status = ::wknet::session::HttpRequestCreate(session->Engine, &apiRequest);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ::wknet::session::HttpRequestSetUrl(apiRequest, url, urlLength);
        if (NT_SUCCESS(status)) {
            status = ::wknet::session::HttpRequestSetMethod(apiRequest, detail::ToApiMethod(method));
        }
        if (NT_SUCCESS(status)) {
            status = ApplyOptionsToRequest(apiRequest, options);
        }
        if (NT_SUCCESS(status)) {
            status = ApplyBodyToRequest(apiRequest, body, headers);
        }
        // Apply session default headers first; request headers override on name collision.
        if (NT_SUCCESS(status) && session->DefaultHeaders != nullptr) {
            status = ApplyHeadersToRequest(apiRequest, session->DefaultHeaders, false);
        }
        // Apply session Authorization when the request does not set Authorization.
        if (NT_SUCCESS(status) &&
            session->AuthHeaderValue != nullptr &&
            session->AuthHeaderValueLength != 0 &&
            !FindHeader(headers, "Authorization", nullptr, nullptr) &&
            (session->DefaultHeaders == nullptr ||
             !FindHeader(session->DefaultHeaders, "Authorization", nullptr, nullptr))) {
            status = ::wknet::session::HttpRequestSetHeader(
                apiRequest,
                "Authorization",
                13,
                session->AuthHeaderValue,
                session->AuthHeaderValueLength);
        }
        // Apply Cookie jar contents when the request does not set Cookie.
        if (NT_SUCCESS(status) &&
            !FindHeader(headers, "Cookie", nullptr, nullptr) &&
            (session->DefaultHeaders == nullptr ||
             !FindHeader(session->DefaultHeaders, "Cookie", nullptr, nullptr))) {
            char cookieHeader[8192] = {};
            SIZE_T cookieLength = 0;
            // Wall-clock for Max-Age expiry evaluation (user-mode tests use a fixed value).
#if defined(WKNET_USER_MODE_TEST)
            const ULONGLONG now100ns = 1;
#else
            LARGE_INTEGER t = {};
            KeQuerySystemTimePrecise(&t);
            const ULONGLONG now100ns = static_cast<ULONGLONG>(t.QuadPart);
#endif
            NTSTATUS cookieStatus = ::wknet::session::CookieJarBuildHeader(
                &session->CookieJar,
                url,
                urlLength,
                false,
                now100ns,
                cookieHeader,
                sizeof(cookieHeader),
                &cookieLength);
            if (NT_SUCCESS(cookieStatus) && cookieLength != 0) {
                status = ::wknet::session::HttpRequestSetHeader(
                    apiRequest,
                    "Cookie",
                    6,
                    cookieHeader,
                    cookieLength);
            }
        }
        const bool skipContentType = body != nullptr && FindHeader(headers, "Content-Type", nullptr, nullptr);
        if (NT_SUCCESS(status)) {
            status = ApplyHeadersToRequest(apiRequest, headers, skipContentType);
        }

        if (!NT_SUCCESS(status)) {
            ::wknet::session::HttpRequestRelease(apiRequest);
            return status;
        }

        *request = apiRequest;
        return STATUS_SUCCESS;
    }

    NTSTATUS SendCore(
        Session* session,
        Method method,
        const char* url,
        SIZE_T urlLength,
        const Headers* headers,
        const Body* body,
        const SendOptions* options,
        Response** response) noexcept
    {
        if (response != nullptr) {
            *response = nullptr;
        }
        if (response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        {
            NTSTATUS passive = ::wknet::session::CheckPassiveLevel();
            if (!NT_SUCCESS(passive)) {
                return passive;
            }
        }

        ::wknet::session::RequestHandle apiRequest = nullptr;
        NTSTATUS status = PrepareRequest(session, method, url, urlLength, headers, body, options, &apiRequest);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ::wknet::session::HttpSendOptions apiOptions = {};
        const ::wknet::session::HttpSendOptions* apiOptionsPtr = nullptr;
        if (options != nullptr) {
            FillEngineSendOptions(*options, apiOptions);
            apiOptionsPtr = &apiOptions;
        }

        ::wknet::session::ResponseHandle apiResp = nullptr;
        status = ::wknet::session::HttpSendSync(session->Engine, apiRequest, apiOptionsPtr, &apiResp);
        ::wknet::session::HttpRequestRelease(apiRequest);

        if (NT_SUCCESS(status)) {
            // Apply Set-Cookie response headers to the session cookie jar.
            if (apiResp != nullptr) {
#if defined(WKNET_USER_MODE_TEST)
                const ULONGLONG now100ns = 1;
#else
                LARGE_INTEGER t = {};
                KeQuerySystemTimePrecise(&t);
                const ULONGLONG now100ns = static_cast<ULONGLONG>(t.QuadPart);
#endif
                const SIZE_T headerCount = ::wknet::session::ResponseHeaderCount(apiResp);
                for (SIZE_T hi = 0; hi < headerCount; ++hi) {
                    const char* name = nullptr;
                    SIZE_T nameLength = 0;
                    const char* value = nullptr;
                    SIZE_T valueLength = 0;
                    if (!NT_SUCCESS(::wknet::session::ResponseGetHeaderAt(
                            apiResp, hi, &name, &nameLength, &value, &valueLength))) {
                        continue;
                    }
                    if (nameLength == 10 &&
                        (name[0] == 'S' || name[0] == 's') &&
                        TextEqualsLiteralIgnoreCase(name, nameLength, "Set-Cookie")) {
                        (void)::wknet::session::CookieJarStoreFromSetCookie(
                            &session->CookieJar,
                            url,
                            urlLength,
                            value,
                            valueLength,
                            now100ns);
                    }
                }
            }
            *response = detail::FromApiResponse(apiResp);
        }
        else if (apiResp != nullptr) {
            ::wknet::session::ResponseRelease(apiResp);
        }
        return status;
    }
}

namespace detail
{
void FillApiSendOptions(
    const SendOptions& src,
    ::wknet::session::HttpSendOptions& dst) noexcept
{
    FillEngineSendOptions(src, dst);
}

NTSTATUS PrepareHttpRequest(
    Session* session,
    Method method,
    const char* url,
    SIZE_T urlLength,
    const Headers* headers,
    const Body* body,
    const SendOptions* options,
    ::wknet::session::RequestHandle* request) noexcept
{
    return PrepareRequest(session, method, url, urlLength, headers, body, options, request);
}
}

NTSTATUS Send(Session* session, Method method, const char* url, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept
{
    return SendEx(session, method, url, StringLength(url), headers, body, options, response);
}

NTSTATUS SendEx(Session* session, Method method, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept
{
    return SendCore(session, method, url, urlLength, headers, body, options, response);
}

NTSTATUS Send(Request* request, Method method, const char* url, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept
{
    return SendEx(request, method, url, StringLength(url), headers, body, options, response);
}

NTSTATUS SendEx(Request* request, Method method, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept
{
    return SendCore(detail::SessionFromSendHandle(request), method, url, urlLength, headers, body, options, response);
}

NTSTATUS Get(Session* session, const char* url, Response** response) noexcept { return GetEx(session, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS GetEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Get, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Post(Session* session, const char* url, const Body* body, Response** response) noexcept { return PostEx(session, url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PostEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Post, url, urlLength, headers, body, options, response); }
NTSTATUS Put(Session* session, const char* url, const Body* body, Response** response) noexcept { return PutEx(session, url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PutEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Put, url, urlLength, headers, body, options, response); }
NTSTATUS Patch(Session* session, const char* url, const Body* body, Response** response) noexcept { return PatchEx(session, url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PatchEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Patch, url, urlLength, headers, body, options, response); }
NTSTATUS Delete(Session* session, const char* url, Response** response) noexcept { return DeleteEx(session, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS DeleteEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Delete, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Head(Session* session, const char* url, Response** response) noexcept { return HeadEx(session, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS HeadEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Head, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Options(Session* session, const char* url, Response** response) noexcept { return OptionsEx(session, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS OptionsEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Options, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Trace(Session* session, const char* url, Response** response) noexcept { return TraceEx(session, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS TraceEx(Session* session, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(session, Method::Trace, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Get(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept { return GetEx(session, url, urlLength, nullptr, nullptr, response); }
NTSTATUS Post(Session* session, const char* url, SIZE_T urlLength, const UCHAR* data, SIZE_T dataLength, Response** response) noexcept
{
    Body* body = nullptr;
    NTSTATUS status = BodyCreateBytes(data, dataLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = PostEx(session, url, urlLength, nullptr, body, nullptr, response);
    BodyRelease(body);
    return status;
}
NTSTATUS Put(Session* session, const char* url, SIZE_T urlLength, const UCHAR* data, SIZE_T dataLength, Response** response) noexcept
{
    Body* body = nullptr;
    NTSTATUS status = BodyCreateBytes(data, dataLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = PutEx(session, url, urlLength, nullptr, body, nullptr, response);
    BodyRelease(body);
    return status;
}
NTSTATUS Patch(Session* session, const char* url, SIZE_T urlLength, const UCHAR* data, SIZE_T dataLength, Response** response) noexcept
{
    Body* body = nullptr;
    NTSTATUS status = BodyCreateBytes(data, dataLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = PatchEx(session, url, urlLength, nullptr, body, nullptr, response);
    BodyRelease(body);
    return status;
}
NTSTATUS Delete(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept { return DeleteEx(session, url, urlLength, nullptr, nullptr, response); }
NTSTATUS Head(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept { return HeadEx(session, url, urlLength, nullptr, nullptr, response); }
NTSTATUS Options(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept { return OptionsEx(session, url, urlLength, nullptr, nullptr, response); }
NTSTATUS Trace(Session* session, const char* url, SIZE_T urlLength, Response** response) noexcept { return TraceEx(session, url, urlLength, nullptr, nullptr, response); }

NTSTATUS Send(Request* request, Response** response) noexcept
{
    return SendEx(request, nullptr, response);
}

NTSTATUS Send(Request* request, const SendOptions* options, Response** response) noexcept
{
    return SendEx(request, options, response);
}

NTSTATUS SendEx(Request* request, const SendOptions* options, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    {
        NTSTATUS passive = ::wknet::session::CheckPassiveLevel();
        if (!NT_SUCCESS(passive)) {
            return passive;
        }
    }
    if (request == nullptr || request->Magic != detail::HighRequestMagic ||
        request->Closed != 0 ||
        request->BuilderUrl == nullptr || request->BuilderUrlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Session* session = request->Parent;
    bool ownsSession = false;
    if (session == nullptr) {
        NTSTATUS status = detail::AcquireTransientSession(&session);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        ownsSession = true;
    } else if (!detail::IsValidSession(session)) {
        return STATUS_INVALID_PARAMETER;
    }

    SendOptions mergedOptions = options != nullptr ? *options : DefaultSendOptions();
    const SendOptions* effectiveOptions = nullptr;
    if (request->BuilderOptions != nullptr) {
        if (request->BuilderOptions->HasTlsOverride) {
            mergedOptions.Tls = request->BuilderOptions->Tls;
            mergedOptions.HasTlsOverride = true;
        }
        mergedOptions.ConnectionPolicy = request->BuilderOptions->ConnectionPolicy;
        mergedOptions.Family = request->BuilderOptions->Family;
        mergedOptions.AcceptEncodingPreferences = request->BuilderOptions->AcceptEncodingPreferences;
        mergedOptions.AcceptEncodingPreferenceCount = request->BuilderOptions->AcceptEncodingPreferenceCount;
        effectiveOptions = &mergedOptions;
    } else if (options != nullptr) {
        effectiveOptions = &mergedOptions;
    }

    NTSTATUS status = SendCore(
        session,
        request->BuilderMethod,
        request->BuilderUrl,
        request->BuilderUrlLength,
        request->BuilderHeaders,
        request->BuilderBody,
        effectiveOptions,
        response);

    if (ownsSession) {
        detail::ReleaseTransientSession(session);
    }
    return status;
}

NTSTATUS Send(Session* session, Request* request, Response** response) noexcept
{
    return SendEx(session, request, nullptr, response);
}

NTSTATUS Send(Session* session, Request* request, const SendOptions* options, Response** response) noexcept
{
    return SendEx(session, request, options, response);
}

NTSTATUS SendEx(Session* session, Request* request, const SendOptions* options, Response** response) noexcept
{
    if (request == nullptr || request->Magic != detail::HighRequestMagic) {
        if (response != nullptr) {
            *response = nullptr;
        }
        return STATUS_INVALID_PARAMETER;
    }
    if (session != nullptr && request->Parent != nullptr && session != request->Parent) {
        if (response != nullptr) {
            *response = nullptr;
        }
        return STATUS_INVALID_PARAMETER;
    }
    if (request->Parent == nullptr && session != nullptr) {
        Session* previous = request->Parent;
        request->Parent = session;
        NTSTATUS status = SendEx(request, options, response);
        request->Parent = previous;
        return status;
    }
    return SendEx(request, options, response);
}

NTSTATUS Send(Method method, const char* url, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept
{
    return SendEx(method, url, StringLength(url), headers, body, options, response);
}

NTSTATUS SendEx(Method method, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept
{
    if (response != nullptr) {
        *response = nullptr;
    }
    Session* session = nullptr;
    NTSTATUS status = detail::AcquireTransientSession(&session);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = SendCore(session, method, url, urlLength, headers, body, options, response);
    detail::ReleaseTransientSession(session);
    return status;
}

NTSTATUS Get(const char* url, Response** response) noexcept { return GetEx(url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS GetEx(const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(Method::Get, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Post(const char* url, const Body* body, Response** response) noexcept { return PostEx(url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PostEx(const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(Method::Post, url, urlLength, headers, body, options, response); }
NTSTATUS Put(const char* url, const Body* body, Response** response) noexcept { return PutEx(url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PutEx(const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(Method::Put, url, urlLength, headers, body, options, response); }
NTSTATUS Patch(const char* url, const Body* body, Response** response) noexcept { return PatchEx(url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PatchEx(const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(Method::Patch, url, urlLength, headers, body, options, response); }
NTSTATUS Delete(const char* url, Response** response) noexcept { return DeleteEx(url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS DeleteEx(const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(Method::Delete, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Head(const char* url, Response** response) noexcept { return HeadEx(url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS HeadEx(const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(Method::Head, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Options(const char* url, Response** response) noexcept { return OptionsEx(url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS OptionsEx(const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(Method::Options, url, urlLength, headers, nullptr, options, response); }


NTSTATUS Get(Request* request, const char* url, Response** response) noexcept { return GetEx(request, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS GetEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Get, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Post(Request* request, const char* url, const Body* body, Response** response) noexcept { return PostEx(request, url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PostEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Post, url, urlLength, headers, body, options, response); }
NTSTATUS Put(Request* request, const char* url, const Body* body, Response** response) noexcept { return PutEx(request, url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PutEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Put, url, urlLength, headers, body, options, response); }
NTSTATUS Patch(Request* request, const char* url, const Body* body, Response** response) noexcept { return PatchEx(request, url, StringLength(url), nullptr, body, nullptr, response); }
NTSTATUS PatchEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const Body* body, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Patch, url, urlLength, headers, body, options, response); }
NTSTATUS Delete(Request* request, const char* url, Response** response) noexcept { return DeleteEx(request, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS DeleteEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Delete, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Head(Request* request, const char* url, Response** response) noexcept { return HeadEx(request, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS HeadEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Head, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Options(Request* request, const char* url, Response** response) noexcept { return OptionsEx(request, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS OptionsEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Options, url, urlLength, headers, nullptr, options, response); }
NTSTATUS Trace(Request* request, const char* url, Response** response) noexcept { return TraceEx(request, url, StringLength(url), nullptr, nullptr, response); }
NTSTATUS TraceEx(Request* request, const char* url, SIZE_T urlLength, const Headers* headers, const SendOptions* options, Response** response) noexcept { return SendEx(request, Method::Trace, url, urlLength, headers, nullptr, options, response); }
}
